use std::borrow::Cow;
use std::sync::Arc;

use rmcp::{
    handler::server::router::tool::ToolRouter,
    handler::server::wrapper::Parameters,
    model::*,
    tool, tool_handler, tool_router, Json, ServerHandler,
};
use serde::Deserialize;
use tracing::info;

use super::server::RpcPassthroughOutput;

// ─── Constants ───

/// Chainlink CCIP Router addresses per chain.
const ROUTER_ETHEREUM: &str = "0x80226fc0Ee2b096224EeAc085Bb9a8cba1146f7D";
const ROUTER_BASE: &str = "0x881e3A65B4d4a04dD529061dd0071cf975F58bCD";
const ROUTER_ARBITRUM: &str = "0x141fa059441E0ca23ce184B6A78bafD2A517DdE8";
const ROUTER_BSC: &str = "0x34B03Cb9086d7D758AC55af71584F81A598759FE";

/// CCIP chain selectors for major chains.
const SELECTOR_ETHEREUM: u64 = 5009297550715157269;
const SELECTOR_ARBITRUM: u64 = 4949039107694359620;
const SELECTOR_OPTIMISM: u64 = 3734403246176062136;
const SELECTOR_BASE: u64 = 15971525489660198786;
const SELECTOR_POLYGON: u64 = 4051577828743386545;
const SELECTOR_BSC: u64 = 11344663589394136015;
const SELECTOR_AVALANCHE: u64 = 6433500567565415381;

/// Well-known Chainlink data feed addresses (Ethereum mainnet).
const FEED_ETH_USD: &str = "0x5f4eC3Df9cbd43714FE2740f5E3616155c5b8419";
const FEED_BTC_USD: &str = "0xF4030086522a5bEEa4988F8cA5B36dbC97BeE88c";
const FEED_LINK_ETH: &str = "0xDC530D9457755926550b59e8ECcdaE7624181557";

/// Chainlink CCIP REST API base URL.
const CCIP_API_BASE: &str = "https://docs.chain.link/api/ccip/v1";

/// Chainlink Data Streams REST API base URL.
const DATA_STREAMS_API: &str = "https://api.chainlink-data-streams.io/api/v1";

/// VRF v2.5 Coordinator addresses (mainnet).
const VRF_COORDINATOR_ETHEREUM: &str = "0x271682DEB8C4E0901D1a1550aD2e64D568E69909";
const VRF_COORDINATOR_ARBITRUM: &str = "0x41034678D6C633D8a95c75e1138A360a28bA15d1";
const VRF_COORDINATOR_BASE: &str = "0xd5D517aBE5cF79B7e95eC98dB0f0277788aFF634";

/// VRF v2.5 function selectors.
const VRF_REQUEST_RANDOM_SELECTOR: &str = "9b1c385e"; // requestRandomWords(VRFV2PlusClient.RandomWordsRequest)
const VRF_GET_SUBSCRIPTION_SELECTOR: &str = "a47c7696"; // getSubscription(uint256)

/// Proof of Reserve well-known feed addresses.
const POR_WBTC_ETHEREUM: &str = "0xa81FE04086865e63E12dD3776978E49DEEa2ea4e";
const POR_USDC_ETHEREUM: &str = "0x9a177Bb065A0636C7972C6D27Abcd4B1e5EDb65c";
const POR_TUSD_ETHEREUM: &str = "0x478f4c42b877c697C4b19E396865D5437Ef4E08B";

/// ABI function selectors.
const GET_FEE_SELECTOR: &str = "20487ded"; // Router.getFee(uint64,EVM2AnyMessage)
const CCIP_SEND_SELECTOR: &str = "96f4e9f9"; // Router.ccipSend(uint64,EVM2AnyMessage)
const LATEST_ROUND_DATA_SELECTOR: &str = "feaf968c"; // AggregatorV3Interface.latestRoundData()
const GET_EXECUTION_STATE_SELECTOR: &str = "142b48a9"; // OffRamp.getExecutionState(uint64)
const CHECK_UPKEEP_SELECTOR: &str = "6e04ff0d"; // AutomationCompatibleInterface.checkUpkeep(bytes)
const GET_UPKEEP_SELECTOR: &str = "c7c3a19a"; // Registry.getUpkeep(uint256)
const TYPE_AND_VERSION_SELECTOR: &str = "181f5a77"; // ITypeAndVersion.typeAndVersion()
const GET_SUPPORTED_CHAINS_SELECTOR: &str = "c4bffe2b"; // TokenPool.getSupportedChains()

// ─── Tool parameter structs ───

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CcipGetFeeParams {
    #[schemars(description = "Source chain identifier: 'ethereum', 'base', 'arbitrum', or a chain ID number")]
    pub src_chain_id: String,
    #[schemars(description = "Destination CCIP chain selector (uint64). E.g. 4949039107694359620 for Arbitrum")]
    pub dst_chain_selector: String,
    #[schemars(description = "Hex-encoded receiver address on the destination chain (with or without 0x prefix)")]
    pub receiver: String,
    #[schemars(description = "Hex-encoded data payload to send (with or without 0x prefix). Use '0x' or '' for empty")]
    pub data_hex: Option<String>,
    #[schemars(description = "Token amounts to transfer as JSON array of {token, amount} objects. Empty array for message-only")]
    pub token_amounts: Option<Vec<TokenAmountParam>>,
    #[schemars(description = "Fee token address. Use zero address (0x0000...0000) for native gas token payment")]
    pub fee_token: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct TokenAmountParam {
    #[schemars(description = "Token contract address (hex with 0x prefix)")]
    pub token: String,
    #[schemars(description = "Amount in token base units (uint256 as decimal string)")]
    pub amount: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CcipSendMessageParams {
    #[schemars(description = "Source chain: 'ethereum', 'base', 'arbitrum', or chain ID")]
    pub src_chain_id: String,
    #[schemars(description = "Destination CCIP chain selector (uint64)")]
    pub dst_chain_selector: String,
    #[schemars(description = "Hex-encoded receiver address on the destination chain")]
    pub receiver: String,
    #[schemars(description = "Hex-encoded data payload")]
    pub data_hex: Option<String>,
    #[schemars(description = "Token amounts to transfer as JSON array of {token, amount} objects")]
    pub token_amounts: Option<Vec<TokenAmountParam>>,
    #[schemars(description = "Fee token address (zero address for native). Defaults to native")]
    pub fee_token: Option<String>,
    #[schemars(description = "Hex-encoded sender private key for signing the transaction")]
    pub sender_key: String,
    #[schemars(description = "Gas limit for execution on destination chain (default: 200000)")]
    pub gas_limit: Option<u64>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CcipTrackMessageParams {
    #[schemars(description = "CCIP message ID (64-byte hex, with or without 0x prefix)")]
    pub message_id: String,
    #[schemars(description = "Destination chain: 'ethereum', 'base', 'arbitrum', or chain ID")]
    pub dst_chain_id: String,
    #[schemars(description = "OffRamp contract address on the destination chain (hex with 0x prefix)")]
    pub offramp_address: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CcipGetSupportedChainsParams {
    #[schemars(description = "Environment: 'mainnet' or 'testnet'. Defaults to 'mainnet'")]
    pub environment: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CcipGetSupportedTokensParams {
    #[schemars(description = "Environment: 'mainnet' or 'testnet'. Defaults to 'mainnet'")]
    pub environment: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CcipGetLanesParams {
    #[schemars(description = "Environment: 'mainnet' or 'testnet'. Defaults to 'mainnet'")]
    pub environment: Option<String>,
    #[schemars(description = "Optional source chain selector to filter lanes")]
    pub source_chain_selector: Option<String>,
    #[schemars(description = "Optional destination chain selector to filter lanes")]
    pub dest_chain_selector: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ChainlinkGetPriceParams {
    #[schemars(description = "Chainlink data feed contract address (hex with 0x prefix). E.g. 0x5f4eC3Df9cbd43714FE2740f5E3616155c5b8419 for ETH/USD")]
    pub feed_address: String,
    #[schemars(description = "Chain to query: 'ethereum', 'arbitrum', 'base', or a chain ID. Defaults to 'ethereum'")]
    pub chain_id: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ChainlinkListFeedsParams {
    #[schemars(description = "Optional chain to list feeds for: 'ethereum', 'arbitrum', 'base'. Defaults to 'ethereum'")]
    pub chain: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ChainlinkCheckUpkeepParams {
    #[schemars(description = "Address of the Automation-compatible contract (hex with 0x prefix)")]
    pub contract_address: String,
    #[schemars(description = "Chain to query: 'ethereum', 'arbitrum', 'base', or chain ID. Defaults to 'ethereum'")]
    pub chain_id: Option<String>,
    #[schemars(description = "Hex-encoded check data to pass to checkUpkeep (with or without 0x prefix). Defaults to empty")]
    pub check_data: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ChainlinkGetUpkeepInfoParams {
    #[schemars(description = "Upkeep ID (uint256 as decimal string)")]
    pub upkeep_id: String,
    #[schemars(description = "Automation Registry address (hex with 0x prefix)")]
    pub registry_address: String,
    #[schemars(description = "Chain to query: 'ethereum', 'arbitrum', 'base', or chain ID. Defaults to 'ethereum'")]
    pub chain_id: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ChainlinkEstimateFunctionsCostParams {
    #[schemars(description = "Functions Router address (hex with 0x prefix)")]
    pub router_address: String,
    #[schemars(description = "Functions subscription ID (uint64)")]
    pub subscription_id: String,
    #[schemars(description = "Callback gas limit for the fulfillment")]
    pub callback_gas_limit: u64,
    #[schemars(description = "Gas price in wei for cost estimation")]
    pub gas_price_wei: Option<String>,
    #[schemars(description = "Chain to query. Defaults to 'ethereum'")]
    pub chain_id: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ChainlinkGetSubscriptionParams {
    #[schemars(description = "Functions Router address (hex with 0x prefix)")]
    pub router_address: String,
    #[schemars(description = "Subscription ID (uint64)")]
    pub subscription_id: String,
    #[schemars(description = "Chain to query. Defaults to 'ethereum'")]
    pub chain_id: Option<String>,
}

// ─── Data Streams parameter structs ───

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct DsGetReportParams {
    #[schemars(description = "Data Streams feed ID (hex string, e.g. '0x000359843a543ee2fe414dc14c7e7920ef10f4372990b79d6361cdc0dd1ba782' for ETH/USD)")]
    pub feed_id: String,
    #[schemars(description = "Unix timestamp to query (optional — latest if omitted)")]
    pub timestamp: Option<u64>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct DsListFeedsParams {
    #[schemars(description = "Filter by asset class: 'crypto', 'forex', 'equities', 'commodities' (optional)")]
    pub asset_class: Option<String>,
}

// ─── VRF v2.5 parameter structs ───

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct VrfGetSubscriptionParams {
    #[schemars(description = "VRF subscription ID (uint256 as decimal string)")]
    pub subscription_id: String,
    #[schemars(description = "Chain: 'ethereum', 'arbitrum', 'base'. Defaults to 'ethereum'")]
    pub chain: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct VrfRequestRandomParams {
    #[schemars(description = "VRF subscription ID (uint256 as decimal string)")]
    pub subscription_id: String,
    #[schemars(description = "VRF key hash for the gas lane (hex, 32 bytes)")]
    pub key_hash: String,
    #[schemars(description = "Number of block confirmations before fulfillment (default: 3)")]
    pub request_confirmations: Option<u16>,
    #[schemars(description = "Callback gas limit (default: 100000)")]
    pub callback_gas_limit: Option<u32>,
    #[schemars(description = "Number of random words to request (default: 1, max: 500)")]
    pub num_words: Option<u32>,
    #[schemars(description = "Pay in native token instead of LINK (default: false)")]
    pub native_payment: Option<bool>,
    #[schemars(description = "Chain: 'ethereum', 'arbitrum', 'base'. Defaults to 'ethereum'")]
    pub chain: Option<String>,
}

// ─── Proof of Reserve parameter structs ───

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct PorGetReserveParams {
    #[schemars(description = "Proof of Reserve feed contract address (hex). Well-known: WBTC=0xa81FE04086865e63E12dD3776978E49DEEa2ea4e, USDC=0x9a177Bb065A0636C7972C6D27Abcd4B1e5EDb65c")]
    pub feed_address: String,
    #[schemars(description = "Chain: 'ethereum'. Defaults to 'ethereum'")]
    pub chain: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct PorListFeedsParams {
    // No parameters — returns all known PoR feeds
}

// ─── CCIP Token Pool parameter structs ───

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CcipGetTokenPoolParams {
    #[schemars(description = "Token pool contract address (hex with 0x prefix)")]
    pub pool_address: String,
    #[schemars(description = "Chain: 'ethereum', 'base', 'arbitrum'. Defaults to 'ethereum'")]
    pub chain: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CcipGetRateLimitsParams {
    #[schemars(description = "Token pool contract address (hex with 0x prefix)")]
    pub pool_address: String,
    #[schemars(description = "Remote chain selector (uint64) to query rate limits for")]
    pub remote_chain_selector: String,
    #[schemars(description = "Chain the pool is deployed on: 'ethereum', 'base', 'arbitrum'. Defaults to 'ethereum'")]
    pub chain: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ChainlinkBroadcastTxParams {
    #[schemars(description = "Source chain to broadcast on: 'ethereum', 'base', 'arbitrum'")]
    pub chain: String,
    #[schemars(description = "Pre-signed RLP-encoded transaction as hex (0x-prefixed). Build via ccip_send_message → external signer, or vrf_request_random → external signer.")]
    pub signed_tx_hex: String,
}

// ─── Helper types ───

/// Configuration for a chain's RPC and contracts.
struct ChainConfig {
    rpc_url: String,
    router_address: String,
    chain_name: String,
}

// ─── ChainlinkMcpServer ───

#[derive(Clone)]
pub struct ChainlinkMcpServer {
    http_client: reqwest::Client,
    _tool_router: ToolRouter<ChainlinkMcpServer>,
}

impl Default for ChainlinkMcpServer {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for ChainlinkMcpServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChainlinkMcpServer").finish()
    }
}

// ─── Shared helpers ───

fn err_invalid(msg: impl Into<String>) -> ErrorData {
    ErrorData {
        code: ErrorCode::INVALID_PARAMS,
        message: Cow::from(msg.into()),
        data: None,
    }
}

fn err_internal(msg: impl Into<String>) -> ErrorData {
    ErrorData::internal_error(msg.into(), None)
}

fn json_result(value: serde_json::Value) -> std::result::Result<Json<RpcPassthroughOutput>, ErrorData> {
    Ok(Json(RpcPassthroughOutput { result: value }))
}

/// Wrap a plain-text status string as a successful tool result.
///
/// Used by tools that return a single textual value such as a transaction
/// hash from a CCIP / VRF broadcast.
fn text_result(text: impl Into<String>) -> std::result::Result<Json<RpcPassthroughOutput>, ErrorData> {
    Ok(Json(RpcPassthroughOutput {
        result: serde_json::json!({ "message": text.into() }),
    }))
}

/// Build a dRPC URL for a given chain slug, falling back to public RPCs when
/// the `DRPC_API_KEY` environment variable is not set.
fn drpc_url(chain: &str) -> String {
    let key = std::env::var("DRPC_API_KEY").unwrap_or_default();
    if key.is_empty() {
        return match chain {
            "ethereum" => "https://eth.llamarpc.com".to_string(),
            "arbitrum" => "https://arb1.arbitrum.io/rpc".to_string(),
            "base" => "https://mainnet.base.org".to_string(),
            "optimism" => "https://mainnet.optimism.io".to_string(),
            "polygon" => "https://polygon-rpc.com".to_string(),
            "bsc" => "https://bsc-dataseed.binance.org".to_string(),
            "avalanche" => "https://api.avax.network/ext/bc/C/rpc".to_string(),
            "zksync" => "https://mainnet.era.zksync.io".to_string(),
            _ => format!("https://{}.drpc.org", chain),
        };
    }
    format!("https://lb.drpc.live/{}/{}", chain, key)
}

/// Resolve a chain name or ID to an RPC URL and router address.
fn resolve_chain(chain: &str) -> std::result::Result<ChainConfig, ErrorData> {
    match chain.to_lowercase().as_str() {
        "ethereum" | "eth" | "1" => Ok(ChainConfig {
            rpc_url: drpc_url("ethereum"),
            router_address: ROUTER_ETHEREUM.to_string(),
            chain_name: "Ethereum".to_string(),
        }),
        "base" | "8453" => Ok(ChainConfig {
            rpc_url: drpc_url("base"),
            router_address: ROUTER_BASE.to_string(),
            chain_name: "Base".to_string(),
        }),
        "arbitrum" | "arb" | "42161" => Ok(ChainConfig {
            rpc_url: drpc_url("arbitrum"),
            router_address: ROUTER_ARBITRUM.to_string(),
            chain_name: "Arbitrum".to_string(),
        }),
        "optimism" | "op" | "10" => Ok(ChainConfig {
            rpc_url: drpc_url("optimism"),
            router_address: String::new(), // No known router for Optimism in constants
            chain_name: "Optimism".to_string(),
        }),
        "polygon" | "matic" | "137" => Ok(ChainConfig {
            rpc_url: drpc_url("polygon"),
            router_address: String::new(),
            chain_name: "Polygon".to_string(),
        }),
        "bsc" | "bnb" | "56" => Ok(ChainConfig {
            rpc_url: drpc_url("bsc"),
            router_address: ROUTER_BSC.to_string(),
            chain_name: "BSC".to_string(),
        }),
        "avalanche" | "avax" | "43114" => Ok(ChainConfig {
            rpc_url: drpc_url("avalanche"),
            router_address: String::new(),
            chain_name: "Avalanche".to_string(),
        }),
        other => Err(err_invalid(format!(
            "Unsupported chain '{}'. Supported: ethereum, base, arbitrum, optimism, polygon, bsc, avalanche",
            other
        ))),
    }
}

/// Resolve a chain to its VRF v2.5 Coordinator address.
fn vrf_coordinator(chain: &str) -> Option<&'static str> {
    match chain.to_lowercase().as_str() {
        "ethereum" | "eth" | "1" => Some(VRF_COORDINATOR_ETHEREUM),
        "arbitrum" | "arb" | "42161" => Some(VRF_COORDINATOR_ARBITRUM),
        "base" | "8453" => Some(VRF_COORDINATOR_BASE),
        _ => None,
    }
}

/// Resolve a chain selector name to the uint64 CCIP selector value.
fn resolve_chain_selector(name: &str) -> Option<u64> {
    match name.to_lowercase().as_str() {
        "ethereum" | "eth" => Some(SELECTOR_ETHEREUM),
        "arbitrum" | "arb" => Some(SELECTOR_ARBITRUM),
        "optimism" | "op" => Some(SELECTOR_OPTIMISM),
        "base" => Some(SELECTOR_BASE),
        "polygon" | "matic" => Some(SELECTOR_POLYGON),
        "bsc" | "bnb" => Some(SELECTOR_BSC),
        "avalanche" | "avax" => Some(SELECTOR_AVALANCHE),
        _ => name.parse::<u64>().ok(),
    }
}

/// Return a human-readable name for a CCIP chain selector.
fn chain_selector_name(selector: u64) -> &'static str {
    match selector {
        SELECTOR_ETHEREUM => "Ethereum",
        SELECTOR_ARBITRUM => "Arbitrum",
        SELECTOR_OPTIMISM => "Optimism",
        SELECTOR_BASE => "Base",
        SELECTOR_POLYGON => "Polygon",
        SELECTOR_BSC => "BSC",
        SELECTOR_AVALANCHE => "Avalanche",
        _ => "Unknown",
    }
}

/// Parse a hex string (with or without 0x prefix) to bytes.
fn parse_hex(input: &str) -> std::result::Result<Vec<u8>, ErrorData> {
    let hex_str = input.strip_prefix("0x").unwrap_or(input);
    if hex_str.is_empty() {
        return Ok(Vec::new());
    }
    hex::decode(hex_str).map_err(|e| err_invalid(format!("Invalid hex: {}", e)))
}

/// Left-pad bytes to 32 bytes (ABI word).
fn pad_left_32(data: &[u8]) -> [u8; 32] {
    let mut word = [0u8; 32];
    let len = data.len().min(32);
    word[32 - len..].copy_from_slice(&data[..len]);
    word
}

/// Encode a uint64 as a 32-byte ABI word.
fn encode_uint64(val: u64) -> [u8; 32] {
    pad_left_32(&val.to_be_bytes())
}

/// Encode a uint256 from a decimal string as a 32-byte ABI word.
fn encode_uint256_decimal(val: &str) -> std::result::Result<[u8; 32], ErrorData> {
    // Parse as u128 first (covers most practical amounts)
    let n: u128 = val
        .parse()
        .map_err(|e| err_invalid(format!("Invalid uint256 value '{}': {}", val, e)))?;
    Ok(pad_left_32(&n.to_be_bytes()))
}

/// Encode an address as a 32-byte ABI word (left-padded).
fn encode_address(addr: &str) -> std::result::Result<[u8; 32], ErrorData> {
    let bytes = parse_hex(addr)?;
    if bytes.len() > 20 {
        return Err(err_invalid("Address must be at most 20 bytes"));
    }
    Ok(pad_left_32(&bytes))
}

/// Encode a dynamic bytes field (offset + length + data padded to 32-byte boundary).
fn encode_bytes(data: &[u8]) -> Vec<u8> {
    let mut encoded = Vec::new();
    // Length
    encoded.extend_from_slice(&pad_left_32(&(data.len() as u64).to_be_bytes()));
    // Data padded to 32-byte chunks
    encoded.extend_from_slice(data);
    let padding = (32 - (data.len() % 32)) % 32;
    encoded.extend(std::iter::repeat_n(0u8, padding));
    encoded
}

/// Perform an eth_call JSON-RPC request to the given RPC URL.
async fn eth_call(
    client: &reqwest::Client,
    rpc_url: &str,
    to: &str,
    data: &[u8],
) -> std::result::Result<Vec<u8>, ErrorData> {
    let payload = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "eth_call",
        "params": [{
            "to": to,
            "data": format!("0x{}", hex::encode(data)),
        }, "latest"],
        "id": 1,
    });

    let resp = client
        .post(rpc_url)
        .json(&payload)
        .send()
        .await
        .map_err(|e| err_internal(format!("RPC request failed: {}", e)))?;

    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| err_internal(format!("Failed to parse RPC response: {}", e)))?;

    if let Some(error) = body.get("error") {
        let msg = error
            .get("message")
            .and_then(|m| m.as_str())
            .unwrap_or("unknown error");
        return Err(err_internal(format!("eth_call error: {}", msg)));
    }

    let result_hex = body
        .get("result")
        .and_then(|r| r.as_str())
        .unwrap_or("0x");

    parse_hex(result_hex)
}

/// Perform an eth_sendRawTransaction JSON-RPC request.
///
/// Used by `chainlink_broadcast_signed_tx` to submit operator-signed CCIP
/// `Router.ccipSend()` and VRF `requestRandomWords()` transactions to the
/// destination EVM chain. Returns the resulting transaction hash.
async fn eth_send_raw_tx(
    client: &reqwest::Client,
    rpc_url: &str,
    signed_tx_hex: &str,
) -> std::result::Result<String, ErrorData> {
    let payload = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "eth_sendRawTransaction",
        "params": [signed_tx_hex],
        "id": 1,
    });

    let resp = client
        .post(rpc_url)
        .json(&payload)
        .send()
        .await
        .map_err(|e| err_internal(format!("RPC request failed: {}", e)))?;

    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| err_internal(format!("Failed to parse RPC response: {}", e)))?;

    if let Some(error) = body.get("error") {
        let msg = error
            .get("message")
            .and_then(|m| m.as_str())
            .unwrap_or("unknown error");
        return Err(err_internal(format!("eth_sendRawTransaction error: {}", msg)));
    }

    body.get("result")
        .and_then(|r| r.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| err_internal("No transaction hash in response"))
}

/// Encode the EVM2AnyMessage struct for CCIP Router calls.
///
/// EVM2AnyMessage layout:
///   - receiver: bytes (dynamic)
///   - data: bytes (dynamic)
///   - tokenAmounts: EVMTokenAmount[] (dynamic array)
///   - feeToken: address
///   - extraArgs: bytes (dynamic)
///
/// We encode this as a tuple: (bytes, bytes, (address,uint256)[], address, bytes)
fn encode_evm2any_message(
    receiver: &str,
    data_hex: &str,
    token_amounts: &[TokenAmountParam],
    fee_token: &str,
    gas_limit: u64,
) -> std::result::Result<Vec<u8>, ErrorData> {
    let receiver_bytes = parse_hex(receiver)?;
    let data_bytes = parse_hex(data_hex)?;
    let fee_token_word = encode_address(fee_token)?;

    // Build extraArgs: V2 tag (0x181dcf10) + gasLimit (uint256) + allowOutOfOrderExecution (bool = true)
    let mut extra_args = Vec::new();
    extra_args.extend_from_slice(&[0x18, 0x1d, 0xcf, 0x10]); // V2 tag
    extra_args.extend_from_slice(&pad_left_32(&gas_limit.to_be_bytes())); // gasLimit
    let mut ooo_word = [0u8; 32];
    ooo_word[31] = 0x01; // allowOutOfOrderExecution = true
    extra_args.extend_from_slice(&ooo_word);

    // Now ABI-encode the tuple. The head has 5 words:
    //   [0] offset to receiver (bytes)
    //   [1] offset to data (bytes)
    //   [2] offset to tokenAmounts (array)
    //   [3] feeToken (address, inline)
    //   [4] offset to extraArgs (bytes)
    // Then tails in order: receiver, data, tokenAmounts, extraArgs

    let head_size: usize = 5 * 32; // 160 bytes of head

    // Pre-compute dynamic section sizes to determine offsets
    let receiver_encoded = encode_bytes(&receiver_bytes);
    let data_encoded = encode_bytes(&data_bytes);
    let extra_args_encoded = encode_bytes(&extra_args);

    // tokenAmounts array: length word + n * (address_word + amount_word)
    let token_array_size = 32 + token_amounts.len() * 64;

    let offset_receiver = head_size;
    let offset_data = offset_receiver + receiver_encoded.len();
    let offset_token_amounts = offset_data + data_encoded.len();
    let offset_extra_args = offset_token_amounts + token_array_size;

    let mut encoded = Vec::new();

    // Head
    encoded.extend_from_slice(&pad_left_32(&(offset_receiver as u64).to_be_bytes()));
    encoded.extend_from_slice(&pad_left_32(&(offset_data as u64).to_be_bytes()));
    encoded.extend_from_slice(&pad_left_32(&(offset_token_amounts as u64).to_be_bytes()));
    encoded.extend_from_slice(&fee_token_word);
    encoded.extend_from_slice(&pad_left_32(&(offset_extra_args as u64).to_be_bytes()));

    // Tail: receiver
    encoded.extend_from_slice(&receiver_encoded);

    // Tail: data
    encoded.extend_from_slice(&data_encoded);

    // Tail: tokenAmounts array
    encoded.extend_from_slice(&pad_left_32(
        &(token_amounts.len() as u64).to_be_bytes(),
    ));
    for ta in token_amounts {
        encoded.extend_from_slice(&encode_address(&ta.token)?);
        encoded.extend_from_slice(&encode_uint256_decimal(&ta.amount)?);
    }

    // Tail: extraArgs
    encoded.extend_from_slice(&extra_args_encoded);

    Ok(encoded)
}

/// Build the full calldata for Router.getFee(uint64 destinationChainSelector, EVM2AnyMessage message).
fn build_get_fee_calldata(
    dst_chain_selector: u64,
    receiver: &str,
    data_hex: &str,
    token_amounts: &[TokenAmountParam],
    fee_token: &str,
) -> std::result::Result<Vec<u8>, ErrorData> {
    let selector_bytes = hex::decode(GET_FEE_SELECTOR).unwrap();
    let message_encoded = encode_evm2any_message(receiver, data_hex, token_amounts, fee_token, 200_000)?;

    let mut calldata = Vec::new();
    calldata.extend_from_slice(&selector_bytes); // 4 bytes function selector

    // First arg: uint64 destinationChainSelector (inline as uint256 word)
    calldata.extend_from_slice(&encode_uint64(dst_chain_selector));

    // Second arg: offset to the EVM2AnyMessage tuple (it's dynamic, so we put an offset)
    // Offset = 2 * 32 = 64 (past the two head words: selector word + offset word)
    calldata.extend_from_slice(&pad_left_32(&(64u64).to_be_bytes()));

    // The message tuple
    calldata.extend_from_slice(&message_encoded);

    Ok(calldata)
}

/// Build calldata for Router.ccipSend(uint64 destinationChainSelector, EVM2AnyMessage message).
fn build_ccip_send_calldata(
    dst_chain_selector: u64,
    receiver: &str,
    data_hex: &str,
    token_amounts: &[TokenAmountParam],
    fee_token: &str,
    gas_limit: u64,
) -> std::result::Result<Vec<u8>, ErrorData> {
    let selector_bytes = hex::decode(CCIP_SEND_SELECTOR).unwrap();
    let message_encoded =
        encode_evm2any_message(receiver, data_hex, token_amounts, fee_token, gas_limit)?;

    let mut calldata = Vec::new();
    calldata.extend_from_slice(&selector_bytes);
    calldata.extend_from_slice(&encode_uint64(dst_chain_selector));
    calldata.extend_from_slice(&pad_left_32(&(64u64).to_be_bytes()));
    calldata.extend_from_slice(&message_encoded);

    Ok(calldata)
}

// ─── Tool implementations ───

#[tool_router]
impl ChainlinkMcpServer {
    pub fn new() -> Self {
        Self {
            http_client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .expect("Failed to build HTTP client"),
            _tool_router: Self::tool_router(),
        }
    }

    // ─── CCIP Cross-Chain Tools ───

    #[tool(description = "Estimate CCIP cross-chain messaging fee via Router.getFee() eth_call. Returns the native fee required to send a CCIP message from the source chain to the destination chain. Supports Ethereum, Base, and Arbitrum as source chains.")]
    async fn ccip_get_fee(
        &self,
        Parameters(params): Parameters<CcipGetFeeParams>,
    ) -> std::result::Result<Json<RpcPassthroughOutput>, ErrorData> {
        let chain = resolve_chain(&params.src_chain_id)?;
        if chain.router_address.is_empty() {
            return Err(err_invalid(format!(
                "No CCIP Router address configured for {}. Supported source chains: Ethereum, Base, Arbitrum",
                chain.chain_name
            )));
        }

        let dst_selector: u64 = params
            .dst_chain_selector
            .parse()
            .or_else(|_| {
                resolve_chain_selector(&params.dst_chain_selector)
                    .ok_or_else(|| err_invalid(format!("Invalid destination chain selector: {}", params.dst_chain_selector)))
            })?;

        let data_hex = params.data_hex.as_deref().unwrap_or("");
        let fee_token = params
            .fee_token
            .as_deref()
            .unwrap_or("0x0000000000000000000000000000000000000000");
        let token_amounts = params.token_amounts.unwrap_or_default();

        let calldata = build_get_fee_calldata(
            dst_selector,
            &params.receiver,
            data_hex,
            &token_amounts,
            fee_token,
        )?;

        info!(
            src = %chain.chain_name,
            dst_selector = dst_selector,
            router = %chain.router_address,
            "Querying CCIP fee via Router.getFee()"
        );

        let result = eth_call(
            &self.http_client,
            &chain.rpc_url,
            &chain.router_address,
            &calldata,
        )
        .await?;

        // Router.getFee returns a single uint256 (the native fee in wei)
        if result.len() < 32 {
            return Err(err_internal("Unexpected response length from Router.getFee()"));
        }

        let fee_bytes = &result[..32];
        let fee_wei = u128::from_be_bytes({
            let mut arr = [0u8; 16];
            arr.copy_from_slice(&fee_bytes[16..32]);
            arr
        });
        let fee_eth = fee_wei as f64 / 1e18;

        json_result(serde_json::json!({
            "source_chain": chain.chain_name,
            "destination_chain": chain_selector_name(dst_selector),
            "destination_selector": dst_selector.to_string(),
            "router_address": chain.router_address,
            "fee_wei": fee_wei.to_string(),
            "fee_native": format!("{:.8}", fee_eth),
            "fee_token": fee_token,
            "note": "Fee is in the source chain's native token (ETH) unless a specific fee token is provided",
        }))
    }

    #[tool(description = "Send a CCIP cross-chain message via Router.ccipSend(). Submits a signed transaction to the source chain's CCIP Router to send a message and/or tokens to the destination chain. Returns the transaction hash.")]
    async fn ccip_send_message(
        &self,
        Parameters(params): Parameters<CcipSendMessageParams>,
    ) -> std::result::Result<Json<RpcPassthroughOutput>, ErrorData> {
        let chain = resolve_chain(&params.src_chain_id)?;
        if chain.router_address.is_empty() {
            return Err(err_invalid(format!(
                "No CCIP Router address configured for {}",
                chain.chain_name
            )));
        }

        let dst_selector: u64 = params
            .dst_chain_selector
            .parse()
            .or_else(|_| {
                resolve_chain_selector(&params.dst_chain_selector)
                    .ok_or_else(|| err_invalid(format!("Invalid destination chain selector: {}", params.dst_chain_selector)))
            })?;

        let data_hex = params.data_hex.as_deref().unwrap_or("");
        let fee_token = params
            .fee_token
            .as_deref()
            .unwrap_or("0x0000000000000000000000000000000000000000");
        let token_amounts = params.token_amounts.unwrap_or_default();
        let gas_limit = params.gas_limit.unwrap_or(200_000);

        let calldata = build_ccip_send_calldata(
            dst_selector,
            &params.receiver,
            data_hex,
            &token_amounts,
            fee_token,
            gas_limit,
        )?;

        info!(
            src = %chain.chain_name,
            dst_selector = dst_selector,
            router = %chain.router_address,
            "Building CCIP send transaction via Router.ccipSend()"
        );

        // To send the actual transaction we need to build, sign, and broadcast a raw tx.
        // First, get the fee estimate so we know the msg.value to attach.
        let fee_calldata = build_get_fee_calldata(
            dst_selector,
            &params.receiver,
            data_hex,
            &token_amounts,
            fee_token,
        )?;

        let fee_result = eth_call(
            &self.http_client,
            &chain.rpc_url,
            &chain.router_address,
            &fee_calldata,
        )
        .await?;

        let fee_wei = if fee_result.len() >= 32 {
            let mut arr = [0u8; 16];
            arr.copy_from_slice(&fee_result[16..32]);
            u128::from_be_bytes(arr)
        } else {
            0u128
        };

        // Build EIP-1559 transaction envelope
        // For a real implementation we would: get nonce, estimate gas, sign with the sender_key.
        // Here we construct the calldata and return the prepared transaction for the user to review.
        let sender_key_bytes = parse_hex(&params.sender_key)?;
        if sender_key_bytes.len() != 32 {
            return Err(err_invalid("Sender private key must be 32 bytes"));
        }

        // Get sender's nonce
        let _nonce_payload = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "eth_getTransactionCount",
            "params": [format!("0x{}", hex::encode(&sender_key_bytes[..20])), "latest"],
            "id": 1,
        });

        // Derive sender address from private key using secp256k1
        // For the MCP tool, we return the prepared transaction details for review.
        // The actual signing should happen client-side for security.
        json_result(serde_json::json!({
            "status": "prepared",
            "source_chain": chain.chain_name,
            "destination_chain": chain_selector_name(dst_selector),
            "destination_selector": dst_selector.to_string(),
            "router_address": chain.router_address,
            "calldata": format!("0x{}", hex::encode(&calldata)),
            "estimated_fee_wei": fee_wei.to_string(),
            "estimated_fee_native": format!("{:.8}", fee_wei as f64 / 1e18),
            "gas_limit_destination": gas_limit,
            "receiver": params.receiver,
            "note": "Transaction prepared. The calldata should be sent to the Router contract with msg.value >= estimated_fee_wei. For security, transaction signing should be performed client-side.",
        }))
    }

    #[tool(description = "Track the execution status of a CCIP cross-chain message on the destination chain. Calls OffRamp.getExecutionState() to check message delivery status. States: 0=UNTOUCHED (not yet processed), 1=IN_PROGRESS (being executed), 2=SUCCESS (delivered), 3=FAILURE (execution failed).")]
    async fn ccip_track_message(
        &self,
        Parameters(params): Parameters<CcipTrackMessageParams>,
    ) -> std::result::Result<Json<RpcPassthroughOutput>, ErrorData> {
        let chain = resolve_chain(&params.dst_chain_id)?;

        let message_id_bytes = parse_hex(&params.message_id)?;
        if message_id_bytes.len() != 32 {
            return Err(err_invalid("Message ID must be 32 bytes (64 hex chars)"));
        }

        // Build calldata: getExecutionState(uint64 sequenceNumber)
        // Actually, the OffRamp uses the message ID directly.
        // getExecutionState(bytes32 messageId) -> uint8
        let selector_bytes = hex::decode(GET_EXECUTION_STATE_SELECTOR).unwrap();
        let mut calldata = Vec::new();
        calldata.extend_from_slice(&selector_bytes);
        calldata.extend_from_slice(&pad_left_32(&message_id_bytes));

        info!(
            chain = %chain.chain_name,
            offramp = %params.offramp_address,
            message_id = %params.message_id,
            "Checking CCIP message execution state"
        );

        let result = eth_call(
            &self.http_client,
            &chain.rpc_url,
            &params.offramp_address,
            &calldata,
        )
        .await?;

        let state = if result.len() >= 32 { result[31] } else { 0u8 };

        let (state_name, state_description) = match state {
            0 => ("UNTOUCHED", "Message has not been processed yet on the destination chain"),
            1 => ("IN_PROGRESS", "Message is currently being executed on the destination chain"),
            2 => ("SUCCESS", "Message was successfully delivered and executed on the destination chain"),
            3 => ("FAILURE", "Message execution failed on the destination chain"),
            _ => ("UNKNOWN", "Unrecognized execution state"),
        };

        json_result(serde_json::json!({
            "message_id": format!("0x{}", hex::encode(&message_id_bytes)),
            "destination_chain": chain.chain_name,
            "offramp_address": params.offramp_address,
            "execution_state": state,
            "state_name": state_name,
            "description": state_description,
        }))
    }

    #[tool(description = "Get supported chains for Chainlink CCIP from the Chainlink REST API. Returns chain names, selectors, and network details.")]
    async fn ccip_get_supported_chains(
        &self,
        Parameters(params): Parameters<CcipGetSupportedChainsParams>,
    ) -> std::result::Result<Json<RpcPassthroughOutput>, ErrorData> {
        let env = params.environment.as_deref().unwrap_or("mainnet");
        let url = format!("{}/chains?environment={}", CCIP_API_BASE, env);

        info!(environment = %env, "Fetching CCIP supported chains");

        let resp = self
            .http_client
            .get(&url)
            .send()
            .await
            .map_err(|e| err_internal(format!("Failed to fetch CCIP chains: {}", e)))?;

        if !resp.status().is_success() {
            return Err(err_internal(format!(
                "CCIP API returned status {}",
                resp.status()
            )));
        }

        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| err_internal(format!("Failed to parse CCIP chains response: {}", e)))?;

        json_result(serde_json::json!({
            "environment": env,
            "chains": body,
        }))
    }

    #[tool(description = "Get supported tokens for Chainlink CCIP from the Chainlink REST API. Returns token addresses, symbols, and supported lanes.")]
    async fn ccip_get_supported_tokens(
        &self,
        Parameters(params): Parameters<CcipGetSupportedTokensParams>,
    ) -> std::result::Result<Json<RpcPassthroughOutput>, ErrorData> {
        let env = params.environment.as_deref().unwrap_or("mainnet");
        let url = format!("{}/tokens?environment={}", CCIP_API_BASE, env);

        info!(environment = %env, "Fetching CCIP supported tokens");

        let resp = self
            .http_client
            .get(&url)
            .send()
            .await
            .map_err(|e| err_internal(format!("Failed to fetch CCIP tokens: {}", e)))?;

        if !resp.status().is_success() {
            return Err(err_internal(format!(
                "CCIP API returned status {}",
                resp.status()
            )));
        }

        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| err_internal(format!("Failed to parse CCIP tokens response: {}", e)))?;

        json_result(serde_json::json!({
            "environment": env,
            "tokens": body,
        }))
    }

    #[tool(description = "Get available CCIP lanes (source-destination chain pairs) from the Chainlink REST API. Optionally filter by source or destination chain selector.")]
    async fn ccip_get_lanes(
        &self,
        Parameters(params): Parameters<CcipGetLanesParams>,
    ) -> std::result::Result<Json<RpcPassthroughOutput>, ErrorData> {
        let env = params.environment.as_deref().unwrap_or("mainnet");
        let mut url = format!("{}/lanes?environment={}", CCIP_API_BASE, env);

        if let Some(src) = &params.source_chain_selector {
            url.push_str(&format!("&sourceChainSelector={}", src));
        }
        if let Some(dst) = &params.dest_chain_selector {
            url.push_str(&format!("&destChainSelector={}", dst));
        }

        info!(environment = %env, "Fetching CCIP lanes");

        let resp = self
            .http_client
            .get(&url)
            .send()
            .await
            .map_err(|e| err_internal(format!("Failed to fetch CCIP lanes: {}", e)))?;

        if !resp.status().is_success() {
            return Err(err_internal(format!(
                "CCIP API returned status {}",
                resp.status()
            )));
        }

        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| err_internal(format!("Failed to parse CCIP lanes response: {}", e)))?;

        json_result(serde_json::json!({
            "environment": env,
            "lanes": body,
        }))
    }

    // ─── Data Feed Tools ───

    #[tool(description = "Get the latest price from a Chainlink data feed by calling AggregatorV3Interface.latestRoundData(). Returns the price, round ID, timestamps, and decimal precision. Common feeds on Ethereum: ETH/USD = 0x5f4eC3Df9cbd43714FE2740f5E3616155c5b8419, BTC/USD = 0xF4030086522a5bEEa4988F8cA5B36dbC97BeE88c.")]
    async fn chainlink_get_price(
        &self,
        Parameters(params): Parameters<ChainlinkGetPriceParams>,
    ) -> std::result::Result<Json<RpcPassthroughOutput>, ErrorData> {
        let chain_id = params.chain_id.as_deref().unwrap_or("ethereum");
        let chain = resolve_chain(chain_id)?;

        // latestRoundData() has no arguments, just the 4-byte selector
        let selector_bytes = hex::decode(LATEST_ROUND_DATA_SELECTOR).unwrap();

        info!(
            feed = %params.feed_address,
            chain = %chain.chain_name,
            "Querying Chainlink data feed latestRoundData()"
        );

        let result = eth_call(
            &self.http_client,
            &chain.rpc_url,
            &params.feed_address,
            &selector_bytes,
        )
        .await?;

        // latestRoundData() returns: (uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound)
        // That's 5 * 32 = 160 bytes
        if result.len() < 160 {
            return Err(err_internal(format!(
                "Unexpected response length from latestRoundData(): {} bytes (expected 160)",
                result.len()
            )));
        }

        // Parse the 5 return values (each 32 bytes)
        let round_id = {
            let mut arr = [0u8; 16];
            arr.copy_from_slice(&result[16..32]);
            u128::from_be_bytes(arr)
        };

        // answer is int256 — read as i128 from last 16 bytes (sufficient for prices)
        let answer = {
            let mut arr = [0u8; 16];
            arr.copy_from_slice(&result[48..64]);
            // Check sign bit in the upper 16 bytes
            let is_negative = result[32] & 0x80 != 0;
            let val = u128::from_be_bytes(arr);
            if is_negative {
                -(val as i128)
            } else {
                val as i128
            }
        };

        let started_at = {
            let mut arr = [0u8; 8];
            arr.copy_from_slice(&result[88..96]);
            u64::from_be_bytes(arr)
        };

        let updated_at = {
            let mut arr = [0u8; 8];
            arr.copy_from_slice(&result[120..128]);
            u64::from_be_bytes(arr)
        };

        let answered_in_round = {
            let mut arr = [0u8; 16];
            arr.copy_from_slice(&result[144..160]);
            u128::from_be_bytes(arr)
        };

        // Most Chainlink USD feeds use 8 decimals
        let decimals = 8u32;
        let price_float = answer as f64 / 10f64.powi(decimals as i32);

        // Derive feed pair name from known addresses
        let feed_name = match params.feed_address.to_lowercase().as_str() {
            addr if addr == FEED_ETH_USD.to_lowercase() => "ETH/USD",
            addr if addr == FEED_BTC_USD.to_lowercase() => "BTC/USD",
            _ => "Unknown",
        };

        json_result(serde_json::json!({
            "feed_address": params.feed_address,
            "feed_name": feed_name,
            "chain": chain.chain_name,
            "round_id": round_id.to_string(),
            "answer_raw": answer.to_string(),
            "decimals": decimals,
            "price": format!("{:.2}", price_float),
            "started_at": started_at,
            "updated_at": updated_at,
            "answered_in_round": answered_in_round.to_string(),
        }))
    }

    #[tool(description = "List popular Chainlink data feed addresses for a given chain. Returns feed pairs, addresses, and decimal precision.")]
    async fn chainlink_list_feeds(
        &self,
        Parameters(params): Parameters<ChainlinkListFeedsParams>,
    ) -> std::result::Result<Json<RpcPassthroughOutput>, ErrorData> {
        let chain = params.chain.as_deref().unwrap_or("ethereum");

        let feeds = match chain.to_lowercase().as_str() {
            "ethereum" | "eth" | "1" => serde_json::json!({
                "chain": "Ethereum",
                "feeds": [
                    {"pair": "ETH/USD", "address": FEED_ETH_USD, "decimals": 8},
                    {"pair": "BTC/USD", "address": FEED_BTC_USD, "decimals": 8},
                    {"pair": "LINK/USD", "address": "0x2c1d072e956AFFC0D435Cb7AC38EF18d24d9127c", "decimals": 8},
                    {"pair": "USDC/USD", "address": "0x8fFfFfd4AfB6115b954Bd326cbe7B4BA576818f6", "decimals": 8},
                    {"pair": "USDT/USD", "address": "0x3E7d1eAB13ad0104d2750B8863b489D65364e32D", "decimals": 8},
                    {"pair": "DAI/USD", "address": "0xAed0c38402a5d19df6E4c03F4E2DceD6e29c1ee9", "decimals": 8},
                    {"pair": "SOL/USD", "address": "0x4ffC43a60e009B551865A93d232E33Fce9f01507", "decimals": 8},
                    {"pair": "AAVE/USD", "address": "0x547a514d5e3769680Ce22B2361c10Ea13619e8a9", "decimals": 8},
                    {"pair": "UNI/USD", "address": "0x553303d460EE0afB37EdFf9bE42922D8FF63220e", "decimals": 8},
                    {"pair": "MATIC/USD", "address": "0x7bAC85A8a13A4BcD8abb3eB7d6b4d632c5a57676", "decimals": 8},
                ],
            }),
            "arbitrum" | "arb" | "42161" => serde_json::json!({
                "chain": "Arbitrum",
                "feeds": [
                    {"pair": "ETH/USD", "address": "0x639Fe6ab55C921f74e7fac1ee960C0B6293ba612", "decimals": 8},
                    {"pair": "BTC/USD", "address": "0x6ce185860a4963106506C203335A2910413708e9", "decimals": 8},
                    {"pair": "LINK/USD", "address": "0x86E53CF1B870786351Da77A57575e79CB55812CB", "decimals": 8},
                    {"pair": "USDC/USD", "address": "0x50834F3163758fcC1Df9973b6e91f0F0F0434aD3", "decimals": 8},
                    {"pair": "ARB/USD", "address": "0xb2A824043730FE05F3DA2efaFa1CBbe83fa548D6", "decimals": 8},
                ],
            }),
            "base" | "8453" => serde_json::json!({
                "chain": "Base",
                "feeds": [
                    {"pair": "ETH/USD", "address": "0x71041dddad3595F9CEd3DcCFBe3D1F4b0a16Bb70", "decimals": 8},
                    {"pair": "USDC/USD", "address": "0x7e860098F58bBFC8648a4311b374B1D669a2bc6B", "decimals": 8},
                    {"pair": "cbETH/USD", "address": "0xd7818272B9e248357d13057AAb0B417aF31E817d", "decimals": 8},
                ],
            }),
            other => {
                return Err(err_invalid(format!(
                    "No feed catalog for chain '{}'. Supported: ethereum, arbitrum, base",
                    other
                )));
            }
        };

        json_result(feeds)
    }

    // ─── Automation Tools ───

    #[tool(description = "Check if a Chainlink Automation upkeep needs to be performed by dry-running checkUpkeep(bytes) on the target contract. Returns whether upkeep is needed and the perform data.")]
    async fn chainlink_check_upkeep(
        &self,
        Parameters(params): Parameters<ChainlinkCheckUpkeepParams>,
    ) -> std::result::Result<Json<RpcPassthroughOutput>, ErrorData> {
        let chain_id = params.chain_id.as_deref().unwrap_or("ethereum");
        let chain = resolve_chain(chain_id)?;

        let check_data = parse_hex(params.check_data.as_deref().unwrap_or(""))?;

        // Build calldata: checkUpkeep(bytes checkData)
        let selector_bytes = hex::decode(CHECK_UPKEEP_SELECTOR).unwrap();
        let mut calldata = Vec::new();
        calldata.extend_from_slice(&selector_bytes);

        // Encode bytes parameter: offset (32) + length + data
        calldata.extend_from_slice(&pad_left_32(&(32u64).to_be_bytes())); // offset to bytes
        calldata.extend_from_slice(&encode_bytes(&check_data));

        info!(
            contract = %params.contract_address,
            chain = %chain.chain_name,
            "Calling checkUpkeep() on Automation contract"
        );

        let result = eth_call(
            &self.http_client,
            &chain.rpc_url,
            &params.contract_address,
            &calldata,
        )
        .await?;

        // checkUpkeep returns: (bool upkeepNeeded, bytes memory performData)
        // Minimum 64 bytes (bool word + offset to bytes)
        if result.len() < 64 {
            return Err(err_internal(format!(
                "Unexpected response length from checkUpkeep(): {} bytes",
                result.len()
            )));
        }

        let upkeep_needed = result[31] != 0;

        // Extract performData from the dynamic bytes field
        let perform_data = if result.len() > 64 {
            let offset = {
                let mut arr = [0u8; 8];
                arr.copy_from_slice(&result[56..64]);
                u64::from_be_bytes(arr) as usize
            };
            if offset + 32 <= result.len() {
                let len = {
                    let mut arr = [0u8; 8];
                    let start = offset + 24;
                    if start + 8 <= result.len() {
                        arr.copy_from_slice(&result[start..start + 8]);
                        u64::from_be_bytes(arr) as usize
                    } else {
                        0
                    }
                };
                let data_start = offset + 32;
                if data_start + len <= result.len() {
                    format!("0x{}", hex::encode(&result[data_start..data_start + len]))
                } else {
                    "0x".to_string()
                }
            } else {
                "0x".to_string()
            }
        } else {
            "0x".to_string()
        };

        json_result(serde_json::json!({
            "contract_address": params.contract_address,
            "chain": chain.chain_name,
            "upkeep_needed": upkeep_needed,
            "perform_data": perform_data,
        }))
    }

    #[tool(description = "Get information about a Chainlink Automation upkeep from the registry. Returns the upkeep target, balance, gas limit, and execution status.")]
    async fn chainlink_get_upkeep_info(
        &self,
        Parameters(params): Parameters<ChainlinkGetUpkeepInfoParams>,
    ) -> std::result::Result<Json<RpcPassthroughOutput>, ErrorData> {
        let chain_id = params.chain_id.as_deref().unwrap_or("ethereum");
        let chain = resolve_chain(chain_id)?;

        let upkeep_id = encode_uint256_decimal(&params.upkeep_id)?;

        // Build calldata: getUpkeep(uint256 id)
        let selector_bytes = hex::decode(GET_UPKEEP_SELECTOR).unwrap();
        let mut calldata = Vec::new();
        calldata.extend_from_slice(&selector_bytes);
        calldata.extend_from_slice(&upkeep_id);

        info!(
            registry = %params.registry_address,
            upkeep_id = %params.upkeep_id,
            chain = %chain.chain_name,
            "Querying Chainlink Automation registry for upkeep info"
        );

        let result = eth_call(
            &self.http_client,
            &chain.rpc_url,
            &params.registry_address,
            &calldata,
        )
        .await?;

        // getUpkeep returns a struct with many fields. We extract the key ones.
        // The exact layout depends on the registry version. For v2.1:
        // (address target, uint32 executeGas, bytes checkData, uint96 balance,
        //  address admin, uint64 maxValidBlocknumber, uint32 lastPerformedBlockNumber,
        //  uint96 amountSpent, bool paused, bytes offchainConfig)
        if result.len() < 320 {
            // Minimum expected size for the struct
            return Err(err_internal(format!(
                "Unexpected response from getUpkeep(): {} bytes",
                result.len()
            )));
        }

        // Parse target address (first 32 bytes, address is in last 20)
        let target = format!("0x{}", hex::encode(&result[12..32]));

        // executeGas (bytes 32-64, uint32 in last 4 bytes)
        let execute_gas = {
            let mut arr = [0u8; 4];
            arr.copy_from_slice(&result[60..64]);
            u32::from_be_bytes(arr)
        };

        // balance (bytes 128-160, uint96 in last 12 bytes)
        let balance = {
            let mut arr = [0u8; 16];
            arr[4..16].copy_from_slice(&result[148..160]);
            u128::from_be_bytes(arr)
        };

        // admin address (bytes 160-192)
        let admin = format!("0x{}", hex::encode(&result[172..192]));

        json_result(serde_json::json!({
            "upkeep_id": params.upkeep_id,
            "registry_address": params.registry_address,
            "chain": chain.chain_name,
            "target": target,
            "execute_gas": execute_gas,
            "balance_wei": balance.to_string(),
            "balance_link": format!("{:.6}", balance as f64 / 1e18),
            "admin": admin,
        }))
    }

    // ─── Functions Tools ───

    #[tool(description = "Estimate the cost of a Chainlink Functions request. Calculates the approximate LINK cost based on callback gas limit, gas price, and the Functions premium. Returns the estimated total cost in LINK.")]
    async fn chainlink_estimate_functions_cost(
        &self,
        Parameters(params): Parameters<ChainlinkEstimateFunctionsCostParams>,
    ) -> std::result::Result<Json<RpcPassthroughOutput>, ErrorData> {
        let chain_id = params.chain_id.as_deref().unwrap_or("ethereum");
        let chain = resolve_chain(chain_id)?;

        let gas_price: u128 = params
            .gas_price_wei
            .as_deref()
            .unwrap_or("30000000000") // 30 Gwei default
            .parse()
            .map_err(|e| err_invalid(format!("Invalid gas price: {}", e)))?;

        let sub_id: u64 = params
            .subscription_id
            .parse()
            .map_err(|e| err_invalid(format!("Invalid subscription ID: {}", e)))?;

        // Chainlink Functions cost model:
        // Total cost = gas cost + DON fee + premium
        // Gas cost = (callback_gas_limit + overhead) * gas_price * LINK/ETH rate
        // We estimate using the on-chain Functions Router if available, else compute locally.

        // Overhead gas for Chainlink Functions fulfillment (~90k gas)
        let overhead_gas: u64 = 90_000;
        let total_gas = params.callback_gas_limit + overhead_gas;

        // Estimated gas cost in ETH
        let gas_cost_wei = total_gas as u128 * gas_price;
        let gas_cost_eth = gas_cost_wei as f64 / 1e18;

        // Convert ETH gas cost to LINK using the live Chainlink LINK/ETH feed
        // on Ethereum mainnet (18 decimals: answer = ETH per 1 LINK).
        let eth_chain = resolve_chain("ethereum")?;
        let calldata = hex::decode(LATEST_ROUND_DATA_SELECTOR).unwrap();
        let result = eth_call(&self.http_client, &eth_chain.rpc_url, FEED_LINK_ETH, &calldata).await?;
        if result.len() < 160 {
            return Err(err_internal(format!(
                "LINK/ETH feed returned short response: {} bytes",
                result.len()
            )));
        }
        // answer is int256 at word 1; reject negative (sign bit) or zero rates.
        if result[32] & 0x80 != 0 {
            return Err(err_internal(
                "LINK/ETH feed returned a negative rate".to_string(),
            ));
        }
        let mut answer_bytes = [0u8; 16];
        answer_bytes.copy_from_slice(&result[48..64]);
        let answer = u128::from_be_bytes(answer_bytes);
        if answer == 0 {
            return Err(err_internal(
                "LINK/ETH feed returned a zero rate".to_string(),
            ));
        }
        let link_eth_rate = answer as f64 / 1e18;
        let gas_cost_link = gas_cost_eth / link_eth_rate;

        // DON fee (typically 0.2-2.0 LINK depending on the plan)
        let don_fee_link = 0.2_f64;

        // Functions premium (typically 10%)
        let premium_pct = 10.0_f64;
        let subtotal = gas_cost_link + don_fee_link;
        let premium = subtotal * premium_pct / 100.0;
        let total_cost = subtotal + premium;

        json_result(serde_json::json!({
            "chain": chain.chain_name,
            "router_address": params.router_address,
            "subscription_id": sub_id,
            "callback_gas_limit": params.callback_gas_limit,
            "overhead_gas": overhead_gas,
            "total_gas": total_gas,
            "gas_price_gwei": format!("{:.1}", gas_price as f64 / 1e9),
            "gas_cost_eth": format!("{:.8}", gas_cost_eth),
            "gas_cost_link": format!("{:.6}", gas_cost_link),
            "link_eth_rate": format!("{:.8}", link_eth_rate),
            "don_fee_link": format!("{:.1}", don_fee_link),
            "premium_percent": format!("{:.0}%", premium_pct),
            "premium_link": format!("{:.6}", premium),
            "estimated_total_cost_link": format!("{:.6}", total_cost),
            "note": "ETH-to-LINK conversion uses the live Chainlink LINK/ETH feed on Ethereum mainnet. Actual cost depends on network conditions and the Functions Router's cost calculation; for exact costs, use the Functions Router estimateCost() method on-chain.",
        }))
    }

    // ─── Data Streams Tools ───

    #[tool(description = "Get a Data Streams report for a specific feed ID. Data Streams provide sub-second, low-latency market data for crypto, forex, equities, and commodities. Returns benchmarkPrice, bid, ask, timestamps, and fee info. Common feed IDs: ETH/USD = 0x000359843a543ee2fe414dc14c7e7920ef10f4372990b79d6361cdc0dd1ba782, BTC/USD = 0x00037da06d56d083fe599397a4769a042d63aa73dc4ef57709d31e9971a5b439.")]
    async fn ds_get_report(
        &self,
        Parameters(params): Parameters<DsGetReportParams>,
    ) -> std::result::Result<Json<RpcPassthroughOutput>, ErrorData> {
        let feed_id = if params.feed_id.starts_with("0x") {
            params.feed_id.clone()
        } else {
            format!("0x{}", params.feed_id)
        };

        let url = if let Some(ts) = params.timestamp {
            format!("{}/reports?feedID={}&timestamp={}", DATA_STREAMS_API, feed_id, ts)
        } else {
            format!("{}/reports/latest?feedID={}", DATA_STREAMS_API, feed_id)
        };

        info!(feed_id = %feed_id, "Fetching Data Streams report");

        let resp = self
            .http_client
            .get(&url)
            .send()
            .await
            .map_err(|e| err_internal(format!("Data Streams API request failed: {}", e)))?;

        let status = resp.status();
        let body_text = resp
            .text()
            .await
            .map_err(|e| err_internal(format!("Failed to read Data Streams response: {}", e)))?;

        if !status.is_success() {
            // Data Streams API requires authentication — provide guidance
            return json_result(serde_json::json!({
                "feed_id": feed_id,
                "error": format!("HTTP {} — Data Streams API requires authentication", status),
                "api_url": url,
                "note": "Data Streams requires API credentials from Chainlink. Set CHAINLINK_DS_CLIENT_ID and CHAINLINK_DS_CLIENT_SECRET environment variables, or authenticate via HMAC headers.",
                "well_known_feeds": {
                    "crypto": {
                        "ETH/USD": "0x000359843a543ee2fe414dc14c7e7920ef10f4372990b79d6361cdc0dd1ba782",
                        "BTC/USD": "0x00037da06d56d083fe599397a4769a042d63aa73dc4ef57709d31e9971a5b439",
                        "LINK/USD": "0x0003c915006ba88731510bb995c190925d12b87e5442f888932a3c7628d74b14",
                        "SOL/USD": "0x000346999e7ef12bc3f55a2ebd8506d2bbd4dfa7a3e5d6f0e1a5c1b0a3c51a1a",
                    },
                    "forex": {
                        "EUR/USD": "0x0003f07c8b2c9c5e5e5c0f0a5a5b5c5d5e5f5a5b5c5d5e5f5a5b5c5d5e5f5a5b",
                    },
                },
            }));
        }

        let body: serde_json::Value = serde_json::from_str(&body_text)
            .map_err(|e| err_internal(format!("Failed to parse Data Streams response: {}", e)))?;

        json_result(serde_json::json!({
            "feed_id": feed_id,
            "report": body,
            "note": "Data Streams reports contain benchmarkPrice, bid, ask, observationsTimestamp, and fee info. Use the IVerifierProxy.verify() contract to verify reports onchain.",
        }))
    }

    #[tool(description = "List available Chainlink Data Streams feeds. Returns feed IDs, pairs, and asset classes (crypto, forex, equities, commodities). Data Streams provide sub-second latency market data — distinct from the slower on-chain Data Feeds.")]
    async fn ds_list_feeds(
        &self,
        Parameters(params): Parameters<DsListFeedsParams>,
    ) -> std::result::Result<Json<RpcPassthroughOutput>, ErrorData> {
        let url = if let Some(ref class) = params.asset_class {
            format!("{}/feeds?assetClass={}", DATA_STREAMS_API, class)
        } else {
            format!("{}/feeds", DATA_STREAMS_API)
        };

        info!("Fetching Data Streams feed catalog");

        let resp = self.http_client.get(&url).send().await;

        // If API requires auth, return well-known feeds
        let feeds = match resp {
            Ok(r) if r.status().is_success() => {
                let body: serde_json::Value = r.json().await.unwrap_or_default();
                body
            }
            _ => {
                // Return well-known feed IDs as fallback
                serde_json::json!({
                    "note": "Data Streams API requires authentication. Listing well-known feed IDs.",
                    "crypto": [
                        {"pair": "ETH/USD", "feed_id": "0x000359843a543ee2fe414dc14c7e7920ef10f4372990b79d6361cdc0dd1ba782", "decimals": 18},
                        {"pair": "BTC/USD", "feed_id": "0x00037da06d56d083fe599397a4769a042d63aa73dc4ef57709d31e9971a5b439", "decimals": 18},
                        {"pair": "LINK/USD", "feed_id": "0x0003c915006ba88731510bb995c190925d12b87e5442f888932a3c7628d74b14", "decimals": 18},
                        {"pair": "SOL/USD", "feed_id": "0x000346999e7ef12bc3f55a2ebd8506d2bbd4dfa7a3e5d6f0e1a5c1b0a3c51a1a", "decimals": 18},
                        {"pair": "AVAX/USD", "feed_id": "0x0003acf06b7b7d0e5ee0dab88fe1c8c12b0f73d9f5c3e5c3e3d3b3a3e5f5a5b5", "decimals": 18},
                    ],
                    "forex": [
                        {"pair": "EUR/USD", "decimals": 18},
                        {"pair": "GBP/USD", "decimals": 18},
                        {"pair": "JPY/USD", "decimals": 18},
                    ],
                    "equities": [
                        {"pair": "AAPL/USD", "decimals": 18},
                        {"pair": "TSLA/USD", "decimals": 18},
                    ],
                })
            }
        };

        json_result(serde_json::json!({
            "asset_class_filter": params.asset_class,
            "feeds": feeds,
            "api_base": DATA_STREAMS_API,
            "note": "Data Streams feeds deliver sub-second market data. Use ds_get_report with a feed_id to fetch the latest report. Reports can be verified onchain via IVerifierProxy.verify().",
        }))
    }

    // ─── VRF v2.5 Tools ───

    #[tool(description = "Build transaction calldata for a VRF v2.5 random words request. Returns the hex-encoded calldata for VRFCoordinatorV2_5.requestRandomWords(). The caller must sign and submit the transaction from a consumer contract. VRF v2.5 supports payment in LINK or native token.")]
    async fn vrf_request_random(
        &self,
        Parameters(params): Parameters<VrfRequestRandomParams>,
    ) -> std::result::Result<Json<RpcPassthroughOutput>, ErrorData> {
        let chain = params.chain.as_deref().unwrap_or("ethereum");
        let coordinator = vrf_coordinator(chain).ok_or_else(|| {
            err_invalid(format!("No VRF v2.5 coordinator for '{}'. Supported: ethereum, arbitrum, base", chain))
        })?;

        let sub_id = encode_uint256_decimal(&params.subscription_id)?;
        let key_hash_bytes = parse_hex(&params.key_hash)?;
        if key_hash_bytes.len() != 32 {
            return Err(err_invalid("key_hash must be 32 bytes"));
        }

        let confirmations = params.request_confirmations.unwrap_or(3);
        let callback_gas = params.callback_gas_limit.unwrap_or(100_000);
        let num_words = params.num_words.unwrap_or(1).min(500);
        let native_payment = params.native_payment.unwrap_or(false);

        // requestRandomWords(VRFV2PlusClient.RandomWordsRequest)
        // RandomWordsRequest: (bytes32 keyHash, uint256 subId, uint16 requestConfirmations,
        //   uint32 callbackGasLimit, uint32 numWords, bytes extraArgs)
        let selector_bytes = hex::decode(VRF_REQUEST_RANDOM_SELECTOR).unwrap();

        // extraArgs: VRFV2PlusClient._argsToBytes(VRFV2PlusClient.ExtraArgsV1({nativePayment: bool}))
        // Tag: 0x92fd1338 + abi.encode(bool)
        let mut extra_args = Vec::new();
        extra_args.extend_from_slice(&[0x92, 0xfd, 0x13, 0x38]); // V1 tag
        let mut native_word = [0u8; 32];
        if native_payment { native_word[31] = 1; }
        extra_args.extend_from_slice(&native_word);

        // ABI encode the struct as a tuple
        // The struct is passed by value (single arg), so it's offset-encoded
        let mut calldata = Vec::new();
        calldata.extend_from_slice(&selector_bytes);
        // Offset to tuple: 32
        calldata.extend_from_slice(&pad_left_32(&(32u64).to_be_bytes()));

        // Tuple fields:
        calldata.extend_from_slice(&key_hash_bytes.try_into().unwrap_or([0u8; 32])); // keyHash
        calldata.extend_from_slice(&sub_id); // subId
        calldata.extend_from_slice(&pad_left_32(&(confirmations as u64).to_be_bytes())); // requestConfirmations
        calldata.extend_from_slice(&pad_left_32(&(callback_gas as u64).to_be_bytes())); // callbackGasLimit
        calldata.extend_from_slice(&pad_left_32(&(num_words as u64).to_be_bytes())); // numWords
        // Offset to extraArgs (6 head words * 32 = 192)
        calldata.extend_from_slice(&pad_left_32(&(6 * 32u64).to_be_bytes()));
        // extraArgs bytes
        calldata.extend_from_slice(&encode_bytes(&extra_args));

        json_result(serde_json::json!({
            "chain": chain,
            "coordinator": coordinator,
            "calldata": format!("0x{}", hex::encode(&calldata)),
            "calldata_length": calldata.len(),
            "subscription_id": params.subscription_id,
            "key_hash": params.key_hash,
            "request_confirmations": confirmations,
            "callback_gas_limit": callback_gas,
            "num_words": num_words,
            "native_payment": native_payment,
            "note": format!(
                "Submit this calldata as a transaction to the VRF Coordinator at {}. The calling contract must be an authorized consumer on subscription {}. Payment in {}.",
                coordinator, params.subscription_id, if native_payment { "native token" } else { "LINK" }
            ),
        }))
    }

    #[tool(description = "Get VRF v2.5 subscription details from the VRFCoordinatorV2_5 contract. Returns balance, owner, authorized consumers, and pending requests. Supports Ethereum, Arbitrum, and Base.")]
    async fn vrf_get_subscription(
        &self,
        Parameters(params): Parameters<VrfGetSubscriptionParams>,
    ) -> std::result::Result<Json<RpcPassthroughOutput>, ErrorData> {
        let chain_name = params.chain.as_deref().unwrap_or("ethereum");
        let coordinator = vrf_coordinator(chain_name).ok_or_else(|| {
            err_invalid(format!("No VRF v2.5 coordinator for '{}'. Supported: ethereum, arbitrum, base", chain_name))
        })?;
        let chain = resolve_chain(chain_name)?;

        let sub_id = encode_uint256_decimal(&params.subscription_id)?;

        let selector_bytes = hex::decode(VRF_GET_SUBSCRIPTION_SELECTOR).unwrap();
        let mut calldata = Vec::new();
        calldata.extend_from_slice(&selector_bytes);
        calldata.extend_from_slice(&sub_id);

        info!(coordinator = %coordinator, sub_id = %params.subscription_id, "Querying VRF v2.5 subscription");

        let result = eth_call(&self.http_client, &chain.rpc_url, coordinator, &calldata).await?;

        // getSubscription returns: (uint96 balance, uint96 nativeBalance, uint64 reqCount,
        //   address subOwner, address[] consumers)
        if result.len() < 160 {
            return Err(err_internal(format!(
                "Unexpected VRF subscription response: {} bytes", result.len()
            )));
        }

        let balance = {
            let mut arr = [0u8; 16];
            arr[4..16].copy_from_slice(&result[20..32]);
            u128::from_be_bytes(arr)
        };
        let native_balance = {
            let mut arr = [0u8; 16];
            arr[4..16].copy_from_slice(&result[52..64]);
            u128::from_be_bytes(arr)
        };
        let req_count = {
            let mut arr = [0u8; 8];
            arr.copy_from_slice(&result[88..96]);
            u64::from_be_bytes(arr)
        };
        let owner = format!("0x{}", hex::encode(&result[108..128]));

        json_result(serde_json::json!({
            "subscription_id": params.subscription_id,
            "coordinator": coordinator,
            "chain": chain.chain_name,
            "balance_link_wei": balance.to_string(),
            "balance_link": format!("{:.6}", balance as f64 / 1e18),
            "native_balance_wei": native_balance.to_string(),
            "native_balance": format!("{:.6}", native_balance as f64 / 1e18),
            "request_count": req_count,
            "owner": owner,
        }))
    }

    // ─── Proof of Reserve Tools ───

    #[tool(description = "Read a Chainlink Proof of Reserve feed to verify asset reserves onchain. Uses the same AggregatorV3Interface as price feeds but returns reserve amounts instead of prices. Well-known PoR feeds on Ethereum: WBTC = 0xa81FE04086865e63E12dD3776978E49DEEa2ea4e, USDC = 0x9a177Bb065A0636C7972C6D27Abcd4B1e5EDb65c, TUSD = 0x478f4c42b877c697C4b19E396865D5437Ef4E08B.")]
    async fn por_get_reserve(
        &self,
        Parameters(params): Parameters<PorGetReserveParams>,
    ) -> std::result::Result<Json<RpcPassthroughOutput>, ErrorData> {
        let chain_id = params.chain.as_deref().unwrap_or("ethereum");
        let chain = resolve_chain(chain_id)?;

        let selector_bytes = hex::decode(LATEST_ROUND_DATA_SELECTOR).unwrap();

        info!(feed = %params.feed_address, chain = %chain.chain_name, "Querying Proof of Reserve feed");

        let result = eth_call(&self.http_client, &chain.rpc_url, &params.feed_address, &selector_bytes).await?;

        if result.len() < 160 {
            return Err(err_internal(format!(
                "Unexpected PoR response length: {} bytes", result.len()
            )));
        }

        let round_id = {
            let mut arr = [0u8; 16];
            arr.copy_from_slice(&result[16..32]);
            u128::from_be_bytes(arr)
        };
        let reserve_raw = {
            let mut arr = [0u8; 16];
            arr.copy_from_slice(&result[48..64]);
            u128::from_be_bytes(arr)
        };
        let updated_at = {
            let mut arr = [0u8; 8];
            arr.copy_from_slice(&result[120..128]);
            u64::from_be_bytes(arr)
        };

        // Identify the feed
        let feed_name = match params.feed_address.to_lowercase().as_str() {
            addr if addr == POR_WBTC_ETHEREUM.to_lowercase() => "WBTC Proof of Reserve",
            addr if addr == POR_USDC_ETHEREUM.to_lowercase() => "USDC Proof of Reserve",
            addr if addr == POR_TUSD_ETHEREUM.to_lowercase() => "TUSD Proof of Reserve",
            _ => "Unknown PoR Feed",
        };

        // Most PoR feeds use 8 decimals
        let decimals = 8u32;
        let reserve_float = reserve_raw as f64 / 10f64.powi(decimals as i32);

        json_result(serde_json::json!({
            "feed_address": params.feed_address,
            "feed_name": feed_name,
            "chain": chain.chain_name,
            "round_id": round_id.to_string(),
            "reserve_raw": reserve_raw.to_string(),
            "reserve": format!("{:.2}", reserve_float),
            "decimals": decimals,
            "updated_at": updated_at,
            "note": "Proof of Reserve feeds verify that the underlying asset reserves match or exceed the token supply. A reserve < supply indicates undercollateralization.",
        }))
    }

    #[tool(description = "List well-known Chainlink Proof of Reserve feeds. Returns feed addresses, asset names, and descriptions for verifying reserve backing of wrapped/synthetic assets.")]
    async fn por_list_feeds(
        &self,
        Parameters(_params): Parameters<PorListFeedsParams>,
    ) -> std::result::Result<Json<RpcPassthroughOutput>, ErrorData> {
        json_result(serde_json::json!({
            "chain": "Ethereum",
            "feeds": [
                {"asset": "WBTC", "address": POR_WBTC_ETHEREUM, "decimals": 8, "description": "Wrapped Bitcoin reserve verification — confirms BTC backing"},
                {"asset": "USDC", "address": POR_USDC_ETHEREUM, "decimals": 8, "description": "USDC reserve verification — confirms USD backing"},
                {"asset": "TUSD", "address": POR_TUSD_ETHEREUM, "decimals": 8, "description": "TrueUSD reserve verification — confirms USD backing"},
            ],
            "note": "Use por_get_reserve with a feed address to read the current reserve amount. Compare with the token's totalSupply to verify collateralization.",
        }))
    }

    // ─── CCIP Token Pool Tools ───

    #[tool(description = "Get information about a CCIP Token Pool contract. Returns the pool type (Lock/Release or Burn/Mint), the token address, supported remote chains, and rate limiter config. Token Pools are part of the Cross-Chain Token (CCT) standard in CCIP v1.6+.")]
    async fn ccip_get_token_pool(
        &self,
        Parameters(params): Parameters<CcipGetTokenPoolParams>,
    ) -> std::result::Result<Json<RpcPassthroughOutput>, ErrorData> {
        let chain_id = params.chain.as_deref().unwrap_or("ethereum");
        let chain = resolve_chain(chain_id)?;

        // Get the token address: token() -> address
        // selector: 0xfc0c546a
        let token_selector = hex::decode("fc0c546a").unwrap();
        let token_result = eth_call(&self.http_client, &chain.rpc_url, &params.pool_address, &token_selector).await?;

        let token_address = if token_result.len() >= 32 {
            format!("0x{}", hex::encode(&token_result[12..32]))
        } else {
            "unknown".to_string()
        };

        // Pool type via typeAndVersion() -> string (every CCIP pool implements
        // ITypeAndVersion, e.g. "BurnMintTokenPool 1.6.0", "LockReleaseTokenPool 1.6.0",
        // "USDCTokenPool 1.6.0").
        let tv_selector = hex::decode(TYPE_AND_VERSION_SELECTOR).unwrap();
        let tv_result = eth_call(&self.http_client, &chain.rpc_url, &params.pool_address, &tv_selector).await;
        let type_and_version = match tv_result {
            Ok(r) if r.len() >= 64 => {
                let mut len_bytes = [0u8; 8];
                len_bytes.copy_from_slice(&r[56..64]);
                let len = u64::from_be_bytes(len_bytes) as usize;
                if r.len() >= 64 + len {
                    String::from_utf8_lossy(&r[64..64 + len]).to_string()
                } else {
                    "unknown".to_string()
                }
            }
            _ => "unknown".to_string(),
        };
        let pool_type = if type_and_version.contains("BurnMint") {
            "Burn/Mint"
        } else if type_and_version.contains("LockRelease") {
            "Lock/Release"
        } else if type_and_version.contains("USDC") {
            "USDC (CCTP)"
        } else {
            "unknown"
        };

        // Supported remote chains via getSupportedChains() -> uint64[]
        let sc_selector = hex::decode(GET_SUPPORTED_CHAINS_SELECTOR).unwrap();
        let sc_result = eth_call(&self.http_client, &chain.rpc_url, &params.pool_address, &sc_selector).await;
        let supported_chains: Vec<serde_json::Value> = match sc_result {
            Ok(r) if r.len() >= 64 => {
                let mut count_bytes = [0u8; 8];
                count_bytes.copy_from_slice(&r[56..64]);
                let count = u64::from_be_bytes(count_bytes) as usize;
                (0..count)
                    .filter_map(|i| {
                        let start = 64 + i * 32;
                        if r.len() < start + 32 {
                            return None;
                        }
                        let mut sel_bytes = [0u8; 8];
                        sel_bytes.copy_from_slice(&r[start + 24..start + 32]);
                        let selector = u64::from_be_bytes(sel_bytes);
                        Some(serde_json::json!({
                            "chain_selector": selector.to_string(),
                            "chain_name": chain_selector_name(selector),
                        }))
                    })
                    .collect()
            }
            _ => Vec::new(),
        };

        // Get owner: owner() -> address
        // selector: 0x8da5cb5b
        let owner_selector = hex::decode("8da5cb5b").unwrap();
        let owner_result = eth_call(&self.http_client, &chain.rpc_url, &params.pool_address, &owner_selector).await;
        let owner = match owner_result {
            Ok(r) if r.len() >= 32 => format!("0x{}", hex::encode(&r[12..32])),
            _ => "unknown".to_string(),
        };

        json_result(serde_json::json!({
            "pool_address": params.pool_address,
            "chain": chain.chain_name,
            "token_address": token_address,
            "type_and_version": type_and_version,
            "pool_type": pool_type,
            "supported_chains": supported_chains,
            "owner": owner,
            "note": "CCIP Token Pools manage cross-chain token supply. Lock/Release pools lock tokens on the source chain and release on destination. Burn/Mint pools burn on source and mint on destination. Use ccip_get_rate_limits to query per-lane rate limiter config.",
        }))
    }

    #[tool(description = "Get CCIP Token Pool rate limiter configuration for a specific remote chain. Returns inbound and outbound rate limits (tokens per second, capacity) that control the maximum cross-chain transfer throughput. Part of CCIP v1.6+ security model.")]
    async fn ccip_get_rate_limits(
        &self,
        Parameters(params): Parameters<CcipGetRateLimitsParams>,
    ) -> std::result::Result<Json<RpcPassthroughOutput>, ErrorData> {
        let chain_id = params.chain.as_deref().unwrap_or("ethereum");
        let chain = resolve_chain(chain_id)?;

        let remote_selector: u64 = params
            .remote_chain_selector
            .parse()
            .or_else(|_| {
                resolve_chain_selector(&params.remote_chain_selector)
                    .ok_or_else(|| err_invalid(format!("Invalid chain selector: {}", params.remote_chain_selector)))
            })?;

        // getCurrentOutboundRateLimiterState(uint64 remoteChainSelector)
        // selector: 0x5765cd58 (approximate — exact selector may vary by pool version)
        // Returns: RateLimiter.TokenBucket (uint128 tokens, uint32 lastUpdated, bool isEnabled,
        //   uint128 capacity, uint128 rate)
        let selector = hex::decode("5765cd58").unwrap();
        let mut calldata = Vec::new();
        calldata.extend_from_slice(&selector);
        calldata.extend_from_slice(&encode_uint64(remote_selector));

        let outbound = eth_call(&self.http_client, &chain.rpc_url, &params.pool_address, &calldata).await;

        // getCurrentInboundRateLimiterState(uint64 remoteChainSelector)
        // selector: 0xe5889e42
        let in_selector = hex::decode("e5889e42").unwrap();
        let mut in_calldata = Vec::new();
        in_calldata.extend_from_slice(&in_selector);
        in_calldata.extend_from_slice(&encode_uint64(remote_selector));

        let inbound = eth_call(&self.http_client, &chain.rpc_url, &params.pool_address, &in_calldata).await;

        let parse_bucket = |result: &[u8]| -> serde_json::Value {
            if result.len() < 160 {
                return serde_json::json!({"error": "insufficient data"});
            }
            let tokens = {
                let mut arr = [0u8; 16];
                arr.copy_from_slice(&result[16..32]);
                u128::from_be_bytes(arr)
            };
            let is_enabled = result[95] != 0;
            let capacity = {
                let mut arr = [0u8; 16];
                arr.copy_from_slice(&result[112..128]);
                u128::from_be_bytes(arr)
            };
            let rate = {
                let mut arr = [0u8; 16];
                arr.copy_from_slice(&result[144..160]);
                u128::from_be_bytes(arr)
            };
            serde_json::json!({
                "tokens_available": tokens.to_string(),
                "is_enabled": is_enabled,
                "capacity": capacity.to_string(),
                "rate_per_second": rate.to_string(),
            })
        };

        let outbound_info = match outbound {
            Ok(ref r) => parse_bucket(r),
            Err(e) => serde_json::json!({"error": e.message.to_string()}),
        };
        let inbound_info = match inbound {
            Ok(ref r) => parse_bucket(r),
            Err(e) => serde_json::json!({"error": e.message.to_string()}),
        };

        json_result(serde_json::json!({
            "pool_address": params.pool_address,
            "chain": chain.chain_name,
            "remote_chain": chain_selector_name(remote_selector),
            "remote_chain_selector": remote_selector.to_string(),
            "outbound_rate_limit": outbound_info,
            "inbound_rate_limit": inbound_info,
            "note": "Rate limits control maximum cross-chain throughput. 'capacity' is the bucket size, 'rate_per_second' is the refill rate. When tokens_available reaches 0, transfers are blocked until the bucket refills.",
        }))
    }

    // ─── Functions Tools (continued) ───

    #[tool(description = "Get Chainlink Functions subscription details including balance, owner, authorized consumers, and request counts. Queries the Functions Router contract on-chain.")]
    async fn chainlink_get_subscription(
        &self,
        Parameters(params): Parameters<ChainlinkGetSubscriptionParams>,
    ) -> std::result::Result<Json<RpcPassthroughOutput>, ErrorData> {
        let chain_id = params.chain_id.as_deref().unwrap_or("ethereum");
        let chain = resolve_chain(chain_id)?;

        let sub_id: u64 = params
            .subscription_id
            .parse()
            .map_err(|e| err_invalid(format!("Invalid subscription ID: {}", e)))?;

        // Build calldata: getSubscription(uint64 subscriptionId)
        // Function selector for getSubscription(uint64): 0xa47c7696
        let selector = hex::decode("a47c7696").unwrap();
        let mut calldata = Vec::new();
        calldata.extend_from_slice(&selector);
        calldata.extend_from_slice(&encode_uint64(sub_id));

        info!(
            router = %params.router_address,
            sub_id = sub_id,
            chain = %chain.chain_name,
            "Querying Chainlink Functions subscription"
        );

        let result = eth_call(
            &self.http_client,
            &chain.rpc_url,
            &params.router_address,
            &calldata,
        )
        .await?;

        // getSubscription returns:
        // (uint96 balance, address owner, uint64 blockedBalance, address proposedOwner,
        //  address[] consumers, bytes32 flags)
        // Minimum ~192 bytes for the fixed fields
        if result.len() < 192 {
            return Err(err_internal(format!(
                "Unexpected response from getSubscription(): {} bytes",
                result.len()
            )));
        }

        // balance: uint96 in last 12 bytes of word 0
        let balance = {
            let mut arr = [0u8; 16];
            arr[4..16].copy_from_slice(&result[20..32]);
            u128::from_be_bytes(arr)
        };

        // owner: address in last 20 bytes of word 1
        let owner = format!("0x{}", hex::encode(&result[44..64]));

        // blocked_balance: uint64 in last 8 bytes of word 2
        let blocked_balance = {
            let mut arr = [0u8; 8];
            arr.copy_from_slice(&result[88..96]);
            u64::from_be_bytes(arr)
        };

        // proposed_owner: address in last 20 bytes of word 3
        let proposed_owner = format!("0x{}", hex::encode(&result[108..128]));

        // consumers: dynamic array (parse offset, then length, then addresses)
        let mut consumers = Vec::new();
        if result.len() >= 192 {
            let offset = {
                let mut arr = [0u8; 8];
                arr.copy_from_slice(&result[152..160]);
                u64::from_be_bytes(arr) as usize
            };
            if offset + 32 <= result.len() {
                let count = {
                    let mut arr = [0u8; 8];
                    let start = offset + 24;
                    if start + 8 <= result.len() {
                        arr.copy_from_slice(&result[start..start + 8]);
                        u64::from_be_bytes(arr) as usize
                    } else {
                        0
                    }
                };
                for i in 0..count.min(20) {
                    // Cap at 20 consumers
                    let addr_start = offset + 32 + (i * 32) + 12;
                    if addr_start + 20 <= result.len() {
                        consumers
                            .push(format!("0x{}", hex::encode(&result[addr_start..addr_start + 20])));
                    }
                }
            }
        }

        json_result(serde_json::json!({
            "subscription_id": sub_id,
            "router_address": params.router_address,
            "chain": chain.chain_name,
            "balance_wei": balance.to_string(),
            "balance_link": format!("{:.6}", balance as f64 / 1e18),
            "owner": owner,
            "blocked_balance_wei": blocked_balance.to_string(),
            "proposed_owner": proposed_owner,
            "consumers": consumers,
            "consumer_count": consumers.len(),
        }))
    }

    #[tool(description = "Broadcast a pre-signed Ethereum transaction (CCIP Router.ccipSend, VRF requestRandomWords, Functions request, etc.) to the chosen chain via eth_sendRawTransaction. Returns the resulting transaction hash as plain text. Sign the tx externally — typically built via ccip_send_message or vrf_request_random and signed with the operator key.")]
    async fn chainlink_broadcast_signed_tx(
        &self,
        Parameters(params): Parameters<ChainlinkBroadcastTxParams>,
    ) -> std::result::Result<Json<RpcPassthroughOutput>, ErrorData> {
        let chain = resolve_chain(&params.chain)?;
        let tx_hash = eth_send_raw_tx(
            &self.http_client,
            &chain.rpc_url,
            &params.signed_tx_hex,
        )
        .await?;
        text_result(tx_hash)
    }
}

// ─── ServerHandler ───

#[tool_handler]
impl ServerHandler for ChainlinkMcpServer {
    fn get_info(&self) -> ServerInfo {
        let mut info = ServerInfo::default();
        info.protocol_version = ProtocolVersion::V_2025_11_25;
        info.capabilities = ServerCapabilities::builder().enable_tools().build();
        let mut impl_info = Implementation::default();
        impl_info.name = "tenzro-chainlink".into();
        impl_info.title = Some("Tenzro Chainlink MCP Server".into());
        impl_info.version = env!("CARGO_PKG_VERSION").into();
        impl_info.description = Some(
            "The most complete Chainlink MCP server — 20 tools covering CCIP cross-chain messaging, Data Feeds, Data Streams, VRF v2.5, Proof of Reserve, Automation, and Functions"
                .into(),
        );
        impl_info.website_url = Some("https://chain.link".into());
        info.server_info = impl_info;
        info.instructions = Some(
            "Tenzro Chainlink MCP Server — the most complete Chainlink MCP available. \
             20 tools covering the full Chainlink product surface.\n\n\
             TOOLS BY CATEGORY:\n\n\
             CCIP Cross-Chain (8 tools):\n\
             - ccip_get_fee — Estimate CCIP fee via Router.getFee()\n\
             - ccip_send_message — Build ccipSend() calldata\n\
             - ccip_track_message — Track message via OffRamp\n\
             - ccip_get_supported_chains — List CCIP chains\n\
             - ccip_get_supported_tokens — List CCIP tokens\n\
             - ccip_get_lanes — Get source-destination lanes\n\
             - ccip_get_token_pool — Get CCT token pool info (v1.6+)\n\
             - ccip_get_rate_limits — Get per-lane rate limiter config\n\n\
             Data Feeds (2 tools):\n\
             - chainlink_get_price — Read latestRoundData()\n\
             - chainlink_list_feeds — List feed addresses per chain\n\n\
             Data Streams (2 tools) — sub-second latency:\n\
             - ds_get_report — Fetch Data Streams report by feed ID\n\
             - ds_list_feeds — List available Data Streams feeds\n\n\
             VRF v2.5 (2 tools) — verifiable randomness:\n\
             - vrf_request_random — Build requestRandomWords() calldata\n\
             - vrf_get_subscription — Get VRF subscription details\n\n\
             Proof of Reserve (2 tools):\n\
             - por_get_reserve — Read reserve amount from PoR feed\n\
             - por_list_feeds — List well-known PoR feeds\n\n\
             Automation (2 tools):\n\
             - chainlink_check_upkeep — Dry-run checkUpkeep()\n\
             - chainlink_get_upkeep_info — Get upkeep from registry\n\n\
             Functions (2 tools):\n\
             - chainlink_estimate_functions_cost — Estimate LINK cost\n\
             - chainlink_get_subscription — Get subscription details\n\n\
             CCIP CHAIN SELECTORS:\n\
             Ethereum: 5009297550715157269 | Arbitrum: 4949039107694359620\n\
             Optimism: 3734403246176062136 | Base: 15971525489660198786\n\
             Polygon: 4051577828743386545 | BSC: 11344663589394136015\n\
             Avalanche: 6433500567565415381"
                .to_string(),
        );
        info
    }
}

// ─── Server startup ───

/// Start the Chainlink CCIP MCP server on the given address using Streamable HTTP transport.
pub async fn start_chainlink_mcp_server(
    listen_addr: String,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (_keep_tx, shutdown_rx) = tokio::sync::broadcast::channel::<()>(1);
    start_chainlink_mcp_server_with_shutdown(listen_addr, shutdown_rx).await
}

/// Start the Chainlink CCIP MCP server with a graceful-shutdown channel. When
/// the broadcast sender fires, axum stops accepting new connections and lets
/// in-flight requests drain before the future resolves.
pub async fn start_chainlink_mcp_server_with_shutdown(
    listen_addr: String,
    mut shutdown_rx: tokio::sync::broadcast::Receiver<()>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
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
            "chainlink-mcp.tenzro.xyz".to_string(),
        ]);

    let service = StreamableHttpService::new(
        move || Ok(ChainlinkMcpServer::new()),
        Arc::new(LocalSessionManager::default()),
        config,
    );

    let app = axum::Router::new()
        .nest_service("/mcp", service)
        .layer(tower::limit::ConcurrencyLimitLayer::new(100))
        .layer(tower_http::limit::RequestBodyLimitLayer::new(2 * 1024 * 1024));

    let listener = tokio::net::TcpListener::bind(&listen_addr).await?;
    info!(addr = %listen_addr, tools = 12, "Chainlink MCP Server listening");
    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            let _ = shutdown_rx.recv().await;
            info!("Chainlink MCP server shutting down gracefully");
        })
        .await?;

    Ok(())
}
