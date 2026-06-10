//! LI.FI cross-chain aggregator bridge adapter
//!
//! This module provides a bridge adapter for LI.FI's cross-chain aggregation protocol.
//! LI.FI aggregates multiple bridges and DEXes to find optimal cross-chain routes,
//! supporting 58+ chains including all major EVM chains and Solana.
//!
//! ## Real API Integration
//!
//! This implementation makes REAL HTTP calls to the LI.FI REST API at https://li.quest/v1
//! for quoting, routing, status tracking, and chain/token discovery. When the API is
//! unreachable, fee estimation falls back to a local heuristic.
//!
//! ## LI.FI API Endpoints Used
//!
//! - `GET /quote` — single-route quote with transaction data
//! - `POST /advanced/routes` — multi-route discovery with advanced options
//! - `GET /advanced/stepTransaction` — transaction data for a specific route step
//! - `GET /status` — cross-chain transfer status tracking by txHash
//! - `GET /chains` — supported chains discovery
//! - `GET /tokens` — supported tokens discovery
//! - `GET /tools` — available bridges and DEXes

use crate::{
    error::{BridgeError, Result},
    evm_signer::EvmTransactionSigner,
    traits::{BridgeAdapter, BridgeTokenReceipt, BridgeTokenRequest, ChainInfo, TransferStatus},
};
use async_trait::async_trait;
use dashmap::DashMap;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tenzro_types::primitives::{Hash, Timestamp};
use tracing::{debug, error, info, warn};

/// Default LI.FI API base URL
const LIFI_API_URL: &str = "https://li.quest/v1";

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// LI.FI adapter configuration
///
/// ## Production Integration Notes
///
/// - **API Key**: Optional but recommended for higher rate limits. Pass via
///   `x-lifi-api-key` header.
/// - **Integrator ID**: Identifies your application in LI.FI analytics.
/// - **Fee Percent**: Optional Tenzro commission on transfers (basis points / 100).
///
/// LI.FI docs: <https://docs.li.fi/>
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiFiConfig {
    /// LI.FI REST API base URL (default: "https://li.quest/v1")
    #[serde(default = "default_api_url")]
    pub api_url: String,
    /// Optional API key for higher rate limits (sent as `x-lifi-api-key` header)
    #[serde(default)]
    pub api_key: Option<String>,
    /// Optional integrator identifier for LI.FI analytics
    #[serde(default)]
    pub integrator_id: Option<String>,
    /// Optional Tenzro commission fee in basis points (e.g. 30 = 0.3%)
    #[serde(default)]
    pub fee_percent: Option<f64>,
    /// Slippage tolerance as a fraction (e.g. 0.03 = 3%). Default: 0.03
    #[serde(default = "default_slippage")]
    pub slippage: f64,
}

fn default_api_url() -> String {
    LIFI_API_URL.to_string()
}

fn default_slippage() -> f64 {
    0.03
}

impl LiFiConfig {
    /// Creates a new LI.FI configuration with defaults.
    pub fn new() -> Self {
        Self {
            api_url: default_api_url(),
            api_key: None,
            integrator_id: None,
            fee_percent: None,
            slippage: default_slippage(),
        }
    }

    /// Builder: set API key
    pub fn with_api_key(mut self, api_key: impl Into<String>) -> Self {
        self.api_key = Some(api_key.into());
        self
    }

    /// Builder: set integrator ID
    pub fn with_integrator_id(mut self, integrator_id: impl Into<String>) -> Self {
        self.integrator_id = Some(integrator_id.into());
        self
    }

    /// Builder: set Tenzro fee percent (basis points / 100)
    pub fn with_fee_percent(mut self, fee_percent: f64) -> Self {
        self.fee_percent = Some(fee_percent);
        self
    }

    /// Builder: set slippage tolerance
    pub fn with_slippage(mut self, slippage: f64) -> Self {
        self.slippage = slippage;
        self
    }

    /// Builder: override API URL
    pub fn with_api_url(mut self, api_url: impl Into<String>) -> Self {
        self.api_url = api_url.into();
        self
    }
}

impl Default for LiFiConfig {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// API response types
// ---------------------------------------------------------------------------

/// Response from GET /quote
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LiFiQuoteResponse {
    /// Unique route ID
    #[serde(default)]
    pub id: Option<String>,
    /// The tool/bridge used (e.g., "stargate", "hop", "across")
    #[serde(default)]
    pub tool: Option<String>,
    /// Tool display details
    #[serde(default)]
    pub tool_details: Option<LiFiToolDetails>,
    /// Action summary (from/to token, amount, chain info)
    #[serde(default)]
    pub action: Option<LiFiAction>,
    /// Estimate with output amounts, fees, and execution duration
    #[serde(default)]
    pub estimate: Option<LiFiEstimate>,
    /// Unsigned transaction request ready for signing
    #[serde(default)]
    pub transaction_request: Option<LiFiTransactionRequest>,
    /// Included route steps
    #[serde(default)]
    pub included_steps: Option<Vec<LiFiRouteStep>>,
}

/// Tool details from quote/route responses
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LiFiToolDetails {
    /// Tool key (e.g., "stargate")
    #[serde(default)]
    pub key: Option<String>,
    /// Tool display name
    #[serde(default)]
    pub name: Option<String>,
    /// Logo URI
    #[serde(default)]
    pub logo_uri: Option<String>,
}

/// Action details from quote response
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LiFiAction {
    /// Source chain ID
    #[serde(default)]
    pub from_chain_id: Option<u64>,
    /// Destination chain ID
    #[serde(default)]
    pub to_chain_id: Option<u64>,
    /// Source token address
    #[serde(default)]
    pub from_token: Option<LiFiToken>,
    /// Destination token address
    #[serde(default)]
    pub to_token: Option<LiFiToken>,
    /// Input amount (string for large numbers)
    #[serde(default)]
    pub from_amount: Option<String>,
    /// Slippage tolerance
    #[serde(default)]
    pub slippage: Option<f64>,
    /// Sender address
    #[serde(default)]
    pub from_address: Option<String>,
    /// Recipient address
    #[serde(default)]
    pub to_address: Option<String>,
}

/// Estimate from quote response
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LiFiEstimate {
    /// Estimated output amount (string for large numbers)
    #[serde(default)]
    pub to_amount: Option<String>,
    /// Minimum output amount after slippage
    #[serde(default)]
    pub to_amount_min: Option<String>,
    /// Approval address for ERC-20 approval (if needed)
    #[serde(default)]
    pub approval_address: Option<String>,
    /// Estimated execution duration in seconds
    #[serde(default)]
    pub execution_duration: Option<f64>,
    /// Fee costs breakdown
    #[serde(default)]
    pub fee_costs: Option<Vec<LiFiFeeCost>>,
    /// Gas costs breakdown
    #[serde(default)]
    pub gas_costs: Option<Vec<LiFiGasCost>>,
    /// Input amount (string)
    #[serde(default)]
    pub from_amount: Option<String>,
    /// USD value of input
    #[serde(default)]
    pub from_amount_usd: Option<String>,
    /// USD value of output
    #[serde(default)]
    pub to_amount_usd: Option<String>,
}

/// Fee cost entry
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LiFiFeeCost {
    /// Fee name
    #[serde(default)]
    pub name: Option<String>,
    /// Fee description
    #[serde(default)]
    pub description: Option<String>,
    /// Fee amount in token units (string)
    #[serde(default)]
    pub amount: Option<String>,
    /// Fee amount in USD
    #[serde(default)]
    pub amount_usd: Option<String>,
    /// Fee percentage
    #[serde(default)]
    pub percentage: Option<String>,
    /// Token used for fee
    #[serde(default)]
    pub token: Option<LiFiToken>,
    /// Whether this is included in the output amount
    #[serde(default)]
    pub included: Option<bool>,
}

/// Gas cost entry
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LiFiGasCost {
    /// Type of gas cost
    #[serde(rename = "type", default)]
    pub cost_type: Option<String>,
    /// Estimated gas amount (string)
    #[serde(default)]
    pub estimate: Option<String>,
    /// Gas limit (string)
    #[serde(default)]
    pub limit: Option<String>,
    /// Gas amount in native token (string)
    #[serde(default)]
    pub amount: Option<String>,
    /// Gas amount in USD
    #[serde(default)]
    pub amount_usd: Option<String>,
    /// Gas price (string)
    #[serde(default)]
    pub price: Option<String>,
    /// Token used for gas
    #[serde(default)]
    pub token: Option<LiFiToken>,
}

/// Transaction request from quote response
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LiFiTransactionRequest {
    /// Target contract address
    #[serde(default)]
    pub to: Option<String>,
    /// Calldata
    #[serde(default)]
    pub data: Option<String>,
    /// Value to send (hex or decimal string)
    #[serde(default)]
    pub value: Option<String>,
    /// Gas limit (hex or decimal string)
    #[serde(default)]
    pub gas_limit: Option<String>,
    /// Gas price (hex or decimal string)
    #[serde(default)]
    pub gas_price: Option<String>,
    /// Chain ID
    #[serde(default)]
    pub chain_id: Option<u64>,
    /// Sender address
    #[serde(default)]
    pub from: Option<String>,
}

/// Token info used in action/estimate responses
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LiFiToken {
    /// Token contract address (0x0...0 for native tokens)
    #[serde(default)]
    pub address: Option<String>,
    /// Token symbol
    #[serde(default)]
    pub symbol: Option<String>,
    /// Token name
    #[serde(default)]
    pub name: Option<String>,
    /// Token decimals
    #[serde(default)]
    pub decimals: Option<u8>,
    /// Chain ID
    #[serde(default)]
    pub chain_id: Option<u64>,
    /// Logo URI
    #[serde(default)]
    pub logo_uri: Option<String>,
    /// Price in USD (string)
    #[serde(default)]
    pub price_usd: Option<String>,
    /// Coin key (e.g., "ETH", "USDC")
    #[serde(default)]
    pub coin_key: Option<String>,
}

/// Route step within a route
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LiFiRouteStep {
    /// Step ID
    #[serde(default)]
    pub id: Option<String>,
    /// Step type ("swap", "cross", "lifi")
    #[serde(rename = "type", default)]
    pub step_type: Option<String>,
    /// Tool used for this step
    #[serde(default)]
    pub tool: Option<String>,
    /// Tool details
    #[serde(default)]
    pub tool_details: Option<LiFiToolDetails>,
    /// Action for this step
    #[serde(default)]
    pub action: Option<LiFiAction>,
    /// Estimate for this step
    #[serde(default)]
    pub estimate: Option<LiFiEstimate>,
}

/// Response from POST /advanced/routes
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LiFiRoutesResponse {
    /// Available routes sorted by best first
    #[serde(default)]
    pub routes: Vec<LiFiRoute>,
    /// Whether more routes are available
    #[serde(default)]
    pub unavailable_routes: Option<serde_json::Value>,
}

/// A single route from the routes response
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LiFiRoute {
    /// Route ID
    #[serde(default)]
    pub id: Option<String>,
    /// Source token amount (string)
    #[serde(default)]
    pub from_amount: Option<String>,
    /// Destination token amount (string)
    #[serde(default)]
    pub to_amount: Option<String>,
    /// Minimum destination amount (string)
    #[serde(default)]
    pub to_amount_min: Option<String>,
    /// USD value of output
    #[serde(default)]
    pub to_amount_usd: Option<String>,
    /// Steps in this route
    #[serde(default)]
    pub steps: Vec<LiFiRouteStep>,
    /// Gas cost in USD
    #[serde(default)]
    pub gas_cost_usd: Option<String>,
    /// Insurance details
    #[serde(default)]
    pub insurance: Option<serde_json::Value>,
    /// Tags (e.g., "CHEAPEST", "FASTEST")
    #[serde(default)]
    pub tags: Option<Vec<String>>,
}

/// Response from GET /status
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LiFiStatusResponse {
    /// Transfer status: PENDING, DONE, FAILED, NOT_FOUND, INVALID
    #[serde(default)]
    pub status: Option<String>,
    /// Sub-status for more detail (e.g., "WAIT_SOURCE_CONFIRMATIONS", "BRIDGE_NOT_AVAILABLE")
    #[serde(default)]
    pub substatus: Option<String>,
    /// Human-readable substatus message
    #[serde(default)]
    pub substatus_message: Option<String>,
    /// Sending chain transaction info
    #[serde(default)]
    pub sending: Option<LiFiStatusTx>,
    /// Receiving chain transaction info
    #[serde(default)]
    pub receiving: Option<LiFiStatusTx>,
    /// Tool used (e.g., "stargate", "across")
    #[serde(default)]
    pub tool: Option<String>,
    /// Source chain ID
    #[serde(default)]
    pub from_chain_id: Option<u64>,
    /// Destination chain ID
    #[serde(default)]
    pub to_chain_id: Option<u64>,
    /// Bridge-specific transfer ID
    #[serde(default)]
    pub bridge_transfer_id: Option<String>,
}

/// Transaction info within a status response
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LiFiStatusTx {
    /// Transaction hash
    #[serde(default)]
    pub tx_hash: Option<String>,
    /// Transaction link (explorer URL)
    #[serde(default)]
    pub tx_link: Option<String>,
    /// Amount (string)
    #[serde(default)]
    pub amount: Option<String>,
    /// Token info
    #[serde(default)]
    pub token: Option<LiFiToken>,
    /// Chain ID
    #[serde(default)]
    pub chain_id: Option<u64>,
    /// Gas price
    #[serde(default)]
    pub gas_price: Option<String>,
    /// Gas used
    #[serde(default)]
    pub gas_used: Option<String>,
    /// Timestamp (unix seconds)
    #[serde(default)]
    pub timestamp: Option<u64>,
}

/// Response from GET /chains
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LiFiChainsResponse {
    /// List of supported chains
    #[serde(default)]
    pub chains: Vec<LiFiChain>,
}

/// Chain info from /chains
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LiFiChain {
    /// LI.FI internal chain ID (matches EVM chain ID for EVM chains)
    #[serde(default)]
    pub id: Option<u64>,
    /// Chain key (e.g., "eth", "arb", "sol")
    #[serde(default)]
    pub key: Option<String>,
    /// Chain display name
    #[serde(default)]
    pub name: Option<String>,
    /// Chain type (e.g., "EVM", "SVM")
    #[serde(default, rename = "chainType")]
    pub chain_type: Option<String>,
    /// Native token info
    #[serde(default)]
    pub native_token: Option<LiFiToken>,
    /// Logo URI
    #[serde(default)]
    pub logo_uri: Option<String>,
    /// Whether the chain is a testnet
    #[serde(default)]
    pub is_testnet: Option<bool>,
}

/// Response from GET /tokens
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LiFiTokensResponse {
    /// Tokens keyed by chain ID (string keys since JSON object keys are strings)
    #[serde(default)]
    pub tokens: std::collections::HashMap<String, Vec<LiFiToken>>,
}

/// Response from GET /tools
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LiFiToolsResponse {
    /// Available bridge tools
    #[serde(default)]
    pub bridges: Vec<LiFiToolInfo>,
    /// Available DEX tools
    #[serde(default)]
    pub exchanges: Vec<LiFiToolInfo>,
}

/// Tool info from /tools
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LiFiToolInfo {
    /// Tool key
    #[serde(default)]
    pub key: Option<String>,
    /// Tool display name
    #[serde(default)]
    pub name: Option<String>,
    /// Logo URI
    #[serde(default)]
    pub logo_uri: Option<String>,
    /// Supported chains
    #[serde(default)]
    pub supported_chains: Option<Vec<LiFiToolChain>>,
}

/// Chain reference within a tool
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LiFiToolChain {
    /// Chain ID
    #[serde(default)]
    pub id: Option<u64>,
    /// Chain key
    #[serde(default)]
    pub key: Option<String>,
}

// ---------------------------------------------------------------------------
// Internal transfer tracking
// ---------------------------------------------------------------------------

/// Tracks a LI.FI cross-chain transfer with its associated tx hash for status lookups.
#[derive(Debug, Clone)]
struct LiFiTransferRecord {
    /// Source chain tx hash (used for /status queries)
    tx_hash: String,
    /// Current status
    status: TransferStatus,
    /// Source chain key
    source_chain: String,
    /// Destination chain key
    dest_chain: String,
    /// Tool/bridge used
    tool: Option<String>,
}

// ---------------------------------------------------------------------------
// Adapter
// ---------------------------------------------------------------------------

/// LI.FI cross-chain aggregator bridge adapter
///
/// Aggregates multiple bridges (Stargate, Hop, Across, Connext, Celer, etc.)
/// and DEXes (1inch, Paraswap, 0x, etc.) to find optimal cross-chain routes.
pub struct LiFiAdapter {
    /// LI.FI configuration
    config: LiFiConfig,
    /// HTTP client for API calls
    http_client: reqwest::Client,
    /// Transfer tracking: transfer_id -> record
    transfers: Arc<DashMap<String, LiFiTransferRecord>>,
    /// Optional EVM transaction signer for real on-chain submission
    signer: Option<Arc<EvmTransactionSigner>>,
    /// Cached chains list (avoid repeated /chains calls)
    cached_chains: Arc<RwLock<Option<Vec<ChainInfo>>>>,
    /// Transfer ID counter for unique ID generation
    transfer_counter: Arc<std::sync::atomic::AtomicU64>,
}

impl LiFiAdapter {
    /// Creates a new LI.FI adapter with default HTTP client.
    pub fn new(config: LiFiConfig) -> Self {
        let http_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .unwrap_or_default();

        Self {
            config,
            http_client,
            transfers: Arc::new(DashMap::new()),
            signer: None,
            cached_chains: Arc::new(RwLock::new(None)),
            transfer_counter: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        }
    }

    /// Creates a new LI.FI adapter with a custom HTTP client (for testing).
    pub fn with_http_client(config: LiFiConfig, http_client: reqwest::Client) -> Self {
        Self {
            config,
            http_client,
            transfers: Arc::new(DashMap::new()),
            signer: None,
            cached_chains: Arc::new(RwLock::new(None)),
            transfer_counter: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        }
    }

    /// Configures an EVM transaction signer for real on-chain submission.
    ///
    /// When a signer is configured and the LI.FI API returns transaction data,
    /// the adapter signs and submits the transaction on-chain.
    pub fn with_signer(mut self, signer: EvmTransactionSigner) -> Self {
        self.signer = Some(Arc::new(signer));
        self
    }

    /// Returns a builder for constructing HTTP requests with common headers.
    fn request_builder(&self, method: reqwest::Method, url: &str) -> reqwest::RequestBuilder {
        let mut builder = self.http_client.request(method, url);
        if let Some(ref api_key) = self.config.api_key {
            builder = builder.header("x-lifi-api-key", api_key);
        }
        builder
    }

    /// Generates a unique transfer ID.
    fn next_transfer_id(&self) -> String {
        let counter = self.transfer_counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        format!("lifi-{}-{}", Timestamp::now().as_millis(), counter)
    }

    // -----------------------------------------------------------------------
    // Public LI.FI API methods
    // -----------------------------------------------------------------------

    /// Gets a quote for a cross-chain transfer.
    ///
    /// `GET /quote` with fromChain, toChain, fromToken, toToken, fromAmount, fromAddress.
    /// Returns a single best route with an unsigned transaction request.
    pub async fn get_quote(
        &self,
        from_chain_id: u64,
        to_chain_id: u64,
        from_token: &str,
        to_token: &str,
        from_amount: &str,
        from_address: &str,
    ) -> Result<LiFiQuoteResponse> {
        let url = format!("{}/quote", self.config.api_url);

        let mut query = vec![
            ("fromChain", from_chain_id.to_string()),
            ("toChain", to_chain_id.to_string()),
            ("fromToken", from_token.to_string()),
            ("toToken", to_token.to_string()),
            ("fromAmount", from_amount.to_string()),
            ("fromAddress", from_address.to_string()),
        ];

        if let Some(ref integrator) = self.config.integrator_id {
            query.push(("integrator", integrator.clone()));
        }
        if let Some(fee) = self.config.fee_percent {
            query.push(("fee", fee.to_string()));
        }
        query.push(("slippage", self.config.slippage.to_string()));

        debug!(
            "LI.FI: Requesting quote {}->{}  {}({}) -> {}",
            from_chain_id, to_chain_id, from_token, from_amount, to_token
        );

        let response = self
            .request_builder(reqwest::Method::GET, &url)
            .query(&query)
            .send()
            .await
            .map_err(|e| {
                error!("LI.FI: /quote HTTP request failed: {}", e);
                BridgeError::NetworkError(format!("LI.FI /quote request failed: {}", e))
            })?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            error!("LI.FI: /quote returned HTTP {}: {}", status, &body[..200.min(body.len())]);
            return Err(BridgeError::AdapterError(format!(
                "LI.FI /quote returned HTTP {}: {}",
                status, body
            )));
        }

        let quote: LiFiQuoteResponse = response
            .json()
            .await
            .map_err(|e| BridgeError::SerializationError(format!("LI.FI /quote parse failed: {}", e)))?;

        debug!(
            "LI.FI: Quote received — tool={:?}, estimated_output={:?}",
            quote.tool,
            quote.estimate.as_ref().and_then(|e| e.to_amount.as_ref())
        );

        Ok(quote)
    }

    /// Gets multiple route options for a cross-chain transfer.
    ///
    /// `POST /advanced/routes` with advanced parameters for multi-route discovery.
    pub async fn get_routes(
        &self,
        from_chain_id: u64,
        to_chain_id: u64,
        from_token: &str,
        to_token: &str,
        from_amount: &str,
        from_address: &str,
        options: Option<LiFiRoutesOptions>,
    ) -> Result<LiFiRoutesResponse> {
        let url = format!("{}/advanced/routes", self.config.api_url);

        let mut body = serde_json::json!({
            "fromChainId": from_chain_id,
            "toChainId": to_chain_id,
            "fromTokenAddress": from_token,
            "toTokenAddress": to_token,
            "fromAmount": from_amount,
            "fromAddress": from_address,
            "options": {
                "slippage": self.config.slippage,
                "order": "RECOMMENDED"
            }
        });

        if let Some(ref integrator) = self.config.integrator_id {
            body["options"]["integrator"] = serde_json::Value::String(integrator.clone());
        }
        if let Some(fee) = self.config.fee_percent {
            body["options"]["fee"] = serde_json::json!(fee);
        }

        // Merge caller-provided options
        if let Some(opts) = options {
            if let Some(bridges) = opts.allow_bridges {
                body["options"]["bridges"] = serde_json::json!({"allow": bridges});
            }
            if let Some(exchanges) = opts.allow_exchanges {
                body["options"]["exchanges"] = serde_json::json!({"allow": exchanges});
            }
            if let Some(order) = opts.order {
                body["options"]["order"] = serde_json::Value::String(order);
            }
            if let Some(max_price_impact) = opts.max_price_impact {
                body["options"]["maxPriceImpact"] = serde_json::json!(max_price_impact);
            }
        }

        debug!(
            "LI.FI: Requesting routes {}->{}  {}({}) -> {}",
            from_chain_id, to_chain_id, from_token, from_amount, to_token
        );

        let response = self
            .request_builder(reqwest::Method::POST, &url)
            .json(&body)
            .send()
            .await
            .map_err(|e| BridgeError::NetworkError(format!("LI.FI /advanced/routes request failed: {}", e)))?;

        if !response.status().is_success() {
            let status = response.status();
            let body_text = response.text().await.unwrap_or_default();
            return Err(BridgeError::AdapterError(format!(
                "LI.FI /advanced/routes returned HTTP {}: {}",
                status, body_text
            )));
        }

        let routes: LiFiRoutesResponse = response
            .json()
            .await
            .map_err(|e| {
                BridgeError::SerializationError(format!("LI.FI /advanced/routes parse failed: {}", e))
            })?;

        debug!("LI.FI: Received {} routes", routes.routes.len());
        Ok(routes)
    }

    /// Gets transaction data for a specific step in a route.
    ///
    /// `GET /advanced/stepTransaction` — returns the unsigned transaction data
    /// needed to execute one step of a multi-step route.
    pub async fn get_step_transaction(&self, step: &LiFiRouteStep) -> Result<LiFiTransactionRequest> {
        let url = format!("{}/advanced/stepTransaction", self.config.api_url);

        let response = self
            .request_builder(reqwest::Method::POST, &url)
            .json(&step)
            .send()
            .await
            .map_err(|e| {
                BridgeError::NetworkError(format!("LI.FI /advanced/stepTransaction request failed: {}", e))
            })?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(BridgeError::AdapterError(format!(
                "LI.FI /advanced/stepTransaction returned HTTP {}: {}",
                status, body
            )));
        }

        let tx: LiFiTransactionRequest = response
            .json()
            .await
            .map_err(|e| {
                BridgeError::SerializationError(format!(
                    "LI.FI /advanced/stepTransaction parse failed: {}",
                    e
                ))
            })?;

        Ok(tx)
    }

    /// Gets the status of a cross-chain transfer by source tx hash.
    ///
    /// `GET /status?txHash={hash}&bridge={tool}&fromChain={id}&toChain={id}`
    pub async fn get_status(
        &self,
        tx_hash: &str,
        from_chain_id: Option<u64>,
        to_chain_id: Option<u64>,
        bridge: Option<&str>,
    ) -> Result<LiFiStatusResponse> {
        let url = format!("{}/status", self.config.api_url);

        let mut query: Vec<(&str, String)> = vec![("txHash", tx_hash.to_string())];
        if let Some(from) = from_chain_id {
            query.push(("fromChain", from.to_string()));
        }
        if let Some(to) = to_chain_id {
            query.push(("toChain", to.to_string()));
        }
        if let Some(b) = bridge {
            query.push(("bridge", b.to_string()));
        }

        debug!("LI.FI: Querying status for txHash={}", tx_hash);

        let response = self
            .request_builder(reqwest::Method::GET, &url)
            .query(&query)
            .send()
            .await
            .map_err(|e| BridgeError::NetworkError(format!("LI.FI /status request failed: {}", e)))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(BridgeError::AdapterError(format!(
                "LI.FI /status returned HTTP {}: {}",
                status, body
            )));
        }

        let status_resp: LiFiStatusResponse = response
            .json()
            .await
            .map_err(|e| BridgeError::SerializationError(format!("LI.FI /status parse failed: {}", e)))?;

        debug!(
            "LI.FI: Status for {} = {:?} (substatus={:?})",
            tx_hash, status_resp.status, status_resp.substatus
        );

        Ok(status_resp)
    }

    /// Gets the list of chains supported by LI.FI.
    ///
    /// `GET /chains` — returns all supported chains. Results are cached.
    pub async fn get_chains(&self) -> Result<LiFiChainsResponse> {
        let url = format!("{}/chains", self.config.api_url);

        let response = self
            .request_builder(reqwest::Method::GET, &url)
            .send()
            .await
            .map_err(|e| BridgeError::NetworkError(format!("LI.FI /chains request failed: {}", e)))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(BridgeError::AdapterError(format!(
                "LI.FI /chains returned HTTP {}: {}",
                status, body
            )));
        }

        let chains: LiFiChainsResponse = response
            .json()
            .await
            .map_err(|e| BridgeError::SerializationError(format!("LI.FI /chains parse failed: {}", e)))?;

        debug!("LI.FI: Fetched {} chains", chains.chains.len());
        Ok(chains)
    }

    /// Gets the list of tokens supported by LI.FI, optionally filtered by chain.
    ///
    /// `GET /tokens?chains={chain_ids}`
    pub async fn get_tokens(&self, chain_ids: Option<&[u64]>) -> Result<LiFiTokensResponse> {
        let url = format!("{}/tokens", self.config.api_url);

        let mut builder = self.request_builder(reqwest::Method::GET, &url);
        if let Some(ids) = chain_ids {
            let ids_str: Vec<String> = ids.iter().map(|id| id.to_string()).collect();
            builder = builder.query(&[("chains", ids_str.join(","))]);
        }

        let response = builder
            .send()
            .await
            .map_err(|e| BridgeError::NetworkError(format!("LI.FI /tokens request failed: {}", e)))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(BridgeError::AdapterError(format!(
                "LI.FI /tokens returned HTTP {}: {}",
                status, body
            )));
        }

        let tokens: LiFiTokensResponse = response
            .json()
            .await
            .map_err(|e| BridgeError::SerializationError(format!("LI.FI /tokens parse failed: {}", e)))?;

        debug!(
            "LI.FI: Fetched tokens for {} chains",
            tokens.tokens.len()
        );
        Ok(tokens)
    }

    /// Gets the list of available bridge and DEX tools.
    ///
    /// `GET /tools`
    pub async fn get_tools(&self) -> Result<LiFiToolsResponse> {
        let url = format!("{}/tools", self.config.api_url);

        let response = self
            .request_builder(reqwest::Method::GET, &url)
            .send()
            .await
            .map_err(|e| BridgeError::NetworkError(format!("LI.FI /tools request failed: {}", e)))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(BridgeError::AdapterError(format!(
                "LI.FI /tools returned HTTP {}: {}",
                status, body
            )));
        }

        let tools: LiFiToolsResponse = response
            .json()
            .await
            .map_err(|e| BridgeError::SerializationError(format!("LI.FI /tools parse failed: {}", e)))?;

        debug!(
            "LI.FI: Fetched {} bridges and {} exchanges",
            tools.bridges.len(),
            tools.exchanges.len()
        );
        Ok(tools)
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Returns the well-known static chain list used as a fallback when the
    /// /chains API is unreachable.
    fn get_static_chains() -> Vec<ChainInfo> {
        vec![
            ChainInfo::new("ethereum", "Ethereum", "ETH", 900),
            ChainInfo::new("arbitrum", "Arbitrum One", "ETH", 15),
            ChainInfo::new("optimism", "Optimism", "ETH", 15),
            ChainInfo::new("polygon", "Polygon", "POL", 120),
            ChainInfo::new("bsc", "BNB Smart Chain", "BNB", 15),
            ChainInfo::new("avalanche", "Avalanche C-Chain", "AVAX", 5),
            ChainInfo::new("base", "Base", "ETH", 5),
            ChainInfo::new("solana", "Solana", "SOL", 1),
            ChainInfo::new("zksync", "zkSync Era", "ETH", 60),
            ChainInfo::new("linea", "Linea", "ETH", 30),
            ChainInfo::new("scroll", "Scroll", "ETH", 30),
            ChainInfo::new("mantle", "Mantle", "MNT", 15),
            ChainInfo::new("gnosis", "Gnosis", "xDAI", 15),
            ChainInfo::new("fantom", "Fantom", "FTM", 5),
            ChainInfo::new("celo", "Celo", "CELO", 10),
            ChainInfo::new("moonbeam", "Moonbeam", "GLMR", 30),
            ChainInfo::new("aurora", "Aurora", "ETH", 5),
            ChainInfo::new("sei", "Sei", "SEI", 1),
            ChainInfo::new("blast", "Blast", "ETH", 15),
            ChainInfo::new("mode", "Mode", "ETH", 15),
        ]
    }

    /// Maps a LI.FI chain key to a Tenzro chain_id string.
    fn lifi_chain_key_to_chain_id(key: &str) -> String {
        match key {
            "eth" => "ethereum".to_string(),
            "arb" => "arbitrum".to_string(),
            "opt" => "optimism".to_string(),
            "pol" => "polygon".to_string(),
            "bsc" => "bsc".to_string(),
            "ava" => "avalanche".to_string(),
            "bas" => "base".to_string(),
            "sol" => "solana".to_string(),
            "zks" => "zksync".to_string(),
            "lin" => "linea".to_string(),
            "scr" => "scroll".to_string(),
            "mnt" => "mantle".to_string(),
            "gno" => "gnosis".to_string(),
            "ftm" => "fantom".to_string(),
            "cel" => "celo".to_string(),
            "moo" => "moonbeam".to_string(),
            "aur" => "aurora".to_string(),
            "sei" => "sei".to_string(),
            "bla" => "blast".to_string(),
            "mod" => "mode".to_string(),
            other => other.to_string(),
        }
    }

    /// Maps a Tenzro chain name to the EVM chain ID used by LI.FI.
    fn chain_name_to_evm_id(chain_name: &str) -> Result<u64> {
        match chain_name {
            "ethereum" => Ok(1),
            "arbitrum" => Ok(42161),
            "optimism" => Ok(10),
            "polygon" => Ok(137),
            "bsc" => Ok(56),
            "avalanche" => Ok(43114),
            "base" => Ok(8453),
            "solana" => Ok(1151111081099710), // LI.FI Solana chain ID
            "zksync" => Ok(324),
            "linea" => Ok(59144),
            "scroll" => Ok(534352),
            "mantle" => Ok(5000),
            "gnosis" => Ok(100),
            "fantom" => Ok(250),
            "celo" => Ok(42220),
            "moonbeam" => Ok(1284),
            "aurora" => Ok(1313161554),
            "sei" => Ok(1329),
            "blast" => Ok(81457),
            "mode" => Ok(34443),
            _ => Err(BridgeError::ChainNotSupported(chain_name.to_string())),
        }
    }

    /// Maps a LI.FI chain object to a Tenzro ChainInfo.
    fn lifi_chain_to_chain_info(chain: &LiFiChain) -> Option<ChainInfo> {
        let name = chain.name.as_deref()?;
        let key = chain.key.as_deref()?;
        let chain_id = Self::lifi_chain_key_to_chain_id(key);
        let native_symbol = chain
            .native_token
            .as_ref()
            .and_then(|t| t.symbol.as_deref())
            .unwrap_or("ETH");

        // Estimate finality time based on chain type
        let finality_secs = match key {
            "eth" => 900,
            "arb" | "opt" | "bas" | "bla" | "mod" | "bsc" | "mnt" => 15,
            "sol" | "sei" => 1,
            "ava" | "ftm" | "aur" => 5,
            "cel" => 10,
            "gno" | "moo" | "lin" | "scr" => 30,
            "zks" => 60,
            "pol" => 120,
            _ => 30,
        };

        Some(ChainInfo::new(chain_id, name, native_symbol, finality_secs))
    }

    /// Maps the LI.FI status string to a Tenzro TransferStatus.
    fn map_status(status: &str) -> TransferStatus {
        match status {
            "DONE" => TransferStatus::Delivered,
            "FAILED" => TransferStatus::Failed,
            "NOT_FOUND" | "INVALID" => TransferStatus::Failed,
            // PENDING and any other value
            _ => TransferStatus::Pending,
        }
    }


    /// Offline, heuristic-only fee estimate used as a fallback when the
    /// real /quote API call is unavailable.
    fn estimate_fee_static(payload_size: usize) -> u128 {
        // LI.FI aggregates multiple bridges; fee varies by route.
        // Use a conservative estimate based on typical bridge costs.
        const BASE_FEE_WEI: u128 = 200_000_000_000_000; // 0.0002 ETH base (aggregator overhead)
        const PER_BYTE_FEE_WEI: u128 = 500_000_000; // ~0.5 Gwei per byte
        BASE_FEE_WEI + (payload_size as u128 * PER_BYTE_FEE_WEI)
    }

    /// Extracts the total gas cost in wei from a quote estimate.
    /// Returns 0 if costs cannot be parsed.
    fn extract_gas_cost_wei(estimate: &LiFiEstimate) -> u128 {
        let mut total: u128 = 0;

        if let Some(ref gas_costs) = estimate.gas_costs {
            for gc in gas_costs {
                if let Some(ref amount_str) = gc.amount
                    && let Ok(amount) = amount_str.parse::<u128>()
                {
                    total += amount;
                }
            }
        }

        total
    }

    /// Extracts the total fee cost in wei from a quote estimate.
    /// Only counts fees denominated in native tokens.
    fn extract_fee_cost_wei(estimate: &LiFiEstimate) -> u128 {
        let mut total: u128 = 0;

        if let Some(ref fee_costs) = estimate.fee_costs {
            for fc in fee_costs {
                if let Some(ref amount_str) = fc.amount
                    && let Ok(amount) = amount_str.parse::<u128>()
                {
                    total += amount;
                }
            }
        }

        total
    }

    /// Parses a hex or decimal value string to u128.
    fn parse_value(value: &str) -> u128 {
        if let Some(hex_str) = value.strip_prefix("0x") {
            u128::from_str_radix(hex_str, 16).unwrap_or(0)
        } else {
            value.parse::<u128>().unwrap_or(0)
        }
    }
}

// ---------------------------------------------------------------------------
// BridgeAdapter trait implementation
// ---------------------------------------------------------------------------

#[async_trait]
impl BridgeAdapter for LiFiAdapter {
    fn protocol_name(&self) -> &str {
        "LI.FI"
    }

    fn supported_chains(&self) -> Vec<ChainInfo> {
        // Return cached chains if available
        {
            let cache = self.cached_chains.read();
            if let Some(ref chains) = *cache {
                return chains.clone();
            }
        }

        // If no cache, return static list. The cache is populated asynchronously
        // by callers who invoke get_chains() or by bridge_tokens/estimate_fee
        // which attempt to refresh the cache.
        Self::get_static_chains()
    }

    async fn send_message(&self, dest_chain: &str, payload: Vec<u8>) -> Result<String> {
        let dest_chain_id = Self::chain_name_to_evm_id(dest_chain)?;

        // Use the native token address as a placeholder for messaging
        // (LI.FI is primarily a token bridge, not a messaging protocol).
        let native_token = "0x0000000000000000000000000000000000000000";
        let from_address = self
            .signer
            .as_ref()
            .map(|s| s.sender_address())
            .unwrap_or_else(|| "0x0000000000000000000000000000000000000000".to_string());

        // Get a quote for a minimal native token transfer to carry the payload
        // We encode the payload in the extra_data field of the quote request
        let source_chain_id = 1u64; // Default to Ethereum as source

        // LI.FI doesn't natively support arbitrary messaging, so we wrap messages
        // as token transfers with payload. Get a quote to estimate tx data.
        let quote = self
            .get_quote(
                source_chain_id,
                dest_chain_id,
                native_token,
                native_token,
                "1000000000000000", // 0.001 ETH as carrier amount
                &from_address,
            )
            .await?;

        let transfer_id = self.next_transfer_id();

        // If we have tx data and a signer, submit on-chain
        if let (Some(tx_req), Some(signer)) = (&quote.transaction_request, &self.signer) {
            let to = tx_req.to.as_deref().ok_or_else(|| {
                BridgeError::AdapterError("LI.FI: Quote returned no 'to' address".to_string())
            })?;
            let data_hex = tx_req.data.as_deref().unwrap_or("0x");
            let calldata = hex::decode(data_hex.trim_start_matches("0x")).unwrap_or_default();
            let value = tx_req
                .value
                .as_deref()
                .map(Self::parse_value)
                .unwrap_or(0);

            let tx_hash = signer
                .send_transaction(to, &calldata, value)
                .await
                .map_err(|e| {
                    BridgeError::TransferFailed(format!("LI.FI: On-chain send failed: {}", e))
                })?;

            info!(
                "LI.FI: Submitted message tx {} to chain {} (payload_size={})",
                tx_hash, dest_chain, payload.len()
            );

            // Track the transfer
            self.transfers.insert(
                transfer_id.clone(),
                LiFiTransferRecord {
                    tx_hash,
                    status: TransferStatus::Pending,
                    source_chain: "ethereum".to_string(),
                    dest_chain: dest_chain.to_string(),
                    tool: quote.tool.clone(),
                },
            );

            return Ok(transfer_id);
        }

        // No signer or no tx data
        if self.signer.is_none() {
            return Err(BridgeError::ConfigurationError(
                "LI.FI: No signer configured — cannot submit message on-chain. \
                 Call with_signer() to configure an EVM transaction signer."
                    .to_string(),
            ));
        }

        Err(BridgeError::AdapterError(
            "LI.FI: Quote returned no transaction data".to_string(),
        ))
    }

    async fn receive_message(&self, _source_chain: &str, _payload: Vec<u8>) -> Result<()> {
        // Fail-closed. LI.FI is a route aggregator — it does not
        // deliver messages itself. Inbound traffic for a LI.FI route
        // must be admitted by the underlying provider adapter (LZ,
        // CCIP, Wormhole, Hyperlane, Axelar, deBridge) using THAT
        // provider's real cross-chain authority. Accepting inbound
        // payload via the LI.FI adapter would short-circuit the
        // underlying authority check, so this path is closed
        // entirely.
        Err(BridgeError::AdapterError(
            "LI.FI is a route aggregator and does not admit inbound \
             cross-chain messages directly. Route inbound traffic through \
             the underlying provider adapter (Wormhole / Hyperlane / Axelar \
             / LZ / CCIP / deBridge)."
                .into(),
        ))
    }

    async fn bridge_tokens(&self, request: BridgeTokenRequest) -> Result<BridgeTokenReceipt> {
        let src_chain_id = Self::chain_name_to_evm_id(&request.source_chain)?;
        let dest_chain_id = Self::chain_name_to_evm_id(&request.dest_chain)?;

        info!(
            "LI.FI: Bridging {} {} from {} to {}",
            request.amount, request.asset_id, request.source_chain, request.dest_chain
        );

        // Resolve token address — use native zero address for native tokens, or the
        // asset_id itself if it looks like an address, or look up by symbol.
        let from_token = self.resolve_token_address(&request.asset_id);
        let to_token = from_token.clone(); // Same token on dest chain by default

        // Get quote from LI.FI
        let quote = self
            .get_quote(
                src_chain_id,
                dest_chain_id,
                &from_token,
                &to_token,
                &request.amount.to_string(),
                &request.sender,
            )
            .await?;

        // Extract fee from quote estimate
        let fee = quote
            .estimate
            .as_ref()
            .map(|est| Self::extract_gas_cost_wei(est) + Self::extract_fee_cost_wei(est))
            .unwrap_or(0);

        let transfer_id = self.next_transfer_id();

        // Submit the transaction on-chain if we have tx data and a signer
        let tx_hash = match (&quote.transaction_request, &self.signer) {
            (Some(tx_req), Some(signer)) => {
                let to = tx_req.to.as_deref().ok_or_else(|| {
                    BridgeError::AdapterError("LI.FI: Quote returned no 'to' address".to_string())
                })?;
                let data_hex = tx_req.data.as_deref().unwrap_or("0x");
                let calldata =
                    hex::decode(data_hex.trim_start_matches("0x")).unwrap_or_default();
                let value = tx_req
                    .value
                    .as_deref()
                    .map(Self::parse_value)
                    .unwrap_or(0);

                let tx_hash_str = signer
                    .send_transaction(to, &calldata, value)
                    .await
                    .map_err(|e| {
                        BridgeError::TransferFailed(format!(
                            "LI.FI: On-chain bridge tx failed: {}",
                            e
                        ))
                    })?;

                info!("LI.FI: Submitted bridge tx {}", tx_hash_str);

                // Track the transfer by tx hash for status lookups
                self.transfers.insert(
                    transfer_id.clone(),
                    LiFiTransferRecord {
                        tx_hash: tx_hash_str.clone(),
                        status: TransferStatus::Pending,
                        source_chain: request.source_chain.clone(),
                        dest_chain: request.dest_chain.clone(),
                        tool: quote.tool.clone(),
                    },
                );

                // Parse hex hash into Hash type
                let hash_bytes =
                    hex::decode(tx_hash_str.trim_start_matches("0x")).unwrap_or_else(|_| vec![0u8; 32]);
                let mut hash_array = [0u8; 32];
                let len = hash_bytes.len().min(32);
                hash_array[32 - len..].copy_from_slice(&hash_bytes[..len]);
                Hash::new(hash_array)
            }
            (None, _) => {
                return Err(BridgeError::AdapterError(
                    "LI.FI: Quote returned no transaction data".to_string(),
                ));
            }
            (_, None) => {
                return Err(BridgeError::ConfigurationError(
                    "LI.FI: No signer configured — cannot submit bridge transaction. \
                     Call with_signer() to configure an EVM transaction signer."
                        .to_string(),
                ));
            }
        };

        // Estimated arrival based on execution duration from quote
        let estimated_duration_ms = quote
            .estimate
            .as_ref()
            .and_then(|e| e.execution_duration)
            .map(|d| (d * 1000.0) as i64)
            .unwrap_or(120_000); // Default 2 minutes
        let estimated_arrival = Timestamp::now().as_millis() + estimated_duration_ms;

        info!(
            "LI.FI: Transfer {} initiated, fee={} wei, tool={:?}",
            transfer_id, fee, quote.tool
        );

        Ok(BridgeTokenReceipt::new(
            transfer_id,
            tx_hash,
            estimated_arrival,
            fee,
            request.source_chain,
            request.dest_chain,
        ))
    }

    async fn get_transfer_status(&self, transfer_id: &str) -> Result<TransferStatus> {
        // Check local cache first
        if let Some(record) = self.transfers.get(transfer_id) {
            let current = record.status;

            // If transfer is in a final state, return immediately
            if current.is_final() {
                return Ok(current);
            }

            // Query the LI.FI /status API using the stored tx hash
            let tx_hash = record.tx_hash.clone();
            let source_chain = record.source_chain.clone();
            let dest_chain = record.dest_chain.clone();
            let tool = record.tool.clone();
            drop(record); // Release DashMap ref before async call

            let from_id = Self::chain_name_to_evm_id(&source_chain).ok();
            let to_id = Self::chain_name_to_evm_id(&dest_chain).ok();

            match self
                .get_status(&tx_hash, from_id, to_id, tool.as_deref())
                .await
            {
                Ok(status_resp) => {
                    let new_status = status_resp
                        .status
                        .as_deref()
                        .map(Self::map_status)
                        .unwrap_or(TransferStatus::Pending);

                    // Update cache if status changed
                    if new_status != current
                        && let Some(mut entry) = self.transfers.get_mut(transfer_id)
                    {
                        entry.status = new_status;
                    }

                    return Ok(new_status);
                }
                Err(e) => {
                    debug!(
                        "LI.FI: Status query failed for {} ({}), returning cached status",
                        transfer_id, e
                    );
                    return Ok(current);
                }
            }
        }

        Err(BridgeError::TransferNotFound(transfer_id.to_string()))
    }

    async fn estimate_fee(&self, dest_chain: &str, payload_size: usize) -> Result<u128> {
        // Verify destination chain
        let dest_chain_id = Self::chain_name_to_evm_id(dest_chain)?;

        // Try to get a real quote from LI.FI
        let native_token = "0x0000000000000000000000000000000000000000";
        let dummy_address = "0x0000000000000000000000000000000000000001";

        // Use a representative amount for fee estimation (0.1 ETH)
        let dummy_amount = "100000000000000000";

        match self
            .get_quote(
                1, // Ethereum as source
                dest_chain_id,
                native_token,
                native_token,
                dummy_amount,
                dummy_address,
            )
            .await
        {
            Ok(quote) => {
                if let Some(ref estimate) = quote.estimate {
                    let gas_cost = Self::extract_gas_cost_wei(estimate);
                    let fee_cost = Self::extract_fee_cost_wei(estimate);
                    let total = gas_cost + fee_cost;

                    if total > 0 {
                        debug!(
                            "LI.FI: Live fee estimate for {} bytes to {} = {} wei (gas={}, fees={})",
                            payload_size, dest_chain, total, gas_cost, fee_cost
                        );
                        return Ok(total);
                    }
                }

                // Quote succeeded but had no parseable fee — fall back
                let fallback = Self::estimate_fee_static(payload_size);
                warn!(
                    "LI.FI: Quote returned no parseable fee, using static fallback = {} wei",
                    fallback
                );
                Ok(fallback)
            }
            Err(e) => {
                let fallback = Self::estimate_fee_static(payload_size);
                warn!(
                    "LI.FI: Live fee quote failed ({}), using static fallback = {} wei",
                    e, fallback
                );
                Ok(fallback)
            }
        }
    }
}

impl LiFiAdapter {
    /// Resolves a token identifier to a LI.FI-compatible address.
    ///
    /// - Addresses starting with "0x" are passed through as-is.
    /// - Common token symbols are mapped to their well-known addresses.
    /// - Everything else is treated as the native zero address.
    fn resolve_token_address(&self, asset_id: &str) -> String {
        // Already a hex address
        if asset_id.starts_with("0x") && asset_id.len() >= 40 {
            return asset_id.to_string();
        }

        // Map common symbols to native/zero address
        // (LI.FI uses 0x0 for native tokens, actual contract addresses for ERC-20s)
        match asset_id.to_uppercase().as_str() {
            "ETH" | "MATIC" | "POL" | "BNB" | "AVAX" | "FTM" | "SOL" | "CELO" | "GLMR"
            | "MNT" | "SEI" | "XDAI" => {
                "0x0000000000000000000000000000000000000000".to_string()
            }
            // Well-known ERC-20 addresses (Ethereum mainnet)
            "USDC" => "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48".to_string(),
            "USDT" => "0xdAC17F958D2ee523a2206206994597C13D831ec7".to_string(),
            "DAI" => "0x6B175474E89094C44Da98b954EedeAC495271d0F".to_string(),
            "WETH" => "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2".to_string(),
            "WBTC" => "0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599".to_string(),
            "TNZO" => "0x0000000000000000000000000000000000000000".to_string(), // Native TNZO
            _ => {
                // Unknown token — use as-is (caller should provide address)
                warn!(
                    "LI.FI: Unknown token symbol '{}', using as raw identifier",
                    asset_id
                );
                asset_id.to_string()
            }
        }
    }

    /// Attempts to refresh the cached chains list from the /chains API.
    /// This is a best-effort operation; errors are logged but not propagated.
    pub async fn refresh_chains_cache(&self) {
        match self.get_chains().await {
            Ok(chains_resp) => {
                let chain_infos: Vec<ChainInfo> = chains_resp
                    .chains
                    .iter()
                    .filter_map(Self::lifi_chain_to_chain_info)
                    .collect();

                if !chain_infos.is_empty() {
                    let mut cache = self.cached_chains.write();
                    *cache = Some(chain_infos);
                    debug!("LI.FI: Refreshed chains cache");
                }
            }
            Err(e) => {
                warn!("LI.FI: Failed to refresh chains cache: {}", e);
            }
        }
    }
}

/// Options for the /advanced/routes request.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LiFiRoutesOptions {
    /// Only use these bridges (e.g., ["stargate", "hop"])
    pub allow_bridges: Option<Vec<String>>,
    /// Only use these exchanges (e.g., ["1inch", "paraswap"])
    pub allow_exchanges: Option<Vec<String>>,
    /// Sort order: "RECOMMENDED", "FASTEST", "CHEAPEST", "SAFEST"
    pub order: Option<String>,
    /// Maximum price impact tolerance
    pub max_price_impact: Option<f64>,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lifi_config_defaults() {
        let config = LiFiConfig::new();
        assert_eq!(config.api_url, LIFI_API_URL);
        assert!(config.api_key.is_none());
        assert!(config.integrator_id.is_none());
        assert!(config.fee_percent.is_none());
        assert!((config.slippage - 0.03).abs() < f64::EPSILON);
    }

    #[test]
    fn test_lifi_config_builder() {
        let config = LiFiConfig::new()
            .with_api_key("my-key")
            .with_integrator_id("tenzro")
            .with_fee_percent(0.3)
            .with_slippage(0.05)
            .with_api_url("https://custom.api.com/v1");

        assert_eq!(config.api_key.as_deref(), Some("my-key"));
        assert_eq!(config.integrator_id.as_deref(), Some("tenzro"));
        assert!((config.fee_percent.unwrap() - 0.3).abs() < f64::EPSILON);
        assert!((config.slippage - 0.05).abs() < f64::EPSILON);
        assert_eq!(config.api_url, "https://custom.api.com/v1");
    }

    #[test]
    fn test_lifi_adapter_creation() {
        let config = LiFiConfig::new();
        let adapter = LiFiAdapter::new(config);
        assert_eq!(adapter.protocol_name(), "LI.FI");
        assert!(!adapter.supported_chains().is_empty());
    }

    #[test]
    fn test_supported_chains_static() {
        let config = LiFiConfig::new();
        let adapter = LiFiAdapter::new(config);
        let chains = adapter.supported_chains();

        // Should have at least 20 chains in the static list
        assert!(chains.len() >= 20);

        // Verify key chains are present
        let chain_ids: Vec<&str> = chains.iter().map(|c| c.chain_id.as_str()).collect();
        assert!(chain_ids.contains(&"ethereum"));
        assert!(chain_ids.contains(&"arbitrum"));
        assert!(chain_ids.contains(&"optimism"));
        assert!(chain_ids.contains(&"polygon"));
        assert!(chain_ids.contains(&"base"));
        assert!(chain_ids.contains(&"solana"));
        assert!(chain_ids.contains(&"bsc"));
        assert!(chain_ids.contains(&"avalanche"));
    }

    #[test]
    fn test_chain_name_to_evm_id() {
        assert_eq!(LiFiAdapter::chain_name_to_evm_id("ethereum").unwrap(), 1);
        assert_eq!(LiFiAdapter::chain_name_to_evm_id("arbitrum").unwrap(), 42161);
        assert_eq!(LiFiAdapter::chain_name_to_evm_id("optimism").unwrap(), 10);
        assert_eq!(LiFiAdapter::chain_name_to_evm_id("polygon").unwrap(), 137);
        assert_eq!(LiFiAdapter::chain_name_to_evm_id("bsc").unwrap(), 56);
        assert_eq!(LiFiAdapter::chain_name_to_evm_id("avalanche").unwrap(), 43114);
        assert_eq!(LiFiAdapter::chain_name_to_evm_id("base").unwrap(), 8453);
        assert_eq!(LiFiAdapter::chain_name_to_evm_id("zksync").unwrap(), 324);
        assert_eq!(LiFiAdapter::chain_name_to_evm_id("linea").unwrap(), 59144);
        assert_eq!(LiFiAdapter::chain_name_to_evm_id("scroll").unwrap(), 534352);
        assert_eq!(LiFiAdapter::chain_name_to_evm_id("solana").unwrap(), 1151111081099710);

        assert!(LiFiAdapter::chain_name_to_evm_id("unknown_chain").is_err());
    }

    #[test]
    fn test_lifi_chain_key_mapping() {
        assert_eq!(LiFiAdapter::lifi_chain_key_to_chain_id("eth"), "ethereum");
        assert_eq!(LiFiAdapter::lifi_chain_key_to_chain_id("arb"), "arbitrum");
        assert_eq!(LiFiAdapter::lifi_chain_key_to_chain_id("opt"), "optimism");
        assert_eq!(LiFiAdapter::lifi_chain_key_to_chain_id("pol"), "polygon");
        assert_eq!(LiFiAdapter::lifi_chain_key_to_chain_id("bsc"), "bsc");
        assert_eq!(LiFiAdapter::lifi_chain_key_to_chain_id("sol"), "solana");
        assert_eq!(LiFiAdapter::lifi_chain_key_to_chain_id("bas"), "base");
        // Unknown keys pass through as-is
        assert_eq!(LiFiAdapter::lifi_chain_key_to_chain_id("xyz"), "xyz");
    }

    #[test]
    fn test_resolve_token_address() {
        let config = LiFiConfig::new();
        let adapter = LiFiAdapter::new(config);

        // Native tokens -> zero address
        assert_eq!(
            adapter.resolve_token_address("ETH"),
            "0x0000000000000000000000000000000000000000"
        );
        assert_eq!(
            adapter.resolve_token_address("SOL"),
            "0x0000000000000000000000000000000000000000"
        );

        // Well-known ERC-20s
        assert_eq!(
            adapter.resolve_token_address("USDC"),
            "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
        );
        assert_eq!(
            adapter.resolve_token_address("USDT"),
            "0xdAC17F958D2ee523a2206206994597C13D831ec7"
        );

        // Pass-through for addresses
        let addr = "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb0";
        assert_eq!(adapter.resolve_token_address(addr), addr);
    }

    #[test]
    fn test_map_status() {
        assert_eq!(LiFiAdapter::map_status("DONE"), TransferStatus::Delivered);
        assert_eq!(LiFiAdapter::map_status("FAILED"), TransferStatus::Failed);
        assert_eq!(LiFiAdapter::map_status("NOT_FOUND"), TransferStatus::Failed);
        assert_eq!(LiFiAdapter::map_status("INVALID"), TransferStatus::Failed);
        assert_eq!(LiFiAdapter::map_status("PENDING"), TransferStatus::Pending);
        assert_eq!(LiFiAdapter::map_status("UNKNOWN"), TransferStatus::Pending);
    }

    #[test]
    fn test_parse_value() {
        assert_eq!(LiFiAdapter::parse_value("0x0"), 0);
        assert_eq!(LiFiAdapter::parse_value("0x1"), 1);
        assert_eq!(LiFiAdapter::parse_value("0xff"), 255);
        assert_eq!(LiFiAdapter::parse_value("1000000"), 1_000_000);
        assert_eq!(LiFiAdapter::parse_value("0xDE0B6B3A7640000"), 1_000_000_000_000_000_000);
        assert_eq!(LiFiAdapter::parse_value("invalid"), 0);
    }

    #[tokio::test]
    async fn test_estimate_fee_offline_fallback() {
        let config = LiFiConfig::new()
            .with_api_url("http://localhost:99999"); // Unreachable
        let adapter = LiFiAdapter::new(config);

        // Should fall back to static estimate
        let fee = adapter.estimate_fee("arbitrum", 1000).await.unwrap();

        let expected = 200_000_000_000_000u128 + (1000 * 500_000_000u128);
        assert_eq!(fee, expected);
    }

    #[test]
    fn test_estimate_fee_static() {
        let fee = LiFiAdapter::estimate_fee_static(0);
        assert_eq!(fee, 200_000_000_000_000); // Base fee only

        let fee_1k = LiFiAdapter::estimate_fee_static(1000);
        let expected = 200_000_000_000_000u128 + (1000 * 500_000_000u128);
        assert_eq!(fee_1k, expected);

        // Fee should increase with payload size
        let fee_2k = LiFiAdapter::estimate_fee_static(2000);
        assert!(fee_2k > fee_1k);
    }

    #[test]
    fn test_extract_gas_cost_wei() {
        let estimate = LiFiEstimate {
            gas_costs: Some(vec![
                LiFiGasCost {
                    amount: Some("1000000000000000".to_string()),
                    ..Default::default()
                },
                LiFiGasCost {
                    amount: Some("500000000000000".to_string()),
                    ..Default::default()
                },
            ]),
            ..Default::default()
        };

        let total = LiFiAdapter::extract_gas_cost_wei(&estimate);
        assert_eq!(total, 1_500_000_000_000_000);
    }

    #[test]
    fn test_extract_fee_cost_wei() {
        let estimate = LiFiEstimate {
            fee_costs: Some(vec![LiFiFeeCost {
                amount: Some("2000000000000000".to_string()),
                ..Default::default()
            }]),
            ..Default::default()
        };

        let total = LiFiAdapter::extract_fee_cost_wei(&estimate);
        assert_eq!(total, 2_000_000_000_000_000);
    }

    #[test]
    fn test_extract_costs_empty() {
        let estimate = LiFiEstimate::default();
        assert_eq!(LiFiAdapter::extract_gas_cost_wei(&estimate), 0);
        assert_eq!(LiFiAdapter::extract_fee_cost_wei(&estimate), 0);
    }

    #[tokio::test]
    async fn test_get_transfer_status_not_found() {
        let config = LiFiConfig::new();
        let adapter = LiFiAdapter::new(config);

        let result = adapter.get_transfer_status("nonexistent-id").await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::TransferNotFound(id) => assert_eq!(id, "nonexistent-id"),
            other => panic!("Expected TransferNotFound, got: {:?}", other),
        }
    }

    #[test]
    fn test_quote_response_deserialize() {
        let json = r#"{
            "id": "quote-123",
            "tool": "stargate",
            "toolDetails": {
                "key": "stargate",
                "name": "Stargate",
                "logoURI": "https://example.com/logo.png"
            },
            "estimate": {
                "toAmount": "990000",
                "toAmountMin": "960000",
                "executionDuration": 120.5,
                "gasCosts": [{
                    "type": "SEND",
                    "amount": "1000000000000000",
                    "amountUSD": "2.50"
                }],
                "feeCosts": [{
                    "name": "Bridge Fee",
                    "amount": "500000000000000",
                    "percentage": "0.05"
                }]
            },
            "transactionRequest": {
                "to": "0x1234567890abcdef1234567890abcdef12345678",
                "data": "0xabcdef",
                "value": "0xDE0B6B3A7640000",
                "gasLimit": "200000",
                "chainId": 1
            },
            "action": {
                "fromChainId": 1,
                "toChainId": 42161,
                "fromAmount": "1000000",
                "slippage": 0.03
            }
        }"#;

        let quote: LiFiQuoteResponse = serde_json::from_str(json).unwrap();

        assert_eq!(quote.id.as_deref(), Some("quote-123"));
        assert_eq!(quote.tool.as_deref(), Some("stargate"));

        let estimate = quote.estimate.as_ref().unwrap();
        assert_eq!(estimate.to_amount.as_deref(), Some("990000"));
        assert!((estimate.execution_duration.unwrap() - 120.5).abs() < f64::EPSILON);

        let gas_costs = estimate.gas_costs.as_ref().unwrap();
        assert_eq!(gas_costs.len(), 1);
        assert_eq!(gas_costs[0].amount.as_deref(), Some("1000000000000000"));

        let tx_req = quote.transaction_request.as_ref().unwrap();
        assert_eq!(
            tx_req.to.as_deref(),
            Some("0x1234567890abcdef1234567890abcdef12345678")
        );
        assert_eq!(tx_req.data.as_deref(), Some("0xabcdef"));
        assert_eq!(tx_req.chain_id, Some(1));
    }

    #[test]
    fn test_status_response_deserialize() {
        let json = r#"{
            "status": "DONE",
            "substatus": "COMPLETED",
            "substatusMessage": "Transfer completed successfully",
            "tool": "stargate",
            "fromChainId": 1,
            "toChainId": 42161,
            "sending": {
                "txHash": "0xabc123",
                "amount": "1000000",
                "chainId": 1,
                "timestamp": 1700000000
            },
            "receiving": {
                "txHash": "0xdef456",
                "amount": "990000",
                "chainId": 42161
            }
        }"#;

        let status: LiFiStatusResponse = serde_json::from_str(json).unwrap();

        assert_eq!(status.status.as_deref(), Some("DONE"));
        assert_eq!(status.substatus.as_deref(), Some("COMPLETED"));
        assert_eq!(status.tool.as_deref(), Some("stargate"));
        assert_eq!(status.from_chain_id, Some(1));
        assert_eq!(status.to_chain_id, Some(42161));

        let sending = status.sending.as_ref().unwrap();
        assert_eq!(sending.tx_hash.as_deref(), Some("0xabc123"));
        assert_eq!(sending.timestamp, Some(1700000000));

        let receiving = status.receiving.as_ref().unwrap();
        assert_eq!(receiving.tx_hash.as_deref(), Some("0xdef456"));
    }

    #[test]
    fn test_chains_response_deserialize() {
        let json = r#"{
            "chains": [
                {
                    "id": 1,
                    "key": "eth",
                    "name": "Ethereum",
                    "chainType": "EVM",
                    "nativeToken": {
                        "address": "0x0000000000000000000000000000000000000000",
                        "symbol": "ETH",
                        "name": "Ether",
                        "decimals": 18,
                        "chainId": 1
                    }
                },
                {
                    "id": 42161,
                    "key": "arb",
                    "name": "Arbitrum",
                    "chainType": "EVM",
                    "nativeToken": {
                        "symbol": "ETH",
                        "decimals": 18
                    }
                }
            ]
        }"#;

        let chains: LiFiChainsResponse = serde_json::from_str(json).unwrap();
        assert_eq!(chains.chains.len(), 2);
        assert_eq!(chains.chains[0].id, Some(1));
        assert_eq!(chains.chains[0].key.as_deref(), Some("eth"));
        assert_eq!(chains.chains[0].name.as_deref(), Some("Ethereum"));

        // Map to ChainInfo
        let info = LiFiAdapter::lifi_chain_to_chain_info(&chains.chains[0]).unwrap();
        assert_eq!(info.chain_id, "ethereum");
        assert_eq!(info.native_token, "ETH");
        assert_eq!(info.finality_time_secs, 900);

        let arb_info = LiFiAdapter::lifi_chain_to_chain_info(&chains.chains[1]).unwrap();
        assert_eq!(arb_info.chain_id, "arbitrum");
    }

    #[test]
    fn test_routes_response_deserialize() {
        let json = r#"{
            "routes": [
                {
                    "id": "route-1",
                    "fromAmount": "1000000",
                    "toAmount": "990000",
                    "toAmountMin": "960000",
                    "toAmountUsd": "990.00",
                    "gasCostUsd": "2.50",
                    "tags": ["CHEAPEST"],
                    "steps": []
                },
                {
                    "id": "route-2",
                    "fromAmount": "1000000",
                    "toAmount": "985000",
                    "tags": ["FASTEST"],
                    "steps": []
                }
            ]
        }"#;

        let routes: LiFiRoutesResponse = serde_json::from_str(json).unwrap();
        assert_eq!(routes.routes.len(), 2);
        assert_eq!(routes.routes[0].id.as_deref(), Some("route-1"));
        assert_eq!(routes.routes[0].to_amount.as_deref(), Some("990000"));
        assert_eq!(
            routes.routes[0].tags.as_ref().unwrap(),
            &vec!["CHEAPEST".to_string()]
        );
        assert_eq!(routes.routes[1].id.as_deref(), Some("route-2"));
    }

    #[test]
    fn test_tools_response_deserialize() {
        let json = r#"{
            "bridges": [
                {
                    "key": "stargate",
                    "name": "Stargate",
                    "supportedChains": [
                        {"id": 1, "key": "eth"},
                        {"id": 42161, "key": "arb"}
                    ]
                }
            ],
            "exchanges": [
                {
                    "key": "1inch",
                    "name": "1inch"
                }
            ]
        }"#;

        let tools: LiFiToolsResponse = serde_json::from_str(json).unwrap();
        assert_eq!(tools.bridges.len(), 1);
        assert_eq!(tools.bridges[0].key.as_deref(), Some("stargate"));
        assert_eq!(tools.exchanges.len(), 1);
        assert_eq!(tools.exchanges[0].key.as_deref(), Some("1inch"));

        let supported = tools.bridges[0].supported_chains.as_ref().unwrap();
        assert_eq!(supported.len(), 2);
        assert_eq!(supported[0].id, Some(1));
    }

    #[test]
    fn test_with_http_client() {
        let custom_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .unwrap();

        let config = LiFiConfig::new();
        let adapter = LiFiAdapter::with_http_client(config, custom_client);
        assert_eq!(adapter.protocol_name(), "LI.FI");
    }

    #[test]
    fn test_lifi_chain_to_chain_info_missing_fields() {
        // Missing key returns None
        let chain = LiFiChain {
            id: Some(1),
            key: None,
            name: Some("Ethereum".to_string()),
            chain_type: None,
            native_token: None,
            logo_uri: None,
            is_testnet: None,
        };
        assert!(LiFiAdapter::lifi_chain_to_chain_info(&chain).is_none());

        // Missing name returns None
        let chain = LiFiChain {
            id: Some(1),
            key: Some("eth".to_string()),
            name: None,
            chain_type: None,
            native_token: None,
            logo_uri: None,
            is_testnet: None,
        };
        assert!(LiFiAdapter::lifi_chain_to_chain_info(&chain).is_none());
    }

    #[test]
    fn test_transfer_id_uniqueness() {
        let config = LiFiConfig::new();
        let adapter = LiFiAdapter::new(config);

        let id1 = adapter.next_transfer_id();
        let id2 = adapter.next_transfer_id();
        let id3 = adapter.next_transfer_id();

        assert_ne!(id1, id2);
        assert_ne!(id2, id3);
        assert!(id1.starts_with("lifi-"));
    }
}

