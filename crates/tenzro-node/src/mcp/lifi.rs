use std::sync::Arc;

use rmcp::{
    handler::server::router::tool::ToolRouter,
    handler::server::wrapper::Parameters,
    model::*,
    tool, tool_handler, tool_router, ServerHandler,
};
use serde::Deserialize;

const LIFI_API_URL: &str = "https://li.quest/v1";

// ─── Tool parameter structs ───

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GetChainsParams {}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GetTokensParams {
    #[schemars(description = "Comma-separated chain IDs to filter tokens (e.g. '1,137,42161'). Omit for all chains.")]
    pub chains: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GetTokenParams {
    #[schemars(description = "Chain ID (e.g. 1 for Ethereum, 137 for Polygon, 42161 for Arbitrum)")]
    pub chain_id: u64,
    #[schemars(description = "Token contract address (e.g. '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48' for USDC on Ethereum). Use '0x0000000000000000000000000000000000000000' for native tokens.")]
    pub token_address: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GetToolsParams {}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GetConnectionsParams {
    #[schemars(description = "Source chain ID (e.g. 1 for Ethereum)")]
    pub from_chain: u64,
    #[schemars(description = "Destination chain ID (e.g. 137 for Polygon)")]
    pub to_chain: u64,
    #[schemars(description = "Source token address (optional, filters connections to specific token)")]
    pub from_token: Option<String>,
    #[schemars(description = "Destination token address (optional, filters connections to specific token)")]
    pub to_token: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GetQuoteParams {
    #[schemars(description = "Source chain ID (e.g. 1 for Ethereum)")]
    pub from_chain: u64,
    #[schemars(description = "Destination chain ID (e.g. 137 for Polygon)")]
    pub to_chain: u64,
    #[schemars(description = "Source token address (e.g. '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48' for USDC)")]
    pub from_token: String,
    #[schemars(description = "Destination token address")]
    pub to_token: String,
    #[schemars(description = "Amount in smallest unit (wei for ETH, base units for ERC-20)")]
    pub from_amount: String,
    #[schemars(description = "Sender wallet address (0x...)")]
    pub from_address: String,
    #[schemars(description = "Slippage tolerance as decimal (default 0.03 = 3%)")]
    pub slippage: Option<f64>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GetRoutesParams {
    #[schemars(description = "Source chain ID")]
    pub from_chain_id: u64,
    #[schemars(description = "Destination chain ID")]
    pub to_chain_id: u64,
    #[schemars(description = "Source token address")]
    pub from_token_address: String,
    #[schemars(description = "Destination token address")]
    pub to_token_address: String,
    #[schemars(description = "Amount in smallest unit (wei for ETH, base units for ERC-20)")]
    pub from_amount: String,
    #[schemars(description = "Sender wallet address (0x...)")]
    pub from_address: String,
    #[schemars(description = "Slippage tolerance as decimal (default 0.03 = 3%)")]
    pub slippage: Option<f64>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GetStatusParams {
    #[schemars(description = "Transaction hash to check status for")]
    pub tx_hash: String,
    #[schemars(description = "Bridge name (optional, e.g. 'stargate', 'hop', 'across')")]
    pub bridge: Option<String>,
    #[schemars(description = "Source chain ID (optional, helps disambiguate)")]
    pub from_chain: Option<u64>,
    #[schemars(description = "Destination chain ID (optional, helps disambiguate)")]
    pub to_chain: Option<u64>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GetGasPricesParams {
    #[schemars(description = "Comma-separated chain IDs (e.g. '1,137,42161'). Omit for all chains.")]
    pub chains: Option<String>,
}

// ─── MCP Server ───

/// LI.FI MCP server providing 9 tools for cross-chain bridge aggregation:
///   - Discovery: chains, tokens, token info, tools (bridges/exchanges)
///   - Routing: connections, quote, advanced routes
///   - Tracking: transaction status
///   - Gas: gas prices per chain

#[derive(Clone)]
pub struct LifiMcpServer {
    http: reqwest::Client,
    _tool_router: ToolRouter<LifiMcpServer>,
}

impl Default for LifiMcpServer {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for LifiMcpServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LifiMcpServer").finish()
    }
}

fn err_internal(msg: impl Into<String>) -> ErrorData {
    ErrorData::internal_error(msg.into(), None)
}

fn json_result(value: serde_json::Value) -> std::result::Result<CallToolResult, ErrorData> {
    Ok(CallToolResult::success(vec![Content::text(
        serde_json::to_string_pretty(&value).unwrap(),
    )]))
}

#[tool_router]
impl LifiMcpServer {
    pub fn new() -> Self {
        Self {
            http: reqwest::Client::new(),
            _tool_router: Self::tool_router(),
        }
    }

    // ─── Helper: LI.FI API GET ───

    async fn api_get(
        &self,
        path: &str,
        query: &[(&str, &str)],
    ) -> std::result::Result<serde_json::Value, ErrorData> {
        let url = format!("{}{}", LIFI_API_URL, path);
        let resp = self
            .http
            .get(&url)
            .query(query)
            .send()
            .await
            .map_err(|e| err_internal(format!("LI.FI API request failed: {}", e)))?;

        let status = resp.status();
        let text = resp
            .text()
            .await
            .map_err(|e| err_internal(format!("Failed to read LI.FI response body: {}", e)))?;

        if !status.is_success() {
            return Err(err_internal(format!(
                "LI.FI API error ({}): {}",
                status,
                &text[..text.len().min(500)]
            )));
        }

        serde_json::from_str(&text)
            .map_err(|e| err_internal(format!("Invalid JSON from LI.FI API: {}", e)))
    }

    // ─── Helper: LI.FI API POST ───

    async fn api_post(
        &self,
        path: &str,
        body: serde_json::Value,
    ) -> std::result::Result<serde_json::Value, ErrorData> {
        let url = format!("{}{}", LIFI_API_URL, path);
        let resp = self
            .http
            .post(&url)
            .json(&body)
            .send()
            .await
            .map_err(|e| err_internal(format!("LI.FI API request failed: {}", e)))?;

        let status = resp.status();
        let text = resp
            .text()
            .await
            .map_err(|e| err_internal(format!("Failed to read LI.FI response body: {}", e)))?;

        if !status.is_success() {
            return Err(err_internal(format!(
                "LI.FI API error ({}): {}",
                status,
                &text[..text.len().min(500)]
            )));
        }

        serde_json::from_str(&text)
            .map_err(|e| err_internal(format!("Invalid JSON from LI.FI API: {}", e)))
    }

    // ─── Discovery Tools ───

    #[tool(description = "Get all blockchain networks supported by LI.FI for cross-chain transfers and swaps. Returns chain IDs, names, native tokens, and supported bridge/exchange protocols.")]
    async fn lifi_get_chains(
        &self,
        #[allow(unused)] Parameters(_params): Parameters<GetChainsParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let data = self.api_get("/chains", &[]).await?;

        let chains = data
            .get("chains")
            .cloned()
            .unwrap_or_else(|| data.clone());

        let count = chains.as_array().map(|a| a.len()).unwrap_or(0);

        let result = serde_json::json!({
            "source": "lifi_api",
            "total_chains": count,
            "chains": chains,
        });
        json_result(result)
    }

    #[tool(description = "Get tokens available on LI.FI-supported chains. Optionally filter by chain IDs. Returns token addresses, symbols, decimals, and logos.")]
    async fn lifi_get_tokens(
        &self,
        Parameters(params): Parameters<GetTokensParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let mut query = Vec::new();
        let chains_str;
        if let Some(ref chains) = params.chains {
            chains_str = chains.clone();
            query.push(("chains", chains_str.as_str()));
        }

        let data = self.api_get("/tokens", &query).await?;

        let tokens = data
            .get("tokens")
            .cloned()
            .unwrap_or_else(|| data.clone());

        let result = serde_json::json!({
            "source": "lifi_api",
            "tokens": tokens,
        });
        json_result(result)
    }

    #[tool(description = "Get detailed information about a specific token on a specific chain, including address, symbol, decimals, name, and logo URI.")]
    async fn lifi_get_token(
        &self,
        Parameters(params): Parameters<GetTokenParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let chain_str = params.chain_id.to_string();
        let query = [
            ("chain", chain_str.as_str()),
            ("token", params.token_address.as_str()),
        ];

        let data = self.api_get("/token", &query).await?;

        let result = serde_json::json!({
            "source": "lifi_api",
            "chain_id": params.chain_id,
            "token_address": params.token_address,
            "token": data,
        });
        json_result(result)
    }

    #[tool(description = "Get available bridge and DEX exchange tools integrated into LI.FI. Returns protocol names, supported chains, and tool types (bridge vs exchange).")]
    async fn lifi_get_tools(
        &self,
        #[allow(unused)] Parameters(_params): Parameters<GetToolsParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let data = self.api_get("/tools", &[]).await?;

        let bridges = data.get("bridges").cloned().unwrap_or(serde_json::json!([]));
        let exchanges = data.get("exchanges").cloned().unwrap_or(serde_json::json!([]));
        let bridge_count = bridges.as_array().map(|a| a.len()).unwrap_or(0);
        let exchange_count = exchanges.as_array().map(|a| a.len()).unwrap_or(0);

        let result = serde_json::json!({
            "source": "lifi_api",
            "total_bridges": bridge_count,
            "total_exchanges": exchange_count,
            "bridges": bridges,
            "exchanges": exchanges,
        });
        json_result(result)
    }

    // ─── Routing Tools ───

    #[tool(description = "Get available cross-chain connections between two chains. Optionally filter by source and destination tokens. Shows which bridges and exchanges can transfer between the specified chains.")]
    async fn lifi_get_connections(
        &self,
        Parameters(params): Parameters<GetConnectionsParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let from_chain_str = params.from_chain.to_string();
        let to_chain_str = params.to_chain.to_string();
        let mut query = vec![
            ("fromChain", from_chain_str.as_str()),
            ("toChain", to_chain_str.as_str()),
        ];

        let from_token_str;
        if let Some(ref ft) = params.from_token {
            from_token_str = ft.clone();
            query.push(("fromToken", from_token_str.as_str()));
        }
        let to_token_str;
        if let Some(ref tt) = params.to_token {
            to_token_str = tt.clone();
            query.push(("toToken", to_token_str.as_str()));
        }

        let data = self.api_get("/connections", &query).await?;

        let connections = data
            .get("connections")
            .cloned()
            .unwrap_or_else(|| data.clone());

        let result = serde_json::json!({
            "source": "lifi_api",
            "from_chain": params.from_chain,
            "to_chain": params.to_chain,
            "connections": connections,
        });
        json_result(result)
    }

    #[tool(description = "Get a single best quote for a cross-chain swap or bridge transfer. Returns the optimal route with estimated output, fees, execution time, and transaction data ready to sign.")]
    async fn lifi_get_quote(
        &self,
        Parameters(params): Parameters<GetQuoteParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let from_chain_str = params.from_chain.to_string();
        let to_chain_str = params.to_chain.to_string();
        let slippage = params.slippage.unwrap_or(0.03);
        let slippage_str = slippage.to_string();

        let query = [
            ("fromChain", from_chain_str.as_str()),
            ("toChain", to_chain_str.as_str()),
            ("fromToken", params.from_token.as_str()),
            ("toToken", params.to_token.as_str()),
            ("fromAmount", params.from_amount.as_str()),
            ("fromAddress", params.from_address.as_str()),
            ("slippage", slippage_str.as_str()),
        ];

        let data = self.api_get("/quote", &query).await?;

        let result = serde_json::json!({
            "source": "lifi_api",
            "from_chain": params.from_chain,
            "to_chain": params.to_chain,
            "from_token": params.from_token,
            "to_token": params.to_token,
            "from_amount": params.from_amount,
            "slippage": slippage,
            "quote": data,
            "note": "This is a quote with transaction data. To execute, sign and submit the transaction from the 'transactionRequest' field using your wallet."
        });
        json_result(result)
    }

    #[tool(description = "Get multiple route options for a cross-chain swap or bridge transfer, ranked by output amount. Use this for comparing routes across different bridges and DEXes. Returns routes with fees, estimated time, and step-by-step breakdown.")]
    async fn lifi_get_routes(
        &self,
        Parameters(params): Parameters<GetRoutesParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let slippage = params.slippage.unwrap_or(0.03);

        let body = serde_json::json!({
            "fromChainId": params.from_chain_id,
            "toChainId": params.to_chain_id,
            "fromTokenAddress": params.from_token_address,
            "toTokenAddress": params.to_token_address,
            "fromAmount": params.from_amount,
            "fromAddress": params.from_address,
            "options": {
                "slippage": slippage,
            }
        });

        let data = self.api_post("/advanced/routes", body).await?;

        let routes = data.get("routes").cloned().unwrap_or(serde_json::json!([]));
        let route_count = routes.as_array().map(|a| a.len()).unwrap_or(0);

        let result = serde_json::json!({
            "source": "lifi_api",
            "from_chain_id": params.from_chain_id,
            "to_chain_id": params.to_chain_id,
            "from_token": params.from_token_address,
            "to_token": params.to_token_address,
            "from_amount": params.from_amount,
            "slippage": slippage,
            "total_routes": route_count,
            "routes": routes,
            "note": "Routes are ranked by output amount. Each route contains steps with transaction data to sign and submit sequentially."
        });
        json_result(result)
    }

    // ─── Tracking Tools ───

    #[tool(description = "Check the status of a cross-chain transfer by transaction hash. Returns status (PENDING, DONE, FAILED, NOT_FOUND), bridge used, source/destination chain info, and amounts.")]
    async fn lifi_get_status(
        &self,
        Parameters(params): Parameters<GetStatusParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let mut query = vec![("txHash", params.tx_hash.as_str())];

        let bridge_str;
        if let Some(ref b) = params.bridge {
            bridge_str = b.clone();
            query.push(("bridge", bridge_str.as_str()));
        }
        let from_chain_str;
        if let Some(fc) = params.from_chain {
            from_chain_str = fc.to_string();
            query.push(("fromChain", from_chain_str.as_str()));
        }
        let to_chain_str;
        if let Some(tc) = params.to_chain {
            to_chain_str = tc.to_string();
            query.push(("toChain", to_chain_str.as_str()));
        }

        let data = self.api_get("/status", &query).await?;

        let status = data
            .get("status")
            .and_then(|s| s.as_str())
            .unwrap_or("UNKNOWN");

        let result = serde_json::json!({
            "source": "lifi_api",
            "tx_hash": params.tx_hash,
            "status": status,
            "details": data,
        });
        json_result(result)
    }

    // ─── Gas Tools ───

    #[tool(description = "Get current gas prices for LI.FI-supported chains. Optionally filter by chain IDs. Returns gas prices in native units for each chain.")]
    async fn lifi_get_gas_prices(
        &self,
        Parameters(params): Parameters<GetGasPricesParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let mut query = Vec::new();
        let chains_str;
        if let Some(ref chains) = params.chains {
            chains_str = chains.clone();
            query.push(("chains", chains_str.as_str()));
        }

        let data = self.api_get("/gas/prices", &query).await?;

        let result = serde_json::json!({
            "source": "lifi_api",
            "gas_prices": data,
        });
        json_result(result)
    }
}

// ─── ServerHandler ───

#[tool_handler]
impl ServerHandler for LifiMcpServer {
    fn get_info(&self) -> ServerInfo {
        let mut info = ServerInfo::default();
        info.protocol_version = ProtocolVersion::V_2025_11_25;
        info.capabilities = ServerCapabilities::builder().enable_tools().build();
        let mut impl_info = Implementation::default();
        impl_info.name = "tenzro-lifi".into();
        impl_info.title = Some("Tenzro LI.FI MCP Server".into());
        impl_info.version = env!("CARGO_PKG_VERSION").into();
        impl_info.description = Some(
            "LI.FI cross-chain bridge aggregator — quotes, routes, swaps, token/chain discovery, gas prices, transaction tracking"
                .into(),
        );
        impl_info.website_url = Some("https://tenzro.com".into());
        info.server_info = impl_info;
        info.instructions = Some(
            "Tenzro LI.FI MCP Server — cross-chain bridge aggregation powered by LI.FI.\n\n\
             TOOLS BY CATEGORY:\n\n\
             Discovery:\n\
             - lifi_get_chains — Get all supported blockchain networks\n\
             - lifi_get_tokens — Get available tokens, filter by chain\n\
             - lifi_get_token — Get specific token info on a chain\n\
             - lifi_get_tools — Get available bridges and DEX exchanges\n\n\
             Routing:\n\
             - lifi_get_connections — Get cross-chain connections between two chains\n\
             - lifi_get_quote — Get best single quote for a cross-chain transfer\n\
             - lifi_get_routes — Get multiple route options ranked by output\n\n\
             Tracking:\n\
             - lifi_get_status — Check cross-chain transfer status by tx hash\n\n\
             Gas:\n\
             - lifi_get_gas_prices — Get gas prices for supported chains"
                .to_string(),
        );
        info
    }
}

// ─── Server startup ───

/// Start the LI.FI MCP server on the given address using Streamable HTTP transport.
/// This is a standalone server (no OAuth, no Tenzro node dependency) that proxies
/// LI.FI REST API calls for cross-chain bridge aggregation, route finding, and swaps.
pub async fn start_lifi_mcp_server(
    listen_addr: String,
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
            "lifi-mcp.tenzro.network".to_string(),
        ]);

    let service = StreamableHttpService::new(
        move || Ok(LifiMcpServer::new()),
        Arc::new(LocalSessionManager::default()),
        config,
    );

    let app = axum::Router::new().nest_service("/mcp", service);
    let listener = tokio::net::TcpListener::bind(&listen_addr).await?;
    tracing::info!(
        addr = %listen_addr,
        tools = 9,
        api = "https://li.quest/v1",
        mode = "stateless-json",
        "LI.FI MCP Server listening (endpoint: /mcp)"
    );
    axum::serve(listener, app).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tool_parameter_schemas() {
        let _schema = schemars::schema_for!(GetChainsParams);
        let _schema = schemars::schema_for!(GetTokensParams);
        let _schema = schemars::schema_for!(GetTokenParams);
        let _schema = schemars::schema_for!(GetToolsParams);
        let _schema = schemars::schema_for!(GetConnectionsParams);
        let _schema = schemars::schema_for!(GetQuoteParams);
        let _schema = schemars::schema_for!(GetRoutesParams);
        let _schema = schemars::schema_for!(GetStatusParams);
        let _schema = schemars::schema_for!(GetGasPricesParams);
    }

    #[test]
    fn test_server_creation() {
        let server = LifiMcpServer::new();
        assert!(format!("{:?}", server).contains("LifiMcpServer"));
    }

    #[test]
    fn test_server_info() {
        let server = LifiMcpServer::new();
        let info = server.get_info();
        assert_eq!(info.server_info.name, "tenzro-lifi");
        assert_eq!(
            info.server_info.title.as_deref(),
            Some("Tenzro LI.FI MCP Server")
        );
    }
}
