//! Canton MCP Server — Model Context Protocol tools for Canton Network / DAML integration
//!
//! Provides 14 MCP tools for interacting with a Canton participant node:
//! - DAML contract management (submit, query, events, transactions)
//! - Party management (allocate, list)
//! - Canton network info (domains, health)
//! - CIP-56 Canton Coin token operations (balance, transfer)
//! - Tokenization (asset creation, DvP settlement)
//! - Administration (DAR upload, fee schedule)
//!
//! All tools communicate with the Canton JSON Ledger API v2 and Admin API
//! via HTTP/JSON using reqwest.

use std::borrow::Cow;
use std::sync::Arc;

use rmcp::{
    handler::server::router::tool::ToolRouter,
    handler::server::wrapper::Parameters,
    model::*,
    tool, tool_handler, tool_router, ServerHandler,
};
use serde::Deserialize;

// ─── Tool parameter structs ───

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CantonSubmitCommandParams {
    #[schemars(description = "Command type: 'create' or 'exercise'")]
    pub command_type: String,
    #[schemars(description = "DAML template identifier (e.g. 'Module:Template')")]
    pub template_id: String,
    #[schemars(description = "Command arguments as a JSON object string")]
    pub arguments: String,
    #[schemars(description = "Party to act as (e.g. 'Alice::fingerprint')")]
    pub act_as: String,
    #[schemars(description = "User ID for command submission")]
    pub user_id: String,
    #[schemars(description = "Contract ID to exercise on (required for 'exercise' command type)")]
    pub contract_id: Option<String>,
    #[schemars(description = "Choice name to exercise (required for 'exercise' command type)")]
    pub choice: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CantonListContractsParams {
    #[schemars(description = "DAML template identifier to filter by (e.g. 'Module:Template')")]
    pub template_id: String,
    #[schemars(description = "Party to query active contracts for")]
    pub party: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CantonGetEventsParams {
    #[schemars(description = "Contract ID to get events for")]
    pub contract_id: String,
    #[schemars(description = "Parties requesting the events")]
    pub requesting_parties: Vec<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CantonGetTransactionParams {
    #[schemars(description = "Transaction ID to look up")]
    pub transaction_id: String,
    #[schemars(description = "Parties requesting the transaction tree")]
    pub requesting_parties: Vec<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CantonAllocatePartyParams {
    #[schemars(description = "Hint for the party name (e.g. 'Alice')")]
    pub party_hint: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CantonListPartiesParams {
    // No parameters — returns all known parties
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CantonListDomainsParams {
    // No parameters — returns all connected synchronization domains
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CantonGetHealthParams {
    // No parameters — returns participant health
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CantonGetBalanceParams {
    #[schemars(description = "Party to check Canton Coin (CC) balance for")]
    pub party: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CantonTransferParams {
    #[schemars(description = "Sender party identifier")]
    pub from_party: String,
    #[schemars(description = "Recipient party identifier")]
    pub to_party: String,
    #[schemars(description = "Amount of Canton Coin (CC) to transfer")]
    pub amount: String,
    #[schemars(description = "User ID for command submission")]
    pub user_id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CantonCreateAssetParams {
    #[schemars(description = "Asset type: 'bond', 'equity', 'repo', or 'custom'")]
    pub asset_type: String,
    #[schemars(description = "Party issuing the asset")]
    pub issuer: String,
    #[schemars(description = "Human-readable description of the asset")]
    pub description: String,
    #[schemars(description = "Nominal amount or quantity of the asset")]
    pub amount: String,
    #[schemars(description = "Maturity date in ISO 8601 format (required for bonds, optional otherwise)")]
    pub maturity_date: Option<String>,
    #[schemars(description = "User ID for command submission")]
    pub user_id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CantonDvpSettleParams {
    #[schemars(description = "Buyer party identifier")]
    pub buyer: String,
    #[schemars(description = "Seller party identifier")]
    pub seller: String,
    #[schemars(description = "Contract ID of the asset leg (delivery)")]
    pub asset_contract_id: String,
    #[schemars(description = "Payment amount in Canton Coin (CC)")]
    pub payment_amount: String,
    #[schemars(description = "User ID for command submission")]
    pub user_id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CantonUploadDarParams {
    #[schemars(description = "Base64-encoded DAR file content (use base64 encoding of the .dar binary)")]
    pub dar_content_base64: String,
    #[schemars(description = "Optional filename for the DAR package")]
    pub filename: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CantonGetFeeScheduleParams {
    #[schemars(description = "Synchronizer domain ID to query fee schedule for")]
    pub synchronizer_id: String,
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

fn json_result(value: serde_json::Value) -> std::result::Result<CallToolResult, ErrorData> {
    Ok(CallToolResult::success(vec![Content::text(
        serde_json::to_string_pretty(&value).unwrap(),
    )]))
}

#[allow(dead_code)]
fn text_result(text: impl Into<String>) -> std::result::Result<CallToolResult, ErrorData> {
    Ok(CallToolResult::success(vec![Content::text(text.into())]))
}

// ─── Canton MCP Server ───

/// Canton MCP Server providing 14 tools for Canton Network / DAML interaction.
///
/// Communicates with a Canton participant node via:
/// - JSON Ledger API v2 (default: `http://localhost:7575/v2`)
/// - Admin API (default: `http://localhost:7576`)
#[derive(Clone)]
pub struct CantonMcpServer {
    /// Canton JSON Ledger API base URL (e.g. "http://localhost:7575")
    ledger_api_url: String,
    /// Canton Admin API base URL (e.g. "http://localhost:7576")
    admin_api_url: String,
    /// Optional JWT token for authentication
    jwt_token: Option<String>,
    /// HTTP client for API calls
    http: reqwest::Client,
    /// Tool router
    _tool_router: ToolRouter<CantonMcpServer>,
}

impl Default for CantonMcpServer {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for CantonMcpServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CantonMcpServer")
            .field("ledger_api_url", &self.ledger_api_url)
            .field("admin_api_url", &self.admin_api_url)
            .finish()
    }
}

#[tool_router]
impl CantonMcpServer {
    /// Create a new Canton MCP server with default URLs.
    pub fn new() -> Self {
        Self {
            ledger_api_url: "http://localhost:7575".to_string(),
            admin_api_url: "http://localhost:7576".to_string(),
            jwt_token: None,
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .expect("Failed to create HTTP client"),
            _tool_router: Self::tool_router(),
        }
    }

    /// Create with custom JSON Ledger API URL.
    #[allow(dead_code)]
    pub fn with_ledger_api_url(mut self, url: impl Into<String>) -> Self {
        self.ledger_api_url = url.into();
        self
    }

    /// Create with custom Admin API URL.
    #[allow(dead_code)]
    pub fn with_admin_api_url(mut self, url: impl Into<String>) -> Self {
        self.admin_api_url = url.into();
        self
    }

    /// Set JWT authentication token.
    #[allow(dead_code)]
    pub fn with_jwt_token(mut self, token: impl Into<String>) -> Self {
        self.jwt_token = Some(token.into());
        self
    }

    // ─── Internal helpers ───

    /// Build an authenticated request to the JSON Ledger API v2.
    fn ledger_request(
        &self,
        method: reqwest::Method,
        endpoint: &str,
    ) -> reqwest::RequestBuilder {
        let url = format!("{}/v2{}", self.ledger_api_url, endpoint);
        let mut builder = self.http.request(method, url);
        if let Some(ref token) = self.jwt_token {
            builder = builder.bearer_auth(token);
        }
        builder
    }

    /// Build an authenticated request to the Admin API.
    fn admin_request(
        &self,
        method: reqwest::Method,
        endpoint: &str,
    ) -> reqwest::RequestBuilder {
        let url = format!("{}{}", self.admin_api_url, endpoint);
        let mut builder = self.http.request(method, url);
        if let Some(ref token) = self.jwt_token {
            builder = builder.bearer_auth(token);
        }
        builder
    }

    /// Execute a JSON Ledger API v2 POST and return the response body as JSON.
    async fn ledger_post(
        &self,
        endpoint: &str,
        body: &serde_json::Value,
    ) -> std::result::Result<serde_json::Value, ErrorData> {
        let resp = self
            .ledger_request(reqwest::Method::POST, endpoint)
            .json(body)
            .send()
            .await
            .map_err(|e| err_internal(format!("Canton JSON Ledger API request failed: {}", e)))?;

        let status = resp.status();
        let body_text = resp
            .text()
            .await
            .map_err(|e| err_internal(format!("Failed to read Canton response: {}", e)))?;

        if !status.is_success() {
            return Err(err_internal(format!(
                "Canton JSON Ledger API returned {}: {}",
                status, body_text
            )));
        }

        serde_json::from_str(&body_text)
            .map_err(|e| err_internal(format!("Failed to parse Canton response: {}", e)))
    }

    /// Execute a JSON Ledger API v2 GET and return the response body as JSON.
    async fn ledger_get(
        &self,
        endpoint: &str,
    ) -> std::result::Result<serde_json::Value, ErrorData> {
        let resp = self
            .ledger_request(reqwest::Method::GET, endpoint)
            .send()
            .await
            .map_err(|e| err_internal(format!("Canton JSON Ledger API request failed: {}", e)))?;

        let status = resp.status();
        let body_text = resp
            .text()
            .await
            .map_err(|e| err_internal(format!("Failed to read Canton response: {}", e)))?;

        if !status.is_success() {
            return Err(err_internal(format!(
                "Canton JSON Ledger API returned {}: {}",
                status, body_text
            )));
        }

        serde_json::from_str(&body_text)
            .map_err(|e| err_internal(format!("Failed to parse Canton response: {}", e)))
    }

    /// Execute an Admin API GET and return the response body as JSON.
    async fn admin_get(
        &self,
        endpoint: &str,
    ) -> std::result::Result<serde_json::Value, ErrorData> {
        let resp = self
            .admin_request(reqwest::Method::GET, endpoint)
            .send()
            .await
            .map_err(|e| err_internal(format!("Canton Admin API request failed: {}", e)))?;

        let status = resp.status();
        let body_text = resp
            .text()
            .await
            .map_err(|e| err_internal(format!("Failed to read Admin API response: {}", e)))?;

        if !status.is_success() {
            return Err(err_internal(format!(
                "Canton Admin API returned {}: {}",
                status, body_text
            )));
        }

        serde_json::from_str(&body_text)
            .map_err(|e| err_internal(format!("Failed to parse Admin API response: {}", e)))
    }

    /// Execute an Admin API POST and return the response body as JSON.
    #[allow(dead_code)]
    async fn admin_post(
        &self,
        endpoint: &str,
        body: &serde_json::Value,
    ) -> std::result::Result<serde_json::Value, ErrorData> {
        let resp = self
            .admin_request(reqwest::Method::POST, endpoint)
            .json(body)
            .send()
            .await
            .map_err(|e| err_internal(format!("Canton Admin API request failed: {}", e)))?;

        let status = resp.status();
        let body_text = resp
            .text()
            .await
            .map_err(|e| err_internal(format!("Failed to read Admin API response: {}", e)))?;

        if !status.is_success() {
            return Err(err_internal(format!(
                "Canton Admin API returned {}: {}",
                status, body_text
            )));
        }

        serde_json::from_str(&body_text)
            .map_err(|e| err_internal(format!("Failed to parse Admin API response: {}", e)))
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  1. DAML Contract Tools
    // ═══════════════════════════════════════════════════════════════════════

    #[tool(description = "Submit a DAML command (Create or Exercise) to the Canton JSON Ledger API v2. Creates new contracts or exercises choices on existing ones. Returns the transaction with created/exercised events.")]
    async fn canton_submit_command(
        &self,
        #[allow(unused_variables)]
        Parameters(params): Parameters<CantonSubmitCommandParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        // Parse arguments JSON string into a Value
        let arguments: serde_json::Value = serde_json::from_str(&params.arguments)
            .map_err(|e| err_invalid_params(format!("Invalid JSON arguments: {}", e)))?;

        let command = match params.command_type.to_lowercase().as_str() {
            "create" => {
                serde_json::json!({
                    "Create": {
                        "templateId": params.template_id,
                        "createArguments": arguments,
                    }
                })
            }
            "exercise" => {
                let contract_id = params.contract_id.ok_or_else(|| {
                    err_invalid_params("contract_id is required for 'exercise' command type")
                })?;
                let choice = params.choice.ok_or_else(|| {
                    err_invalid_params("choice is required for 'exercise' command type")
                })?;
                serde_json::json!({
                    "Exercise": {
                        "templateId": params.template_id,
                        "contractId": contract_id,
                        "choice": choice,
                        "choiceArgument": arguments,
                    }
                })
            }
            other => {
                return Err(err_invalid_params(format!(
                    "Unsupported command type '{}'. Use 'create' or 'exercise'.",
                    other
                )));
            }
        };

        let command_id = format!("tenzro-mcp-{}", uuid::Uuid::new_v4());

        let body = serde_json::json!({
            "commandId": command_id,
            "userId": params.user_id,
            "actAs": [params.act_as],
            "readAs": [],
            "commands": [command],
        });

        let response = self
            .ledger_post("/commands/submit-and-wait-for-transaction", &body)
            .await?;

        json_result(serde_json::json!({
            "success": true,
            "command_id": command_id,
            "command_type": params.command_type,
            "template_id": params.template_id,
            "act_as": params.act_as,
            "transaction": response,
        }))
    }

    #[tool(description = "Query active DAML contracts on a Canton participant via the JSON Ledger API v2. Filters by template ID and party. Returns contract IDs, payloads, signatories, and observers.")]
    async fn canton_list_contracts(
        &self,
        #[allow(unused_variables)]
        Parameters(params): Parameters<CantonListContractsParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let body = serde_json::json!({
            "filter": {
                "filtersByParty": {
                    params.party.clone(): {
                        "cumulative": [{
                            "identifierFilter": {
                                "templateFilter": {
                                    "templateIds": [params.template_id]
                                }
                            }
                        }]
                    }
                }
            }
        });

        let response = self
            .ledger_post("/state/active-contracts", &body)
            .await?;

        // Extract contracts from response — handles both v2 response shapes
        let contracts = if let Some(entries) = response.get("contractEntries") {
            entries.clone()
        } else if let Some(results) = response.get("results") {
            results.clone()
        } else {
            serde_json::json!([])
        };

        json_result(serde_json::json!({
            "party": params.party,
            "template_id": params.template_id,
            "contracts": contracts,
        }))
    }

    #[tool(description = "Get create and archive events for a specific DAML contract via the JSON Ledger API v2. Returns the contract lifecycle events including creation arguments, signatories, and archive status.")]
    async fn canton_get_events(
        &self,
        #[allow(unused_variables)]
        Parameters(params): Parameters<CantonGetEventsParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let body = serde_json::json!({
            "contractId": params.contract_id,
            "requestingParties": params.requesting_parties,
        });

        let response = self
            .ledger_post("/events/events-by-contract-id", &body)
            .await?;

        json_result(serde_json::json!({
            "contract_id": params.contract_id,
            "requesting_parties": params.requesting_parties,
            "events": response,
        }))
    }

    #[tool(description = "Get a transaction by transaction ID via the Canton JSON Ledger API v2. Returns the complete transaction including all created, exercised, and archived events.")]
    async fn canton_get_transaction(
        &self,
        #[allow(unused_variables)]
        Parameters(params): Parameters<CantonGetTransactionParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        // Canton 3.5 unified the per-id update lookup at /v2/updates/update-by-id.
        // Both transaction-by-id and transaction-tree-by-id were removed.
        let body = serde_json::json!({
            "updateId": params.transaction_id,
            "requestingParties": params.requesting_parties,
        });

        let response = self
            .ledger_post("/updates/update-by-id", &body)
            .await?;

        json_result(serde_json::json!({
            "transaction_id": params.transaction_id,
            "requesting_parties": params.requesting_parties,
            "update": response,
        }))
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  2. Party Management
    // ═══════════════════════════════════════════════════════════════════════

    #[tool(description = "Allocate a new party on the Canton participant node. Returns the fully-qualified party identifier (name::fingerprint) for use in DAML commands and queries.")]
    async fn canton_allocate_party(
        &self,
        #[allow(unused_variables)]
        Parameters(params): Parameters<CantonAllocatePartyParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        // Canton 3.5: party allocation moved to POST /v2/parties.
        // The `displayName` field was removed; only `partyIdHint` is supported.
        let body = serde_json::json!({
            "partyIdHint": params.party_hint,
        });

        let response = self
            .ledger_post("/parties", &body)
            .await?;

        // Extract party details from response
        let party_id = response
            .get("partyDetails")
            .and_then(|d| d.get("party"))
            .and_then(|p| p.as_str())
            .unwrap_or("unknown");

        json_result(serde_json::json!({
            "success": true,
            "party": party_id,
            "details": response,
        }))
    }

    #[tool(description = "List all known parties on the Canton participant node. Returns party identifiers and hosting participant information.")]
    async fn canton_list_parties(
        &self,
        #[allow(unused_variables)]
        Parameters(_params): Parameters<CantonListPartiesParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        // Canton 3.5: GET /v2/parties replaces POST /v2/party-management/list-known-parties.
        let response = self
            .ledger_get("/parties")
            .await?;

        let parties = response
            .get("partyDetails")
            .cloned()
            .unwrap_or_else(|| serde_json::json!([]));

        json_result(serde_json::json!({
            "parties": parties,
        }))
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  3. Canton Network
    // ═══════════════════════════════════════════════════════════════════════

    #[tool(description = "List connected Canton synchronization domains (synchronizers). Returns domain IDs, connection status, sequencer endpoints, and whether each is the Global Synchronizer.")]
    async fn canton_list_domains(
        &self,
        #[allow(unused_variables)]
        Parameters(_params): Parameters<CantonListDomainsParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let response = self
            .admin_get("/admin/domain/list-connected")
            .await;

        match response {
            Ok(domains) => json_result(serde_json::json!({
                "connected_domains": domains,
            })),
            Err(_) => {
                // Fall back to participant status endpoint
                let status = self
                    .admin_get("/admin/participant/status")
                    .await
                    .unwrap_or_else(|_| serde_json::json!({}));

                let domains = status
                    .get("connectedDomains")
                    .or_else(|| status.get("connectedSynchronizers"))
                    .cloned()
                    .unwrap_or_else(|| serde_json::json!([]));

                json_result(serde_json::json!({
                    "connected_domains": domains,
                    "source": "participant_status",
                }))
            }
        }
    }

    #[tool(description = "Check Canton participant health and connectivity. Returns node status, connected domains, active parties, and uptime information.")]
    async fn canton_get_health(
        &self,
        #[allow(unused_variables)]
        Parameters(_params): Parameters<CantonGetHealthParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        // Try the health endpoint first
        let health = self
            .admin_get("/admin/health")
            .await
            .unwrap_or_else(|_| serde_json::json!({"status": "unreachable"}));

        // Also try participant status for richer info
        let status = self
            .admin_get("/admin/participant/status")
            .await
            .ok();

        json_result(serde_json::json!({
            "health": health,
            "participant_status": status,
            "ledger_api_url": self.ledger_api_url,
            "admin_api_url": self.admin_api_url,
            "authenticated": self.jwt_token.is_some(),
        }))
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  4. Token (CIP-56 Canton Coin)
    // ═══════════════════════════════════════════════════════════════════════

    #[tool(description = "Get the Canton Coin (CC) balance for a party. Queries the CIP-56 token balance via the Canton JSON Ledger API v2 by looking up active Holding contracts (Splice.Amulet:Amulet template).")]
    async fn canton_get_balance(
        &self,
        #[allow(unused_variables)]
        Parameters(params): Parameters<CantonGetBalanceParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        // Query active Holding contracts for the party (CIP-56 standard)
        // Canton 3.x JSON Ledger API v2 uses identifierFilter wrapping templateFilter
        let body = serde_json::json!({
            "filter": {
                "filtersByParty": {
                    params.party.clone(): {
                        "cumulative": [{
                            "identifierFilter": {
                                "templateFilter": {
                                    "templateIds": ["Splice.Amulet:Amulet"]
                                }
                            }
                        }]
                    }
                }
            }
        });

        let response = self
            .ledger_post("/state/active-contracts", &body)
            .await;

        match response {
            Ok(data) => {
                // Sum up amounts from all active Holding/Amulet contracts
                let contracts = data
                    .get("contractEntries")
                    .or_else(|| data.get("results"))
                    .and_then(|v| v.as_array())
                    .cloned()
                    .unwrap_or_default();

                let mut total_balance = 0.0f64;
                for contract in &contracts {
                    // Navigate to the amount field in the contract payload
                    if let Some(amount_str) = contract
                        .get("payload")
                        .or_else(|| contract.get("createArguments"))
                        .and_then(|p| p.get("amount"))
                        .and_then(|a| a.as_str())
                    {
                        if let Ok(val) = amount_str.parse::<f64>() {
                            total_balance += val;
                        }
                    } else if let Some(amount_num) = contract
                        .get("payload")
                        .or_else(|| contract.get("createArguments"))
                        .and_then(|p| p.get("amount"))
                        .and_then(|a| a.as_f64())
                    {
                        total_balance += amount_num;
                    }
                }

                json_result(serde_json::json!({
                    "party": params.party,
                    "balance_cc": format!("{:.10}", total_balance),
                    "holding_contracts": contracts.len(),
                }))
            }
            Err(e) => {
                // Return zero balance with error context
                json_result(serde_json::json!({
                    "party": params.party,
                    "balance_cc": "0",
                    "holding_contracts": 0,
                    "note": format!("Could not query balance: {}", e.message),
                }))
            }
        }
    }

    #[tool(description = "Transfer Canton Coin (CC) tokens between parties. Submits a DAML transfer command via the JSON Ledger API v2 using the CIP-56 Amulet transfer workflow (Splice.AmuletRules:Transfer template).")]
    async fn canton_transfer(
        &self,
        #[allow(unused_variables)]
        Parameters(params): Parameters<CantonTransferParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let command_id = format!("tenzro-mcp-transfer-{}", uuid::Uuid::new_v4());

        // Create a transfer command using the Splice.Amulet transfer template
        let body = serde_json::json!({
            "commandId": command_id,
            "userId": params.user_id,
            "actAs": [params.from_party],
            "readAs": [],
            "commands": [{
                "Create": {
                    "templateId": "Splice.AmuletRules:Transfer",
                    "createArguments": {
                        "sender": params.from_party,
                        "receiver": params.to_party,
                        "amount": params.amount,
                    }
                }
            }],
        });

        let response = self
            .ledger_post("/commands/submit-and-wait-for-transaction", &body)
            .await?;

        json_result(serde_json::json!({
            "success": true,
            "command_id": command_id,
            "from": params.from_party,
            "to": params.to_party,
            "amount": params.amount,
            "transaction": response,
        }))
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  5. Tokenization
    // ═══════════════════════════════════════════════════════════════════════

    #[tool(description = "Create a tokenized asset (bond, equity, repo, or custom) as a DAML contract on Canton. Submits a Create command with the asset parameters. For bonds, maturity_date is required.")]
    async fn canton_create_asset(
        &self,
        #[allow(unused_variables)]
        Parameters(params): Parameters<CantonCreateAssetParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        // Validate asset type
        let asset_type_lower = params.asset_type.to_lowercase();
        let valid_types = ["bond", "equity", "repo", "custom"];
        if !valid_types.contains(&asset_type_lower.as_str()) {
            return Err(err_invalid_params(format!(
                "Unsupported asset type '{}'. Use one of: bond, equity, repo, custom.",
                params.asset_type
            )));
        }

        // Bonds require maturity_date
        if asset_type_lower == "bond" && params.maturity_date.is_none() {
            return Err(err_invalid_params(
                "maturity_date is required for bond asset type",
            ));
        }

        // Derive template ID from asset type
        let template_id = match asset_type_lower.as_str() {
            "bond" => "Tenzro.Assets:Bond",
            "equity" => "Tenzro.Assets:Equity",
            "repo" => "Tenzro.Assets:Repo",
            _ => "Tenzro.Assets:CustomAsset",
        };

        let command_id = format!(
            "tenzro-mcp-asset-{}-{}",
            asset_type_lower,
            uuid::Uuid::new_v4()
        );

        let mut create_arguments = serde_json::json!({
            "issuer": params.issuer,
            "description": params.description,
            "amount": params.amount,
            "assetType": params.asset_type,
        });

        if let Some(ref maturity) = params.maturity_date {
            create_arguments
                .as_object_mut()
                .unwrap()
                .insert("maturityDate".to_string(), serde_json::json!(maturity));
        }

        let body = serde_json::json!({
            "commandId": command_id,
            "userId": params.user_id,
            "actAs": [params.issuer],
            "readAs": [],
            "commands": [{
                "Create": {
                    "templateId": template_id,
                    "createArguments": create_arguments,
                }
            }],
        });

        let response = self
            .ledger_post("/commands/submit-and-wait-for-transaction", &body)
            .await?;

        json_result(serde_json::json!({
            "success": true,
            "command_id": command_id,
            "asset_type": params.asset_type,
            "template_id": template_id,
            "issuer": params.issuer,
            "amount": params.amount,
            "maturity_date": params.maturity_date,
            "transaction": response,
        }))
    }

    #[tool(description = "Execute atomic Delivery-vs-Payment (DvP) settlement on Canton. Creates a DvP settlement contract that atomically swaps the asset leg (delivery) and payment leg in a single DAML transaction, ensuring neither party bears settlement risk.")]
    async fn canton_dvp_settle(
        &self,
        #[allow(unused_variables)]
        Parameters(params): Parameters<CantonDvpSettleParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let command_id = format!("tenzro-mcp-dvp-{}", uuid::Uuid::new_v4());

        // Exercise the DvP Settle choice on the asset contract.
        // The DvP template atomically archives the asset leg and creates
        // new contracts with swapped ownership, while the payment leg
        // is settled simultaneously.
        let body = serde_json::json!({
            "commandId": command_id,
            "userId": params.user_id,
            "actAs": [params.buyer, params.seller],
            "readAs": [],
            "commands": [{
                "Exercise": {
                    "templateId": "Tenzro.Settlement:DvP",
                    "contractId": params.asset_contract_id,
                    "choice": "Settle",
                    "choiceArgument": {
                        "buyer": params.buyer,
                        "seller": params.seller,
                        "paymentAmount": params.payment_amount,
                    }
                }
            }],
        });

        let response = self
            .ledger_post("/commands/submit-and-wait-for-transaction", &body)
            .await?;

        json_result(serde_json::json!({
            "success": true,
            "command_id": command_id,
            "settlement_type": "dvp",
            "asset_contract_id": params.asset_contract_id,
            "payment_amount": params.payment_amount,
            "buyer": params.buyer,
            "seller": params.seller,
            "transaction": response,
        }))
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  6. Administration
    // ═══════════════════════════════════════════════════════════════════════

    #[tool(description = "Upload a DAR (DAML Archive) file to the Canton participant node. The DAR is installed and its packages become available for contract creation. Provide base64-encoded DAR content.")]
    async fn canton_upload_dar(
        &self,
        #[allow(unused_variables)]
        Parameters(params): Parameters<CantonUploadDarParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        use base64::Engine;

        let dar_bytes = base64::engine::general_purpose::STANDARD
            .decode(&params.dar_content_base64)
            .map_err(|e| {
                err_invalid_params(format!("Invalid base64 DAR content: {}", e))
            })?;

        let dar_size = dar_bytes.len();

        let filename = params
            .filename
            .unwrap_or_else(|| "package.dar".to_string());

        // Upload via Admin API using raw binary body with octet-stream content type.
        // Canton's PackageService accepts DAR bytes directly at /admin/packages/upload-dar.
        let url = format!("{}/admin/packages/upload-dar", self.admin_api_url);
        let mut builder = self
            .http
            .post(&url)
            .header("Content-Type", "application/octet-stream")
            .body(dar_bytes);
        if let Some(ref token) = self.jwt_token {
            builder = builder.bearer_auth(token);
        }

        let resp = builder
            .send()
            .await
            .map_err(|e| err_internal(format!("DAR upload request failed: {}", e)))?;

        let status = resp.status();
        let body_text = resp
            .text()
            .await
            .map_err(|e| err_internal(format!("Failed to read upload response: {}", e)))?;

        if !status.is_success() {
            return Err(err_internal(format!(
                "DAR upload failed with {}: {}",
                status, body_text
            )));
        }

        let response: serde_json::Value = serde_json::from_str(&body_text)
            .unwrap_or_else(|_| serde_json::json!({"raw": body_text}));

        json_result(serde_json::json!({
            "success": true,
            "filename": filename,
            "size_bytes": dar_size,
            "response": response,
        }))
    }

    #[tool(description = "Get the fee schedule for a Canton synchronizer domain. Queries the Admin API at /admin/synchronizer/{id}/fee-schedule. Returns base fee, per-byte fee, and other fee parameters.")]
    async fn canton_get_fee_schedule(
        &self,
        #[allow(unused_variables)]
        Parameters(params): Parameters<CantonGetFeeScheduleParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let endpoint = format!(
            "/admin/synchronizer/{}/fee-schedule",
            params.synchronizer_id
        );

        let response = self.admin_get(&endpoint).await;

        match response {
            Ok(schedule) => {
                let base_fee = schedule
                    .get("base_fee")
                    .or_else(|| schedule.get("baseFee"))
                    .cloned()
                    .unwrap_or(serde_json::json!("unknown"));
                let per_byte_fee = schedule
                    .get("per_byte_fee")
                    .or_else(|| schedule.get("perByteFee"))
                    .cloned()
                    .unwrap_or(serde_json::json!("unknown"));

                json_result(serde_json::json!({
                    "synchronizer_id": params.synchronizer_id,
                    "base_fee": base_fee,
                    "per_byte_fee": per_byte_fee,
                    "full_schedule": schedule,
                }))
            }
            Err(e) => {
                // Return static fallback estimates
                json_result(serde_json::json!({
                    "synchronizer_id": params.synchronizer_id,
                    "base_fee": "0.005",
                    "per_byte_fee": "0.000001",
                    "source": "static_fallback",
                    "note": format!("Could not query live fee schedule: {}", e.message),
                }))
            }
        }
    }
}

// ─── ServerHandler ───

#[tool_handler]
impl ServerHandler for CantonMcpServer {
    fn get_info(&self) -> ServerInfo {
        let mut info = ServerInfo::default();
        info.protocol_version = ProtocolVersion::V_2025_11_25;
        info.capabilities = ServerCapabilities::builder().enable_tools().build();
        let mut impl_info = Implementation::default();
        impl_info.name = "tenzro-canton".into();
        impl_info.title = Some("Tenzro Canton MCP Server".into());
        impl_info.version = env!("CARGO_PKG_VERSION").into();
        impl_info.description = Some(
            "Canton Network / DAML tools — smart contracts, parties, CIP-56 tokens, DvP settlement, tokenized assets"
                .into(),
        );
        impl_info.website_url = Some("https://tenzro.com".into());
        info.server_info = impl_info;
        info.instructions = Some(
            "Tenzro Canton MCP Server — interact with Canton Network and DAML smart contracts.\n\n\
             TOOLS BY CATEGORY:\n\n\
             DAML Contract Tools:\n\
             - canton_submit_command — Submit a DAML command (Create or Exercise) via Canton 3.x JSON Ledger API v2 (submit-and-wait-for-transaction)\n\
             - canton_list_contracts — Query active contracts via /v2/state/active-contracts (identifierFilter)\n\
             - canton_get_events — Get events for a contract via /v2/events/events-by-contract-id\n\
             - canton_get_transaction — Get update by ID via /v2/updates/update-by-id\n\n\
             Party Management:\n\
             - canton_allocate_party — Allocate a new party on the participant\n\
             - canton_list_parties — List known parties on the participant\n\n\
             Canton Network:\n\
             - canton_list_domains — List connected synchronization domains\n\
             - canton_get_health — Check participant health and connectivity\n\n\
             Token (CIP-56 Canton Coin):\n\
             - canton_get_balance — Get Canton Coin (CC) balance for a party\n\
             - canton_transfer — Transfer CC tokens between parties\n\n\
             Tokenization:\n\
             - canton_create_asset — Create a tokenized asset (bond, equity, repo) via DAML\n\
             - canton_dvp_settle — Execute atomic Delivery-vs-Payment settlement\n\n\
             Administration:\n\
             - canton_upload_dar — Upload a DAR file to the participant\n\
             - canton_get_fee_schedule — Get fee schedule for a synchronizer domain"
                .to_string(),
        );
        info
    }
}

// ─── Server startup ───

/// Start the Canton MCP server on the given address using Streamable HTTP transport.
pub async fn start_canton_mcp_server(
    listen_addr: String,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use rmcp::transport::streamable_http_server::{
        session::local::LocalSessionManager, StreamableHttpService, StreamableHttpServerConfig,
    };

    // Use stateless mode with JSON responses — same pattern as the main MCP server.
    // Each HTTP POST is independent, no session management, no SSE framing.
    let config = StreamableHttpServerConfig::default()
        .with_stateful_mode(false)
        .with_json_response(true)
        .with_allowed_hosts(vec![
            "localhost".to_string(),
            "127.0.0.1".to_string(),
            "::1".to_string(),
            "0.0.0.0".to_string(),
            "canton-mcp.tenzro.network".to_string(),
        ]);

    let service = StreamableHttpService::new(
        move || Ok(CantonMcpServer::new()),
        Arc::new(LocalSessionManager::default()),
        config,
    );

    let app = axum::Router::new().nest_service("/mcp", service);

    let listener = tokio::net::TcpListener::bind(&listen_addr).await?;
    tracing::info!(
        addr = %listen_addr,
        tools = 14,
        mode = "stateless-json",
        "Canton MCP Server listening (endpoint: /mcp)"
    );

    axum::serve(listener, app).await?;

    Ok(())
}
