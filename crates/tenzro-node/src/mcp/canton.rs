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

use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use rmcp::{
    handler::server::router::tool::ToolRouter,
    handler::server::wrapper::Parameters,
    model::*,
    tool, tool_handler, tool_router, Json, ServerHandler,
};
use serde::Deserialize;
use tenzro_bridge::canton_auth::CantonTokenProvider;

use super::server::RpcPassthroughOutput;
use crate::api_key::{ApiKeyManager, ApiKeyScope, AuthorizeOutcome};

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

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CantonReconnectSynchronizerParams {
    #[schemars(description = "Synchronizer alias to reconnect (e.g. 'global', 'devnet')")]
    pub synchronizer_alias: String,
    #[schemars(description = "If true, retry the connection on transient failure (default: false)")]
    #[serde(default)]
    pub retry_on_failure: bool,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CantonGrantUserRightsParams {
    #[schemars(
        description = "Canton User Management Service user id to grant rights to. Pass null to grant to the OAuth principal's own user (`<client_id>@clients`)."
    )]
    pub user_id: Option<String>,
    #[schemars(
        description = "Fully-qualified party id (`<hint>::<participant-hash>`) the user will be allowed to act/read as. Canton rejects bare hints."
    )]
    pub party: String,
    #[schemars(description = "Grant CanActAs (default: true)")]
    #[serde(default = "default_true")]
    pub can_act_as: bool,
    #[schemars(description = "Grant CanReadAs (default: false)")]
    #[serde(default)]
    pub can_read_as: bool,
    #[schemars(
        description = "Canton IdentityProviderConfig id the user lives under. Required for IDP-scoped users (Stage 2 tenants); omit for users in the participant's default IDP."
    )]
    #[serde(default)]
    pub identity_provider_id: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CantonListUserRightsParams {
    #[schemars(
        description = "User id to list rights for. Pass null to list rights for the OAuth principal's own user."
    )]
    pub user_id: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CantonGetMyAnalyticsParams {
    #[schemars(
        description = "Your API key handle (`key_id`, 16-hex prefix of the SHA-256 of the plaintext key). Returned alongside the plaintext when the operator mints the key; cache it for analytics self-reads."
    )]
    pub key_id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CantonListApiKeyAnalyticsParams {
    #[schemars(
        description = "Optional API key handle (`key_id`, 16-hex prefix of the SHA-256 of the key) to filter to a single tenant. Omit to return every tenant."
    )]
    pub key_id: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CantonWatchPartyParams {
    #[schemars(
        description = "Fully-qualified party id (`<hint>::<participant-hash>`) to watch. The MCP server is operator-scoped, so any party reachable from the operator's participant credential is accessible."
    )]
    pub party: String,
    #[schemars(description = "DAML template ids to filter the active-contract set by. At least one is required.")]
    pub template_ids: Vec<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CantonCreateIdpParams {
    #[schemars(description = "Per-Canton-unique IdentityProviderConfig id")]
    pub identity_provider_id: String,
    #[schemars(description = "OAuth issuer URL")]
    pub issuer_url: String,
    #[schemars(description = "OAuth JWKS URL")]
    pub jwks_url: String,
    #[schemars(description = "OAuth audience claim Canton expects on tenant JWTs")]
    pub audience: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CantonDeleteIdpParams {
    #[schemars(description = "IdentityProviderConfig id to delete")]
    pub identity_provider_id: String,
}

fn default_true() -> bool {
    true
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
/// Used by tools that return a simple confirmation message rather than
/// structured JSON (e.g. operational POST endpoints with empty 200 responses).
fn text_result(text: impl Into<String>) -> std::result::Result<Json<RpcPassthroughOutput>, ErrorData> {
    Ok(Json(RpcPassthroughOutput {
        result: serde_json::json!({ "message": text.into() }),
    }))
}

// ─── Canton MCP Server ───

/// Canton MCP Server providing 14 tools for Canton Network / DAML interaction.
///
/// Communicates with a Canton participant node via:
/// - JSON Ledger API v2 — `ledger_api_url` is the BASE url (e.g.
///   `https://json.canton.example-operator.invalid`); request paths append `/v2/...`
/// - Admin API (e.g. `https://admin.devnet.tenzro.xyz`)
///
/// Authentication precedence:
/// 1. If a [`CantonTokenProvider`] is attached via [`with_token_provider`],
///    every request fetches a cached bearer JWT via the OAuth2 client-
///    credentials flow. This is the Tenzro devnet path.
/// 2. Otherwise falls back to a static `jwt_token` configured via
///    [`with_jwt_token`]. This is the local / unauth path.
#[derive(Clone)]
pub struct CantonMcpServer {
    /// Canton JSON Ledger API base URL (e.g. "https://json.canton.example-operator.invalid")
    ledger_api_url: String,
    /// Canton Admin API base URL (e.g. "https://admin.devnet.tenzro.xyz")
    admin_api_url: String,
    /// Optional static JWT token (used only when no token provider is attached).
    jwt_token: Option<String>,
    /// Optional OAuth2 client-credentials token provider.
    token_provider: Option<Arc<CantonTokenProvider>>,
    /// Optional handle to the host node's per-tenant Canton analytics
    /// store. Wired by [`crate::mcp::server`] at boot when the node
    /// hosts this MCP server in-process; absent when the MCP runs
    /// stand-alone against an external Canton participant. Surfaces
    /// `canton_get_my_analytics` / `canton_list_api_key_analytics`.
    analytics: Option<Arc<crate::canton_analytics::CantonAnalyticsManager>>,
    /// Optional handle to the host node's API-key manager. Required by
    /// `canton_get_my_analytics` so the MCP can resolve the presented
    /// API key to its `key_id`.
    api_keys: Option<Arc<crate::api_key::ApiKeyManager>>,
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
    /// Create a new Canton MCP server. URLs default to the Tenzro-operated
    /// Canton devnet. Override with [`with_ledger_api_url`] /
    /// [`with_admin_api_url`] for self-hosted participants.
    pub fn new() -> Self {
        Self {
            ledger_api_url: "https://json.canton.example-operator.invalid".to_string(),
            admin_api_url: "https://admin.devnet.tenzro.xyz".to_string(),
            jwt_token: None,
            token_provider: None,
            analytics: None,
            api_keys: None,
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .expect("Failed to create HTTP client"),
            _tool_router: Self::tool_router(),
        }
    }

    /// Wires the in-process analytics + api-key managers so analytics
    /// tools can serve answers without an extra hop through the
    /// node's JSON-RPC. Idempotent — pass `None` to clear.
    pub fn with_node_state(
        mut self,
        analytics: Option<Arc<crate::canton_analytics::CantonAnalyticsManager>>,
        api_keys: Option<Arc<crate::api_key::ApiKeyManager>>,
    ) -> Self {
        self.analytics = analytics;
        self.api_keys = api_keys;
        self
    }

    /// Create with custom JSON Ledger API URL.
    pub fn with_ledger_api_url(mut self, url: impl Into<String>) -> Self {
        self.ledger_api_url = url.into();
        self
    }

    /// Create with custom Admin API URL.
    pub fn with_admin_api_url(mut self, url: impl Into<String>) -> Self {
        self.admin_api_url = url.into();
        self
    }

    /// Set static JWT authentication token. Used only when no token provider
    /// is attached.
    pub fn with_jwt_token(mut self, token: impl Into<String>) -> Self {
        self.jwt_token = Some(token.into());
        self
    }

    /// Attach an OAuth2 client-credentials token provider. Required for the
    /// Tenzro-operated Canton devnet.
    pub fn with_token_provider(mut self, provider: Arc<CantonTokenProvider>) -> Self {
        self.token_provider = Some(provider);
        self
    }

    // ─── Internal helpers ───

    /// Resolve the bearer JWT for outgoing requests. Prefers the
    /// [`CantonTokenProvider`] (OAuth2 client-credentials) when attached,
    /// falls back to a static configured token.
    async fn resolve_bearer(&self) -> std::result::Result<Option<String>, ErrorData> {
        if let Some(ref provider) = self.token_provider {
            let token = provider.bearer().await.map_err(|e| {
                err_internal(format!("Canton auth: token refresh failed: {}", e))
            })?;
            return Ok(Some(token));
        }
        Ok(self.jwt_token.clone())
    }

    /// Build an authenticated request to the JSON Ledger API v2.
    async fn ledger_request(
        &self,
        method: reqwest::Method,
        endpoint: &str,
    ) -> std::result::Result<reqwest::RequestBuilder, ErrorData> {
        let url = format!("{}/v2{}", self.ledger_api_url, endpoint);
        let mut builder = self.http.request(method, url);
        if let Some(token) = self.resolve_bearer().await? {
            builder = builder.bearer_auth(token);
        }
        Ok(builder)
    }

    /// Build an authenticated request to the Admin API.
    async fn admin_request(
        &self,
        method: reqwest::Method,
        endpoint: &str,
    ) -> std::result::Result<reqwest::RequestBuilder, ErrorData> {
        let url = format!("{}{}", self.admin_api_url, endpoint);
        let mut builder = self.http.request(method, url);
        if let Some(token) = self.resolve_bearer().await? {
            builder = builder.bearer_auth(token);
        }
        Ok(builder)
    }

    /// Execute a JSON Ledger API v2 POST and return the response body as JSON.
    async fn ledger_post(
        &self,
        endpoint: &str,
        body: &serde_json::Value,
    ) -> std::result::Result<serde_json::Value, ErrorData> {
        let resp = self
            .ledger_request(reqwest::Method::POST, endpoint)
            .await?
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
            .await?
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

    /// Execute a JSON Ledger API v2 DELETE and return the response
    /// body as JSON. Empty response bodies return `Value::Null`.
    async fn ledger_delete(
        &self,
        endpoint: &str,
    ) -> std::result::Result<serde_json::Value, ErrorData> {
        let resp = self
            .ledger_request(reqwest::Method::DELETE, endpoint)
            .await?
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

        if body_text.trim().is_empty() {
            return Ok(serde_json::Value::Null);
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
            .await?
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
    ///
    /// Used by mutating admin tools (e.g. reconnect / disconnect synchronizer,
    /// dynamic parameter updates).
    async fn admin_post(
        &self,
        endpoint: &str,
        body: &serde_json::Value,
    ) -> std::result::Result<serde_json::Value, ErrorData> {
        let resp = self
            .admin_request(reqwest::Method::POST, endpoint)
            .await?
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
        Parameters(params): Parameters<CantonSubmitCommandParams>,
    ) -> std::result::Result<Json<RpcPassthroughOutput>, ErrorData> {
        // Parse arguments JSON string into a Value
        let arguments: serde_json::Value = serde_json::from_str(&params.arguments)
            .map_err(|e| err_invalid_params(format!("Invalid JSON arguments: {}", e)))?;

        // Canton 3.5+ JSON Ledger API v2 requires each command to be
        // externally tagged (`CreateCommand` / `ExerciseCommand`) — circe
        // rejects the un-tagged form with `JSON decoding to CNil should
        // never happen at 'commands.commands[0]'`. The wire shape mirrors
        // `tenzro_bridge::canton::JsonApiCommandV2`.
        let command = match params.command_type.to_lowercase().as_str() {
            "create" => {
                serde_json::json!({
                    "CreateCommand": {
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
                    "ExerciseCommand": {
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

        // Canton 3.5+ requires the JsCommands payload nested under a
        // top-level `commands` key. A flat root body returns HTTP 400 /
        // INVALID_ARGUMENT at the wire layer before the DAML payload is
        // even reached.
        let body = serde_json::json!({
            "commands": {
                "commandId": command_id,
                "userId": params.user_id,
                "actAs": [params.act_as],
                "readAs": [],
                "commands": [command],
            }
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

    #[tool(description = "Query active DAML contracts on a Canton participant via the JSON Ledger API v2 (Canton 3.5+). Filters by template ID and party. Returns contract IDs, payloads, signatories, and observers. The `party` argument must be the fully-qualified party id (`<hint>::<participant-hash>`) — Canton 3.5+ rejects bare hints.")]
    async fn canton_list_contracts(
        &self,
        Parameters(params): Parameters<CantonListContractsParams>,
    ) -> std::result::Result<Json<RpcPassthroughOutput>, ErrorData> {
        // Canton 3.5+ requires `activeAtOffset` as a JSON number — null
        // / empty-string get rejected with HTTP 400. Fetch the current
        // ledger-end first.
        let offset = self.fetch_ledger_end_offset().await?;
        let body = serde_json::json!({
            "filter": {
                "filtersByParty": {
                    params.party.clone(): {
                        "cumulative": [{
                            "identifierFilter": {
                                "TemplateFilter": {
                                    "value": { "templateId": params.template_id }
                                }
                            }
                        }]
                    }
                }
            },
            "verbose": true,
            "activeAtOffset": offset
        });

        let response = self
            .ledger_post("/state/active-contracts", &body)
            .await?;

        // Canton 3.5+ returns a bare top-level JSON array; older drafts
        // wrapped in `{contractEntries:...}` or `{results:...}`.
        let contracts = if response.is_array() {
            response.clone()
        } else if let Some(entries) = response.get("contractEntries") {
            entries.clone()
        } else if let Some(results) = response.get("results") {
            results.clone()
        } else {
            serde_json::json!([])
        };

        json_result(serde_json::json!({
            "party": params.party,
            "template_id": params.template_id,
            "active_at_offset": offset,
            "contracts": contracts,
        }))
    }

    /// Helper: fetch the participant's current ledger-end offset.
    async fn fetch_ledger_end_offset(&self) -> std::result::Result<i64, ErrorData> {
        let url = format!("{}/v2/state/ledger-end", self.ledger_api_url);
        let mut builder = self.http.get(&url);
        if let Some(ref token) = self.jwt_token {
            builder = builder.bearer_auth(token);
        }
        let resp = builder
            .send()
            .await
            .map_err(|e| err_internal(format!("Canton ledger-end fetch failed: {}", e)))?;
        if !resp.status().is_success() {
            return Err(err_internal(format!(
                "Canton ledger-end fetch HTTP {}",
                resp.status()
            )));
        }
        let body: serde_json::Value = resp.json().await.map_err(|e| {
            err_internal(format!("Invalid Canton ledger-end response: {}", e))
        })?;
        body.get("offset")
            .and_then(|v| v.as_i64())
            .ok_or_else(|| err_internal("Canton ledger-end response missing 'offset' field".to_string()))
    }

    #[tool(description = "Get create and archive events for a specific DAML contract via the JSON Ledger API v2. Returns the contract lifecycle events including creation arguments, signatories, and archive status.")]
    async fn canton_get_events(
        &self,
        Parameters(params): Parameters<CantonGetEventsParams>,
    ) -> std::result::Result<Json<RpcPassthroughOutput>, ErrorData> {
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
        Parameters(params): Parameters<CantonGetTransactionParams>,
    ) -> std::result::Result<Json<RpcPassthroughOutput>, ErrorData> {
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
        Parameters(params): Parameters<CantonAllocatePartyParams>,
    ) -> std::result::Result<Json<RpcPassthroughOutput>, ErrorData> {
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
        #[allow(unused)] Parameters(_params): Parameters<CantonListPartiesParams>,
    ) -> std::result::Result<Json<RpcPassthroughOutput>, ErrorData> {
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

    #[tool(
        description = "Grant CanActAs / CanReadAs rights on a Canton party to a user (Canton 3.5+ User Management Service, CIP-26). Required before a user can submit DAML commands on behalf of a newly-allocated party. Pass user_id=null to grant to the operator's own OAuth user. The `party` argument must be the fully-qualified party id."
    )]
    async fn canton_grant_user_rights(
        &self,
        Parameters(params): Parameters<CantonGrantUserRightsParams>,
    ) -> std::result::Result<Json<RpcPassthroughOutput>, ErrorData> {
        if !params.can_act_as && !params.can_read_as {
            return Err(err_invalid_params(
                "at least one of can_act_as / can_read_as must be true",
            ));
        }
        // Resolve user_id — null means the operator's own
        // `<client_id>@clients` user.
        let user_id = match params.user_id {
            Some(u) => u,
            None => match self.token_provider.as_ref() {
                Some(p) => format!("{}@clients", p.client_id()),
                None => {
                    return Err(err_invalid_params(
                        "user_id=null requires an OAuth token provider so the operator's own user can be derived",
                    ));
                }
            },
        };
        let mut rights = Vec::new();
        if params.can_act_as {
            rights.push(serde_json::json!({
                "kind": { "CanActAs": { "value": { "party": params.party.clone() } } }
            }));
        }
        if params.can_read_as {
            rights.push(serde_json::json!({
                "kind": { "CanReadAs": { "value": { "party": params.party.clone() } } }
            }));
        }
        // Canton 3.5: userId MUST also be in the body, not just URL.
        // IDP-scoped users additionally need identityProviderId in the
        // body or Canton resolves them in the default IDP and 403s.
        let mut body = serde_json::json!({
            "userId": user_id,
            "rights": rights,
        });
        if let Some(idp) = params.identity_provider_id.as_deref() {
            body["identityProviderId"] = serde_json::Value::String(idp.to_string());
        }
        let path = format!("/users/{}/rights", urlencoding::encode(&user_id));
        let response = self.ledger_post(&path, &body).await?;
        json_result(response)
    }

    #[tool(
        description = "List the rights granted to a Canton user via the User Management Service (CIP-26). Returns `{rights:[{kind:{CanActAs|CanReadAs:{value:{party}}}}, ...]}`. Pass user_id=null for the operator's own user."
    )]
    async fn canton_list_user_rights(
        &self,
        Parameters(params): Parameters<CantonListUserRightsParams>,
    ) -> std::result::Result<Json<RpcPassthroughOutput>, ErrorData> {
        let user_id = match params.user_id {
            Some(u) => u,
            None => match self.token_provider.as_ref() {
                Some(p) => format!("{}@clients", p.client_id()),
                None => {
                    return Err(err_invalid_params(
                        "user_id=null requires an OAuth token provider so the operator's own user can be derived",
                    ));
                }
            },
        };
        let path = format!("/users/{}/rights", urlencoding::encode(&user_id));
        let response = self.ledger_get(&path).await?;
        json_result(response)
    }

    #[tool(
        description = "Subject self-read: returns this tenant's Canton call aggregates (calls_total, errors_total, per-method counts, first_seen_at, last_called_at). Pass your `key_id` (16-hex prefix of the SHA-256 of your API key) — given to you alongside the plaintext key at issuance. Requires the host node to have wired analytics + api-key state into this MCP."
    )]
    async fn canton_get_my_analytics(
        &self,
        Parameters(params): Parameters<CantonGetMyAnalyticsParams>,
    ) -> std::result::Result<Json<RpcPassthroughOutput>, ErrorData> {
        let analytics = self.analytics.as_ref().ok_or_else(|| {
            err_internal(
                "Canton analytics is not wired into this MCP server (only available when run in-process with TenzroNode)",
            )
        })?;
        let row = analytics.get(&params.key_id).ok_or_else(|| {
            ErrorData {
                code: ErrorCode::INVALID_PARAMS,
                message: Cow::from(format!(
                    "No analytics record for key_id {} (key is unknown, or has not made a canton call yet)",
                    params.key_id
                )),
                data: None,
            }
        })?;
        let value = serde_json::to_value(&row).map_err(|e| {
            err_internal(format!("Canton analytics serialize failed: {}", e))
        })?;
        json_result(value)
    }

    #[tool(
        description = "Operator admin-read: list per-tenant Canton call aggregates for every API key (or one tenant when key_id is set). Requires the host node to have wired analytics state into this MCP. Rows are sorted by last_called_at descending."
    )]
    async fn canton_list_api_key_analytics(
        &self,
        Parameters(params): Parameters<CantonListApiKeyAnalyticsParams>,
    ) -> std::result::Result<Json<RpcPassthroughOutput>, ErrorData> {
        let analytics = self.analytics.as_ref().ok_or_else(|| {
            err_internal(
                "Canton analytics is not wired into this MCP server (only available when run in-process with TenzroNode)",
            )
        })?;
        let mut rows = analytics.list_all();
        if let Some(filter) = params.key_id.as_deref() {
            rows.retain(|r| r.key_id == filter);
        }
        rows.sort_by_key(|r| std::cmp::Reverse(r.last_called_at.unwrap_or(0)));
        let value = serde_json::to_value(&rows).map_err(|e| {
            err_internal(format!("Canton analytics serialize failed: {}", e))
        })?;
        json_result(serde_json::json!({ "analytics": value }))
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  3. Canton Network
    // ═══════════════════════════════════════════════════════════════════════

    #[tool(description = "List connected Canton synchronization domains (synchronizers). Returns domain IDs, connection status, sequencer endpoints, and whether each is the Global Synchronizer.")]
    async fn canton_list_domains(
        &self,
        #[allow(unused)] Parameters(_params): Parameters<CantonListDomainsParams>,
    ) -> std::result::Result<Json<RpcPassthroughOutput>, ErrorData> {
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
        #[allow(unused)] Parameters(_params): Parameters<CantonGetHealthParams>,
    ) -> std::result::Result<Json<RpcPassthroughOutput>, ErrorData> {
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
        Parameters(params): Parameters<CantonGetBalanceParams>,
    ) -> std::result::Result<Json<RpcPassthroughOutput>, ErrorData> {
        // Query active Holding contracts for the party (CIP-56 standard).
        // Canton 3.5+ requires `activeAtOffset` as a JSON number and
        // tagged `TemplateFilter` wrappers (uppercase, singular
        // `templateId`).
        let offset = self.fetch_ledger_end_offset().await?;
        let body = serde_json::json!({
            "filter": {
                "filtersByParty": {
                    params.party.clone(): {
                        "cumulative": [{
                            "identifierFilter": {
                                "TemplateFilter": {
                                    "value": { "templateId": "#splice-amulet:Splice.Amulet:Amulet" }
                                }
                            }
                        }]
                    }
                }
            },
            "verbose": true,
            "activeAtOffset": offset
        });

        let response = self
            .ledger_post("/state/active-contracts", &body)
            .await;

        match response {
            Ok(data) => {
                // Canton 3.5+ returns a bare top-level array; older drafts
                // wrapped in `{contractEntries:...}` or `{results:...}`.
                let contracts = if data.is_array() {
                    data.as_array().cloned().unwrap_or_default()
                } else {
                    data.get("contractEntries")
                        .or_else(|| data.get("results"))
                        .and_then(|v| v.as_array())
                        .cloned()
                        .unwrap_or_default()
                };

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
        Parameters(params): Parameters<CantonTransferParams>,
    ) -> std::result::Result<Json<RpcPassthroughOutput>, ErrorData> {
        let command_id = format!("tenzro-mcp-transfer-{}", uuid::Uuid::new_v4());

        // Create a transfer command using the Splice.Amulet transfer
        // template. Canton 3.5+ requires the JsCommands payload nested
        // under a top-level `commands` key and the individual command to
        // be externally tagged (`CreateCommand`).
        let body = serde_json::json!({
            "commands": {
                "commandId": command_id,
                "userId": params.user_id,
                "actAs": [params.from_party],
                "readAs": [],
                "commands": [{
                    "CreateCommand": {
                        "templateId": "Splice.AmuletRules:Transfer",
                        "createArguments": {
                            "sender": params.from_party,
                            "receiver": params.to_party,
                            "amount": params.amount,
                        }
                    }
                }],
            }
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
        Parameters(params): Parameters<CantonCreateAssetParams>,
    ) -> std::result::Result<Json<RpcPassthroughOutput>, ErrorData> {
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

        // Canton 3.5+ requires the JsCommands payload nested under a
        // top-level `commands` key with externally-tagged commands.
        let body = serde_json::json!({
            "commands": {
                "commandId": command_id,
                "userId": params.user_id,
                "actAs": [params.issuer],
                "readAs": [],
                "commands": [{
                    "CreateCommand": {
                        "templateId": template_id,
                        "createArguments": create_arguments,
                    }
                }],
            }
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
        Parameters(params): Parameters<CantonDvpSettleParams>,
    ) -> std::result::Result<Json<RpcPassthroughOutput>, ErrorData> {
        let command_id = format!("tenzro-mcp-dvp-{}", uuid::Uuid::new_v4());

        // Exercise the DvP Settle choice on the asset contract.
        // The DvP template atomically archives the asset leg and creates
        // new contracts with swapped ownership, while the payment leg
        // is settled simultaneously. Canton 3.5+ requires the JsCommands
        // payload nested under a top-level `commands` key with
        // externally-tagged commands.
        let body = serde_json::json!({
            "commands": {
                "commandId": command_id,
                "userId": params.user_id,
                "actAs": [params.buyer, params.seller],
                "readAs": [],
                "commands": [{
                    "ExerciseCommand": {
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
            }
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
        Parameters(params): Parameters<CantonUploadDarParams>,
    ) -> std::result::Result<Json<RpcPassthroughOutput>, ErrorData> {
        use base64::Engine;

        let dar_bytes = base64::engine::general_purpose::STANDARD
            .decode(&params.dar_content_base64)
            .map_err(|e| {
                err_invalid_params(format!("Invalid base64 DAR content: {}", e))
            })?;

        let dar_size = dar_bytes.len();

        let _filename = params
            .filename
            .unwrap_or_else(|| "package.dar".to_string());

        // Canton 3.5+ JSON Ledger API: POST /v2/packages with raw DAR
        // bytes and `Content-Type: application/octet-stream`. The
        // legacy `/admin/packages/upload-dar` path is only on the gRPC
        // Admin API, which the Tenzro-operated devnet
        // (`json.canton.example-operator.invalid`) does not expose.
        let url = format!("{}/v2/packages", self.ledger_api_url);
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
            "filename": _filename,
            "size_bytes": dar_size,
            "response": response,
        }))
    }

    #[tool(description = "Reconnect a Canton participant to a synchronizer domain. Submits POST /admin/participant/synchronizer/{alias}/reconnect via the Canton Admin API. Used after a synchronizer outage or planned disconnection. Returns a plain-text confirmation on success.")]
    async fn canton_reconnect_synchronizer(
        &self,
        Parameters(params): Parameters<CantonReconnectSynchronizerParams>,
    ) -> std::result::Result<Json<RpcPassthroughOutput>, ErrorData> {
        let endpoint = format!(
            "/admin/participant/synchronizer/{}/reconnect",
            params.synchronizer_alias
        );
        let body = serde_json::json!({
            "retry_on_failure": params.retry_on_failure,
        });

        match self.admin_post(&endpoint, &body).await {
            Ok(_) => text_result(format!(
                "Canton participant reconnected to synchronizer '{}' (retry_on_failure={})",
                params.synchronizer_alias, params.retry_on_failure
            )),
            Err(e) => Err(e),
        }
    }

    #[tool(description = "Get the fee schedule for a Canton synchronizer domain. Queries the Admin API at /admin/synchronizer/{id}/fee-schedule. Returns base fee, per-byte fee, and other fee parameters.")]
    async fn canton_get_fee_schedule(
        &self,
        Parameters(params): Parameters<CantonGetFeeScheduleParams>,
    ) -> std::result::Result<Json<RpcPassthroughOutput>, ErrorData> {
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

    #[tool(description = "Watch active DAML contracts for a specific party. Queries `POST /v2/state/active-contracts` with the party as the sole `filtersByParty` key. The MCP server is operator-scoped, so any party reachable from the operator's participant credential is accessible.")]
    async fn canton_watch_party(
        &self,
        Parameters(params): Parameters<CantonWatchPartyParams>,
    ) -> std::result::Result<Json<RpcPassthroughOutput>, ErrorData> {
        if params.template_ids.is_empty() {
            return Err(err_invalid_params(
                "template_ids required (at least one DAML template id)",
            ));
        }
        let offset = self.fetch_ledger_end_offset().await?;
        let mut filters_by_party = serde_json::Map::new();
        let cumulative: Vec<serde_json::Value> = params
            .template_ids
            .iter()
            .map(|tid| {
                serde_json::json!({
                    "identifierFilter": {
                        "TemplateFilter": {
                            "value": { "templateId": tid }
                        }
                    }
                })
            })
            .collect();
        filters_by_party.insert(
            params.party.clone(),
            serde_json::json!({ "cumulative": cumulative }),
        );
        let body = serde_json::json!({
            "eventFormat": {
                "filtersByParty": filters_by_party,
                "filtersForAnyParty": serde_json::Value::Null,
                "verbose": true,
            },
            "activeAtOffset": offset,
        });
        let response = self.ledger_post("/state/active-contracts", &body).await?;
        json_result(response)
    }

    #[tool(description = "Operator-only: register a per-tenant Canton IdentityProviderConfig (Stage 2.b). Submits POST /v2/idps with the tenant's OAuth issuer / JWKS / audience. Subsequent user provisioning under this IDP is scoped to it, so the tenant's JWTs are isolated from the operator's IDP.")]
    async fn canton_create_idp(
        &self,
        Parameters(params): Parameters<CantonCreateIdpParams>,
    ) -> std::result::Result<Json<RpcPassthroughOutput>, ErrorData> {
        let body = serde_json::json!({
            "identityProviderConfig": {
                "identityProviderId": params.identity_provider_id,
                "isDeactivated": false,
                "issuer": params.issuer_url,
                "jwksUrl": params.jwks_url,
                "audience": params.audience,
            }
        });
        let response = self.ledger_post("/idps", &body).await?;
        json_result(response)
    }

    #[tool(description = "Operator-only: list every Canton IdentityProviderConfig the participant is configured against (Stage 2.b roster). Returns the full IDP roster including the default IDP entry.")]
    async fn canton_list_idps(
        &self,
    ) -> std::result::Result<Json<RpcPassthroughOutput>, ErrorData> {
        let response = self.ledger_get("/idps").await?;
        json_result(response)
    }

    #[tool(description = "Operator-only: delete a Canton IdentityProviderConfig. Canton refuses to delete an IDP that has live users — revoke or migrate the tenants under that IDP first.")]
    async fn canton_delete_idp(
        &self,
        Parameters(params): Parameters<CantonDeleteIdpParams>,
    ) -> std::result::Result<Json<RpcPassthroughOutput>, ErrorData> {
        let path = format!("/idps/{}", urlencoding::encode(&params.identity_provider_id));
        let response = self.ledger_delete(&path).await?;
        json_result(response)
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
             - canton_list_parties — List known parties on the participant\n\
             - canton_grant_user_rights — Grant CanActAs / CanReadAs on a party to a user (CIP-26)\n\
             - canton_list_user_rights — List rights granted to a Canton user\n\n\
             Per-Tenant Analytics:\n\
             - canton_get_my_analytics — Subject self-read of per-tenant call counters\n\
             - canton_list_api_key_analytics — Operator admin-read of every tenant's counters\n\n\
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

/// Axum middleware that gates every request on a scope-`canton` API key
/// presented as the `X-Tenzro-Api-Key` header.
///
/// The Canton MCP server runs as its own subdomain (`canton-mcp.tenzro.xyz`)
/// and dispatches tool calls directly to the upstream Canton JSON Ledger and
/// Admin APIs using the operator's bearer JWT. Without this gate, anyone able
/// to reach the endpoint would get full operator-authority access to the
/// shared Canton validator party.
///
/// This is the MCP-layer twin of the JSON-RPC gate enforced by
/// `gate_api_key` in `rpc.rs` — both consult the same `ApiKeyManager`
/// and require [`ApiKeyScope::Canton`].
///
/// When the manager is absent (no API keys configured on the node), the
/// middleware fails closed: every request returns 401.
async fn require_canton_api_key(
    State(mgr): State<Option<Arc<ApiKeyManager>>>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let presented = request
        .headers()
        .get("x-tenzro-api-key")
        .and_then(|v| v.to_str().ok());

    let outcome = match mgr.as_ref() {
        Some(m) => m.authorize(presented, "tenzro_listCantonDomains"),
        None => AuthorizeOutcome::MissingKey(ApiKeyScope::Canton),
    };

    match outcome {
        AuthorizeOutcome::Allowed => next.run(request).await,
        AuthorizeOutcome::MissingKey(scope) => (
            StatusCode::UNAUTHORIZED,
            format!(
                "Unauthorized: missing X-Tenzro-Api-Key header (required scope: {})",
                scope.as_str()
            ),
        )
            .into_response(),
        AuthorizeOutcome::UnknownOrRevoked => (
            StatusCode::UNAUTHORIZED,
            "Unauthorized: API key is unknown or revoked".to_string(),
        )
            .into_response(),
        AuthorizeOutcome::InsufficientScope(scope) => (
            StatusCode::FORBIDDEN,
            format!(
                "Forbidden: API key lacks required scope ({})",
                scope.as_str()
            ),
        )
            .into_response(),
    }
}

/// Start the Canton MCP server on the given address using Streamable HTTP transport.
///
/// `ledger_api_url` / `admin_api_url` configure the Canton participant endpoints
/// the tools talk to (typically derived from the node's `CantonConfig`).
/// `jwt_token` is the optional bearer token for authenticated participants.
/// `token_provider` is the optional OAuth2 client-credentials provider used
/// by the Tenzro-operated devnet — when set, it takes precedence over
/// `jwt_token`.
///
/// `api_key_manager` enforces caller authorization at the HTTP layer: every
/// request must present a valid `X-Tenzro-Api-Key` with scope
/// [`ApiKeyScope::Canton`]. When `None`, the server fails closed and refuses
/// every request — consistent with the JSON-RPC gate, which would refuse
/// `tenzro_*Canton*` methods on the same input.
pub async fn start_canton_mcp_server(
    listen_addr: String,
    ledger_api_url: String,
    admin_api_url: String,
    jwt_token: Option<String>,
    token_provider: Option<Arc<CantonTokenProvider>>,
    api_key_manager: Option<Arc<ApiKeyManager>>,
    canton_analytics: Option<Arc<crate::canton_analytics::CantonAnalyticsManager>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (_keep_tx, shutdown_rx) = tokio::sync::broadcast::channel::<()>(1);
    start_canton_mcp_server_with_shutdown(
        listen_addr,
        ledger_api_url,
        admin_api_url,
        jwt_token,
        token_provider,
        api_key_manager,
        canton_analytics,
        shutdown_rx,
    )
    .await
}

/// Start the Canton MCP server with a graceful-shutdown channel. When the
/// broadcast sender fires, axum stops accepting new connections and lets
/// in-flight requests drain before the future resolves.
#[allow(clippy::too_many_arguments)]
pub async fn start_canton_mcp_server_with_shutdown(
    listen_addr: String,
    ledger_api_url: String,
    admin_api_url: String,
    jwt_token: Option<String>,
    token_provider: Option<Arc<CantonTokenProvider>>,
    api_key_manager: Option<Arc<ApiKeyManager>>,
    canton_analytics: Option<Arc<crate::canton_analytics::CantonAnalyticsManager>>,
    mut shutdown_rx: tokio::sync::broadcast::Receiver<()>,
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
            "canton-mcp.tenzro.xyz".to_string(),
        ]);

    // Capture Canton endpoints into the per-session factory. The closure is
    // invoked once per inbound MCP session and must return a fresh
    // `CantonMcpServer`, so we clone the configured URLs/JWT into each
    // instance via the `with_*` builders rather than relying on the
    // hard-coded `new()` defaults.
    let factory_api_key_manager = api_key_manager.clone();
    let service = StreamableHttpService::new(
        move || {
            let mut server = CantonMcpServer::new()
                .with_ledger_api_url(ledger_api_url.clone())
                .with_admin_api_url(admin_api_url.clone());
            if let Some(token) = jwt_token.clone() {
                server = server.with_jwt_token(token);
            }
            if let Some(provider) = token_provider.clone() {
                server = server.with_token_provider(provider);
            }
            server = server.with_node_state(
                canton_analytics.clone(),
                factory_api_key_manager.clone(),
            );
            Ok(server)
        },
        Arc::new(LocalSessionManager::default()),
        config,
    );

    // Canton MCP is a server-to-server surface. The X-Tenzro-Api-Key gate
    // already requires a Tenzro-issued credential, but a browser running on
    // a third-party origin could still issue a credentialed fetch if a key
    // leaked. We add an explicit default-deny CORS layer so browser
    // preflights are rejected outright: no `Origin` allow-list, no
    // credentials, no methods, no headers. Server-side callers (CLI, SDKs,
    // MCP clients) don't send `Origin` and are unaffected.
    let cors = tower_http::cors::CorsLayer::new();

    let app = axum::Router::new()
        .nest_service("/mcp", service)
        .layer(axum::middleware::from_fn_with_state(
            api_key_manager.clone(),
            require_canton_api_key,
        ))
        .layer(cors)
        .layer(tower::limit::ConcurrencyLimitLayer::new(100))
        .layer(tower_http::limit::RequestBodyLimitLayer::new(2 * 1024 * 1024));

    let listener = tokio::net::TcpListener::bind(&listen_addr).await?;
    tracing::info!(
        addr = %listen_addr,
        tools = 18,
        mode = "stateless-json",
        auth_gated = api_key_manager.is_some(),
        "Canton MCP Server listening (endpoint: /mcp, X-Tenzro-Api-Key scope=canton required)"
    );

    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            let _ = shutdown_rx.recv().await;
            tracing::info!("Canton MCP server shutting down gracefully");
        })
        .await?;

    Ok(())
}
