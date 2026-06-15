//! Canton/DAML integration commands for the Tenzro CLI
//!
//! Interact with the shared Canton synchronizer domain and DAML contracts
//! through the local Tenzro node. The node proxies calls to its configured
//! Canton participant; callers never see the Auth0 secret.

use clap::{Parser, Subcommand};
use anyhow::{anyhow, Result};
use crate::output;

/// Canton/DAML integration commands (Canton 3.5+ JSON Ledger API).
///
/// All reads + writes route through the local Tenzro node, which proxies
/// to its configured Canton participant. Callers never see the Auth0
/// secret. Every method requires an API key with scope `canton`
/// (passed via `--api-key` or `TENZRO_API_KEY` env var).
#[derive(Debug, Subcommand)]
pub enum CantonCommand {
    /// List configured Canton synchronizer domains
    Domains(CantonDomainsCmd),
    /// Query active DAML contracts (requires at least one template id)
    Contracts(CantonContractsCmd),
    /// Submit a DAML create or exercise command
    Submit(CantonSubmitCmd),
    // ── Canton 3.5+ JSON Ledger API extension surface ──
    /// Combined health probe (`/livez` + `/readyz` + `/v2/version`)
    Health(CantonSimpleCmd),
    /// Participant version + CIP feature flags (`GET /v2/version`)
    Version(CantonSimpleCmd),
    /// OAuth principal's Canton user record (`GET /v2/users/<client_id>@clients`, CIP-26)
    MyUser(CantonSimpleCmd),
    /// List every party known to the participant (`GET /v2/parties/known`)
    Parties(CantonSimpleCmd),
    /// List every DAML package installed on the participant (`GET /v2/packages`)
    Packages(CantonSimpleCmd),
    /// CIP-56 Canton Coin balance (sums every `Splice.Amulet:Amulet` contract)
    CoinBalance(CantonSimpleCmd),
    /// Canton fee schedule from the latest `Splice.AmuletRules:AmuletRules` contract
    FeeSchedule(CantonSimpleCmd),
    /// Connected synchronizers for the participant's party
    ConnectedSynchronizers(CantonSimpleCmd),
    /// Fetch a Canton transaction tree by hex update id
    GetTransaction(CantonGetTransactionCmd),
    /// Upload a DAR (DAML Archive) to the participant via `POST /v2/packages`
    UploadDar(CantonUploadDarCmd),
    /// Allocate a new party on the participant via `POST /v2/parties`
    AllocateParty(CantonAllocatePartyCmd),
    /// Grant `CanActAs` / `CanReadAs` rights on a party to a user (CIP-26)
    GrantRights(CantonGrantRightsCmd),
    /// List rights granted to a Canton user (`GET /v2/users/{userId}/rights`)
    ListRights(CantonListRightsCmd),
    /// Self-read per-tenant Canton call analytics for the presented API key
    MyAnalytics(CantonSimpleCmd),
    /// Operator admin-read: every per-tenant analytics record
    ListAnalytics(CantonListAnalyticsCmd),
    /// Watch active contracts for an explicit party (key must be authorized for it)
    WatchParty(CantonWatchPartyCmd),
    /// Operator-only: register a per-tenant Canton IdentityProviderConfig (Stage 2.b)
    IdpCreate(CantonIdpCreateCmd),
    /// Operator-only: list every Canton IdentityProviderConfig
    IdpList(CantonSimpleCmd),
    /// Operator-only: delete a Canton IdentityProviderConfig
    IdpDelete(CantonIdpDeleteCmd),
    /// Operator-only: mirror a Tenzro workflow into a Canton synchronizer as a WorkflowAnchor
    MirrorWorkflow(CantonMirrorWorkflowCmd),
    /// Operator-only: mirror an Obligation under an already-mirrored workflow
    MirrorObligation(CantonMirrorObligationCmd),
}

impl CantonCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Domains(cmd) => cmd.execute().await,
            Self::Contracts(cmd) => cmd.execute().await,
            Self::Submit(cmd) => cmd.execute().await,
            Self::Health(cmd) => cmd.execute("Canton Health", "tenzro_canton_health").await,
            Self::Version(cmd) => cmd.execute("Canton Version", "tenzro_canton_version").await,
            Self::MyUser(cmd) => cmd.execute("Canton My User", "tenzro_canton_getMyUser").await,
            Self::Parties(cmd) => cmd.execute("Canton Parties", "tenzro_canton_listParties").await,
            Self::Packages(cmd) => cmd.execute("Canton Packages", "tenzro_canton_listPackages").await,
            Self::CoinBalance(cmd) => {
                cmd.execute("Canton Coin Balance", "tenzro_canton_coinBalance").await
            }
            Self::FeeSchedule(cmd) => {
                cmd.execute("Canton Fee Schedule", "tenzro_canton_feeSchedule").await
            }
            Self::ConnectedSynchronizers(cmd) => {
                cmd.execute(
                    "Canton Connected Synchronizers",
                    "tenzro_canton_connectedSynchronizers",
                )
                .await
            }
            Self::GetTransaction(cmd) => cmd.execute().await,
            Self::UploadDar(cmd) => cmd.execute().await,
            Self::AllocateParty(cmd) => cmd.execute().await,
            Self::GrantRights(cmd) => cmd.execute().await,
            Self::ListRights(cmd) => cmd.execute().await,
            Self::MyAnalytics(cmd) => {
                cmd.execute("Canton My Analytics", "tenzro_canton_getMyAnalytics")
                    .await
            }
            Self::ListAnalytics(cmd) => cmd.execute().await,
            Self::WatchParty(cmd) => cmd.execute().await,
            Self::IdpCreate(cmd) => cmd.execute().await,
            Self::IdpList(cmd) => cmd.execute("Canton IDPs", "tenzro_canton_listIdps").await,
            Self::IdpDelete(cmd) => cmd.execute().await,
            Self::MirrorWorkflow(cmd) => cmd.execute().await,
            Self::MirrorObligation(cmd) => cmd.execute().await,
        }
    }
}

/// List Canton domains
#[derive(Debug, Parser)]
pub struct CantonDomainsCmd {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,

    /// Operator-issued Tenzro API key (tnz_...) with scope `canton`.
    /// Falls back to the TENZRO_API_KEY env var when omitted.
    #[arg(long, env = "TENZRO_API_KEY", hide_env_values = true)]
    api_key: Option<String>,
}

impl CantonDomainsCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Canton Domains");

        let spinner = output::create_spinner("Loading domains...");

        let mut rpc = RpcClient::new(&self.rpc);
        if let Some(key) = &self.api_key {
            rpc = rpc.with_api_key(key);
        }

        let result: serde_json::Value = rpc
            .call("tenzro_listCantonDomains", serde_json::json!({}))
            .await?;

        spinner.finish_and_clear();

        let enabled = result.get("enabled").and_then(|v| v.as_bool()).unwrap_or(false);
        output::print_field("Canton Enabled", if enabled { "Yes" } else { "No" });

        if !enabled {
            if let Some(msg) = result.get("message").and_then(|v| v.as_str()) {
                output::print_info(msg);
            }
            return Ok(());
        }

        if let Some(domains) = result.get("domains").and_then(|v| v.as_array()) {
            if domains.is_empty() {
                output::print_info("No Canton domains configured.");
            } else {
                let headers = vec!["ID", "Name", "Native Token", "Finality (s)"];
                let mut rows = Vec::new();
                for domain in domains {
                    rows.push(vec![
                        domain.get("id").and_then(|v| v.as_str()).unwrap_or("unknown").to_string(),
                        domain.get("name").and_then(|v| v.as_str()).unwrap_or("unknown").to_string(),
                        domain.get("native_token").and_then(|v| v.as_str()).unwrap_or("-").to_string(),
                        domain
                            .get("finality_time_secs")
                            .and_then(|v| v.as_u64())
                            .map(|n| n.to_string())
                            .unwrap_or_else(|| "-".to_string()),
                    ]);
                }
                output::print_table(&headers, &rows);
            }
        }

        Ok(())
    }
}

/// Query active DAML contracts
#[derive(Debug, Parser)]
pub struct CantonContractsCmd {
    /// Template ID to query (repeat to include multiple). At least one
    /// template id is required by the Canton v2 active-contracts endpoint.
    #[arg(long = "template", required = true)]
    templates: Vec<String>,

    /// Optional JSON object applied as a structural filter against
    /// `createArguments`. Example: '{"owner":"alice"}'
    #[arg(long)]
    query: Option<String>,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,

    /// Operator-issued Tenzro API key (tnz_...) with scope `canton`.
    /// Falls back to the TENZRO_API_KEY env var when omitted.
    #[arg(long, env = "TENZRO_API_KEY", hide_env_values = true)]
    api_key: Option<String>,
}

impl CantonContractsCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("DAML Contracts");

        let spinner = output::create_spinner("Loading contracts...");

        let mut rpc = RpcClient::new(&self.rpc);
        if let Some(key) = &self.api_key {
            rpc = rpc.with_api_key(key);
        }

        let mut params = serde_json::Map::new();
        params.insert(
            "template_ids".to_string(),
            serde_json::Value::Array(
                self.templates
                    .iter()
                    .map(|t| serde_json::Value::String(t.clone()))
                    .collect(),
            ),
        );
        if let Some(q) = &self.query {
            let parsed: serde_json::Value = serde_json::from_str(q)
                .map_err(|e| anyhow!("--query is not valid JSON: {}", e))?;
            params.insert("query".to_string(), parsed);
        }

        let result: serde_json::Value = rpc
            .call(
                "tenzro_listDamlContracts",
                serde_json::Value::Object(params),
            )
            .await?;

        spinner.finish_and_clear();

        if let Some(contracts) = result.get("contracts").and_then(|v| v.as_array()) {
            if contracts.is_empty() {
                output::print_info("No DAML contracts found.");
            } else {
                let headers = vec!["Contract ID", "Template", "Payload"];
                let mut rows = Vec::new();
                for contract in contracts {
                    let payload_str = match contract.get("payload") {
                        Some(p) => serde_json::to_string(p).unwrap_or_else(|_| "?".to_string()),
                        None => String::new(),
                    };
                    rows.push(vec![
                        contract
                            .get("contract_id")
                            .and_then(|v| v.as_str())
                            .unwrap_or("unknown")
                            .to_string(),
                        contract
                            .get("template_id")
                            .and_then(|v| v.as_str())
                            .unwrap_or("unknown")
                            .to_string(),
                        payload_str,
                    ]);
                }
                output::print_table(&headers, &rows);
                println!("Total: {} contracts", contracts.len());
            }
        }

        Ok(())
    }
}

/// Submit a DAML command
#[derive(Debug, Parser)]
pub struct CantonSubmitCmd {
    /// Command type: `create` or `exercise`
    #[arg(long)]
    command_type: String,

    /// DAML template ID (required for both create and exercise)
    #[arg(long)]
    template: String,

    /// JSON object holding the create arguments (required when
    /// `--command-type create`).
    #[arg(long)]
    create_arguments: Option<String>,

    /// Existing contract id (required when `--command-type exercise`).
    #[arg(long)]
    contract_id: Option<String>,

    /// Choice name (required when `--command-type exercise`).
    #[arg(long)]
    choice: Option<String>,

    /// JSON object holding the choice argument (required when
    /// `--command-type exercise`).
    #[arg(long)]
    choice_argument: Option<String>,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,

    /// Operator-issued Tenzro API key (tnz_...) with scope `canton`.
    /// Falls back to the TENZRO_API_KEY env var when omitted.
    #[arg(long, env = "TENZRO_API_KEY", hide_env_values = true)]
    api_key: Option<String>,
}

impl CantonSubmitCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Submit DAML Command");

        let spinner = output::create_spinner("Submitting command...");

        let mut rpc = RpcClient::new(&self.rpc);
        if let Some(key) = &self.api_key {
            rpc = rpc.with_api_key(key);
        }

        let params = match self.command_type.as_str() {
            "create" => {
                let raw = self
                    .create_arguments
                    .as_deref()
                    .ok_or_else(|| anyhow!("--create-arguments is required for create commands"))?;
                let create_arguments: serde_json::Value = serde_json::from_str(raw)
                    .map_err(|e| anyhow!("--create-arguments is not valid JSON: {}", e))?;
                serde_json::json!({
                    "command_type": "create",
                    "template_id": self.template,
                    "create_arguments": create_arguments,
                })
            }
            "exercise" => {
                let contract_id = self
                    .contract_id
                    .as_deref()
                    .ok_or_else(|| anyhow!("--contract-id is required for exercise commands"))?;
                let choice = self
                    .choice
                    .as_deref()
                    .ok_or_else(|| anyhow!("--choice is required for exercise commands"))?;
                let raw = self
                    .choice_argument
                    .as_deref()
                    .ok_or_else(|| anyhow!("--choice-argument is required for exercise commands"))?;
                let choice_argument: serde_json::Value = serde_json::from_str(raw)
                    .map_err(|e| anyhow!("--choice-argument is not valid JSON: {}", e))?;
                serde_json::json!({
                    "command_type": "exercise",
                    "template_id": self.template,
                    "contract_id": contract_id,
                    "choice": choice,
                    "choice_argument": choice_argument,
                })
            }
            other => {
                return Err(anyhow!(
                    "Unsupported command type '{}' (supported: create, exercise)",
                    other
                ))
            }
        };

        let result: serde_json::Value = rpc
            .call("tenzro_submitDamlCommand", params)
            .await?;

        spinner.finish_and_clear();

        output::print_success("DAML command submitted.");
        println!();

        output::print_field("Command Type", &self.command_type);
        output::print_field("Template ID", &self.template);

        if let Some(cid) = result.get("contract_id").and_then(|v| v.as_str()) {
            output::print_field("Contract ID", cid);
        }
        if let Some(choice) = result.get("choice").and_then(|v| v.as_str()) {
            output::print_field("Choice", choice);
        }
        if let Some(payload) = result.get("payload") {
            if !payload.is_null() {
                output::print_field(
                    "Payload",
                    &serde_json::to_string_pretty(payload).unwrap_or_default(),
                );
            }
        }
        if let Some(er) = result.get("exercise_result") {
            if !er.is_null() {
                output::print_field(
                    "Exercise Result",
                    &serde_json::to_string_pretty(er).unwrap_or_default(),
                );
            }
        }

        Ok(())
    }
}

// ── Canton 3.5+ extension subcommands ──

/// Shared shape for parameter-less Canton 3.5+ JSON Ledger API reads.
#[derive(Debug, Parser)]
pub struct CantonSimpleCmd {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,

    /// Operator-issued Tenzro API key (tnz_...) with scope `canton`.
    /// Falls back to the TENZRO_API_KEY env var when omitted.
    #[arg(long, env = "TENZRO_API_KEY", hide_env_values = true)]
    api_key: Option<String>,
}

impl CantonSimpleCmd {
    pub async fn execute(&self, header: &str, method: &str) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header(header);

        let mut rpc = RpcClient::new(&self.rpc);
        if let Some(key) = &self.api_key {
            rpc = rpc.with_api_key(key);
        }
        let spinner = output::create_spinner("Querying Canton…");

        let result: serde_json::Value = rpc.call(method, serde_json::json!({})).await?;
        spinner.finish_and_clear();

        println!(
            "{}",
            serde_json::to_string_pretty(&result).unwrap_or_else(|_| "?".into())
        );
        Ok(())
    }
}

/// Fetch a Canton transaction tree by hex update id
#[derive(Debug, Parser)]
pub struct CantonGetTransactionCmd {
    /// Hex update id (Canton 3.5+ rejects bare labels)
    #[arg(long)]
    update_id: String,

    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,

    #[arg(long, env = "TENZRO_API_KEY", hide_env_values = true)]
    api_key: Option<String>,
}

impl CantonGetTransactionCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Canton Get Transaction");

        let mut rpc = RpcClient::new(&self.rpc);
        if let Some(key) = &self.api_key {
            rpc = rpc.with_api_key(key);
        }
        let params = serde_json::json!({ "update_id": self.update_id });
        let spinner = output::create_spinner("Fetching transaction…");

        let result: serde_json::Value =
            rpc.call("tenzro_canton_getTransaction", params).await?;
        spinner.finish_and_clear();

        println!(
            "{}",
            serde_json::to_string_pretty(&result).unwrap_or_else(|_| "?".into())
        );
        Ok(())
    }
}

/// Upload a DAR (DAML Archive) to the participant
#[derive(Debug, Parser)]
pub struct CantonUploadDarCmd {
    /// Path to the .dar file on disk
    #[arg(long)]
    file: std::path::PathBuf,

    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,

    #[arg(long, env = "TENZRO_API_KEY", hide_env_values = true)]
    api_key: Option<String>,
}

impl CantonUploadDarCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        use base64::{engine::general_purpose::STANDARD as B64, Engine as _};

        output::print_header("Canton Upload DAR");

        let dar_bytes = std::fs::read(&self.file)
            .map_err(|e| anyhow!("failed to read DAR file {}: {}", self.file.display(), e))?;
        let size = dar_bytes.len();
        let b64 = B64.encode(&dar_bytes);

        output::print_field("File", &self.file.display().to_string());
        output::print_field("Size (bytes)", &size.to_string());

        let mut rpc = RpcClient::new(&self.rpc);
        if let Some(key) = &self.api_key {
            rpc = rpc.with_api_key(key);
        }
        let params = serde_json::json!({ "dar_content_base64": b64 });
        let spinner = output::create_spinner("Uploading DAR…");

        let result: serde_json::Value =
            rpc.call("tenzro_canton_uploadDar", params).await?;
        spinner.finish_and_clear();

        output::print_success("DAR uploaded.");
        println!();
        println!(
            "{}",
            serde_json::to_string_pretty(&result).unwrap_or_else(|_| "?".into())
        );
        Ok(())
    }
}

/// Allocate a new party on the participant
#[derive(Debug, Parser)]
pub struct CantonAllocatePartyCmd {
    /// Human-readable party id hint (e.g. "alice-test"). The participant
    /// appends `::<participant-hash>` to produce the fully-qualified id.
    #[arg(long = "hint")]
    party_id_hint: String,

    /// Optional display name metadata
    #[arg(long)]
    display_name: Option<String>,

    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,

    #[arg(long, env = "TENZRO_API_KEY", hide_env_values = true)]
    api_key: Option<String>,
}

impl CantonAllocatePartyCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Canton Allocate Party");
        output::print_field("Party ID Hint", &self.party_id_hint);

        let mut rpc = RpcClient::new(&self.rpc);
        if let Some(key) = &self.api_key {
            rpc = rpc.with_api_key(key);
        }

        let mut params = serde_json::Map::new();
        params.insert(
            "party_id_hint".into(),
            serde_json::Value::String(self.party_id_hint.clone()),
        );
        if let Some(name) = &self.display_name {
            params.insert(
                "display_name".into(),
                serde_json::Value::String(name.clone()),
            );
        }

        let spinner = output::create_spinner("Allocating party…");
        let result: serde_json::Value = rpc
            .call("tenzro_allocateParty", serde_json::Value::Object(params))
            .await?;
        spinner.finish_and_clear();

        output::print_success("Party allocated.");
        println!();
        println!(
            "{}",
            serde_json::to_string_pretty(&result).unwrap_or_else(|_| "?".into())
        );
        Ok(())
    }
}

/// Grant Canton rights on a party to a user
#[derive(Debug, Parser)]
pub struct CantonGrantRightsCmd {
    /// Fully-qualified party id (`<hint>::<participant-hash>`)
    #[arg(long)]
    party: String,

    /// User id (omit to grant to the OAuth principal's own user
    /// `<client_id>@clients`)
    #[arg(long)]
    user_id: Option<String>,

    /// Grant `CanActAs` (default: true)
    #[arg(long, default_value = "true")]
    can_act_as: bool,

    /// Grant `CanReadAs` (default: false)
    #[arg(long, default_value = "false")]
    can_read_as: bool,

    /// Canton IdentityProviderConfig id the user lives under (required
    /// for IDP-scoped users; omit for the participant's default IDP)
    #[arg(long)]
    identity_provider_id: Option<String>,

    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,

    #[arg(long, env = "TENZRO_API_KEY", hide_env_values = true)]
    api_key: Option<String>,
}

impl CantonGrantRightsCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        if !self.can_act_as && !self.can_read_as {
            return Err(anyhow!(
                "At least one of --can-act-as or --can-read-as must be true"
            ));
        }

        output::print_header("Canton Grant User Rights");
        output::print_field("Party", &self.party);
        output::print_field("Can Act As", &self.can_act_as.to_string());
        output::print_field("Can Read As", &self.can_read_as.to_string());

        let mut rpc = RpcClient::new(&self.rpc);
        if let Some(key) = &self.api_key {
            rpc = rpc.with_api_key(key);
        }

        let mut params = serde_json::Map::new();
        if let Some(uid) = &self.user_id {
            params.insert("user_id".into(), serde_json::Value::String(uid.clone()));
        }
        params.insert("party".into(), serde_json::Value::String(self.party.clone()));
        params.insert("can_act_as".into(), serde_json::Value::Bool(self.can_act_as));
        params.insert("can_read_as".into(), serde_json::Value::Bool(self.can_read_as));
        if let Some(idp) = &self.identity_provider_id {
            params.insert(
                "identity_provider_id".into(),
                serde_json::Value::String(idp.clone()),
            );
        }

        let spinner = output::create_spinner("Granting rights…");
        let result: serde_json::Value = rpc
            .call(
                "tenzro_canton_grantUserRights",
                serde_json::Value::Object(params),
            )
            .await?;
        spinner.finish_and_clear();

        output::print_success("Rights granted.");
        println!();
        println!(
            "{}",
            serde_json::to_string_pretty(&result).unwrap_or_else(|_| "?".into())
        );
        Ok(())
    }
}

/// List rights granted to a Canton user
#[derive(Debug, Parser)]
pub struct CantonListRightsCmd {
    /// User id (omit to list rights for the OAuth principal's own user)
    #[arg(long)]
    user_id: Option<String>,

    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,

    #[arg(long, env = "TENZRO_API_KEY", hide_env_values = true)]
    api_key: Option<String>,
}

impl CantonListRightsCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Canton List User Rights");

        let mut rpc = RpcClient::new(&self.rpc);
        if let Some(key) = &self.api_key {
            rpc = rpc.with_api_key(key);
        }

        let params = match &self.user_id {
            Some(uid) => serde_json::json!({ "user_id": uid }),
            None => serde_json::json!({}),
        };

        let spinner = output::create_spinner("Listing rights…");
        let result: serde_json::Value =
            rpc.call("tenzro_canton_listUserRights", params).await?;
        spinner.finish_and_clear();

        println!(
            "{}",
            serde_json::to_string_pretty(&result).unwrap_or_else(|_| "?".into())
        );
        Ok(())
    }
}

/// Operator admin-read: every per-tenant Canton analytics record.
/// Gated by `X-Tenzro-Admin-Token`; the per-tenant `--api-key` is
/// not relevant here (the admin token reads across all tenants).
#[derive(Debug, Parser)]
pub struct CantonListAnalyticsCmd {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,

    /// Operator admin token (`X-Tenzro-Admin-Token`). Falls back to
    /// `TENZRO_ADMIN_TOKEN` env var.
    #[arg(long, env = "TENZRO_ADMIN_TOKEN", hide_env_values = true)]
    admin_token: Option<String>,

    /// Narrow the result to a single tenant by API-key handle
    /// (`key_id`, the 16-hex prefix of the SHA-256 of the key). Optional.
    #[arg(long)]
    key_id: Option<String>,
}

impl CantonListAnalyticsCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Canton API Key Analytics");

        let mut rpc = RpcClient::new(&self.rpc);
        if let Some(token) = &self.admin_token {
            rpc = rpc.with_admin_token(token);
        } else {
            return Err(anyhow!(
                "missing admin token (pass --admin-token or set TENZRO_ADMIN_TOKEN)"
            ));
        }

        let params = match &self.key_id {
            Some(k) => serde_json::json!({ "key_id": k }),
            None => serde_json::json!({}),
        };

        let spinner = output::create_spinner("Listing analytics…");
        let result: serde_json::Value =
            rpc.call("tenzro_canton_listApiKeyAnalytics", params).await?;
        spinner.finish_and_clear();

        println!(
            "{}",
            serde_json::to_string_pretty(&result).unwrap_or_else(|_| "?".into())
        );
        Ok(())
    }
}

/// Watch active contracts for an explicit party. The presenting key
/// must (a) carry a `canton_user_id` binding and (b) be authorized
/// for `party` (either the party matches the key's `primaryParty`
/// or is on `can_read_as_parties` / `can_act_as_parties`). Anything
/// else returns `-32004`.
#[derive(Debug, Parser)]
pub struct CantonWatchPartyCmd {
    /// Fully-qualified party id (`<hint>::<participant-hash>`) to watch
    #[arg(long)]
    party: String,

    /// Template ids to filter on (repeatable, at least one required)
    #[arg(long = "template-id", required = true)]
    template_ids: Vec<String>,

    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,

    #[arg(long, env = "TENZRO_API_KEY", hide_env_values = true)]
    api_key: Option<String>,
}

impl CantonWatchPartyCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Canton Watch Party");

        let mut rpc = RpcClient::new(&self.rpc);
        if let Some(key) = &self.api_key {
            rpc = rpc.with_api_key(key);
        }

        let params = serde_json::json!({
            "party": self.party,
            "template_ids": self.template_ids,
        });

        let spinner = output::create_spinner("Watching party…");
        let result: serde_json::Value =
            rpc.call("tenzro_canton_watchParty", params).await?;
        spinner.finish_and_clear();

        println!(
            "{}",
            serde_json::to_string_pretty(&result).unwrap_or_else(|_| "?".into())
        );
        Ok(())
    }
}

/// Operator-only: register a per-tenant Canton IdentityProviderConfig
/// (Stage 2.b). Admin-token-gated at the node.
#[derive(Debug, Parser)]
pub struct CantonIdpCreateCmd {
    /// IDP identifier (per Canton, unique per participant)
    #[arg(long)]
    identity_provider_id: String,

    /// OAuth issuer URL
    #[arg(long)]
    issuer_url: String,

    /// OAuth JWKS URL
    #[arg(long)]
    jwks_url: String,

    /// OAuth audience claim Canton expects on the tenant's JWT
    #[arg(long)]
    audience: String,

    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,

    #[arg(long, env = "TENZRO_ADMIN_TOKEN", hide_env_values = true)]
    admin_token: Option<String>,
}

impl CantonIdpCreateCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Canton Create IDP");

        let mut rpc = RpcClient::new(&self.rpc);
        if let Some(token) = &self.admin_token {
            rpc = rpc.with_admin_token(token);
        } else {
            return Err(anyhow!(
                "missing admin token (pass --admin-token or set TENZRO_ADMIN_TOKEN)"
            ));
        }

        let params = serde_json::json!({
            "identity_provider_id": self.identity_provider_id,
            "issuer_url": self.issuer_url,
            "jwks_url": self.jwks_url,
            "audience": self.audience,
        });

        let spinner = output::create_spinner("Creating IDP…");
        let result: serde_json::Value =
            rpc.call("tenzro_canton_createIdp", params).await?;
        spinner.finish_and_clear();

        println!(
            "{}",
            serde_json::to_string_pretty(&result).unwrap_or_else(|_| "?".into())
        );
        Ok(())
    }
}

/// Operator-only: delete a Canton IdentityProviderConfig. The tenant
/// whose IDP is being deleted must already be revoked or migrated —
/// Canton refuses to delete an IDP that has live users.
#[derive(Debug, Parser)]
pub struct CantonIdpDeleteCmd {
    /// IDP identifier to delete
    #[arg(long)]
    identity_provider_id: String,

    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,

    #[arg(long, env = "TENZRO_ADMIN_TOKEN", hide_env_values = true)]
    admin_token: Option<String>,
}

impl CantonIdpDeleteCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Canton Delete IDP");

        let mut rpc = RpcClient::new(&self.rpc);
        if let Some(token) = &self.admin_token {
            rpc = rpc.with_admin_token(token);
        } else {
            return Err(anyhow!(
                "missing admin token (pass --admin-token or set TENZRO_ADMIN_TOKEN)"
            ));
        }

        let params = serde_json::json!({
            "identity_provider_id": self.identity_provider_id,
        });

        let spinner = output::create_spinner("Deleting IDP…");
        let result: serde_json::Value =
            rpc.call("tenzro_canton_deleteIdp", params).await?;
        spinner.finish_and_clear();

        println!(
            "{}",
            serde_json::to_string_pretty(&result).unwrap_or_else(|_| "?".into())
        );
        Ok(())
    }
}

/// Operator-only: mirror a Tenzro workflow into a Canton synchronizer
/// as a `Tenzro.Workflow:WorkflowAnchor` contract. Contract owner is
/// the operator's participant-default party — admin-token-gated.
#[derive(Debug, Parser)]
pub struct CantonMirrorWorkflowCmd {
    /// Workflow id (32-byte hex, with or without 0x prefix)
    #[arg(long)]
    workflow_id: String,

    /// Synchronizer id to mirror the workflow into
    #[arg(long)]
    synchronizer_id: String,

    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,

    #[arg(long, env = "TENZRO_ADMIN_TOKEN", hide_env_values = true)]
    admin_token: Option<String>,
}

impl CantonMirrorWorkflowCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Canton Mirror Workflow");

        let mut rpc = RpcClient::new(&self.rpc);
        if let Some(token) = &self.admin_token {
            rpc = rpc.with_admin_token(token);
        } else {
            return Err(anyhow!(
                "missing admin token (pass --admin-token or set TENZRO_ADMIN_TOKEN)"
            ));
        }

        let params = serde_json::json!({
            "workflow_id": self.workflow_id,
            "synchronizer_id": self.synchronizer_id,
        });

        let spinner = output::create_spinner("Mirroring workflow…");
        let result: serde_json::Value =
            rpc.call("tenzro_mirrorWorkflowToCanton", params).await?;
        spinner.finish_and_clear();

        println!(
            "{}",
            serde_json::to_string_pretty(&result).unwrap_or_else(|_| "?".into())
        );
        Ok(())
    }
}

/// Operator-only: mirror an Obligation under an already-mirrored
/// workflow as a `Tenzro.Workflow:ObligationAnchor` contract.
/// `parent_contract_id` is the WorkflowAnchor created by the
/// matching `mirror-workflow` call. Admin-token-gated.
#[derive(Debug, Parser)]
pub struct CantonMirrorObligationCmd {
    /// Obligation id (32-byte hex)
    #[arg(long)]
    obligation_id: String,

    /// Parent WorkflowAnchor contract id
    #[arg(long)]
    parent_contract_id: String,

    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,

    #[arg(long, env = "TENZRO_ADMIN_TOKEN", hide_env_values = true)]
    admin_token: Option<String>,
}

impl CantonMirrorObligationCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Canton Mirror Obligation");

        let mut rpc = RpcClient::new(&self.rpc);
        if let Some(token) = &self.admin_token {
            rpc = rpc.with_admin_token(token);
        } else {
            return Err(anyhow!(
                "missing admin token (pass --admin-token or set TENZRO_ADMIN_TOKEN)"
            ));
        }

        let params = serde_json::json!({
            "obligation_id": self.obligation_id,
            "parent_contract_id": self.parent_contract_id,
        });

        let spinner = output::create_spinner("Mirroring obligation…");
        let result: serde_json::Value =
            rpc.call("tenzro_mirrorObligationToCanton", params).await?;
        spinner.finish_and_clear();

        println!(
            "{}",
            serde_json::to_string_pretty(&result).unwrap_or_else(|_| "?".into())
        );
        Ok(())
    }
}
