//! Agent marketplace commands

use anyhow::Result;
use clap::{Parser, Subcommand};

use crate::{output, rpc};

#[derive(Debug, Subcommand)]
pub enum MarketplaceCommand {
    /// List available agent templates
    List(ListTemplatesCmd),
    /// Get details of an agent template
    Get(GetTemplateCmd),
    /// Register a new agent template
    Register(RegisterTemplateCmd),
    /// Search agent templates
    Search(SearchTemplatesCmd),
    /// Download an agent template
    Download(DownloadTemplateCmd),
    /// Get agent template statistics
    Stats(TemplateStatsCmd),
    /// Rate an agent template
    Rate(RateTemplateCmd),
    /// Update an existing agent template
    Update(UpdateTemplateCmd),
    /// Run (invoke) a spawned agent template end-to-end
    /// (charges the payer wallet for paid templates: network commission -> treasury, remainder -> creator)
    Run(RunTemplateCmd),
}

impl MarketplaceCommand {
    pub async fn execute(self) -> Result<()> {
        match self {
            Self::List(cmd) => cmd.execute().await,
            Self::Get(cmd) => cmd.execute().await,
            Self::Register(cmd) => cmd.execute().await,
            Self::Search(cmd) => cmd.execute().await,
            Self::Download(cmd) => cmd.execute().await,
            Self::Stats(cmd) => cmd.execute().await,
            Self::Rate(cmd) => cmd.execute().await,
            Self::Update(cmd) => cmd.execute().await,
            Self::Run(cmd) => cmd.execute().await,
        }
    }
}

#[derive(Debug, Parser)]
pub struct ListTemplatesCmd {
    /// Filter by type (autonomous, tool_agent, orchestrator, specialist, multi_modal)
    #[arg(long)]
    template_type: Option<String>,
    /// Only show free templates
    #[arg(long)]
    free_only: bool,
    /// Filter by tag
    #[arg(long)]
    tag: Option<String>,
    /// Maximum number to show
    #[arg(long, default_value = "20")]
    limit: u32,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ListTemplatesCmd {
    pub async fn execute(self) -> Result<()> {
        output::print_header("Agent Marketplace");

        let spinner = output::create_spinner("Fetching agent templates...");
        let rpc = rpc::RpcClient::new(&self.rpc);

        let mut filter = serde_json::json!({ "limit": self.limit });
        if self.free_only {
            filter["free_only"] = serde_json::json!(true);
        }
        if let Some(ref t) = self.template_type {
            filter["template_type"] = serde_json::json!(t);
        }
        if let Some(ref tag) = self.tag {
            filter["tag"] = serde_json::json!(tag);
        }

        let result: Result<serde_json::Value> = rpc.call("tenzro_listAgentTemplates", serde_json::json!([filter])).await;
        spinner.finish_and_clear();

        match result {
            Ok(templates) => {
                let arr = templates.as_array().cloned().unwrap_or_default();
                println!();
                output::print_field("Templates Found", &arr.len().to_string());
                println!();
                for tmpl in &arr {
                    let id = tmpl["template_id"].as_str().unwrap_or("?");
                    let name = tmpl["name"].as_str().unwrap_or("Unnamed");
                    let tmpl_type = tmpl["template_type"].as_str().unwrap_or("?");
                    let status = tmpl["status"].as_str().unwrap_or("?");
                    let downloads = tmpl["download_count"].as_u64().unwrap_or(0);
                    let rating = tmpl["rating"].as_u64().unwrap_or(0);
                    output::print_field("ID", &format!("{:.16}...", id));
                    output::print_field("Name", name);
                    output::print_field("Type", tmpl_type);
                    output::print_field("Status", status);
                    output::print_field("Downloads", &downloads.to_string());
                    output::print_field("Rating", &format!("{}/100", rating));
                    println!();
                }
                if arr.is_empty() {
                    output::print_info("No agent templates found");
                }
            }
            Err(e) => output::print_error(&format!("Failed to list templates: {}", e)),
        }

        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct GetTemplateCmd {
    /// Template ID to look up
    template_id: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl GetTemplateCmd {
    pub async fn execute(self) -> Result<()> {
        output::print_header("Agent Template Details");

        let spinner = output::create_spinner("Fetching template...");
        let rpc = rpc::RpcClient::new(&self.rpc);

        let result: Result<serde_json::Value> = rpc.call(
            "tenzro_getAgentTemplate",
            serde_json::json!([{ "template_id": self.template_id }]),
        ).await;
        spinner.finish_and_clear();

        match result {
            Ok(tmpl) => {
                println!();
                if let Some(obj) = tmpl.as_object() {
                    for (key, val) in obj {
                        if key == "system_prompt" {
                            let preview: String = val.as_str().unwrap_or("").chars().take(100).collect();
                            output::print_field(key, &format!("{}...", preview));
                        } else {
                            output::print_field(key, val.to_string().trim_matches('"'));
                        }
                    }
                }
            }
            Err(e) => output::print_error(&format!("Template not found: {}", e)),
        }

        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct RegisterTemplateCmd {
    /// Template name
    #[arg(long)]
    name: String,
    /// Template description
    #[arg(long)]
    description: String,
    /// Template type (autonomous, tool_agent, orchestrator, specialist, multi_modal)
    #[arg(long, default_value = "autonomous")]
    template_type: String,
    /// System prompt for the agent
    #[arg(long)]
    system_prompt: String,
    /// Comma-separated tags
    #[arg(long)]
    tags: Option<String>,
    /// Optional DID binding for creator attribution (e.g. did:tenzro:human:...).
    /// The DID is bound at registration time and cannot be changed later.
    #[arg(long)]
    creator_did: Option<String>,
    /// Hex-encoded creator payout wallet address (0x...).
    /// MANDATORY for any non-free pricing — all creator payouts are routed here.
    #[arg(long)]
    creator_wallet: Option<String>,
    /// Pricing model in compact string form. One of:
    ///   "free",
    ///   "per_execution:<u128>",
    ///   "per_token:<u128>",
    ///   "subscription:<u128>",
    ///   "revenue_share:<bps>"
    /// (base units = 10^-18 TNZO). Defaults to "free".
    #[arg(long, default_value = "free")]
    pricing: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl RegisterTemplateCmd {
    pub async fn execute(self) -> Result<()> {
        output::print_header("Register Agent Template");

        let spinner = output::create_spinner("Registering template...");
        let rpc = rpc::RpcClient::new(&self.rpc);

        let tags: Vec<String> = self.tags
            .unwrap_or_default()
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        let mut params = serde_json::json!({
            "name": self.name,
            "description": self.description,
            "template_type": self.template_type,
            "system_prompt": self.system_prompt,
            "tags": tags,
            "pricing": self.pricing,
        });
        if let Some(ref did) = self.creator_did {
            params["creator_did"] = serde_json::json!(did);
        }
        if let Some(ref wallet) = self.creator_wallet {
            params["creator_wallet"] = serde_json::json!(wallet);
        }

        let result: Result<serde_json::Value> = rpc.call("tenzro_registerAgentTemplate", serde_json::json!([params])).await;
        spinner.finish_and_clear();

        match result {
            Ok(tmpl) => {
                println!();
                output::print_success("Agent template registered!");
                if let Some(id) = tmpl["template_id"].as_str() {
                    output::print_field("Template ID", id);
                }
                if let Some(status) = tmpl["status"].as_str() {
                    output::print_field("Status", status);
                }
                if let Some(did) = tmpl["creator_did"].as_str() {
                    output::print_field("Creator DID", did);
                }
                if let Some(w) = tmpl["creator_wallet"].as_str() {
                    output::print_field("Creator Wallet", w);
                }
                if let Some(p) = tmpl.get("pricing") {
                    output::print_field("Pricing", &p.to_string());
                }
            }
            Err(e) => output::print_error(&format!("Failed to register template: {}", e)),
        }

        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct SearchTemplatesCmd {
    /// Search query
    query: String,
    /// Maximum results
    #[arg(long, default_value = "10")]
    limit: u32,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl SearchTemplatesCmd {
    pub async fn execute(self) -> Result<()> {
        output::print_header("Search Agent Templates");
        let spinner = output::create_spinner(&format!("Searching for \"{}\"...", self.query));
        let rpc = rpc::RpcClient::new(&self.rpc);
        let result: Result<serde_json::Value> = rpc.call("tenzro_searchAgentTemplates", serde_json::json!([{ "query": self.query, "limit": self.limit }])).await;
        spinner.finish_and_clear();
        match result {
            Ok(templates) => {
                let arr = templates.as_array().cloned().unwrap_or_default();
                output::print_field("Results", &arr.len().to_string());
                for tmpl in &arr {
                    println!();
                    output::print_field("ID", tmpl["template_id"].as_str().unwrap_or("?"));
                    output::print_field("Name", tmpl["name"].as_str().unwrap_or("?"));
                    output::print_field("Type", tmpl["template_type"].as_str().unwrap_or("?"));
                }
                if arr.is_empty() { output::print_info("No templates found."); }
            }
            Err(e) => output::print_error(&format!("Search failed: {}", e)),
        }
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct DownloadTemplateCmd {
    /// Template ID to download
    template_id: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl DownloadTemplateCmd {
    pub async fn execute(self) -> Result<()> {
        output::print_header("Download Agent Template");
        let spinner = output::create_spinner("Downloading...");
        let rpc = rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc.call("tenzro_downloadAgentTemplate", serde_json::json!([{ "template_id": self.template_id }])).await?;
        spinner.finish_and_clear();
        output::print_success("Template downloaded!");
        output::print_field("Template ID", &self.template_id);
        if let Some(v) = result.get("status").and_then(|v| v.as_str()) { output::print_field("Status", v); }
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct TemplateStatsCmd {
    /// Template ID
    template_id: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl TemplateStatsCmd {
    pub async fn execute(self) -> Result<()> {
        output::print_header("Agent Template Statistics");
        let spinner = output::create_spinner("Fetching stats...");
        let rpc = rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc.call("tenzro_getAgentTemplateStats", serde_json::json!([{ "template_id": self.template_id }])).await?;
        spinner.finish_and_clear();
        output::print_field("Template ID", &self.template_id);
        output::print_field("Downloads", &result.get("download_count").and_then(|v| v.as_u64()).unwrap_or(0).to_string());
        output::print_field("Rating", &result.get("rating").and_then(|v| v.as_u64()).map(|r| format!("{}/100", r)).unwrap_or_else(|| "N/A".to_string()));
        output::print_field("Active Instances", &result.get("active_instances").and_then(|v| v.as_u64()).unwrap_or(0).to_string());
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct RateTemplateCmd {
    /// Template ID to rate
    template_id: String,
    /// Rating (0-100)
    #[arg(long)]
    rating: u32,
    /// Review comment
    #[arg(long)]
    comment: Option<String>,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl RateTemplateCmd {
    pub async fn execute(self) -> Result<()> {
        output::print_header("Rate Agent Template");
        let rpc = rpc::RpcClient::new(&self.rpc);
        let _result: serde_json::Value = rpc.call("tenzro_rateAgentTemplate", serde_json::json!([{
            "template_id": self.template_id, "rating": self.rating, "comment": self.comment,
        }])).await?;
        output::print_success(&format!("Rated template {} with {}/100", self.template_id, self.rating));
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct UpdateTemplateCmd {
    /// Template ID to update
    template_id: String,
    /// New description
    #[arg(long)]
    description: Option<String>,
    /// New system prompt
    #[arg(long)]
    system_prompt: Option<String>,
    /// New comma-separated tags
    #[arg(long)]
    tags: Option<String>,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl UpdateTemplateCmd {
    pub async fn execute(self) -> Result<()> {
        output::print_header("Update Agent Template");
        let spinner = output::create_spinner("Updating...");
        let rpc = rpc::RpcClient::new(&self.rpc);
        let mut params = serde_json::json!({ "template_id": self.template_id });
        if let Some(ref d) = self.description { params["description"] = serde_json::json!(d); }
        if let Some(ref s) = self.system_prompt { params["system_prompt"] = serde_json::json!(s); }
        if let Some(ref t) = self.tags {
            let tags: Vec<&str> = t.split(',').map(|s| s.trim()).collect();
            params["tags"] = serde_json::json!(tags);
        }
        let _result: serde_json::Value = rpc.call("tenzro_updateAgentTemplate", serde_json::json!([params])).await?;
        spinner.finish_and_clear();
        output::print_success("Template updated!");
        Ok(())
    }
}

/// Invoke (run) a spawned agent template end-to-end.
///
/// For paid templates the payer wallet is charged:
///   - `AGENT_MARKETPLACE_COMMISSION_BPS` (5%) flows to the network treasury
///   - the remainder is paid to the template's `creator_wallet`
///
/// Successful non-dry-run invocations are metered (invocation_count +
/// total_revenue) and persisted to CF_AGENT_TEMPLATES. `dry_run=true`
/// simulates execution without dispatching real transactions or charging
/// any fees.
#[derive(Debug, Parser)]
pub struct RunTemplateCmd {
    /// UUID of the spawned agent to run (must have been created via `agent spawn-template` first)
    #[arg(long)]
    agent_id: String,
    /// Hex-encoded payer wallet address (0x...). REQUIRED for paid templates.
    #[arg(long)]
    payer_wallet: Option<String>,
    /// Estimated token usage — used only for per_token pricing. Default 0.
    #[arg(long, default_value = "0")]
    tokens_estimate: u64,
    /// Maximum iterations through the template's execution steps. Default 1.
    #[arg(long, default_value = "1")]
    max_iterations: u64,
    /// Simulate execution without dispatching real transactions or charging fees.
    #[arg(long)]
    dry_run: bool,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl RunTemplateCmd {
    pub async fn execute(self) -> Result<()> {
        output::print_header("Run Agent Template");
        let spinner = output::create_spinner("Invoking agent...");
        let rpc = rpc::RpcClient::new(&self.rpc);

        let mut params = serde_json::json!({
            "agent_id": self.agent_id,
            "max_iterations": self.max_iterations,
            "dry_run": self.dry_run,
            "tokens_estimate": self.tokens_estimate,
        });
        if let Some(ref w) = self.payer_wallet {
            params["payer_wallet"] = serde_json::json!(w);
        }

        let result: Result<serde_json::Value> =
            rpc.call("tenzro_runAgentTemplate", serde_json::json!([params])).await;
        spinner.finish_and_clear();

        match result {
            Ok(report) => {
                println!();
                output::print_success("Agent invocation complete!");
                if let Some(v) = report.get("template_id").and_then(|v| v.as_str()) {
                    output::print_field("Template ID", v);
                }
                if let Some(v) = report.get("steps_executed").and_then(|v| v.as_u64()) {
                    output::print_field("Steps Executed", &v.to_string());
                }
                if let Some(v) = report.get("steps_failed").and_then(|v| v.as_u64()) {
                    output::print_field("Steps Failed", &v.to_string());
                }
                if let Some(v) = report.get("steps_skipped_by_dry_run").and_then(|v| v.as_u64()) {
                    if v > 0 {
                        output::print_field("Steps Skipped (dry-run)", &v.to_string());
                    }
                }
                if let Some(v) = report.get("fee_paid").and_then(|v| v.as_str()) {
                    output::print_field("Fee Paid", &format!("{} base units", v));
                }
                if let Some(v) = report.get("commission_bps").and_then(|v| v.as_u64()) {
                    output::print_field("Commission", &format!("{} bps", v));
                }
                if let Some(v) = report.get("network_commission").and_then(|v| v.as_str()) {
                    output::print_field("Network Commission", &format!("{} base units", v));
                }
                if let Some(v) = report.get("creator_share").and_then(|v| v.as_str()) {
                    output::print_field("Creator Share", &format!("{} base units", v));
                }
                if let Some(v) = report.get("payer_wallet").and_then(|v| v.as_str()) {
                    output::print_field("Payer Wallet", v);
                }
                if let Some(v) = report.get("creator_wallet").and_then(|v| v.as_str()) {
                    output::print_field("Creator Wallet", v);
                }
                if let Some(v) = report.get("treasury").and_then(|v| v.as_str()) {
                    output::print_field("Treasury", v);
                }
                if let Some(v) = report.get("invocation_count").and_then(|v| v.as_u64()) {
                    output::print_field("Invocation Count", &v.to_string());
                }
                if let Some(v) = report.get("total_revenue").and_then(|v| v.as_str()) {
                    output::print_field("Total Revenue", &format!("{} base units", v));
                }
            }
            Err(e) => output::print_error(&format!("Agent run failed: {}", e)),
        }

        Ok(())
    }
}
