//! Skill registry commands

use anyhow::Result;
use clap::{Parser, Subcommand};

use crate::{output, rpc};

#[derive(Debug, Subcommand)]
pub enum SkillCommand {
    /// List registered skills on the network
    List(ListSkillsCmd),
    /// Register a new skill
    Register(RegisterSkillCmd),
    /// Search for skills by keyword
    Search(SearchSkillsCmd),
    /// Use (invoke) a skill
    Use(UseSkillCmd),
    /// Get details of a specific skill
    Get(GetSkillCmd),
    /// Get usage statistics for a skill
    Usage(SkillUsageCmd),
    /// Update an existing skill
    Update(UpdateSkillCmd),
    /// Reconcile the skill registry — purge Inactive/Deprecated skills
    Prune(PruneSkillsCmd),
}

impl SkillCommand {
    pub async fn execute(self) -> Result<()> {
        match self {
            Self::List(cmd) => cmd.execute().await,
            Self::Register(cmd) => cmd.execute().await,
            Self::Search(cmd) => cmd.execute().await,
            Self::Use(cmd) => cmd.execute().await,
            Self::Get(cmd) => cmd.execute().await,
            Self::Usage(cmd) => cmd.execute().await,
            Self::Update(cmd) => cmd.execute().await,
            Self::Prune(cmd) => cmd.execute().await,
        }
    }
}

/// Reconcile the node's skill registry — purge Inactive/Deprecated skills
/// older than `purge_after_secs` (default 30 days). Active skills are
/// always retained.
#[derive(Debug, Parser)]
pub struct PruneSkillsCmd {
    /// Purge inactive/deprecated skills older than this many seconds (default: 30 days)
    #[arg(long)]
    purge_after_secs: Option<u64>,

    /// RPC endpoint (default: http://127.0.0.1:8545)
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,

    /// Output format (text, json)
    #[arg(long, default_value = "text")]
    format: String,
}

impl PruneSkillsCmd {
    pub async fn execute(self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Reconciling Skill Registry");

        let rpc = RpcClient::new(&self.rpc);
        let spinner = output::create_spinner("Running skill reconcile on node...");
        let params = match self.purge_after_secs {
            Some(s) => serde_json::json!({ "purge_after_secs": s }),
            None => serde_json::Value::Null,
        };
        let result: serde_json::Value = rpc.call("tenzro_pruneSkillRegistry", params).await?;
        spinner.finish_and_clear();

        if self.format == "json" {
            output::print_json(&result)?;
            return Ok(());
        }

        let purged = result.get("purged").and_then(|v| v.as_u64()).unwrap_or(0);
        output::print_success(&format!(
            "Skill reconcile complete: {} stale skill(s) purged",
            purged
        ));
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct ListSkillsCmd {
    /// Filter by category
    #[arg(long)]
    category: Option<String>,
    /// Filter by required capability
    #[arg(long)]
    capability: Option<String>,
    /// Only show skills publishing a content-addressed bundle a caller can pin
    #[arg(long)]
    bundled_only: bool,
    /// Include inactive and deprecated skills (default hides them)
    #[arg(long)]
    all: bool,
    /// Maximum number to show
    #[arg(long, default_value = "20")]
    limit: u32,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ListSkillsCmd {
    pub async fn execute(self) -> Result<()> {
        output::print_header("Skill Registry");

        let spinner = output::create_spinner("Fetching skills...");
        let rpc = rpc::RpcClient::new(&self.rpc);

        let mut filter = serde_json::json!({ "limit": self.limit });
        if let Some(ref c) = self.category {
            filter["category"] = serde_json::json!(c);
        }
        if let Some(ref c) = self.capability {
            filter["capability"] = serde_json::json!(c);
        }
        if self.bundled_only {
            filter["bundled_only"] = serde_json::json!(true);
        }
        if self.all {
            filter["active_only"] = serde_json::json!(false);
        }

        let result: Result<serde_json::Value> = rpc
            .call("tenzro_listSkills", serde_json::json!([filter]))
            .await;
        spinner.finish_and_clear();

        match result {
            Ok(skills) => {
                let arr = skills.as_array().cloned().unwrap_or_default();
                println!();
                output::print_field("Total Skills", &arr.len().to_string());
                println!();
                for skill in &arr {
                    let skill_id = skill["skill_id"].as_str().unwrap_or("?");
                    let name = skill["name"]
                        .as_str()
                        .or_else(|| skill["skill_id"].as_str())
                        .unwrap_or("Unnamed");
                    let status = skill["status"].as_str().unwrap_or("unknown");
                    let category = skill["category"].as_str().unwrap_or("?");
                    let description = skill["description"].as_str().unwrap_or("No description");

                    output::print_field("ID", skill_id);
                    output::print_field("Name", name);
                    output::print_field("Category", category);
                    output::print_field("Status", status);
                    output::print_field(
                        "Description",
                        &description.chars().take(80).collect::<String>(),
                    );

                    if let Some(caps) = skill["required_capabilities"].as_array() {
                        let cap_list: Vec<&str> = caps.iter().filter_map(|c| c.as_str()).collect();
                        if !cap_list.is_empty() {
                            output::print_field("Capabilities", &cap_list.join(", "));
                        }
                    }
                    if let Some(sha) = skill["bundle"]["sha256"].as_str() {
                        output::print_field("Bundle SHA-256", sha);
                    }
                    println!();
                }
                if arr.is_empty() {
                    output::print_info("No skills found");
                }
            }
            Err(e) => output::print_error(&format!("Failed to list skills: {}", e)),
        }

        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct RegisterSkillCmd {
    /// Skill name
    #[arg(long)]
    name: String,
    /// Skill description
    #[arg(long)]
    description: String,
    /// Comma-separated capabilities (e.g. "nlp,code,math")
    #[arg(long)]
    capabilities: String,
    /// Category (e.g. "inference", "data", "automation")
    #[arg(long, default_value = "general")]
    category: String,
    /// Version string (e.g. "1.0.0")
    #[arg(long, default_value = "1.0.0")]
    version: String,
    /// Creator DID (e.g. "did:tenzro:human:...")
    #[arg(long)]
    creator_did: String,
    /// MCP endpoint URL where the skill is served (optional)
    #[arg(long)]
    endpoint: Option<String>,
    /// Price per call in TNZO base units (0 = free)
    #[arg(long)]
    price_per_call: Option<String>,
    /// Wallet receiving the creator share; required when price_per_call > 0
    #[arg(long)]
    creator_wallet: Option<String>,
    /// Content-addressed artifact locator, e.g. tenzro://blob/<blake3-hex>
    #[arg(long, requires_all = ["bundle_sha256", "bundle_size"])]
    bundle_uri: Option<String>,
    /// Hex SHA-256 of the artifact bytes callers pin against
    #[arg(long, requires_all = ["bundle_uri", "bundle_size"])]
    bundle_sha256: Option<String>,
    /// Artifact size in bytes
    #[arg(long, requires_all = ["bundle_uri", "bundle_sha256"])]
    bundle_size: Option<u64>,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl RegisterSkillCmd {
    pub async fn execute(self) -> Result<()> {
        output::print_header("Register Skill");

        let spinner = output::create_spinner("Registering skill...");
        let rpc = rpc::RpcClient::new(&self.rpc);

        let caps: Vec<&str> = self.capabilities.split(',').map(|s| s.trim()).collect();

        let mut params = serde_json::json!({
            "name": self.name,
            "description": self.description,
            "required_capabilities": caps,
            "category": self.category,
            "version": self.version,
            "creator_did": self.creator_did,
        });

        if let Some(ref ep) = self.endpoint {
            params["endpoint"] = serde_json::json!(ep);
        }
        if let Some(ref price) = self.price_per_call {
            params["price_per_call"] = serde_json::json!(price);
        }
        if let Some(ref wallet) = self.creator_wallet {
            params["creator_wallet"] = serde_json::json!(wallet);
        }
        if let (Some(uri), Some(sha), Some(size)) =
            (&self.bundle_uri, &self.bundle_sha256, self.bundle_size)
        {
            params["bundle"] = serde_json::json!({
                "uri": uri,
                "sha256": sha.trim().to_ascii_lowercase(),
                "size_bytes": size,
            });
        }

        let result: Result<serde_json::Value> = rpc
            .call("tenzro_registerSkill", serde_json::json!([params]))
            .await;
        spinner.finish_and_clear();

        match result {
            Ok(skill) => {
                println!();
                output::print_success("Skill registered successfully!");
                if let Some(id) = skill["skill_id"].as_str() {
                    output::print_field("Skill ID", id);
                }
                if let Some(status) = skill["status"].as_str() {
                    output::print_field("Status", status);
                }
                output::print_field("Name", &self.name);
                output::print_field("Version", &self.version);
                output::print_field("Category", &self.category);
            }
            Err(e) => output::print_error(&format!("Failed to register skill: {}", e)),
        }

        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct SearchSkillsCmd {
    /// Search query (matches name, description, capabilities)
    query: String,
    /// Maximum results to return
    #[arg(long, default_value = "10")]
    limit: u32,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl SearchSkillsCmd {
    pub async fn execute(self) -> Result<()> {
        output::print_header("Search Skills");

        let spinner = output::create_spinner(&format!("Searching for \"{}\"...", self.query));
        let rpc = rpc::RpcClient::new(&self.rpc);

        let params = serde_json::json!({
            "query": self.query,
            "limit": self.limit,
        });

        let result: Result<serde_json::Value> = rpc
            .call("tenzro_searchSkills", serde_json::json!([params]))
            .await;
        spinner.finish_and_clear();

        match result {
            Ok(skills) => {
                let arr = skills.as_array().cloned().unwrap_or_default();
                println!();
                output::print_field("Results", &arr.len().to_string());
                println!();
                for skill in &arr {
                    let skill_id = skill["skill_id"].as_str().unwrap_or("?");
                    let name = skill["name"]
                        .as_str()
                        .or_else(|| skill["skill_id"].as_str())
                        .unwrap_or("Unnamed");
                    let status = skill["status"].as_str().unwrap_or("unknown");
                    let category = skill["category"].as_str().unwrap_or("?");
                    let description = skill["description"].as_str().unwrap_or("No description");

                    output::print_field("ID", skill_id);
                    output::print_field("Name", name);
                    output::print_field("Category", category);
                    output::print_field("Status", status);
                    output::print_field(
                        "Description",
                        &description.chars().take(80).collect::<String>(),
                    );
                    println!();
                }
                if arr.is_empty() {
                    output::print_info(&format!("No skills found for \"{}\"", self.query));
                }
            }
            Err(e) => output::print_error(&format!("Search failed: {}", e)),
        }

        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct UseSkillCmd {
    /// Skill ID to invoke
    skill_id: String,
    /// Input parameters as JSON (e.g. '{"prompt":"hello"}')
    #[arg(long, default_value = "{}")]
    input: String,
    /// Refuse the invocation unless the registry holds this exact version
    #[arg(long)]
    expected_version: Option<String>,
    /// Refuse the invocation unless the registry holds this exact artifact digest
    #[arg(long)]
    expected_sha256: Option<String>,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl UseSkillCmd {
    pub async fn execute(self) -> Result<()> {
        output::print_header("Use Skill");

        let input: serde_json::Value = serde_json::from_str(&self.input)
            .map_err(|e| anyhow::anyhow!("--input is not valid JSON: {}", e))?;

        let spinner = output::create_spinner(&format!("Invoking skill {}...", self.skill_id));
        let rpc = rpc::RpcClient::new(&self.rpc);

        let mut params = serde_json::json!({
            "skill_id": self.skill_id,
            "input": input,
        });
        if let Some(ref v) = self.expected_version {
            params["expected_version"] = serde_json::json!(v);
        }
        if let Some(ref h) = self.expected_sha256 {
            params["expected_sha256"] = serde_json::json!(h);
        }

        let result: Result<serde_json::Value> = rpc
            .call("tenzro_useSkill", serde_json::json!([params]))
            .await;
        spinner.finish_and_clear();

        match result {
            Ok(response) => {
                println!();
                output::print_success("Skill invoked successfully!");
                println!();

                if let Some(output) = response.get("output") {
                    if let Some(text) = output.as_str() {
                        println!("{}", text);
                    } else {
                        println!("{}", serde_json::to_string_pretty(output)?);
                    }
                } else if response.is_object() {
                    for (key, val) in response.as_object().unwrap_or(&serde_json::Map::new()) {
                        output::print_field(key, val.to_string().trim_matches('"'));
                    }
                }
                println!();
            }
            Err(e) => output::print_error(&format!("Failed to invoke skill: {}", e)),
        }

        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct GetSkillCmd {
    /// Skill ID to look up
    skill_id: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl GetSkillCmd {
    pub async fn execute(self) -> Result<()> {
        output::print_header("Skill Details");

        let spinner = output::create_spinner("Fetching skill...");
        let rpc = rpc::RpcClient::new(&self.rpc);

        let result: Result<serde_json::Value> = rpc
            .call(
                "tenzro_getSkill",
                serde_json::json!([{ "skill_id": self.skill_id }]),
            )
            .await;
        spinner.finish_and_clear();

        match result {
            Ok(skill) => {
                println!();
                if let Some(obj) = skill.as_object() {
                    for (key, val) in obj {
                        let display = match val {
                            serde_json::Value::Array(arr) => arr
                                .iter()
                                .filter_map(|v| v.as_str())
                                .collect::<Vec<_>>()
                                .join(", "),
                            _ => val.to_string().trim_matches('"').to_string(),
                        };
                        output::print_field(key, &display);
                    }
                }
            }
            Err(e) => output::print_error(&format!("Skill not found: {}", e)),
        }

        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct SkillUsageCmd {
    /// Skill ID
    skill_id: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl SkillUsageCmd {
    pub async fn execute(self) -> Result<()> {
        output::print_header("Skill Usage");
        let spinner = output::create_spinner("Fetching usage...");
        let rpc = rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_getSkillUsage",
                serde_json::json!([{ "skill_id": self.skill_id }]),
            )
            .await?;
        spinner.finish_and_clear();
        output::print_field("Skill ID", &self.skill_id);
        output::print_field(
            "Total Invocations",
            &result
                .get("total_invocations")
                .and_then(|v| v.as_u64())
                .unwrap_or(0)
                .to_string(),
        );
        output::print_field(
            "Success Rate",
            &result
                .get("success_rate")
                .and_then(|v| v.as_f64())
                .map(|r| format!("{:.1}%", r * 100.0))
                .unwrap_or_else(|| "N/A".to_string()),
        );
        output::print_field(
            "Avg Latency",
            &result
                .get("avg_latency_ms")
                .and_then(|v| v.as_u64())
                .map(|l| format!("{}ms", l))
                .unwrap_or_else(|| "N/A".to_string()),
        );
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct UpdateSkillCmd {
    /// Skill ID to update
    skill_id: String,
    /// New description
    #[arg(long)]
    description: Option<String>,
    /// New version
    #[arg(long)]
    version: Option<String>,
    /// New endpoint
    #[arg(long)]
    endpoint: Option<String>,
    /// New category
    #[arg(long)]
    category: Option<String>,
    /// New status (active, inactive, deprecated)
    #[arg(long)]
    status: Option<String>,
    /// Republish the artifact locator, e.g. tenzro://blob/<blake3-hex>
    #[arg(long, requires_all = ["bundle_sha256", "bundle_size"])]
    bundle_uri: Option<String>,
    /// Hex SHA-256 of the republished artifact bytes
    #[arg(long, requires_all = ["bundle_uri", "bundle_size"])]
    bundle_sha256: Option<String>,
    /// Republished artifact size in bytes
    #[arg(long, requires_all = ["bundle_uri", "bundle_sha256"])]
    bundle_size: Option<u64>,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl UpdateSkillCmd {
    pub async fn execute(self) -> Result<()> {
        output::print_header("Update Skill");
        let spinner = output::create_spinner("Updating...");
        let rpc = rpc::RpcClient::new(&self.rpc);
        let mut params = serde_json::json!({ "skill_id": self.skill_id });
        if let Some(ref d) = self.description {
            params["description"] = serde_json::json!(d);
        }
        if let Some(ref v) = self.version {
            params["version"] = serde_json::json!(v);
        }
        if let Some(ref e) = self.endpoint {
            params["endpoint"] = serde_json::json!(e);
        }
        if let Some(ref c) = self.category {
            params["category"] = serde_json::json!(c);
        }
        if let Some(ref s) = self.status {
            params["status"] = serde_json::json!(s);
        }
        if let (Some(uri), Some(sha), Some(size)) =
            (&self.bundle_uri, &self.bundle_sha256, self.bundle_size)
        {
            params["bundle"] = serde_json::json!({
                "uri": uri,
                "sha256": sha.trim().to_ascii_lowercase(),
                "size_bytes": size,
            });
        }
        let _result: serde_json::Value = rpc
            .call("tenzro_updateSkill", serde_json::json!([params]))
            .await?;
        spinner.finish_and_clear();
        output::print_success("Skill updated!");
        Ok(())
    }
}
