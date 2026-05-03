//! Tool registry commands (MCP server registry)

use anyhow::Result;
use clap::{Parser, Subcommand};

use crate::{output, rpc};

#[derive(Debug, Subcommand)]
pub enum ToolCommand {
    /// List registered tools (MCP servers) on the network
    List(ListToolsCmd),
    /// Register a new tool (MCP server endpoint)
    Register(RegisterToolCmd),
    /// Search for tools by keyword
    Search(SearchToolsCmd),
    /// Invoke a tool via its MCP endpoint
    Use(UseToolCmd),
    /// Get details of a specific tool
    Get(GetToolCmd),
    /// Get usage statistics for a tool
    Usage(ToolUsageCmd),
    /// Update an existing tool
    Update(UpdateToolCmd),
    /// Reconcile the tool registry — purge Inactive/Deprecated tools
    Prune(PruneToolsCmd),
}

impl ToolCommand {
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

/// Reconcile the node's tool registry — purge Inactive/Deprecated tools
/// older than `purge_after_secs` (default 30 days). Active tools are
/// always retained.
#[derive(Debug, Parser)]
pub struct PruneToolsCmd {
    /// Purge inactive/deprecated tools older than this many seconds (default: 30 days)
    #[arg(long)]
    purge_after_secs: Option<u64>,

    /// RPC endpoint (default: http://127.0.0.1:8545)
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,

    /// Output format (text, json)
    #[arg(long, default_value = "text")]
    format: String,
}

impl PruneToolsCmd {
    pub async fn execute(self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Reconciling Tool Registry");

        let rpc = RpcClient::new(&self.rpc);
        let spinner = output::create_spinner("Running tool reconcile on node...");
        let params = match self.purge_after_secs {
            Some(s) => serde_json::json!({ "purge_after_secs": s }),
            None => serde_json::Value::Null,
        };
        let result: serde_json::Value = rpc
            .call("tenzro_pruneToolRegistry", params)
            .await?;
        spinner.finish_and_clear();

        if self.format == "json" {
            output::print_json(&result)?;
            return Ok(());
        }

        let purged = result.get("purged").and_then(|v| v.as_u64()).unwrap_or(0);
        output::print_success(&format!(
            "Tool reconcile complete: {} stale tool(s) purged",
            purged
        ));
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct ListToolsCmd {
    /// Filter by tool type (e.g. "mcp", "api", "native")
    #[arg(long)]
    tool_type: Option<String>,
    /// Filter by category
    #[arg(long)]
    category: Option<String>,
    /// Filter by status (active, inactive, available)
    #[arg(long)]
    status: Option<String>,
    /// Maximum number to show
    #[arg(long, default_value = "20")]
    limit: u32,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ListToolsCmd {
    pub async fn execute(self) -> Result<()> {
        output::print_header("Tool Registry");

        let spinner = output::create_spinner("Fetching tools...");
        let rpc = rpc::RpcClient::new(&self.rpc);

        let mut filter = serde_json::json!({ "limit": self.limit });
        if let Some(ref t) = self.tool_type {
            filter["tool_type"] = serde_json::json!(t);
        }
        if let Some(ref c) = self.category {
            filter["category"] = serde_json::json!(c);
        }
        if let Some(ref s) = self.status {
            filter["status"] = serde_json::json!(s);
        }

        let result: Result<serde_json::Value> = rpc.call("tenzro_listTools", serde_json::json!([filter])).await;
        spinner.finish_and_clear();

        match result {
            Ok(tools) => {
                let arr = tools.as_array().cloned().unwrap_or_default();
                println!();
                output::print_field("Total Tools", &arr.len().to_string());
                println!();
                for tool in &arr {
                    let tool_id = tool["tool_id"].as_str().unwrap_or("?");
                    let name = tool["name"].as_str()
                        .or_else(|| tool["tool_id"].as_str())
                        .unwrap_or("Unnamed");
                    let tool_type = tool["tool_type"].as_str().unwrap_or("mcp");
                    let status = tool["status"].as_str().unwrap_or("unknown");
                    let category = tool["category"].as_str().unwrap_or("?");
                    let endpoint = tool["endpoint"].as_str().unwrap_or("(no endpoint)");
                    let description = tool["description"].as_str().unwrap_or("No description");

                    output::print_field("ID", tool_id);
                    output::print_field("Name", name);
                    output::print_field("Type", tool_type);
                    output::print_field("Category", category);
                    output::print_field("Status", status);
                    output::print_field("Endpoint", endpoint);
                    output::print_field("Description", &description.chars().take(80).collect::<String>());

                    if let Some(caps) = tool["capabilities"].as_array() {
                        let cap_list: Vec<&str> = caps.iter()
                            .filter_map(|c| c.as_str())
                            .collect();
                        if !cap_list.is_empty() {
                            output::print_field("Capabilities", &cap_list.join(", "));
                        }
                    }
                    println!();
                }
                if arr.is_empty() {
                    output::print_info("No tools found");
                }
            }
            Err(e) => output::print_error(&format!("Failed to list tools: {}", e)),
        }

        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct RegisterToolCmd {
    /// Tool name
    #[arg(long)]
    name: String,
    /// Tool description
    #[arg(long)]
    description: String,
    /// MCP server endpoint URL (required for MCP tools)
    #[arg(long)]
    endpoint: String,
    /// Tool type (default: "mcp")
    #[arg(long, default_value = "mcp")]
    tool_type: String,
    /// Comma-separated capabilities (e.g. "web-search,code-execution,file-access")
    #[arg(long, default_value = "")]
    capabilities: String,
    /// Category (e.g. "search", "code", "data", "automation")
    #[arg(long, default_value = "general")]
    category: String,
    /// Version string (e.g. "1.0.0")
    #[arg(long, default_value = "1.0.0")]
    version: String,
    /// Creator DID (optional, e.g. "did:tenzro:human:...")
    #[arg(long)]
    creator_did: Option<String>,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl RegisterToolCmd {
    pub async fn execute(self) -> Result<()> {
        output::print_header("Register Tool");

        let spinner = output::create_spinner("Registering tool...");
        let rpc = rpc::RpcClient::new(&self.rpc);

        let caps: Vec<&str> = if self.capabilities.is_empty() {
            vec![]
        } else {
            self.capabilities.split(',').map(|s| s.trim()).collect()
        };

        let mut params = serde_json::json!({
            "name": self.name,
            "description": self.description,
            "endpoint": self.endpoint,
            "tool_type": self.tool_type,
            "capabilities": caps,
            "category": self.category,
            "version": self.version,
        });

        if let Some(ref did) = self.creator_did {
            params["creator_did"] = serde_json::json!(did);
        }

        let result: Result<serde_json::Value> = rpc.call("tenzro_registerTool", serde_json::json!([params])).await;
        spinner.finish_and_clear();

        match result {
            Ok(tool) => {
                println!();
                output::print_success("Tool registered successfully!");
                if let Some(id) = tool["tool_id"].as_str() {
                    output::print_field("Tool ID", id);
                }
                if let Some(status) = tool["status"].as_str() {
                    output::print_field("Status", status);
                }
                output::print_field("Name", &self.name);
                output::print_field("Type", &self.tool_type);
                output::print_field("Endpoint", &self.endpoint);
                output::print_field("Version", &self.version);
                output::print_field("Category", &self.category);
            }
            Err(e) => output::print_error(&format!("Failed to register tool: {}", e)),
        }

        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct SearchToolsCmd {
    /// Search query (matches name, description, capabilities)
    query: String,
    /// Maximum results to return
    #[arg(long, default_value = "10")]
    limit: u32,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl SearchToolsCmd {
    pub async fn execute(self) -> Result<()> {
        output::print_header("Search Tools");

        let spinner = output::create_spinner(&format!("Searching for \"{}\"...", self.query));
        let rpc = rpc::RpcClient::new(&self.rpc);

        let params = serde_json::json!({
            "query": self.query,
            "limit": self.limit,
        });

        let result: Result<serde_json::Value> = rpc.call("tenzro_searchTools", serde_json::json!([params])).await;
        spinner.finish_and_clear();

        match result {
            Ok(tools) => {
                let arr = tools.as_array().cloned().unwrap_or_default();
                println!();
                output::print_field("Results", &arr.len().to_string());
                println!();
                for tool in &arr {
                    let tool_id = tool["tool_id"].as_str().unwrap_or("?");
                    let name = tool["name"].as_str()
                        .or_else(|| tool["tool_id"].as_str())
                        .unwrap_or("Unnamed");
                    let tool_type = tool["tool_type"].as_str().unwrap_or("mcp");
                    let status = tool["status"].as_str().unwrap_or("unknown");
                    let endpoint = tool["endpoint"].as_str().unwrap_or("(no endpoint)");
                    let description = tool["description"].as_str().unwrap_or("No description");

                    output::print_field("ID", tool_id);
                    output::print_field("Name", name);
                    output::print_field("Type", tool_type);
                    output::print_field("Status", status);
                    output::print_field("Endpoint", endpoint);
                    output::print_field("Description", &description.chars().take(80).collect::<String>());
                    println!();
                }
                if arr.is_empty() {
                    output::print_info(&format!("No tools found for \"{}\"", self.query));
                }
            }
            Err(e) => output::print_error(&format!("Search failed: {}", e)),
        }

        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct UseToolCmd {
    /// Tool ID to invoke
    tool_id: String,
    /// MCP tool name to call on the server (e.g. "web_search")
    #[arg(long)]
    tool_name: Option<String>,
    /// Input parameters as JSON (e.g. '{"query":"hello"}')
    #[arg(long, default_value = "{}")]
    params: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl UseToolCmd {
    pub async fn execute(self) -> Result<()> {
        output::print_header("Use Tool");

        let input_params: serde_json::Value = serde_json::from_str(&self.params)
            .unwrap_or_else(|_| serde_json::json!({}));

        let spinner = output::create_spinner(&format!("Invoking tool {}...", self.tool_id));
        let rpc = rpc::RpcClient::new(&self.rpc);

        let mut call_params = serde_json::json!({
            "tool_id": self.tool_id,
            "params": input_params,
        });
        if let Some(ref tool_name) = self.tool_name {
            call_params["tool_name"] = serde_json::json!(tool_name);
        }

        let result: Result<serde_json::Value> = rpc.call("tenzro_useTool", serde_json::json!([call_params])).await;
        spinner.finish_and_clear();

        match result {
            Ok(response) => {
                println!();
                output::print_success("Tool invoked successfully!");
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
            Err(e) => output::print_error(&format!("Failed to invoke tool: {}", e)),
        }

        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct GetToolCmd {
    /// Tool ID to look up
    tool_id: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl GetToolCmd {
    pub async fn execute(self) -> Result<()> {
        output::print_header("Tool Details");

        let spinner = output::create_spinner("Fetching tool...");
        let rpc = rpc::RpcClient::new(&self.rpc);

        let result: Result<serde_json::Value> = rpc.call(
            "tenzro_getTool",
            serde_json::json!([{ "tool_id": self.tool_id }]),
        ).await;
        spinner.finish_and_clear();

        match result {
            Ok(tool) => {
                println!();
                if let Some(obj) = tool.as_object() {
                    for (key, val) in obj {
                        let display = match val {
                            serde_json::Value::Array(arr) => {
                                arr.iter()
                                    .filter_map(|v| v.as_str())
                                    .collect::<Vec<_>>()
                                    .join(", ")
                            }
                            _ => val.to_string().trim_matches('"').to_string(),
                        };
                        output::print_field(key, &display);
                    }
                }
            }
            Err(e) => output::print_error(&format!("Tool not found: {}", e)),
        }

        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct ToolUsageCmd {
    /// Tool ID
    tool_id: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ToolUsageCmd {
    pub async fn execute(self) -> Result<()> {
        output::print_header("Tool Usage");
        let spinner = output::create_spinner("Fetching usage...");
        let rpc = rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc.call("tenzro_getToolUsage", serde_json::json!([{ "tool_id": self.tool_id }])).await?;
        spinner.finish_and_clear();
        output::print_field("Tool ID", &self.tool_id);
        output::print_field("Total Invocations", &result.get("total_invocations").and_then(|v| v.as_u64()).unwrap_or(0).to_string());
        output::print_field("Success Rate", &result.get("success_rate").and_then(|v| v.as_f64()).map(|r| format!("{:.1}%", r * 100.0)).unwrap_or_else(|| "N/A".to_string()));
        output::print_field("Avg Latency", &result.get("avg_latency_ms").and_then(|v| v.as_u64()).map(|l| format!("{}ms", l)).unwrap_or_else(|| "N/A".to_string()));
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct UpdateToolCmd {
    /// Tool ID to update
    tool_id: String,
    /// New description
    #[arg(long)]
    description: Option<String>,
    /// New version
    #[arg(long)]
    version: Option<String>,
    /// New endpoint URL
    #[arg(long)]
    endpoint: Option<String>,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl UpdateToolCmd {
    pub async fn execute(self) -> Result<()> {
        output::print_header("Update Tool");
        let spinner = output::create_spinner("Updating...");
        let rpc = rpc::RpcClient::new(&self.rpc);
        let mut params = serde_json::json!({ "tool_id": self.tool_id });
        if let Some(ref d) = self.description { params["description"] = serde_json::json!(d); }
        if let Some(ref v) = self.version { params["version"] = serde_json::json!(v); }
        if let Some(ref e) = self.endpoint { params["endpoint"] = serde_json::json!(e); }
        let _result: serde_json::Value = rpc.call("tenzro_updateTool", serde_json::json!([params])).await?;
        spinner.finish_and_clear();
        output::print_success("Tool updated!");
        Ok(())
    }
}
