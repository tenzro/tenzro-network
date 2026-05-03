//! Agent management commands for the Tenzro CLI
//!
//! Register, list, and message AI agents on the Tenzro Network.

use clap::{Parser, Subcommand};
use anyhow::Result;
use crate::output;

/// Agent management commands
#[derive(Debug, Subcommand)]
pub enum AgentCommand {
    /// Register a new AI agent
    Register(AgentRegisterCmd),
    /// List registered agents
    List(AgentListCmd),
    /// Send a message to an agent
    Send(AgentSendCmd),
    /// Spawn a child agent under a parent agent
    Spawn(AgentSpawnCmd),
    /// Run an agentic task loop for an agent
    RunTask(AgentRunTaskCmd),
    /// Create a swarm of member agents
    CreateSwarm(AgentCreateSwarmCmd),
    /// Get the status of a swarm
    GetSwarm(AgentGetSwarmCmd),
    /// Terminate a swarm and all its member agents
    TerminateSwarm(AgentTerminateSwarmCmd),
    /// List agent templates from the registry
    ListTemplates(AgentListTemplatesCmd),
    /// Get details of an agent template
    GetTemplate(AgentGetTemplateCmd),
    /// Spawn an agent from a template (provisions identity + wallet + delegation)
    SpawnTemplate(AgentSpawnTemplateCmd),
    /// Run a spawned agent's execution spec
    RunTemplate(AgentRunTemplateCmd),
    /// Delegate a task to an agent
    Delegate(AgentDelegateCmd),
    /// Discover agents on the network
    Discover(AgentDiscoverCmd),
    /// Fund an agent's wallet
    Fund(AgentFundCmd),
    /// Spawn an agent from a template with skill
    SpawnFromTemplate(AgentSpawnFromTemplateCmd),
    /// Spawn an agent with a specific skill
    SpawnWithSkill(AgentSpawnWithSkillCmd),
    /// Pay for inference on behalf of an agent
    PayForInference(AgentPayForInferenceCmd),
    /// Reconcile the agent registry — auto-suspend idle agents (1h TTL)
    Prune(AgentPruneCmd),
}

impl AgentCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Register(cmd) => cmd.execute().await,
            Self::List(cmd) => cmd.execute().await,
            Self::Send(cmd) => cmd.execute().await,
            Self::Spawn(cmd) => cmd.execute().await,
            Self::RunTask(cmd) => cmd.execute().await,
            Self::CreateSwarm(cmd) => cmd.execute().await,
            Self::GetSwarm(cmd) => cmd.execute().await,
            Self::TerminateSwarm(cmd) => cmd.execute().await,
            Self::ListTemplates(cmd) => cmd.execute().await,
            Self::GetTemplate(cmd) => cmd.execute().await,
            Self::SpawnTemplate(cmd) => cmd.execute().await,
            Self::RunTemplate(cmd) => cmd.execute().await,
            Self::Delegate(cmd) => cmd.execute().await,
            Self::Discover(cmd) => cmd.execute().await,
            Self::Fund(cmd) => cmd.execute().await,
            Self::SpawnFromTemplate(cmd) => cmd.execute().await,
            Self::SpawnWithSkill(cmd) => cmd.execute().await,
            Self::PayForInference(cmd) => cmd.execute().await,
            Self::Prune(cmd) => cmd.execute().await,
        }
    }
}

/// Reconcile the node's agent registry — auto-suspend idle Active agents
/// (1h TTL) and persist the suspension. Terminated agents are preserved
/// indefinitely for audit.
#[derive(Debug, Parser)]
pub struct AgentPruneCmd {
    /// RPC endpoint (default: http://127.0.0.1:8545)
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,

    /// Output format (text, json)
    #[arg(long, default_value = "text")]
    format: String,
}

impl AgentPruneCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Reconciling Agent Registry");

        let rpc = RpcClient::new(&self.rpc);
        let spinner = output::create_spinner("Running agent reconcile on node...");
        let result: serde_json::Value = rpc
            .call("tenzro_pruneAgentRegistry", serde_json::Value::Null)
            .await?;
        spinner.finish_and_clear();

        if self.format == "json" {
            output::print_json(&result)?;
            return Ok(());
        }

        let suspended = result.get("suspended").and_then(|v| v.as_u64()).unwrap_or(0);
        output::print_success(&format!(
            "Agent reconcile complete: {} agent(s) auto-suspended",
            suspended
        ));
        Ok(())
    }
}

/// Register a new AI agent
#[derive(Debug, Parser)]
pub struct AgentRegisterCmd {
    /// Agent name
    #[arg(long)]
    name: String,

    /// Creator address (hex, e.g. 0x...)
    #[arg(long)]
    creator: String,

    /// Agent capabilities (comma-separated: nlp,vision,code,data,blockchain)
    #[arg(long, value_delimiter = ',')]
    capabilities: Option<Vec<String>>,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl AgentRegisterCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Register Agent");

        let spinner = output::create_spinner("Registering agent...");

        let rpc = RpcClient::new(&self.rpc);

        let caps = self.capabilities.clone().unwrap_or_else(|| vec!["general".to_string()]);

        let result: serde_json::Value = rpc.call("tenzro_registerAgent", serde_json::json!({
            "name": self.name,
            "creator": self.creator,
            "capabilities": caps,
        })).await?;

        spinner.finish_and_clear();

        output::print_success("Agent registered successfully!");
        println!();

        if let Some(v) = result.get("agent_id").and_then(|v| v.as_str()) {
            output::print_field("Agent ID", v);
        }
        output::print_field("Name", &self.name);
        output::print_field("Creator", &self.creator);
        if let Some(v) = result.get("wallet_address").and_then(|v| v.as_str()) {
            output::print_field("Wallet", v);
        }
        if let Some(v) = result.get("capabilities").and_then(|v| v.as_u64()) {
            output::print_field("Capabilities", &v.to_string());
        }
        if let Some(v) = result.get("status").and_then(|v| v.as_str()) {
            output::print_field("Status", v);
        }

        Ok(())
    }
}

/// List registered agents
#[derive(Debug, Parser)]
pub struct AgentListCmd {
    /// Show detailed information
    #[arg(long)]
    detailed: bool,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl AgentListCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Agents");

        let spinner = output::create_spinner("Loading agents...");

        let rpc = RpcClient::new(&self.rpc);

        let agents: Vec<serde_json::Value> = rpc.call("tenzro_listAgents", serde_json::json!([])).await.unwrap_or_default();

        spinner.finish_and_clear();

        if agents.is_empty() {
            output::print_info("No agents registered. Register one with: tenzro agent register --name <name> --creator <address>");
            return Ok(());
        }

        if self.detailed {
            for agent in &agents {
                println!();
                if let Some(v) = agent.get("agent_id").and_then(|v| v.as_str()) {
                    output::print_field("Agent ID", v);
                }
                if let Some(v) = agent.get("name").and_then(|v| v.as_str()) {
                    output::print_field("Name", v);
                }
                if let Some(v) = agent.get("creator").and_then(|v| v.as_str()) {
                    output::print_field("Creator", v);
                }
                if let Some(v) = agent.get("wallet_address").and_then(|v| v.as_str()) {
                    output::print_field("Wallet", v);
                }
                if let Some(v) = agent.get("status").and_then(|v| v.as_str()) {
                    output::print_field("Status", v);
                }
                if let Some(caps) = agent.get("capabilities").and_then(|v| v.as_array()) {
                    let cap_names: Vec<&str> = caps.iter()
                        .filter_map(|c| c.get("name").and_then(|n| n.as_str()))
                        .collect();
                    output::print_field("Capabilities", &cap_names.join(", "));
                }
                if let Some(v) = agent.get("created_at").and_then(|v| v.as_str()) {
                    output::print_field("Created", v);
                }
            }
            println!();
        } else {
            let headers = vec!["Agent ID", "Name", "Status", "Creator"];
            let mut rows = Vec::new();
            for agent in &agents {
                rows.push(vec![
                    agent.get("agent_id").and_then(|v| v.as_str()).unwrap_or("unknown").to_string(),
                    agent.get("name").and_then(|v| v.as_str()).unwrap_or("unnamed").to_string(),
                    agent.get("status").and_then(|v| v.as_str()).unwrap_or("unknown").to_string(),
                    agent.get("creator").and_then(|v| v.as_str()).unwrap_or("unknown").to_string(),
                ]);
            }
            output::print_table(&headers, &rows);
        }

        println!("Total: {} agents", agents.len());

        Ok(())
    }
}

/// Send a message to an agent
#[derive(Debug, Parser)]
pub struct AgentSendCmd {
    /// Sending agent ID (UUID)
    #[arg(long)]
    from: String,

    /// Receiving agent ID (UUID)
    #[arg(long)]
    to: String,

    /// Message content
    message: String,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl AgentSendCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Send Agent Message");

        let spinner = output::create_spinner("Sending message...");

        let rpc = RpcClient::new(&self.rpc);

        let result: serde_json::Value = rpc.call("tenzro_sendAgentMessage", serde_json::json!({
            "from": self.from,
            "to": self.to,
            "message": self.message,
        })).await?;

        spinner.finish_and_clear();

        output::print_success("Message sent!");
        println!();
        if let Some(v) = result.get("message_id").and_then(|v| v.as_str()) {
            output::print_field("Message ID", v);
        }
        output::print_field("From", &self.from);
        output::print_field("To", &self.to);
        if let Some(v) = result.get("status").and_then(|v| v.as_str()) {
            output::print_field("Status", v);
        }

        Ok(())
    }
}

/// Spawn a child agent under a parent agent
#[derive(Debug, Parser)]
pub struct AgentSpawnCmd {
    /// Parent agent ID (UUID)
    #[arg(long)]
    parent_id: String,

    /// Name for the new child agent
    #[arg(long)]
    name: String,

    /// Agent capabilities (comma-separated)
    #[arg(long, value_delimiter = ',')]
    capabilities: Option<Vec<String>>,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl AgentSpawnCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Spawn Agent");

        let spinner = output::create_spinner("Spawning child agent...");

        let rpc = RpcClient::new(&self.rpc);

        let caps = self.capabilities.clone().unwrap_or_default();

        let result: serde_json::Value = rpc.call("tenzro_spawnAgent", serde_json::json!([{
            "parent_id": self.parent_id,
            "name": self.name,
            "capabilities": caps,
        }])).await?;

        spinner.finish_and_clear();

        output::print_success("Agent spawned successfully!");
        println!();

        if let Some(v) = result.get("agent_id").and_then(|v| v.as_str()) {
            output::print_field("Agent ID", v);
        }
        if let Some(v) = result.get("parent_id").and_then(|v| v.as_str()) {
            output::print_field("Parent ID", v);
        }
        if let Some(v) = result.get("name").and_then(|v| v.as_str()) {
            output::print_field("Name", v);
        }

        Ok(())
    }
}

/// Run an agentic task loop for an agent
#[derive(Debug, Parser)]
pub struct AgentRunTaskCmd {
    /// Agent ID to run the task
    #[arg(long)]
    agent_id: String,

    /// Task description
    task: String,

    /// Inference endpoint URL (optional)
    #[arg(long)]
    inference_url: Option<String>,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl AgentRunTaskCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Run Agent Task");

        let spinner = output::create_spinner("Running agentic task loop...");

        let rpc = RpcClient::new(&self.rpc);

        let result: serde_json::Value = rpc.call("tenzro_runAgentTask", serde_json::json!([{
            "agent_id": self.agent_id,
            "task": self.task,
            "inference_url": self.inference_url,
        }])).await?;

        spinner.finish_and_clear();

        output::print_success("Task completed!");
        println!();

        if let Some(v) = result.get("agent_id").and_then(|v| v.as_str()) {
            output::print_field("Agent ID", v);
        }
        if let Some(v) = result.get("result").and_then(|v| v.as_str()) {
            output::print_field("Result", v);
        }

        Ok(())
    }
}

/// Create a swarm of member agents
#[derive(Debug, Parser)]
pub struct AgentCreateSwarmCmd {
    /// Orchestrator agent ID
    #[arg(long)]
    orchestrator_id: String,

    /// Member specs as JSON array: '[{"name":"analyst","capabilities":["data"]}]'
    #[arg(long)]
    members: String,

    /// Maximum number of swarm members
    #[arg(long)]
    max_members: Option<usize>,

    /// Task timeout in seconds
    #[arg(long)]
    task_timeout_secs: Option<u64>,

    /// Dispatch tasks in parallel (default: true)
    #[arg(long)]
    parallel: Option<bool>,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl AgentCreateSwarmCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Create Swarm");

        let spinner = output::create_spinner("Creating agent swarm...");

        let rpc = RpcClient::new(&self.rpc);

        let members: serde_json::Value = serde_json::from_str(&self.members)
            .map_err(|e| anyhow::anyhow!("Invalid --members JSON: {}", e))?;

        let result: serde_json::Value = rpc.call("tenzro_createSwarm", serde_json::json!([{
            "orchestrator_id": self.orchestrator_id,
            "members": members,
            "max_members": self.max_members,
            "task_timeout_secs": self.task_timeout_secs,
            "parallel": self.parallel,
        }])).await?;

        spinner.finish_and_clear();

        output::print_success("Swarm created!");
        println!();

        if let Some(v) = result.get("swarm_id").and_then(|v| v.as_str()) {
            output::print_field("Swarm ID", v);
        }
        if let Some(v) = result.get("orchestrator_id").and_then(|v| v.as_str()) {
            output::print_field("Orchestrator", v);
        }

        Ok(())
    }
}

/// Get the status of a swarm
#[derive(Debug, Parser)]
pub struct AgentGetSwarmCmd {
    /// Swarm ID
    #[arg(long)]
    swarm_id: String,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl AgentGetSwarmCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Swarm Status");

        let spinner = output::create_spinner("Fetching swarm status...");

        let rpc = RpcClient::new(&self.rpc);

        let result: serde_json::Value = rpc.call("tenzro_getSwarmStatus", serde_json::json!([{
            "swarm_id": self.swarm_id,
        }])).await?;

        spinner.finish_and_clear();

        println!();
        if let Some(v) = result.get("swarm_id").and_then(|v| v.as_str()) {
            output::print_field("Swarm ID", v);
        }
        if let Some(v) = result.get("orchestrator_id").and_then(|v| v.as_str()) {
            output::print_field("Orchestrator", v);
        }
        if let Some(v) = result.get("status").and_then(|v| v.as_str()) {
            output::print_field("Status", v);
        }
        if let Some(v) = result.get("member_count").and_then(|v| v.as_u64()) {
            output::print_field("Members", &v.to_string());
        }

        if let Some(members) = result.get("members").and_then(|v| v.as_array()) {
            if !members.is_empty() {
                println!();
                let headers = vec!["Agent ID", "Role", "Status"];
                let mut rows = Vec::new();
                for m in members {
                    rows.push(vec![
                        m.get("agent_id").and_then(|v| v.as_str()).unwrap_or("unknown").to_string(),
                        m.get("role").and_then(|v| v.as_str()).unwrap_or("unknown").to_string(),
                        m.get("status").and_then(|v| v.as_str()).unwrap_or("unknown").to_string(),
                    ]);
                }
                output::print_table(&headers, &rows);
            }
        }

        Ok(())
    }
}

/// Terminate a swarm and all its member agents
#[derive(Debug, Parser)]
pub struct AgentTerminateSwarmCmd {
    /// Swarm ID to terminate
    #[arg(long)]
    swarm_id: String,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl AgentTerminateSwarmCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Terminate Swarm");

        let spinner = output::create_spinner("Terminating swarm...");

        let rpc = RpcClient::new(&self.rpc);

        let result: serde_json::Value = rpc.call("tenzro_terminateSwarm", serde_json::json!([{
            "swarm_id": self.swarm_id,
        }])).await?;

        spinner.finish_and_clear();

        output::print_success("Swarm terminated.");
        println!();

        if let Some(v) = result.get("swarm_id").and_then(|v| v.as_str()) {
            output::print_field("Swarm ID", v);
        }
        if let Some(v) = result.get("status").and_then(|v| v.as_str()) {
            output::print_field("Status", v);
        }

        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────
// AgentKit template commands
// ─────────────────────────────────────────────────────────────

/// List agent templates from the registry
#[derive(Debug, Parser)]
pub struct AgentListTemplatesCmd {
    /// Filter by tag
    #[arg(long)]
    tag: Option<String>,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl AgentListTemplatesCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Agent Templates");

        let spinner = output::create_spinner("Fetching templates...");
        let rpc = RpcClient::new(&self.rpc);

        let mut params = serde_json::json!({});
        if let Some(ref tag) = self.tag {
            params["tag"] = serde_json::json!(tag);
        }

        let result: serde_json::Value = rpc.call("tenzro_listAgentTemplates", params).await?;
        spinner.finish_and_clear();

        if let Some(templates) = result.as_array() {
            output::print_success(&format!("Found {} template(s)", templates.len()));
            println!();
            for tpl in templates {
                let name = tpl.get("name").and_then(|v| v.as_str()).unwrap_or("?");
                let id = tpl.get("template_id").and_then(|v| v.as_str()).unwrap_or("?");
                let ver = tpl.get("version").and_then(|v| v.as_str()).unwrap_or("?");
                let has_spec = tpl.get("execution_spec").is_some_and(|v| !v.is_null());
                let spec_label = if has_spec { " [executable]" } else { "" };
                output::print_field(name, &format!("{id} v{ver}{spec_label}"));
            }
        } else {
            output::print_success("No templates found.");
        }

        Ok(())
    }
}

/// Get details of an agent template
#[derive(Debug, Parser)]
pub struct AgentGetTemplateCmd {
    /// Template ID
    #[arg(long)]
    id: String,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl AgentGetTemplateCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Agent Template Details");

        let spinner = output::create_spinner("Fetching template...");
        let rpc = RpcClient::new(&self.rpc);

        let result: serde_json::Value = rpc.call(
            "tenzro_getAgentTemplate",
            serde_json::json!({ "template_id": self.id }),
        ).await?;
        spinner.finish_and_clear();

        if let Some(name) = result.get("name").and_then(|v| v.as_str()) {
            output::print_field("Name", name);
        }
        if let Some(id) = result.get("template_id").and_then(|v| v.as_str()) {
            output::print_field("ID", id);
        }
        if let Some(ver) = result.get("version").and_then(|v| v.as_str()) {
            output::print_field("Version", ver);
        }
        if let Some(desc) = result.get("description").and_then(|v| v.as_str()) {
            output::print_field("Description", desc);
        }
        if let Some(tags) = result.get("tags").and_then(|v| v.as_array()) {
            let tag_strs: Vec<&str> = tags.iter().filter_map(|t| t.as_str()).collect();
            output::print_field("Tags", &tag_strs.join(", "));
        }
        let has_spec = result.get("execution_spec").is_some_and(|v| !v.is_null());
        output::print_field("Executable", if has_spec { "yes" } else { "no" });

        if has_spec {
            if let Some(spec) = result.get("execution_spec") {
                if let Some(steps) = spec.get("steps").and_then(|v| v.as_array()) {
                    output::print_field("Steps", &steps.len().to_string());
                }
            }
        }

        Ok(())
    }
}

/// Spawn an agent from a template
#[derive(Debug, Parser)]
pub struct AgentSpawnTemplateCmd {
    /// Template ID to spawn
    #[arg(long)]
    template_id: String,

    /// Controller display name
    #[arg(long, default_value = "CLI User")]
    display_name: String,

    /// Optional parent machine DID. When set, the spawned agent's
    /// effective delegation scope is the strict intersection of the
    /// parent's scope and the template's spec — the child can never be
    /// broader than its parent on any axis (numeric ceilings,
    /// allow-lists, time bound).
    #[arg(long)]
    parent_machine_did: Option<String>,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl AgentSpawnTemplateCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Spawn Agent from Template");

        let spinner = output::create_spinner("Spawning agent (identity + wallet + delegation)...");
        let rpc = RpcClient::new(&self.rpc);

        let mut payload = serde_json::json!({
            "template_id": self.template_id,
            "display_name": self.display_name,
        });
        if let Some(parent) = &self.parent_machine_did {
            payload["parent_machine_did"] = serde_json::Value::String(parent.clone());
        }

        let result: serde_json::Value = rpc.call(
            "tenzro_spawnAgentTemplate",
            payload,
        ).await?;
        spinner.finish_and_clear();

        output::print_success("Agent spawned successfully!");
        println!();

        if let Some(v) = result.get("agent_id").and_then(|v| v.as_str()) {
            output::print_field("Agent ID", v);
        }
        if let Some(v) = result.get("machine_did").and_then(|v| v.as_str()) {
            output::print_field("Machine DID", v);
        }
        if let Some(v) = result.get("controller_did").and_then(|v| v.as_str()) {
            output::print_field("Controller DID", v);
        }
        if let Some(v) = result.get("wallet_id").and_then(|v| v.as_str()) {
            output::print_field("Wallet ID", v);
        }

        Ok(())
    }
}

/// Run a spawned agent's execution spec
#[derive(Debug, Parser)]
pub struct AgentRunTemplateCmd {
    /// Agent ID (from spawn-template output)
    #[arg(long)]
    agent_id: String,

    /// Maximum iterations
    #[arg(long, default_value = "1")]
    max_iterations: u32,

    /// Dry-run mode (no real dispatches)
    #[arg(long)]
    dry_run: bool,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl AgentRunTemplateCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Run Agent Template");

        let mode = if self.dry_run { " (dry-run)" } else { "" };
        let spinner = output::create_spinner(
            &format!("Running agent {}{mode}...", &self.agent_id[..8.min(self.agent_id.len())]),
        );
        let rpc = RpcClient::new(&self.rpc);

        let result: serde_json::Value = rpc.call(
            "tenzro_runAgentTemplate",
            serde_json::json!({
                "agent_id": self.agent_id,
                "max_iterations": self.max_iterations,
                "dry_run": self.dry_run,
            }),
        ).await?;
        spinner.finish_and_clear();

        output::print_success("Execution complete!");
        println!();

        if let Some(v) = result.get("steps_executed").and_then(|v| v.as_u64()) {
            output::print_field("Steps Executed", &v.to_string());
        }
        if let Some(v) = result.get("steps_skipped_by_delegation").and_then(|v| v.as_u64()) {
            if v > 0 {
                output::print_field("Skipped (delegation)", &v.to_string());
            }
        }
        if let Some(v) = result.get("steps_failed").and_then(|v| v.as_u64()) {
            if v > 0 {
                output::print_field("Failed", &v.to_string());
            }
        }
        if let Some(v) = result.get("total_value_dispatched").and_then(|v| v.as_u64()) {
            output::print_field("Value Dispatched", &format!("{v} wei"));
        }

        Ok(())
    }
}

/// Delegate a task to an agent
#[derive(Debug, Parser)]
pub struct AgentDelegateCmd {
    /// Agent ID to delegate to
    #[arg(long)]
    agent_id: String,
    /// Task description
    #[arg(long)]
    task: String,
    /// Maximum budget (TNZO)
    #[arg(long)]
    budget: Option<String>,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl AgentDelegateCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        output::print_header("Delegate Task to Agent");
        let spinner = output::create_spinner("Delegating...");
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc.call("tenzro_delegateTask", serde_json::json!({
            "agent_id": self.agent_id,
            "task": self.task,
            "budget": self.budget,
        })).await?;
        spinner.finish_and_clear();
        output::print_success("Task delegated!");
        if let Some(v) = result.get("task_id").and_then(|v| v.as_str()) { output::print_field("Task ID", v); }
        if let Some(v) = result.get("status").and_then(|v| v.as_str()) { output::print_field("Status", v); }
        Ok(())
    }
}

/// Discover agents on the network
#[derive(Debug, Parser)]
pub struct AgentDiscoverCmd {
    /// Filter by capability
    #[arg(long)]
    capability: Option<String>,
    /// Maximum results
    #[arg(long, default_value = "20")]
    limit: u32,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl AgentDiscoverCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        output::print_header("Discover Agents");
        let spinner = output::create_spinner("Discovering...");
        let rpc = RpcClient::new(&self.rpc);
        let mut params = serde_json::json!({ "limit": self.limit });
        if let Some(ref cap) = self.capability { params["capability"] = serde_json::json!(cap); }
        let result: serde_json::Value = rpc.call("tenzro_discoverAgents", params).await?;
        spinner.finish_and_clear();
        if let Some(agents) = result.as_array() {
            if agents.is_empty() {
                output::print_info("No agents discovered.");
            } else {
                let headers = vec!["Agent ID", "Name", "Capabilities", "Status"];
                let mut rows = Vec::new();
                for a in agents {
                    rows.push(vec![
                        a.get("agent_id").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                        a.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                        a.get("capabilities").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                        a.get("status").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                    ]);
                }
                output::print_table(&headers, &rows);
            }
        } else { output::print_json(&result)?; }
        Ok(())
    }
}

/// Fund an agent's wallet
#[derive(Debug, Parser)]
pub struct AgentFundCmd {
    /// Agent ID to fund
    #[arg(long)]
    agent_id: String,
    /// Amount to fund (TNZO)
    #[arg(long)]
    amount: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl AgentFundCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        output::print_header("Fund Agent");
        let spinner = output::create_spinner("Funding agent wallet...");
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc.call("tenzro_fundAgent", serde_json::json!({
            "agent_id": self.agent_id,
            "amount": self.amount,
        })).await?;
        spinner.finish_and_clear();
        output::print_success("Agent funded!");
        output::print_field("Agent ID", &self.agent_id);
        output::print_field("Amount", &format!("{} TNZO", self.amount));
        if let Some(v) = result.get("tx_hash").and_then(|v| v.as_str()) { output::print_field("Tx Hash", v); }
        Ok(())
    }
}

/// Spawn an agent from a template
#[derive(Debug, Parser)]
pub struct AgentSpawnFromTemplateCmd {
    /// Template ID to spawn from
    #[arg(long)]
    template_id: String,
    /// Display name for the agent
    #[arg(long, default_value = "CLI Agent")]
    name: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl AgentSpawnFromTemplateCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        output::print_header("Spawn Agent from Template");
        let spinner = output::create_spinner("Spawning...");
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc.call("tenzro_spawnAgentFromTemplate", serde_json::json!({
            "template_id": self.template_id,
            "name": self.name,
        })).await?;
        spinner.finish_and_clear();
        output::print_success("Agent spawned from template!");
        if let Some(v) = result.get("agent_id").and_then(|v| v.as_str()) { output::print_field("Agent ID", v); }
        if let Some(v) = result.get("wallet_address").and_then(|v| v.as_str()) { output::print_field("Wallet", v); }
        Ok(())
    }
}

/// Spawn an agent with a specific skill
#[derive(Debug, Parser)]
pub struct AgentSpawnWithSkillCmd {
    /// Skill ID to equip the agent with
    #[arg(long)]
    skill_id: String,
    /// Agent name
    #[arg(long, default_value = "Skilled Agent")]
    name: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl AgentSpawnWithSkillCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        output::print_header("Spawn Agent with Skill");
        let spinner = output::create_spinner("Spawning...");
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc.call("tenzro_spawnAgentWithSkill", serde_json::json!({
            "skill_id": self.skill_id,
            "name": self.name,
        })).await?;
        spinner.finish_and_clear();
        output::print_success("Agent spawned with skill!");
        if let Some(v) = result.get("agent_id").and_then(|v| v.as_str()) { output::print_field("Agent ID", v); }
        if let Some(v) = result.get("skill_id").and_then(|v| v.as_str()) { output::print_field("Skill", v); }
        Ok(())
    }
}

/// Pay for inference on behalf of an agent
#[derive(Debug, Parser)]
pub struct AgentPayForInferenceCmd {
    /// Agent ID
    #[arg(long)]
    agent_id: String,
    /// Model ID to use
    #[arg(long)]
    model_id: String,
    /// Maximum amount to pay (TNZO)
    #[arg(long)]
    max_amount: Option<String>,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl AgentPayForInferenceCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        output::print_header("Agent Pay for Inference");
        let spinner = output::create_spinner("Processing payment...");
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc.call("tenzro_agentPayForInference", serde_json::json!({
            "agent_id": self.agent_id,
            "model_id": self.model_id,
            "max_amount": self.max_amount,
        })).await?;
        spinner.finish_and_clear();
        output::print_success("Payment authorized!");
        if let Some(v) = result.get("payment_id").and_then(|v| v.as_str()) { output::print_field("Payment ID", v); }
        if let Some(v) = result.get("amount").and_then(|v| v.as_str()) { output::print_field("Amount", v); }
        Ok(())
    }
}
