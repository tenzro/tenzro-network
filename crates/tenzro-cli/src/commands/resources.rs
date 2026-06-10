//! Unified resource discovery + invocation + child-agent spawn CLI.
//!
//! Replaces per-class queries with a single discovery surface across
//! tools, skills, knowledge, workflow templates, agent templates, and
//! models. Use `tenzro resources list` to find what's available on
//! the connected node, `tenzro resources use` to invoke any resource
//! by id, and `tenzro resources spawn-child` to atomically spawn a
//! child agent with funded TNZO budget + spending policy.

use anyhow::Result;
use clap::{Parser, Subcommand};
use serde_json::json;

use crate::{output, rpc};

#[derive(Debug, Subcommand)]
pub enum ResourcesCommand {
    /// Discover resources across registries (tools / skills / knowledge /
    /// workflow templates / agent templates / models)
    List(ListResourcesCmd),
    /// Invoke a resource by id. Class auto-detected unless --class is set.
    Use(UseResourceCmd),
    /// Atomically spawn a child agent: DID + wallet + funded TNZO budget
    /// + runtime spending policy
    SpawnChild(SpawnChildCmd),
}

impl ResourcesCommand {
    pub async fn execute(self) -> Result<()> {
        match self {
            Self::List(cmd) => cmd.execute().await,
            Self::Use(cmd) => cmd.execute().await,
            Self::SpawnChild(cmd) => cmd.execute().await,
        }
    }
}

#[derive(Debug, Parser)]
pub struct ListResourcesCmd {
    /// Restrict to these classes (comma-separated). Default = all.
    /// Class names: tool, skill, knowledge, workflow_template,
    /// agent_template, model.
    #[arg(long)]
    pub classes: Option<String>,
    /// Free-text query — matches name, description, capabilities.
    #[arg(long)]
    pub query: Option<String>,
    /// Capability tags (comma-separated). AND-match.
    #[arg(long)]
    pub tags: Option<String>,
    /// Category filter.
    #[arg(long)]
    pub category: Option<String>,
    /// Max TNZO price per invocation (atto-TNZO decimal string).
    #[arg(long)]
    pub max_price: Option<String>,
    /// Filter by creator DID.
    #[arg(long)]
    pub creator: Option<String>,
    #[arg(long)]
    pub limit: Option<usize>,
    #[arg(long)]
    pub offset: Option<usize>,
}

impl ListResourcesCmd {
    pub async fn execute(self) -> Result<()> {
        let mut params = serde_json::Map::new();
        if let Some(c) = self.classes {
            let arr: Vec<&str> = c.split(',').map(|s| s.trim()).collect();
            params.insert("classes".to_string(), json!(arr));
        }
        if let Some(q) = self.query {
            params.insert("query".to_string(), json!(q));
        }
        if let Some(t) = self.tags {
            let arr: Vec<&str> = t.split(',').map(|s| s.trim()).collect();
            params.insert("capability_tags".to_string(), json!(arr));
        }
        if let Some(cat) = self.category {
            params.insert("category".to_string(), json!(cat));
        }
        if let Some(p) = self.max_price {
            params.insert("max_tnzo_price".to_string(), json!(p));
        }
        if let Some(c) = self.creator {
            params.insert("creator_did".to_string(), json!(c));
        }
        if let Some(l) = self.limit {
            params.insert("limit".to_string(), json!(l));
        }
        if let Some(o) = self.offset {
            params.insert("offset".to_string(), json!(o));
        }
        let client = rpc::RpcClient::new("http://127.0.0.1:8545");
        let result: serde_json::Value = client
            .call("tenzro_listResources", json!(params))
            .await?;
        output::print_json(&result)?;
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct UseResourceCmd {
    /// Resource id from `tenzro resources list`.
    #[arg(long)]
    pub resource_id: String,
    /// Force a specific class — skips auto-detect.
    #[arg(long)]
    pub class: Option<String>,
    /// Invocation parameters as a JSON object.
    #[arg(long, default_value = "{}")]
    pub params: String,
    /// Wallet to pay TNZO from.
    #[arg(long)]
    pub payer_wallet: Option<String>,
}

impl UseResourceCmd {
    pub async fn execute(self) -> Result<()> {
        let inner_params: serde_json::Value = serde_json::from_str(&self.params)?;
        let mut p = serde_json::Map::new();
        p.insert("resource_id".to_string(), json!(self.resource_id));
        if let Some(c) = self.class {
            p.insert("class".to_string(), json!(c));
        }
        p.insert("params".to_string(), inner_params);
        if let Some(w) = self.payer_wallet {
            p.insert("payer_wallet".to_string(), json!(w));
        }
        let client = rpc::RpcClient::new("http://127.0.0.1:8545");
        let result: serde_json::Value =
            client.call("tenzro_useResource", json!(p)).await?;
        output::print_json(&result)?;
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct SpawnChildCmd {
    /// Parent DID — the controller for the new child machine identity.
    #[arg(long)]
    pub parent_did: String,
    /// Display name for the child agent.
    #[arg(long, default_value = "Child Agent")]
    pub display_name: String,
    /// Initial TNZO budget in atto-TNZO. Defaults to 0 (no funding).
    #[arg(long, default_value = "0")]
    pub tnzo_budget: String,
    /// Parent wallet (required when --tnzo-budget > 0).
    #[arg(long)]
    pub parent_wallet: Option<String>,
    /// Unix timestamp (seconds) after which the child's identity expires.
    #[arg(long)]
    pub valid_until: Option<i64>,
    /// Runtime per-transaction TNZO ceiling for the child.
    #[arg(long)]
    pub max_per_transaction: Option<String>,
    /// Runtime rolling-day TNZO ceiling for the child.
    #[arg(long)]
    pub max_daily_spend: Option<String>,
    /// "ed25519" or "secp256k1".
    #[arg(long, default_value = "ed25519")]
    pub key_type: String,
}

impl SpawnChildCmd {
    pub async fn execute(self) -> Result<()> {
        let mut p = serde_json::Map::new();
        p.insert("parent_did".to_string(), json!(self.parent_did));
        p.insert("display_name".to_string(), json!(self.display_name));
        p.insert("tnzo_budget".to_string(), json!(self.tnzo_budget));
        if let Some(w) = self.parent_wallet {
            p.insert("parent_wallet".to_string(), json!(w));
        }
        if let Some(t) = self.valid_until {
            p.insert("valid_until".to_string(), json!(t));
        }
        if let Some(m) = self.max_per_transaction {
            p.insert("max_per_transaction".to_string(), json!(m));
        }
        if let Some(m) = self.max_daily_spend {
            p.insert("max_daily_spend".to_string(), json!(m));
        }
        p.insert("key_type".to_string(), json!(self.key_type));

        let client = rpc::RpcClient::new("http://127.0.0.1:8545");
        let result: serde_json::Value =
            client.call("tenzro_spawnChildAgent", json!(p)).await?;
        output::print_json(&result)?;
        Ok(())
    }
}
