//! Agent memory tier commands for the Tenzro CLI.
//!
//! - `tenzro memory grant`   — grant a memory to an agent (`tenzro_memoryGrant`)
//! - `tenzro memory recall`  — recall memories by query (`tenzro_memoryRecall`)
//! - `tenzro memory archive` — archive a record to the DA backend (`tenzro_memoryArchive`)
//! - `tenzro memory list`    — list newest-first (`tenzro_listMemoryRecords`)
//!
//! Recall mode `hybrid` (default) merges Lance vector kNN with Tantivy BM25
//! via Reciprocal Rank Fusion (k=60). `vector` and `text` restrict to one
//! backend.
//!
//! ## Auth (required)
//!
//! Every memory RPC requires DPoP+JWT bearer auth. Set
//! `TENZRO_BEARER_JWT` and `TENZRO_DPOP_PROOF` in the environment before
//! calling these commands. The server matches the bearer's DID against
//! the requested `agent_did` (or its controller) and rejects
//! cross-agent reads with `-32001`.

use anyhow::Result;
use clap::{Parser, Subcommand};

use crate::output;

/// Agent memory tier commands
#[derive(Debug, Subcommand)]
pub enum MemoryCommand {
    /// Grant a memory to an agent (writes to vector + text indices)
    Grant(MemoryGrantCmd),
    /// Recall memories for an agent (vector / text / hybrid)
    Recall(MemoryRecallCmd),
    /// Archive a memory record to the DA backend
    Archive(MemoryArchiveCmd),
    /// List newest-first memories for an agent
    List(MemoryListCmd),
}

impl MemoryCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Grant(cmd) => cmd.execute().await,
            Self::Recall(cmd) => cmd.execute().await,
            Self::Archive(cmd) => cmd.execute().await,
            Self::List(cmd) => cmd.execute().await,
        }
    }
}

/// Grant a memory to an agent.
#[derive(Debug, Parser)]
pub struct MemoryGrantCmd {
    /// Agent DID the memory belongs to
    #[arg(long)]
    agent_did: String,

    /// The text payload to remember
    #[arg(long)]
    text: String,

    /// Memory kind: granted (default), recalled, self_noted, archived
    #[arg(long, default_value = "granted")]
    kind: String,

    /// Memory source: controller (default), tool, peer, self
    #[arg(long, default_value = "controller")]
    source: String,

    /// Free-form JSON metadata (defaults to {})
    #[arg(long)]
    metadata: Option<String>,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl MemoryGrantCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Grant Agent Memory");

        let metadata: serde_json::Value = match &self.metadata {
            Some(s) => serde_json::from_str(s)?,
            None => serde_json::json!({}),
        };

        let rpc = RpcClient::new(&self.rpc);
        let spinner = output::create_spinner("Granting...");
        let result: serde_json::Value = rpc
            .call(
                "tenzro_memoryGrant",
                serde_json::json!({
                    "agent_did": self.agent_did,
                    "text": self.text,
                    "kind": self.kind,
                    "source": self.source,
                    "metadata": metadata,
                }),
            )
            .await?;
        spinner.finish_and_clear();

        output::print_success("Memory granted");
        println!();
        for (key, val) in result.as_object().unwrap_or(&serde_json::Map::new()) {
            output::print_field(key, val.to_string().trim_matches('"'));
        }
        Ok(())
    }
}

/// Recall memories for an agent.
#[derive(Debug, Parser)]
pub struct MemoryRecallCmd {
    /// Agent DID whose memory tier to search
    #[arg(long)]
    agent_did: String,

    /// Natural-language query
    #[arg(long)]
    query: String,

    /// Top-k results (default 10)
    #[arg(long, default_value = "10")]
    k: u32,

    /// Search mode: hybrid (default, RRF k=60), vector, text
    #[arg(long, default_value = "hybrid")]
    mode: String,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl MemoryRecallCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Recall Agent Memory");

        let rpc = RpcClient::new(&self.rpc);
        let spinner = output::create_spinner("Recalling...");
        let result: serde_json::Value = rpc
            .call(
                "tenzro_memoryRecall",
                serde_json::json!({
                    "agent_did": self.agent_did,
                    "query": self.query,
                    "k": self.k,
                    "mode": self.mode,
                }),
            )
            .await?;
        spinner.finish_and_clear();

        let count = result.get("count").and_then(|v| v.as_u64()).unwrap_or(0);
        output::print_field("Hits", &count.to_string());
        println!();

        let records = result
            .get("records")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        if records.is_empty() {
            output::print_warning("No memories matched.");
            return Ok(());
        }

        for (i, rec) in records.iter().enumerate() {
            println!("Memory #{}", i + 1);
            for (key, val) in rec.as_object().unwrap_or(&serde_json::Map::new()) {
                output::print_field(key, val.to_string().trim_matches('"'));
            }
            println!();
        }
        Ok(())
    }
}

/// Archive a memory record.
#[derive(Debug, Parser)]
pub struct MemoryArchiveCmd {
    /// Record id (UUID v4) to archive
    #[arg(long)]
    record_id: String,

    /// Agent DID owning the record
    #[arg(long)]
    agent_did: String,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl MemoryArchiveCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Archive Agent Memory");

        let rpc = RpcClient::new(&self.rpc);
        let spinner = output::create_spinner("Archiving...");
        let result: serde_json::Value = rpc
            .call(
                "tenzro_memoryArchive",
                serde_json::json!({
                    "record_id": self.record_id,
                    "agent_did": self.agent_did,
                }),
            )
            .await?;
        spinner.finish_and_clear();

        output::print_success("Memory archived (DA pointer attached)");
        println!();
        for (key, val) in result.as_object().unwrap_or(&serde_json::Map::new()) {
            output::print_field(key, val.to_string().trim_matches('"'));
        }
        Ok(())
    }
}

/// List newest-first memories for an agent.
#[derive(Debug, Parser)]
pub struct MemoryListCmd {
    /// Agent DID to list memories for
    #[arg(long)]
    agent_did: String,

    /// Maximum records to return (default 50)
    #[arg(long, default_value = "50")]
    limit: u32,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl MemoryListCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("List Agent Memories");

        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_listMemoryRecords",
                serde_json::json!({
                    "agent_did": self.agent_did,
                    "limit": self.limit,
                }),
            )
            .await?;

        let count = result.get("count").and_then(|v| v.as_u64()).unwrap_or(0);
        output::print_field("Total", &count.to_string());
        println!();

        let records = result
            .get("records")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        if records.is_empty() {
            output::print_warning("No memories on file.");
            return Ok(());
        }

        for (i, rec) in records.iter().enumerate() {
            println!("Memory #{}", i + 1);
            for (key, val) in rec.as_object().unwrap_or(&serde_json::Map::new()) {
                output::print_field(key, val.to_string().trim_matches('"'));
            }
            println!();
        }
        Ok(())
    }
}
