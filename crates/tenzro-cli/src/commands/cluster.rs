//! Local-network cluster planning commands. Computes a deterministic layer
//! placement for a model across a set of candidate members.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use crate::{output, rpc};

#[derive(Debug, Subcommand)]
pub enum ClusterCommand {
    /// List the verified members of a cluster (this node's own by default),
    /// with the hardware of those found on the local network.
    Members(MembersCmd),
    /// Create a cluster or change its members: derive the cluster DID and the
    /// digests the operator's passkey and each member machine must sign
    Derive(DeriveCmd),
    /// Accept this machine's inclusion in a cluster list, signed by its own
    /// hardware key (node administrators only)
    Accept(AcceptCmd),
    /// Submit an operator-approved, member-accepted membership list
    Set(SetCmd),
}

impl ClusterCommand {
    pub async fn execute(self) -> Result<()> {
        match self {
            Self::Members(cmd) => cmd.execute().await,
            Self::Derive(cmd) => cmd.execute().await,
            Self::Accept(cmd) => cmd.execute().await,
            Self::Set(cmd) => cmd.execute().await,
        }
    }
}

#[derive(Debug, Parser)]
pub struct DeriveCmd {
    /// The operator's human DID
    #[arg(long)]
    operator_did: String,
    /// Cluster name
    #[arg(long)]
    name: String,
    /// Sequence number: 1 creates the cluster, each change uses a higher one
    #[arg(long)]
    seq: u64,
    /// Member machine DIDs (repeat for each member)
    #[arg(long = "member", required = true)]
    members: Vec<String>,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl DeriveCmd {
    pub async fn execute(self) -> Result<()> {
        let rpc = rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_deriveClusterMembership",
                serde_json::json!({
                    "operator_did": self.operator_did,
                    "name": self.name,
                    "seq": self.seq,
                    "members": self.members,
                }),
            )
            .await?;
        output::print_json(&result)
    }
}

#[derive(Debug, Parser)]
pub struct AcceptCmd {
    /// The cluster DID
    #[arg(long)]
    cluster_did: String,
    /// Sequence number of the list being accepted
    #[arg(long)]
    seq: u64,
    /// RPC endpoint of the member machine
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl AcceptCmd {
    pub async fn execute(self) -> Result<()> {
        let rpc = rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_acceptClusterMembership",
                serde_json::json!({ "cluster_did": self.cluster_did, "seq": self.seq }),
            )
            .await?;
        output::print_json(&result)
    }
}

#[derive(Debug, Parser)]
pub struct SetCmd {
    /// Path to a JSON file holding the signed membership list
    #[arg(long)]
    membership: String,
    /// The custody challenge id the operator's approval answers
    #[arg(long)]
    challenge_id: String,
    /// RPC endpoint (the node that issued the custody challenge)
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl SetCmd {
    pub async fn execute(self) -> Result<()> {
        let raw = std::fs::read_to_string(&self.membership)
            .with_context(|| format!("reading membership file '{}'", self.membership))?;
        let membership: serde_json::Value = serde_json::from_str(&raw)
            .with_context(|| format!("parsing membership file '{}' as JSON", self.membership))?;
        let rpc = rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_setClusterMembership",
                serde_json::json!({ "membership": membership, "challenge_id": self.challenge_id }),
            )
            .await?;
        output::print_json(&result)
    }
}

#[derive(Debug, Parser)]
pub struct MembersCmd {
    /// Cluster DID to list (defaults to this node's own cluster)
    #[arg(long)]
    cluster_did: Option<String>,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl MembersCmd {
    pub async fn execute(self) -> Result<()> {
        output::print_header("Cluster Members");

        let spinner = output::create_spinner("Discovering members on the local network...");
        let rpc = rpc::RpcClient::new(&self.rpc);
        let result: Result<serde_json::Value> = rpc
            .call(
                "tenzro_clusterMembers",
                serde_json::json!({ "entry": self.cluster_did }),
            )
            .await;
        spinner.finish_and_clear();

        let value = match result {
            Ok(v) => v,
            Err(e) => {
                output::print_error(&format!("Failed to discover cluster members: {}", e));
                return Ok(());
            }
        };

        println!();
        if let Some(did) = value.get("cluster_did").and_then(|v| v.as_str()) {
            output::print_field("Cluster", if did.is_empty() { "(none)" } else { did });
        }
        if let Some(verified) = value.get("verified_members").and_then(|v| v.as_array()) {
            output::print_field("Verified members", &verified.len().to_string());
            for did in verified.iter().filter_map(|v| v.as_str()) {
                output::print_field("  member", did);
            }
        }
        if let Some(n) = value.get("member_count").and_then(|v| v.as_u64()) {
            output::print_field("Found", &n.to_string());
        }
        if let Some(n) = value.get("local_count").and_then(|v| v.as_u64()) {
            output::print_field("On LAN", &n.to_string());
        }
        if let Some(g) = value.get("total_vram_gb").and_then(|v| v.as_f64()) {
            output::print_field("Pooled Memory", &format!("{:.1} GB", g));
        }

        if let Some(members) = value.get("members").and_then(|v| v.as_array()) {
            println!();
            for m in members {
                let address = m.get("address").and_then(|v| v.as_str()).unwrap_or("?");
                let vram = m.get("vram_gb").and_then(|v| v.as_f64()).unwrap_or(0.0);
                let backend = m.get("backend").and_then(|v| v.as_str()).unwrap_or("?");
                let reach = m
                    .get("reachability")
                    .and_then(|v| v.as_str())
                    .unwrap_or("?");
                let head = if m.get("is_head").and_then(|v| v.as_bool()).unwrap_or(false) {
                    " [head]"
                } else {
                    ""
                };
                output::print_field(
                    &format!("  {}", address),
                    &format!("{:.1} GB {} {}{}", vram, backend, reach, head),
                );
            }
        }

        Ok(())
    }
}
