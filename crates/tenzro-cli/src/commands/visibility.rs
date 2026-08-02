//! `tenzro visibility` — what this node tells the network it has.
//!
//! Discovery, not access. A private capability serves the same callers at the
//! same speed; it just stops publishing "here is what I have" to peers. An
//! operator who marks something private and believes it is thereby protected
//! has misread it, so every output here says so.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use crate::output;
use crate::rpc::RpcClient;

/// Control what this node advertises to the network
#[derive(Debug, Subcommand)]
pub enum VisibilityCommand {
    /// Show each capability and whether it is advertised
    Show(ShowCmd),
    /// Stop advertising a capability (or all of them)
    Hide(HideCmd),
    /// Resume advertising a capability (or all of them)
    Publish(PublishCmd),
}

impl VisibilityCommand {
    pub async fn execute(self) -> Result<()> {
        match self {
            Self::Show(c) => c.execute().await,
            Self::Hide(c) => c.execute(true).await,
            Self::Publish(c) => c.execute(false).await,
        }
    }
}

fn client(rpc: &str, admin_token: Option<&str>) -> RpcClient {
    let c = RpcClient::new(rpc);
    match admin_token {
        Some(t) => c.with_admin_token(t.to_string()),
        None => c,
    }
}

fn render(v: &serde_json::Value) {
    println!();
    for cap in v["capabilities"].as_array().unwrap_or(&vec![]) {
        let name = cap["capability"].as_str().unwrap_or("?");
        let advertised = cap["advertised"].as_bool().unwrap_or(true);
        let fixed = !cap["can_be_private"].as_bool().unwrap_or(true);
        let state = if advertised {
            "advertised"
        } else {
            "private   "
        };
        let note = if fixed { "  (cannot be private)" } else { "" };
        output::print_field(name, &format!("{state}{note}"));
    }
    if v["has_private_capabilities"].as_bool().unwrap_or(false) {
        println!();
        output::print_warning(
            "Private controls discovery, not access. Anyone who learns this node's address and \
             holds the required credential can still use these — gate with API-key scopes and \
             service keys.",
        );
    }
}

#[derive(Debug, Parser)]
pub struct ShowCmd {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ShowCmd {
    pub async fn execute(self) -> Result<()> {
        output::print_header("Node Visibility");
        let v: serde_json::Value = client(&self.rpc, None)
            .call("tenzro_nodeVisibility", serde_json::json!({}))
            .await
            .context("reading node visibility")?;
        render(&v);
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct HideCmd {
    /// Capability to hide: ai | storage | database | hosting | rpc | tee |
    /// compute. Omit with --all to hide everything that can be hidden.
    capability: Option<String>,
    /// Hide every capability that can be hidden. Consensus stays advertised —
    /// a validator its peers cannot reach cannot vote.
    #[arg(long)]
    all: bool,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
    /// Operator admin token. Falls back to `TENZRO_ADMIN_TOKEN`.
    #[arg(long)]
    admin_token: Option<String>,
}

#[derive(Debug, Parser)]
pub struct PublishCmd {
    /// Capability to advertise again.
    capability: Option<String>,
    /// Advertise everything.
    #[arg(long)]
    all: bool,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
    /// Operator admin token. Falls back to `TENZRO_ADMIN_TOKEN`.
    #[arg(long)]
    admin_token: Option<String>,
}

macro_rules! impl_set {
    ($t:ty) => {
        impl $t {
            pub async fn execute(self, hide: bool) -> Result<()> {
                let params = if self.all {
                    serde_json::json!({ "preset": if hide { "private" } else { "public" } })
                } else {
                    let cap = self.capability.as_deref().context(
                        "name a capability, or pass --all. \
                         One of: ai, storage, database, hosting, rpc, tee, compute",
                    )?;
                    serde_json::json!({
                        "capability": cap,
                        "visibility": if hide { "private" } else { "network" },
                    })
                };
                output::print_header("Node Visibility");
                let result: Result<serde_json::Value> =
                    client(&self.rpc, self.admin_token.as_deref())
                        .call("tenzro_setNodeVisibility", params)
                        .await;
                match result {
                    Ok(v) => {
                        render(&v);
                        Ok(())
                    }
                    // A refusal is an answer, not a crash. Hiding a validator
                    // is legitimately refused, and an operator who asked for it
                    // needs the reason — not a backtrace with the reason
                    // somewhere inside it.
                    Err(e) => {
                        println!();
                        output::print_error(&e.to_string());
                        Ok(())
                    }
                }
            }
        }
    };
}

impl_set!(HideCmd);
impl_set!(PublishCmd);
