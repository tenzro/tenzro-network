//! Tenzro KERI Key Event Log helpers.

use anyhow::Result;
use clap::{Parser, Subcommand};

use crate::output;
use crate::rpc::RpcClient;

#[derive(Debug, Subcommand)]
pub enum KeriCommand {
    /// Build a KERI inception event.
    BuildInception(BuildInceptionCmd),
}

impl KeriCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::BuildInception(c) => c.execute().await,
        }
    }
}

fn default_rpc() -> String {
    "http://127.0.0.1:8545".to_string()
}

#[derive(Debug, Parser)]
pub struct BuildInceptionCmd {
    #[arg(long, default_value_t = default_rpc())]
    rpc: String,
    /// Comma-separated hex-encoded signing-key public bytes.
    #[arg(long)]
    signing_keys_hex: String,
    /// Comma-separated hex-encoded SHA-256 digests of next signing keys.
    #[arg(long)]
    next_key_digests_hex: String,
    /// Signing threshold (default = number of keys).
    #[arg(long)]
    signing_threshold: Option<u8>,
    /// Next-key threshold (default = number of digests).
    #[arg(long)]
    next_threshold: Option<u8>,
}

impl BuildInceptionCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("KERI Inception");
        let signing_keys: Vec<String> = self
            .signing_keys_hex
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        let next_digests: Vec<String> = self
            .next_key_digests_hex
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        let rpc = RpcClient::new(&self.rpc);
        let mut params = serde_json::json!({
            "signing_keys_hex": signing_keys,
            "next_key_digests_hex": next_digests,
        });
        if let Some(t) = self.signing_threshold {
            params["signing_threshold"] = serde_json::Value::from(t);
        }
        if let Some(t) = self.next_threshold {
            params["next_threshold"] = serde_json::Value::from(t);
        }
        let out: serde_json::Value = rpc.call("tenzro_keriBuildInception", params).await?;
        println!("{}", serde_json::to_string_pretty(&out)?);
        Ok(())
    }
}
