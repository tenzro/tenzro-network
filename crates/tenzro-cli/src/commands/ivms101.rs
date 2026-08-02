//! IVMS101 Travel Rule commands.

use anyhow::Result;
use clap::{Parser, Subcommand};

use crate::output;
use crate::rpc::RpcClient;

#[derive(Debug, Subcommand)]
pub enum Ivms101Command {
    /// Compute the canonical SHA-256 hash for an IVMS101 envelope.
    /// The envelope JSON is read from `--from-file` or stdin.
    Hash(HashCmd),
}

impl Ivms101Command {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Hash(c) => c.execute().await,
        }
    }
}

fn default_rpc() -> String {
    "http://127.0.0.1:8545".to_string()
}

#[derive(Debug, Parser)]
pub struct HashCmd {
    /// File containing the IVMS101 envelope JSON (`-` for stdin).
    #[arg(long, default_value = "-")]
    from_file: String,
    #[arg(long, default_value_t = default_rpc())]
    rpc: String,
}

impl HashCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("IVMS101 — Canonical Hash");
        let raw = if self.from_file == "-" {
            use std::io::Read;
            let mut buf = String::new();
            std::io::stdin().read_to_string(&mut buf)?;
            buf
        } else {
            std::fs::read_to_string(&self.from_file)?
        };
        let envelope: serde_json::Value = serde_json::from_str(&raw)?;
        let rpc = RpcClient::new(&self.rpc);
        let v: serde_json::Value = rpc.call("tenzro_ivms101Hash", envelope).await?;
        println!("{}", serde_json::to_string_pretty(&v)?);
        Ok(())
    }
}
