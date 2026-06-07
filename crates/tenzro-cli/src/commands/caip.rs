//! Tenzro CAIP discovery commands per `ChainAgnostic/namespaces#184`.

use anyhow::Result;
use clap::{Parser, Subcommand};

use crate::output;
use crate::rpc::RpcClient;

#[derive(Debug, Subcommand)]
pub enum CaipCommand {
    /// CAIP-2 chain identifier for the connected node
    Caip2(RpcOnly),
    /// CAIP-10 account identifier for a Tenzro address
    Caip10(Caip10Cmd),
    /// CAIP-19 asset identifier
    Caip19(Caip19Cmd),
}

impl CaipCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Caip2(c) => c.execute().await,
            Self::Caip10(c) => c.execute().await,
            Self::Caip19(c) => c.execute().await,
        }
    }
}

fn default_rpc() -> String {
    "http://127.0.0.1:8545".to_string()
}

#[derive(Debug, Parser)]
pub struct RpcOnly {
    #[arg(long, default_value_t = default_rpc())]
    rpc: String,
}

impl RpcOnly {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("CAIP-2");
        let rpc = RpcClient::new(&self.rpc);
        let v: serde_json::Value = rpc.call("tenzro_caip2", serde_json::json!({})).await?;
        println!("{}", serde_json::to_string_pretty(&v)?);
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct Caip10Cmd {
    #[arg(long)]
    address: String,
    #[arg(long, default_value_t = default_rpc())]
    rpc: String,
}

impl Caip10Cmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("CAIP-10");
        let rpc = RpcClient::new(&self.rpc);
        let v: serde_json::Value = rpc
            .call(
                "tenzro_caip10",
                serde_json::json!({ "address": self.address }),
            )
            .await?;
        println!("{}", serde_json::to_string_pretty(&v)?);
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct Caip19Cmd {
    /// One of `slip44`, `token`, `nft`
    #[arg(long)]
    kind: String,
    /// 32-byte token registry id (hex) — required for kind=token, kind=nft (as collection)
    #[arg(long)]
    token_id: Option<String>,
    /// NFT collection id (hex) — alias for kind=nft
    #[arg(long)]
    collection_id: Option<String>,
    /// NFT token id (decimal or hex) — required for kind=nft
    #[arg(long)]
    nft_token_id: Option<String>,
    #[arg(long, default_value_t = default_rpc())]
    rpc: String,
}

impl Caip19Cmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("CAIP-19");
        let rpc = RpcClient::new(&self.rpc);
        let mut params = serde_json::json!({ "kind": self.kind });
        if let Some(t) = &self.token_id {
            params["token_id"] = serde_json::Value::String(t.clone());
        }
        if let Some(c) = &self.collection_id {
            params["collection_id"] = serde_json::Value::String(c.clone());
        }
        if let Some(n) = &self.nft_token_id {
            params["nft_token_id"] = serde_json::Value::String(n.clone());
        }
        let v: serde_json::Value = rpc.call("tenzro_caip19", params).await?;
        println!("{}", serde_json::to_string_pretty(&v)?);
        Ok(())
    }
}
