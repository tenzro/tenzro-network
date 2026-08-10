//! Hyperlane V3 messaging commands — sovereign Tenzro-validator-set ISM.

use anyhow::Result;
use clap::{Parser, Subcommand};

use crate::output;
use crate::rpc::RpcClient;

#[derive(Debug, Subcommand)]
pub enum HyperlaneCommand {
    /// List supported Hyperlane chains and their canonical domain ids
    ListChains(RpcOnly),
    /// Quote the interchain gas payment for a dispatch
    QuoteDispatch(DispatchCmd),
    /// Dispatch a Hyperlane message
    Dispatch(DispatchCmd),
    /// Look up a Hyperlane message by id
    GetMessage(GetMessageCmd),
}

impl HyperlaneCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::ListChains(c) => c.execute("tenzro_hyperlaneListChains").await,
            Self::QuoteDispatch(c) => c.execute("tenzro_hyperlaneQuoteDispatch").await,
            Self::Dispatch(c) => c.execute("tenzro_hyperlaneDispatch").await,
            Self::GetMessage(c) => c.execute().await,
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
    pub async fn execute(&self, method: &str) -> Result<()> {
        output::print_header(&format!("Hyperlane — {}", method));
        let rpc = RpcClient::new(&self.rpc);
        let v: serde_json::Value = rpc.call(method, serde_json::json!({})).await?;
        println!("{}", serde_json::to_string_pretty(&v)?);
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct DispatchCmd {
    #[arg(long)]
    origin_domain: u32,
    #[arg(long)]
    destination_domain: u32,
    #[arg(long)]
    recipient: String,
    #[arg(long)]
    body_hex: String,
    #[arg(long)]
    sender: Option<String>,
    #[arg(long)]
    interchain_gas_payment: Option<String>,
    #[arg(long, default_value_t = default_rpc())]
    rpc: String,
}

impl DispatchCmd {
    pub async fn execute(&self, method: &str) -> Result<()> {
        output::print_header(&format!("Hyperlane — {}", method));
        let rpc = RpcClient::new(&self.rpc);
        let mut params = serde_json::json!({
            "origin_domain": self.origin_domain,
            "destination_domain": self.destination_domain,
            "recipient": self.recipient,
            "body_hex": self.body_hex,
        });
        if let Some(s) = &self.sender {
            params["sender"] = serde_json::Value::String(s.clone());
        }
        if let Some(p) = &self.interchain_gas_payment {
            params["interchain_gas_payment"] = serde_json::Value::String(p.clone());
        }
        let v: serde_json::Value = rpc.call(method, params).await?;
        println!("{}", serde_json::to_string_pretty(&v)?);
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct GetMessageCmd {
    #[arg(long)]
    message_id: String,
    #[arg(long, default_value_t = default_rpc())]
    rpc: String,
}

impl GetMessageCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Hyperlane — Get Message");
        let rpc = RpcClient::new(&self.rpc);
        let v: serde_json::Value = rpc
            .call(
                "tenzro_hyperlaneGetMessage",
                serde_json::json!({ "message_id": self.message_id }),
            )
            .await?;
        println!("{}", serde_json::to_string_pretty(&v)?);
        Ok(())
    }
}
