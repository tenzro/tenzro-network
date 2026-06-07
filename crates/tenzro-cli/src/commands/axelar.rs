//! Axelar GMP commands — Cosmos / Move / Stellar / XRPL reach.

use anyhow::Result;
use clap::{Parser, Subcommand};

use crate::output;
use crate::rpc::RpcClient;

#[derive(Debug, Subcommand)]
pub enum AxelarCommand {
    /// List supported Axelar chains
    ListChains(RpcOnly),
    /// Dispatch an Axelar `call_contract` GMP message
    CallContract(CallContractCmd),
    /// Pre-pay the Gas Service for a previously-dispatched message
    PayGas(PayGasCmd),
    /// Look up a Axelar GMP message by payload hash
    GetMessage(GetMessageCmd),
}

impl AxelarCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::ListChains(c) => c.execute().await,
            Self::CallContract(c) => c.execute().await,
            Self::PayGas(c) => c.execute().await,
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
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Axelar — List Chains");
        let rpc = RpcClient::new(&self.rpc);
        let v: serde_json::Value = rpc
            .call("tenzro_axelarListChains", serde_json::json!({}))
            .await?;
        println!("{}", serde_json::to_string_pretty(&v)?);
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct CallContractCmd {
    #[arg(long)]
    source_chain: String,
    #[arg(long)]
    destination_chain: String,
    #[arg(long)]
    destination_address: String,
    #[arg(long)]
    payload_hex: String,
    #[arg(long)]
    gas_token: Option<String>,
    #[arg(long)]
    gas_amount: Option<String>,
    #[arg(long, default_value_t = default_rpc())]
    rpc: String,
}

impl CallContractCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Axelar — Call Contract");
        let rpc = RpcClient::new(&self.rpc);
        let mut params = serde_json::json!({
            "source_chain": self.source_chain,
            "destination_chain": self.destination_chain,
            "destination_address": self.destination_address,
            "payload_hex": self.payload_hex,
        });
        if let Some(t) = &self.gas_token {
            params["gas_token"] = serde_json::Value::String(t.clone());
        }
        if let Some(a) = &self.gas_amount {
            params["gas_amount"] = serde_json::Value::String(a.clone());
        }
        let v: serde_json::Value = rpc.call("tenzro_axelarCallContract", params).await?;
        println!("{}", serde_json::to_string_pretty(&v)?);
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct PayGasCmd {
    #[arg(long)]
    payload_hash: String,
    #[arg(long)]
    source_chain: String,
    #[arg(long)]
    destination_chain: String,
    #[arg(long)]
    destination_address: String,
    #[arg(long)]
    gas_token: String,
    #[arg(long)]
    gas_amount: String,
    #[arg(long, default_value_t = default_rpc())]
    rpc: String,
}

impl PayGasCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Axelar — Pay Gas");
        let rpc = RpcClient::new(&self.rpc);
        let v: serde_json::Value = rpc
            .call(
                "tenzro_axelarPayGas",
                serde_json::json!({
                    "payload_hash": self.payload_hash,
                    "source_chain": self.source_chain,
                    "destination_chain": self.destination_chain,
                    "destination_address": self.destination_address,
                    "gas_token": self.gas_token,
                    "gas_amount": self.gas_amount,
                }),
            )
            .await?;
        println!("{}", serde_json::to_string_pretty(&v)?);
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct GetMessageCmd {
    #[arg(long)]
    payload_hash: String,
    #[arg(long, default_value_t = default_rpc())]
    rpc: String,
}

impl GetMessageCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Axelar — Get Message");
        let rpc = RpcClient::new(&self.rpc);
        let v: serde_json::Value = rpc
            .call(
                "tenzro_axelarGetMessage",
                serde_json::json!({ "payload_hash": self.payload_hash }),
            )
            .await?;
        println!("{}", serde_json::to_string_pretty(&v)?);
        Ok(())
    }
}
