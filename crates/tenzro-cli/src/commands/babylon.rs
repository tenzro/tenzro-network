//! Babylon Bitcoin staking commands — finality-providers protocol so
//! Tenzro validators can be BTC-secured.

use anyhow::Result;
use clap::{Parser, Subcommand};

use crate::output;
use crate::rpc::RpcClient;

#[derive(Debug, Subcommand)]
pub enum BabylonCommand {
    /// Register a Tenzro validator as a Babylon finality provider
    RegisterFinalityProvider(RegisterCmd),
    /// Read the registration record for a validator
    GetFinalityProvider(ValidatorCmd),
    /// List every registered finality provider
    ListFinalityProviders(RpcOnly),
    /// Sum BTC delegations for a finality provider
    TotalStakeForProvider(ValidatorCmd),
    /// Submit an EOTS over a Tenzro block hash
    SubmitFinalitySignature(SubmitFinalityCmd),
    /// List BTC delegations for a finality provider
    ListDelegations(ValidatorCmd),
}

impl BabylonCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::RegisterFinalityProvider(c) => c.execute().await,
            Self::GetFinalityProvider(c) => {
                c.execute("tenzro_babylonGetFinalityProvider").await
            }
            Self::ListFinalityProviders(c) => c.execute().await,
            Self::TotalStakeForProvider(c) => {
                c.execute("tenzro_babylonTotalStakeForProvider").await
            }
            Self::SubmitFinalitySignature(c) => c.execute().await,
            Self::ListDelegations(c) => c.execute("tenzro_babylonListDelegations").await,
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
        output::print_header("Babylon — List Finality Providers");
        let rpc = RpcClient::new(&self.rpc);
        let v: serde_json::Value = rpc
            .call("tenzro_babylonListFinalityProviders", serde_json::json!({}))
            .await?;
        println!("{}", serde_json::to_string_pretty(&v)?);
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct RegisterCmd {
    #[arg(long)]
    validator: String,
    #[arg(long)]
    btc_pk: String,
    #[arg(long)]
    commission_bps: u32,
    #[arg(long, default_value_t = default_rpc())]
    rpc: String,
}

impl RegisterCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Babylon — Register Finality Provider");
        let rpc = RpcClient::new(&self.rpc);
        let v: serde_json::Value = rpc
            .call(
                "tenzro_babylonRegisterFinalityProvider",
                serde_json::json!({
                    "validator": self.validator,
                    "btc_pk": self.btc_pk,
                    "commission_bps": self.commission_bps,
                }),
            )
            .await?;
        println!("{}", serde_json::to_string_pretty(&v)?);
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct ValidatorCmd {
    #[arg(long)]
    validator: String,
    #[arg(long, default_value_t = default_rpc())]
    rpc: String,
}

impl ValidatorCmd {
    pub async fn execute(&self, method: &str) -> Result<()> {
        output::print_header(&format!("Babylon — {}", method));
        let rpc = RpcClient::new(&self.rpc);
        let v: serde_json::Value = rpc
            .call(method, serde_json::json!({ "validator": self.validator }))
            .await?;
        println!("{}", serde_json::to_string_pretty(&v)?);
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct SubmitFinalityCmd {
    #[arg(long)]
    validator: String,
    #[arg(long)]
    block_hash: String,
    #[arg(long)]
    eots_signature: String,
    #[arg(long, default_value_t = default_rpc())]
    rpc: String,
}

impl SubmitFinalityCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Babylon — Submit Finality Signature");
        let rpc = RpcClient::new(&self.rpc);
        let v: serde_json::Value = rpc
            .call(
                "tenzro_babylonSubmitFinalitySignature",
                serde_json::json!({
                    "validator": self.validator,
                    "block_hash": self.block_hash,
                    "eots_signature": self.eots_signature,
                }),
            )
            .await?;
        println!("{}", serde_json::to_string_pretty(&v)?);
        Ok(())
    }
}
