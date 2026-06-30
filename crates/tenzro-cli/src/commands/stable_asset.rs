//! Stable-asset issuance commands — issuer-agnostic stable-unit policies on
//! top of the Secure-Mint reserve floor.
//!
//! An issuer registers a unit (`register`), then mints (`mint`) and redeems
//! (`redeem`) against it. Mints are hard-gated by the Secure-Mint reserve
//! floor installed on the same `unit_token`, so a mint that would push
//! circulating above the attested reserve is rejected.

use anyhow::Result;
use clap::{Parser, Subcommand};

use crate::output;
use crate::rpc::RpcClient;

#[derive(Debug, Subcommand)]
pub enum StableAssetCommand {
    /// Register or replace an issuer's stable-asset policy (needs `issuer` scope)
    Register(RegisterCmd),
    /// Read an issuer's stable-asset policy
    Get(IssuerUnitCmd),
    /// Mint units (gated by the Secure-Mint reserve floor)
    Mint(IssuerUnitAmountCmd),
    /// Redeem (burn) units, decrementing circulating supply
    Redeem(IssuerUnitAmountCmd),
}

impl StableAssetCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Register(c) => c.execute().await,
            Self::Get(c) => c.execute("tenzro_getStableAsset").await,
            Self::Mint(c) => c.execute("tenzro_mintStableAsset").await,
            Self::Redeem(c) => c.execute("tenzro_redeemStableAsset").await,
        }
    }
}

fn default_rpc() -> String {
    "http://127.0.0.1:8545".to_string()
}

#[derive(Debug, Parser)]
pub struct RegisterCmd {
    /// Issuer address, 32-byte hex
    #[arg(long)]
    issuer: String,
    /// Unit token address, 20-byte hex
    #[arg(long)]
    unit_token: String,
    /// Human label for the unit (e.g. "USDX")
    #[arg(long)]
    symbol: String,
    /// Reserve source: "custodial" or "on_chain_vault"
    #[arg(long, default_value = "custodial")]
    reserve_kind: String,
    /// Custodial attester DID (for reserve_kind=custodial)
    #[arg(long)]
    attester_did: Option<String>,
    /// On-chain vault address, 32-byte hex (for reserve_kind=on_chain_vault)
    #[arg(long)]
    vault: Option<String>,
    /// Backing asset, CAIP-19 (e.g. "iso4217:USD")
    #[arg(long)]
    asset_caip19: String,
    /// Proof-of-reserve feed id
    #[arg(long)]
    por_feed_id: String,
    /// Allowed settlement rails (repeatable): x402 ap2 mpp visa_tap mastercard tempo open_standard native
    #[arg(long = "rail", required = true)]
    rails: Vec<String>,
    /// Settlement destination address, 32-byte hex
    #[arg(long)]
    settlement_dst: String,
    #[arg(long, default_value_t = default_rpc())]
    rpc: String,
}

impl RegisterCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Stable-Asset — Register");
        let rpc = RpcClient::new(&self.rpc);

        let reserve_source = match self.reserve_kind.as_str() {
            "custodial" => serde_json::json!({
                "kind": "custodial",
                "attester_did": self.attester_did.as_deref().unwrap_or_default(),
                "asset_caip19": self.asset_caip19,
            }),
            "on_chain_vault" => serde_json::json!({
                "kind": "on_chain_vault",
                "vault": self.vault.as_deref().unwrap_or_default(),
                "asset_caip19": self.asset_caip19,
            }),
            other => anyhow::bail!("reserve_kind must be \"custodial\" or \"on_chain_vault\", got {other}"),
        };

        let params = serde_json::json!({
            "issuer": self.issuer,
            "unit_token": self.unit_token,
            "symbol": self.symbol,
            "reserve_source": reserve_source,
            "por_feed_id": self.por_feed_id,
            "allowed_rails": self.rails,
            "settlement_dst": self.settlement_dst,
        });
        let v: serde_json::Value = rpc.call("tenzro_registerStableAsset", params).await?;
        println!("{}", serde_json::to_string_pretty(&v)?);
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct IssuerUnitCmd {
    #[arg(long)]
    issuer: String,
    #[arg(long)]
    unit_token: String,
    #[arg(long, default_value_t = default_rpc())]
    rpc: String,
}

impl IssuerUnitCmd {
    pub async fn execute(&self, method: &str) -> Result<()> {
        output::print_header(&format!("Stable-Asset — {}", method));
        let rpc = RpcClient::new(&self.rpc);
        let v: serde_json::Value = rpc
            .call(
                method,
                serde_json::json!({ "issuer": self.issuer, "unit_token": self.unit_token }),
            )
            .await?;
        println!("{}", serde_json::to_string_pretty(&v)?);
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct IssuerUnitAmountCmd {
    #[arg(long)]
    issuer: String,
    #[arg(long)]
    unit_token: String,
    #[arg(long)]
    amount: String,
    #[arg(long, default_value_t = default_rpc())]
    rpc: String,
}

impl IssuerUnitAmountCmd {
    pub async fn execute(&self, method: &str) -> Result<()> {
        output::print_header(&format!("Stable-Asset — {}", method));
        let rpc = RpcClient::new(&self.rpc);
        let v: serde_json::Value = rpc
            .call(
                method,
                serde_json::json!({
                    "issuer": self.issuer,
                    "unit_token": self.unit_token,
                    "amount": self.amount,
                }),
            )
            .await?;
        println!("{}", serde_json::to_string_pretty(&v)?);
        Ok(())
    }
}
