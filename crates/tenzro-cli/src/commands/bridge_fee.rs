//! Bridge fee in TNZO commands.

use anyhow::Result;
use clap::{Parser, Subcommand};

use crate::output;
use crate::rpc::RpcClient;

#[derive(Debug, Subcommand)]
pub enum BridgeFeeCommand {
    /// Quote a destination-native bridge fee in TNZO
    Quote(QuoteCmd),
    /// Enumerate per-adapter sponsorship-pool vault addresses
    ListPools(ListPoolsCmd),
    /// (Admin) Register a governance-set rate row
    SetRate(SetRateCmd),
    /// Sponsor a previously-quoted destination-native fee
    Sponsor(SponsorCmd),
    /// (Admin) Set the refill-threshold for an adapter's pool
    SetRefill(SetRefillCmd),
    /// Subject self-read: caller's own Chainlink/bridge analytics
    Analytics(AnalyticsCmd),
    /// (Admin) Cross-tenant Chainlink/bridge analytics
    ListAnalytics(ListAnalyticsCmd),
}

impl BridgeFeeCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Quote(c) => c.execute().await,
            Self::ListPools(c) => c.execute().await,
            Self::SetRate(c) => c.execute().await,
            Self::Sponsor(c) => c.execute().await,
            Self::SetRefill(c) => c.execute().await,
            Self::Analytics(c) => c.execute().await,
            Self::ListAnalytics(c) => c.execute().await,
        }
    }
}

fn default_rpc() -> String {
    "http://127.0.0.1:8545".to_string()
}

#[derive(Debug, Parser)]
pub struct QuoteCmd {
    /// Bridge adapter: layerzero | ccip | wormhole | debridge | hyperlane | axelar | lifi | canton
    #[arg(long)]
    adapter: String,
    /// Destination chain CAIP-2 identifier (e.g. eip155:1, solana:mainnet-beta)
    #[arg(long)]
    dest_chain: String,
    /// Destination-native fee in the destination chain smallest unit (u128 decimal)
    #[arg(long)]
    native_fee: String,
    #[arg(long, default_value_t = default_rpc())]
    rpc: String,
}

impl QuoteCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Bridge Fee in TNZO — Quote");
        let rpc = RpcClient::new(&self.rpc);
        let v: serde_json::Value = rpc
            .call(
                "tenzro_quoteBridgeFeeInTnzo",
                serde_json::json!({
                    "adapter": self.adapter,
                    "dest_chain": self.dest_chain,
                    "native_fee_smallest_unit": self.native_fee,
                }),
            )
            .await?;
        println!("{}", serde_json::to_string_pretty(&v)?);
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct ListPoolsCmd {
    #[arg(long, default_value_t = default_rpc())]
    rpc: String,
}

impl ListPoolsCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Bridge Sponsorship Pools");
        let rpc = RpcClient::new(&self.rpc);
        let v: serde_json::Value = rpc
            .call("tenzro_listBridgeSponsorshipPools", serde_json::Value::Null)
            .await?;
        println!("{}", serde_json::to_string_pretty(&v)?);
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct SetRateCmd {
    #[arg(long)]
    adapter: String,
    #[arg(long)]
    dest_chain: String,
    /// Q18 fixed-point rate as decimal string (e.g. 2 * 10^18 for rate 2.0).
    #[arg(long)]
    rate_q18: String,
    #[arg(long, default_value_t = 100)]
    markup_bps: u32,
    #[arg(long, default_value_t = 60_000)]
    valid_window_ms: u64,
    /// Admin token (required; method is admin-gated).
    #[arg(long, env = "TENZRO_ADMIN_TOKEN")]
    admin_token: String,
    #[arg(long, default_value_t = default_rpc())]
    rpc: String,
}

impl SetRateCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Bridge Fee — Set Governance Rate");
        let rpc = RpcClient::new(&self.rpc).with_admin_token(&self.admin_token);
        let v: serde_json::Value = rpc
            .call(
                "tenzro_setBridgeFeeRate",
                serde_json::json!([{
                    "adapter": self.adapter,
                    "dest_chain": self.dest_chain,
                    "rate_q18": self.rate_q18,
                    "markup_bps": self.markup_bps,
                    "valid_window_ms": self.valid_window_ms,
                }]),
            )
            .await?;
        println!("{}", serde_json::to_string_pretty(&v)?);
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct SponsorCmd {
    #[arg(long)]
    quote_id_hex: String,
    #[arg(long)]
    adapter: String,
    #[arg(long)]
    dest_chain: String,
    #[arg(long)]
    native_fee_smallest_unit: String,
    #[arg(long)]
    tnzo_amount_wei: String,
    #[arg(long)]
    rate_q18_hex: String,
    #[arg(long)]
    issued_at_ms: u64,
    #[arg(long)]
    valid_until_ms: u64,
    #[arg(long, default_value = "governance")]
    oracle_backing: String,
    #[arg(long)]
    payer_did: String,
    /// API key with `chainlink` scope.
    #[arg(long, env = "TENZRO_API_KEY")]
    api_key: Option<String>,
    #[arg(long, default_value_t = default_rpc())]
    rpc: String,
}

impl SponsorCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Bridge Fee — Sponsor Quote");
        let mut rpc = RpcClient::new(&self.rpc);
        if let Some(k) = &self.api_key {
            rpc = rpc.with_api_key(k);
        }
        let v: serde_json::Value = rpc
            .call(
                "tenzro_sponsorBridgeFee",
                serde_json::json!([{
                    "quote_id_hex": self.quote_id_hex,
                    "adapter": self.adapter,
                    "dest_chain": self.dest_chain,
                    "native_fee_smallest_unit": self.native_fee_smallest_unit,
                    "tnzo_amount_wei": self.tnzo_amount_wei,
                    "rate_q18_hex": self.rate_q18_hex,
                    "issued_at_ms": self.issued_at_ms,
                    "valid_until_ms": self.valid_until_ms,
                    "oracle_backing": self.oracle_backing,
                    "payer_did": self.payer_did,
                }]),
            )
            .await?;
        println!("{}", serde_json::to_string_pretty(&v)?);
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct SetRefillCmd {
    #[arg(long)]
    adapter: String,
    #[arg(long)]
    refill_threshold_bps: u32,
    /// Admin token (required; method is admin-gated).
    #[arg(long, env = "TENZRO_ADMIN_TOKEN")]
    admin_token: String,
    #[arg(long, default_value_t = default_rpc())]
    rpc: String,
}

impl SetRefillCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Bridge Fee — Set Sponsorship Refill Threshold");
        let rpc = RpcClient::new(&self.rpc).with_admin_token(&self.admin_token);
        let v: serde_json::Value = rpc
            .call(
                "tenzro_setSponsorshipRefillThreshold",
                serde_json::json!([{
                    "adapter": self.adapter,
                    "refill_threshold_bps": self.refill_threshold_bps,
                }]),
            )
            .await?;
        println!("{}", serde_json::to_string_pretty(&v)?);
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct AnalyticsCmd {
    /// API key with `chainlink` scope (subject self-read).
    #[arg(long, env = "TENZRO_API_KEY")]
    api_key: String,
    #[arg(long, default_value_t = default_rpc())]
    rpc: String,
}

impl AnalyticsCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Bridge Analytics — Subject Self-Read");
        let rpc = RpcClient::new(&self.rpc).with_api_key(&self.api_key);
        let v: serde_json::Value = rpc
            .call("tenzro_getBridgeAnalytics", serde_json::Value::Null)
            .await?;
        println!("{}", serde_json::to_string_pretty(&v)?);
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct ListAnalyticsCmd {
    /// Admin token (cross-tenant operator read).
    #[arg(long, env = "TENZRO_ADMIN_TOKEN")]
    admin_token: String,
    /// Optional key_id filter.
    #[arg(long)]
    key_id: Option<String>,
    #[arg(long, default_value_t = default_rpc())]
    rpc: String,
}

impl ListAnalyticsCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Bridge Analytics — Operator List");
        let rpc = RpcClient::new(&self.rpc).with_admin_token(&self.admin_token);
        let params = if let Some(k) = &self.key_id {
            serde_json::json!({ "key_id": k })
        } else {
            serde_json::Value::Null
        };
        let v: serde_json::Value = rpc.call("tenzro_listBridgeAnalytics", params).await?;
        println!("{}", serde_json::to_string_pretty(&v)?);
        Ok(())
    }
}
