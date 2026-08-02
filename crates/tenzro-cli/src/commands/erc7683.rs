//! ERC-7683 cross-chain intent settler commands for the Tenzro CLI (Spec 4).
//!
//! Wraps the `tenzro_get7683Order` / `tenzro_list7683Orders` read RPCs on the
//! origin side and the `tenzro_recordFill7683` / `tenzro_getFill7683` /
//! `tenzro_listFills7683` RPCs on the destination side. The Tenzro ERC-7683
//! envelope is `Tenzro7683Order` persisted in `CF_SETTLEMENTS` under the
//! `7683_origin:` keyspace; fill records live under `7683_dest:`.
//!
//! Order state machine: `Open → AwaitingProof → Settled / Refunded /
//! ForceRefundEligible`.
//!
//! Subcommands:
//!
//! - `tenzro erc7683 get <order_id>`               — fetch persisted order envelope
//! - `tenzro erc7683 list [--state] [--dest-chain] [--limit]`
//! - `tenzro erc7683 record-fill ...`              — destination-side commit
//! - `tenzro erc7683 get-fill <order_id> <origin>` — fetch FillRecord
//! - `tenzro erc7683 list-fills`                   — list every FillRecord

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use crate::output;

/// ERC-7683 cross-chain intent settler commands
#[derive(Debug, Subcommand)]
pub enum Erc7683Command {
    /// Fetch a single Tenzro7683Order by 32-byte order_id (hex)
    Get(Erc7683GetCmd),
    /// Paginated scan over the 7683_origin: keyspace
    List(Erc7683ListCmd),
    /// Destination-side commit of a FillRecord
    RecordFill(Erc7683RecordFillCmd),
    /// Fetch a single FillRecord by (order_id, origin_chain_id)
    GetFill(Erc7683GetFillCmd),
    /// List every FillRecord in the 7683_dest: keyspace
    ListFills(Erc7683ListFillsCmd),
}

impl Erc7683Command {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Get(cmd) => cmd.execute().await,
            Self::List(cmd) => cmd.execute().await,
            Self::RecordFill(cmd) => cmd.execute().await,
            Self::GetFill(cmd) => cmd.execute().await,
            Self::ListFills(cmd) => cmd.execute().await,
        }
    }
}

#[derive(Debug, Parser)]
pub struct Erc7683GetCmd {
    /// 32-byte order id (hex, with or without 0x prefix)
    #[arg(long)]
    order_id: String,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl Erc7683GetCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        output::print_header("ERC-7683 — Order");
        let rpc = RpcClient::new(&self.rpc);
        let v: serde_json::Value = rpc
            .call(
                "tenzro_get7683Order",
                serde_json::json!({ "order_id": self.order_id }),
            )
            .await?;
        println!("{}", serde_json::to_string_pretty(&v)?);
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct Erc7683ListCmd {
    /// State filter — one of: open, awaiting_proof, settled, refunded, force_refund_eligible
    #[arg(long)]
    state: Option<String>,

    /// CAIP-2 numeric destination chain id
    #[arg(long)]
    dest_chain: Option<u32>,

    /// Maximum number of envelopes to return (default 50)
    #[arg(long)]
    limit: Option<usize>,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl Erc7683ListCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        output::print_header("ERC-7683 — Orders");
        let rpc = RpcClient::new(&self.rpc);
        let mut params = serde_json::Map::new();
        if let Some(s) = &self.state {
            params.insert("state".to_string(), serde_json::Value::String(s.clone()));
        }
        if let Some(dc) = self.dest_chain {
            params.insert("dest_chain".to_string(), serde_json::Value::from(dc));
        }
        if let Some(l) = self.limit {
            params.insert("limit".to_string(), serde_json::Value::from(l));
        }
        let v: serde_json::Value = rpc
            .call("tenzro_list7683Orders", serde_json::Value::Object(params))
            .await?;
        println!("{}", serde_json::to_string_pretty(&v)?);
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct Erc7683RecordFillCmd {
    /// 32-byte order id (hex)
    #[arg(long)]
    order_id: String,

    /// CAIP-2 numeric origin chain id
    #[arg(long)]
    origin_chain_id: u32,

    /// Origin settler contract address (hex)
    #[arg(long)]
    origin_settler: String,

    /// Filler address on the destination chain (hex)
    #[arg(long)]
    filler: String,

    /// Recipient address on the destination chain (hex)
    #[arg(long)]
    recipient: String,

    /// Destination-chain fill transaction hash (hex)
    #[arg(long)]
    fill_tx_hash: String,

    /// Wall-clock millis at which the fill landed
    #[arg(long)]
    filled_at_ms: i64,

    /// Proof route — one of: layerzero, wormhole, debridge, hyperlane
    #[arg(long)]
    proof_route: String,

    /// Path to a JSON file holding the outputs array (Vec<Erc7683Output>)
    #[arg(long)]
    outputs_json: std::path::PathBuf,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl Erc7683RecordFillCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        output::print_header("ERC-7683 — Record Fill");

        let raw = std::fs::read_to_string(&self.outputs_json)
            .with_context(|| format!("read outputs file {:?}", self.outputs_json))?;
        let outputs: serde_json::Value =
            serde_json::from_str(&raw).context("parse outputs JSON")?;

        let rpc = RpcClient::new(&self.rpc);
        let v: serde_json::Value = rpc
            .call(
                "tenzro_recordFill7683",
                serde_json::json!({
                    "order_id": self.order_id,
                    "origin_chain_id": self.origin_chain_id,
                    "origin_settler": self.origin_settler,
                    "filler": self.filler,
                    "recipient": self.recipient,
                    "fill_tx_hash": self.fill_tx_hash,
                    "filled_at_ms": self.filled_at_ms,
                    "proof_route": self.proof_route,
                    "outputs": outputs,
                }),
            )
            .await?;
        println!("{}", serde_json::to_string_pretty(&v)?);
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct Erc7683GetFillCmd {
    /// 32-byte order id (hex)
    #[arg(long)]
    order_id: String,

    /// CAIP-2 numeric origin chain id
    #[arg(long)]
    origin_chain_id: u32,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl Erc7683GetFillCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        output::print_header("ERC-7683 — FillRecord");
        let rpc = RpcClient::new(&self.rpc);
        let v: serde_json::Value = rpc
            .call(
                "tenzro_getFill7683",
                serde_json::json!({
                    "order_id": self.order_id,
                    "origin_chain_id": self.origin_chain_id,
                }),
            )
            .await?;
        println!("{}", serde_json::to_string_pretty(&v)?);
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct Erc7683ListFillsCmd {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl Erc7683ListFillsCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        output::print_header("ERC-7683 — FillRecords");
        let rpc = RpcClient::new(&self.rpc);
        let v: serde_json::Value = rpc
            .call("tenzro_listFills7683", serde_json::json!({}))
            .await?;
        println!("{}", serde_json::to_string_pretty(&v)?);
        Ok(())
    }
}
