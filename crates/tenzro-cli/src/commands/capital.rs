//! Capital Intent commands — Tenzro's capital-allocation standard for tokenized
//! assets. Thin JSON-RPC clients over the `tenzro_capitalIntent*` family
//! (`docs/architecture/capital-intent.md`). The intent itself is the
//! regulated-capital-markets analog of an AP2 Intent Mandate.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use crate::output;
use crate::rpc::RpcClient;

const DEFAULT_RPC: &str = "http://127.0.0.1:8545";

/// Capital Intent operations.
#[derive(Debug, Subcommand)]
pub enum CapitalCommand {
    /// Open a signed Capital Intent from a JSON object (inline or @file).
    Open(CapitalOpenCmd),
    /// Submit a solver bid to fulfil an intent.
    Quote(CapitalQuoteCmd),
    /// Assign a solver (optionally locking the principal escrow).
    Assign(CapitalAssignCmd),
    /// Record one executed settlement leg.
    Execute(CapitalExecuteCmd),
    /// Verify proofs (requires all legs settled).
    Verify(CapitalIdCmd),
    /// Settle: release escrow to the solver + finalize.
    Settle(CapitalSettleCmd),
    /// Compensate: refund the principal escrow and fail the intent.
    Compensate(CapitalIdCmd),
    /// Read a capital intent record.
    Get(CapitalIdCmd),
    /// Submit a Proof-of-Reserve attestation backing a tokenized asset.
    ReserveSubmit(CapitalReserveSubmitCmd),
    /// Attested mint — mint only if backed by attested reserves (1:1).
    Mint(CapitalMintCmd),
    /// Read the current reserve attestation.
    GetReserve(CapitalGetReserveCmd),
}

impl CapitalCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Open(c) => c.execute().await,
            Self::Quote(c) => c.execute().await,
            Self::Assign(c) => c.execute().await,
            Self::Execute(c) => c.execute().await,
            Self::Verify(c) => c.execute("tenzro_capitalIntentVerify", "Verify").await,
            Self::Settle(c) => c.execute().await,
            Self::Compensate(c) => c.execute("tenzro_capitalIntentCompensate", "Compensate").await,
            Self::Get(c) => c.execute("tenzro_getCapitalIntent", "Capital Intent").await,
            Self::ReserveSubmit(c) => c.execute().await,
            Self::Mint(c) => c.execute().await,
            Self::GetReserve(c) => c.execute().await,
        }
    }
}

/// Read a JSON arg that is either inline JSON or `@path/to/file.json`.
fn read_json_arg(arg: &str) -> Result<serde_json::Value> {
    let text = if let Some(path) = arg.strip_prefix('@') {
        std::fs::read_to_string(path).with_context(|| format!("reading {path}"))?
    } else {
        arg.to_string()
    };
    serde_json::from_str(&text).context("parsing JSON argument")
}

#[derive(Debug, Parser)]
pub struct CapitalOpenCmd {
    /// CapitalIntent JSON (inline or `@file.json`).
    intent: String,
    #[arg(long, default_value = DEFAULT_RPC)]
    rpc: String,
}

impl CapitalOpenCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Capital Intent: Open");
        let intent = read_json_arg(&self.intent)?;
        let result: serde_json::Value = RpcClient::new(&self.rpc)
            .call("tenzro_capitalIntentOpen", serde_json::json!({ "intent": intent }))
            .await
            .context("calling tenzro_capitalIntentOpen")?;
        output::print_json(&result)?;
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct CapitalQuoteCmd {
    intent_id: String,
    solver_did: String,
    #[arg(long, default_value = "")]
    plan: String,
    #[arg(long, default_value_t = 0)]
    price: u64,
    #[arg(long, default_value_t = 0)]
    eta_secs: u64,
    #[arg(long, default_value = DEFAULT_RPC)]
    rpc: String,
}

impl CapitalQuoteCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Capital Intent: Quote");
        let result: serde_json::Value = RpcClient::new(&self.rpc)
            .call(
                "tenzro_capitalIntentQuote",
                serde_json::json!({
                    "intent_id": self.intent_id, "solver_did": self.solver_did,
                    "plan": self.plan, "price": self.price, "eta_secs": self.eta_secs,
                }),
            )
            .await
            .context("calling tenzro_capitalIntentQuote")?;
        output::print_json(&result)?;
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct CapitalAssignCmd {
    intent_id: String,
    /// Explicit solver DID. Omit (with --auto) to auto-rank received quotes.
    solver_did: Option<String>,
    /// Auto-select the best quote by ERC-8004 reputation, then price, then eta.
    #[arg(long)]
    auto: bool,
    /// Principal funding address (locks escrow up to the authorized ceiling).
    #[arg(long)]
    payer: Option<String>,
    #[arg(long)]
    payee: Option<String>,
    #[arg(long, default_value = DEFAULT_RPC)]
    rpc: String,
}

impl CapitalAssignCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Capital Intent: Assign");
        let mut params = serde_json::json!({ "intent_id": self.intent_id });
        let obj = params.as_object_mut().unwrap();
        if let Some(s) = &self.solver_did {
            obj.insert("solver_did".into(), serde_json::json!(s));
        }
        if self.auto {
            obj.insert("auto".into(), serde_json::json!(true));
        }
        if let Some(p) = &self.payer {
            obj.insert("payer".into(), serde_json::json!(p));
        }
        if let Some(p) = &self.payee {
            obj.insert("payee".into(), serde_json::json!(p));
        }
        let result: serde_json::Value = RpcClient::new(&self.rpc)
            .call("tenzro_capitalIntentAssign", params)
            .await
            .context("calling tenzro_capitalIntentAssign")?;
        output::print_json(&result)?;
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct CapitalExecuteCmd {
    intent_id: String,
    /// Leg JSON (inline or `@file.json`): {venue, asset_id, side, quantity, unit_price, settlement_ref?, proof?}.
    leg: String,
    #[arg(long, default_value = DEFAULT_RPC)]
    rpc: String,
}

impl CapitalExecuteCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Capital Intent: Execute Leg");
        let leg = read_json_arg(&self.leg)?;
        let result: serde_json::Value = RpcClient::new(&self.rpc)
            .call("tenzro_capitalIntentExecute", serde_json::json!({ "intent_id": self.intent_id, "leg": leg }))
            .await
            .context("calling tenzro_capitalIntentExecute")?;
        output::print_json(&result)?;
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct CapitalSettleCmd {
    intent_id: String,
    #[arg(long)]
    payee: Option<String>,
    #[arg(long, default_value = DEFAULT_RPC)]
    rpc: String,
}

impl CapitalSettleCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Capital Intent: Settle");
        let mut params = serde_json::json!({ "intent_id": self.intent_id });
        if let Some(p) = &self.payee {
            params.as_object_mut().unwrap().insert("payee".into(), serde_json::json!(p));
        }
        let result: serde_json::Value = RpcClient::new(&self.rpc)
            .call("tenzro_capitalIntentSettle", params)
            .await
            .context("calling tenzro_capitalIntentSettle")?;
        output::print_json(&result)?;
        Ok(())
    }
}

/// Shared `intent_id`-only command for verify / compensate / get.
#[derive(Debug, Parser)]
pub struct CapitalIdCmd {
    intent_id: String,
    #[arg(long, default_value = DEFAULT_RPC)]
    rpc: String,
}

impl CapitalIdCmd {
    pub async fn execute(&self, method: &str, header: &str) -> Result<()> {
        output::print_header(&format!("Capital Intent: {header}"));
        let result: serde_json::Value = RpcClient::new(&self.rpc)
            .call(method, serde_json::json!({ "intent_id": self.intent_id }))
            .await
            .with_context(|| format!("calling {method}"))?;
        output::print_json(&result)?;
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct CapitalReserveSubmitCmd {
    /// ReserveAttestation JSON (inline or `@file.json`).
    attestation: String,
    #[arg(long, default_value = DEFAULT_RPC)]
    rpc: String,
}

impl CapitalReserveSubmitCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Reserve: Submit Attestation");
        let att = read_json_arg(&self.attestation)?;
        let result: serde_json::Value = RpcClient::new(&self.rpc)
            .call("tenzro_submitReserveAttestation", serde_json::json!({ "attestation": att }))
            .await
            .context("calling tenzro_submitReserveAttestation")?;
        output::print_json(&result)?;
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct CapitalMintCmd {
    /// 32-byte token id (hex).
    token_id: String,
    /// Recipient address.
    to: String,
    /// Amount to mint (decimal, smallest unit).
    amount: String,
    /// Caller (must be the token creator).
    caller: String,
    #[arg(long, default_value = DEFAULT_RPC)]
    rpc: String,
}

impl CapitalMintCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Attested Mint (1:1 backed)");
        let result: serde_json::Value = RpcClient::new(&self.rpc)
            .call(
                "tenzro_attestedMint",
                serde_json::json!({
                    "token_id": self.token_id, "to": self.to,
                    "amount": self.amount, "caller": self.caller,
                }),
            )
            .await
            .context("calling tenzro_attestedMint")?;
        output::print_json(&result)?;
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct CapitalGetReserveCmd {
    /// Tokenized-asset id.
    asset_id: String,
    #[arg(long, default_value = DEFAULT_RPC)]
    rpc: String,
}

impl CapitalGetReserveCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Reserve: Get");
        let result: serde_json::Value = RpcClient::new(&self.rpc)
            .call("tenzro_getReserve", serde_json::json!({ "asset_id": self.asset_id }))
            .await
            .context("calling tenzro_getReserve")?;
        output::print_json(&result)?;
        Ok(())
    }
}
