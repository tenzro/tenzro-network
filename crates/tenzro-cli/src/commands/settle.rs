//! Settlement plans: several value legs, one Commit-or-Abort decision.
//!
//! - `tenzro settle preview --gross <wei> --split <file>` — the exact division
//! - `tenzro settle open --plan <file>`                   — open a plan as its payer
//! - `tenzro settle prove --plan-id <id> --index <n>`     — record a leg's evidence
//! - `tenzro settle get --plan-id <id>`                   — a plan
//! - `tenzro settle decision --plan-id <id>`              — its decision
//! - `tenzro settle receipt --plan-id <id> --index <n>`   — one leg's receipt
//! - `tenzro settle list [--payer] [--status]`            — plans
//!
//! A plan file is the JSON of a `SettlementPlan` `open` operation: `nonce`,
//! `quote_digest`, `split_hash`, `split`, `legs` (each off Tenzro with its
//! `usd_e6`), `decide_deadline_ms`, and `agent` when a delegated agent pays
//! (a completed media job returns one in its `settlement`).

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tenzro_types::settlement::PlanOp;
use tenzro_types::transaction::TransactionType;

use crate::output;
use crate::rpc::RpcClient;

/// Settlement plan commands
#[derive(Debug, Subcommand)]
pub enum SettleCommand {
    /// Preview how a gross amount divides under a split rule
    Preview(PreviewCmd),
    /// Open a plan as its payer
    Open(OpenCmd),
    /// Record that a leg reached its evidence class; commits the plan when it is the last
    Prove(ProveCmd),
    /// Dispute a rail leg its attestor confirmed, as the leg's payee
    Dispute(DisputeCmd),
    /// Show a plan
    Get(PlanIdCmd),
    /// Show a plan's decision
    Decision(PlanIdCmd),
    /// Show one leg's receipt
    Receipt(ReceiptCmd),
    /// List plans
    List(ListCmd),
    /// Post collateral for netted plans
    PostCollateral(CollateralCmd),
    /// Withdraw collateral down to what the open batch's net debit needs
    WithdrawCollateral(CollateralCmd),
    /// Show an asset's netting batch, and a participant's gross-to-net statement
    Netting(NettingCmd),
    /// Reconcile a route's settlement lock against Tenzro's books
    Reconcile(ReconcileCmd),
    /// Show how far a route's settlement lock is reconciled
    Reconciliation(RouteCmd),
    /// List the reconciliation mismatches stored for a route's settlement lock
    Mismatches(RouteCmd),
}

impl SettleCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Preview(cmd) => cmd.execute().await,
            Self::Open(cmd) => cmd.execute().await,
            Self::Prove(cmd) => cmd.execute().await,
            Self::Dispute(cmd) => cmd.execute().await,
            Self::Get(cmd) => cmd.read("tenzro_getPlan", "Settlement plan").await,
            Self::Decision(cmd) => cmd.read("tenzro_getPlanDecision", "Plan decision").await,
            Self::Receipt(cmd) => cmd.execute().await,
            Self::List(cmd) => cmd.execute().await,
            Self::PostCollateral(cmd) => cmd.execute(true).await,
            Self::WithdrawCollateral(cmd) => cmd.execute(false).await,
            Self::Netting(cmd) => cmd.execute().await,
            Self::Reconcile(cmd) => cmd.execute().await,
            Self::Reconciliation(cmd) => {
                cmd.read("tenzro_getReconciliation", "Reconciliation").await
            }
            Self::Mismatches(cmd) => {
                cmd.read("tenzro_listMismatches", "Reconciliation mismatches")
                    .await
            }
        }
    }
}

fn hex32(s: &str) -> Result<[u8; 32]> {
    hex::decode(s.trim_start_matches("0x"))
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
        .ok_or_else(|| anyhow::anyhow!("expected 32 bytes of hex, got {s}"))
}

async fn show(rpc: &str, method: &str, params: serde_json::Value, title: &str) -> Result<()> {
    output::print_header(title);
    let v: serde_json::Value = RpcClient::new(rpc).call(method, params).await?;
    println!("{}", serde_json::to_string_pretty(&v)?);
    Ok(())
}

/// Preview a division.
#[derive(Debug, Parser)]
pub struct PreviewCmd {
    /// Gross amount, wei
    #[arg(long)]
    gross: String,
    /// JSON file holding the split rule
    #[arg(long)]
    split: std::path::PathBuf,
    /// Network fees the payee side bears, wei
    #[arg(long, default_value = "0")]
    network_fees: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl PreviewCmd {
    async fn execute(&self) -> Result<()> {
        let split: serde_json::Value = serde_json::from_slice(
            &std::fs::read(&self.split)
                .with_context(|| format!("reading {}", self.split.display()))?,
        )?;
        show(
            &self.rpc,
            "tenzro_previewSplit",
            serde_json::json!({ "gross": self.gross, "split": split, "network_fees": self.network_fees }),
            "Split preview",
        )
        .await
    }
}

/// Open a plan.
#[derive(Debug, Parser)]
pub struct OpenCmd {
    /// JSON file holding the `open` operation's fields; a `split_hash` left
    /// out is the hash of its `split`
    #[arg(long)]
    plan: std::path::PathBuf,
    #[command(flatten)]
    signer: super::signer::Signer,
}

impl OpenCmd {
    async fn execute(&self) -> Result<()> {
        output::print_header("Settlement plan — Open");
        let mut fields: serde_json::Value = serde_json::from_slice(
            &std::fs::read(&self.plan)
                .with_context(|| format!("reading {}", self.plan.display()))?,
        )?;
        if fields.get("split_hash").is_none() {
            let split: tenzro_types::split::SplitRule =
                serde_json::from_value(fields["split"].clone()).context("the plan's split rule")?;
            fields["split_hash"] = serde_json::Value::String(hex::encode(split.hash()));
        }
        let op: PlanOp = serde_json::from_value(serde_json::json!({ "open": fields }))
            .context("the plan file is not an open operation")?;
        op.validate().map_err(|e| anyhow::anyhow!(e))?;
        let PlanOp::Open {
            nonce,
            quote_digest,
            agent,
            ..
        } = &op
        else {
            unreachable!("parsed as an open operation")
        };
        let payer = match agent {
            Some(a) => tenzro_types::agent_terms::agent_wallet(&a.action.agent_did),
            None => crate::keystore::address32(
                &crate::keystore::client_account(self.signer.key_namespace())?.0,
            )?,
        };
        let chain_id: serde_json::Value = RpcClient::new(self.signer.rpc_url())
            .call("eth_chainId", serde_json::json!([]))
            .await?;
        let chain_id = chain_id
            .as_str()
            .and_then(|h| u64::from_str_radix(h.trim_start_matches("0x"), 16).ok())
            .ok_or_else(|| anyhow::anyhow!("eth_chainId returned {chain_id}"))?;
        let plan_id = tenzro_types::settlement::plan_id(
            chain_id,
            &tenzro_types::primitives::Address::new(payer),
            quote_digest,
            *nonce,
        );
        output::print_field("Plan id", &format!("0x{}", hex::encode(plan_id)));
        self.signer
            .send_tx(TransactionType::SettlementPlan { op }, "SettlementPlan")
            .await
    }
}

/// Record a leg's evidence.
#[derive(Debug, Parser)]
pub struct ProveCmd {
    /// Plan id (32-byte hex)
    #[arg(long)]
    plan_id: String,
    /// The leg's index
    #[arg(long)]
    index: u8,
    /// The leg's evidence, hex: a lock leg's `Locked` event proof, a
    /// hash-locked leg's funding proof or, once funded, its preimage; a
    /// rail leg's settlement confirmation, sent by its attestor or payee
    /// once the plan commits
    #[arg(long, default_value = "")]
    evidence: String,
    /// The fee paid on the leg's network to carry this proof, wei of TNZO;
    /// a commit repays it up to the leg's `max_network_fee`
    #[arg(long, default_value_t = 0)]
    network_fee: u128,
    #[command(flatten)]
    signer: super::signer::Signer,
}

impl ProveCmd {
    async fn execute(&self) -> Result<()> {
        output::print_header("Settlement plan — Prove leg");
        let op = PlanOp::ProveLeg {
            plan_id: hex32(&self.plan_id)?,
            index: self.index,
            evidence: hex::decode(self.evidence.trim_start_matches("0x"))?,
            network_fee: self.network_fee,
        };
        op.validate().map_err(|e| anyhow::anyhow!(e))?;
        self.signer
            .send_tx(TransactionType::SettlementPlan { op }, "SettlementPlan")
            .await
    }
}

/// Dispute a rail leg.
#[derive(Debug, Parser)]
pub struct DisputeCmd {
    /// Plan id (32-byte hex)
    #[arg(long)]
    plan_id: String,
    /// The rail leg's index
    #[arg(long)]
    index: u8,
    /// The payee's evidence that the payment did not arrive, hex
    #[arg(long)]
    evidence: String,
    #[command(flatten)]
    signer: super::signer::Signer,
}

impl DisputeCmd {
    async fn execute(&self) -> Result<()> {
        output::print_header("Settlement plan — Dispute rail leg");
        let op = PlanOp::DisputeRail {
            plan_id: hex32(&self.plan_id)?,
            index: self.index,
            evidence: hex::decode(self.evidence.trim_start_matches("0x"))?,
        };
        op.validate().map_err(|e| anyhow::anyhow!(e))?;
        self.signer
            .send_tx(TransactionType::SettlementPlan { op }, "SettlementPlan")
            .await
    }
}

/// A plan by id.
#[derive(Debug, Parser)]
pub struct PlanIdCmd {
    /// Plan id (32-byte hex)
    #[arg(long)]
    plan_id: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl PlanIdCmd {
    async fn read(&self, method: &str, title: &str) -> Result<()> {
        show(
            &self.rpc,
            method,
            serde_json::json!({ "plan_id": self.plan_id }),
            title,
        )
        .await
    }
}

/// One leg's receipt.
#[derive(Debug, Parser)]
pub struct ReceiptCmd {
    /// Plan id (32-byte hex)
    #[arg(long)]
    plan_id: String,
    /// The leg's index
    #[arg(long)]
    index: u8,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ReceiptCmd {
    async fn execute(&self) -> Result<()> {
        show(
            &self.rpc,
            "tenzro_getLegReceipt",
            serde_json::json!({ "plan_id": self.plan_id, "index": self.index }),
            "Leg receipt",
        )
        .await
    }
}

/// List plans.
#[derive(Debug, Parser)]
pub struct ListCmd {
    /// Only plans this payer opened (32-byte hex)
    #[arg(long)]
    payer: Option<String>,
    /// Only plans in this status: open, committed, aborted
    #[arg(long)]
    status: Option<String>,
    /// Most plans to return
    #[arg(long, default_value_t = 50)]
    limit: u64,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ListCmd {
    async fn execute(&self) -> Result<()> {
        show(
            &self.rpc,
            "tenzro_listPlans",
            serde_json::json!({ "payer": self.payer, "status": self.status, "limit": self.limit }),
            "Settlement plans",
        )
        .await
    }
}

#[derive(Debug, Parser)]
pub struct CollateralCmd {
    /// Token id of the asset (32-byte hex; TNZO's id for TNZO)
    #[arg(long)]
    asset: String,
    /// Amount in the asset's smallest unit
    #[arg(long)]
    amount: u128,
    /// JSON file holding a delegated agent's signed action
    /// (`{ action, signature }`): the collateral is the agent's, moving to or
    /// from its wallet under its terms. A post states the amount; a
    /// withdrawal states none.
    #[arg(long)]
    agent_auth: Option<std::path::PathBuf>,
    #[command(flatten)]
    signer: super::signer::Signer,
}

impl CollateralCmd {
    async fn execute(&self, post: bool) -> Result<()> {
        let asset = hex32(&self.asset)?;
        let agent = match &self.agent_auth {
            Some(path) => Some(
                serde_json::from_slice(
                    &std::fs::read(path).with_context(|| format!("read {}", path.display()))?,
                )
                .context("the agent file holds { action, signature }")?,
            ),
            None => None,
        };
        let op = if post {
            output::print_header("Settlement — Post collateral");
            PlanOp::PostCollateral {
                asset,
                amount: self.amount,
                agent,
            }
        } else {
            output::print_header("Settlement — Withdraw collateral");
            PlanOp::WithdrawCollateral {
                asset,
                amount: self.amount,
                agent,
            }
        };
        self.signer
            .send_tx(TransactionType::SettlementPlan { op }, "SettlementPlan")
            .await
    }
}

#[derive(Debug, Parser)]
pub struct NettingCmd {
    /// Token id of the asset (32-byte hex)
    #[arg(long)]
    asset: String,
    /// Batch number; the latest when omitted
    #[arg(long)]
    seq: Option<u64>,
    /// A participant's address (32-byte hex) for its collateral and statement
    #[arg(long)]
    participant: Option<String>,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl NettingCmd {
    async fn execute(&self) -> Result<()> {
        let mut params = serde_json::json!({ "asset": self.asset });
        if let Some(seq) = self.seq {
            params["seq"] = seq.into();
        }
        if let Some(p) = &self.participant {
            params["participant"] = p.clone().into();
        }
        show(&self.rpc, "tenzro_getNettingBatch", params, "Netting batch").await
    }
}

/// A route with a settlement lock.
#[derive(Debug, Parser)]
pub struct RouteCmd {
    /// The route's bridge protocol: ccip, ibc, deposit or contract
    #[arg(long)]
    adapter: String,
    /// The route's external chain
    #[arg(long)]
    chain: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl RouteCmd {
    async fn read(&self, method: &str, title: &str) -> Result<()> {
        show(
            &self.rpc,
            method,
            serde_json::json!({ "adapter": self.adapter, "chain": self.chain }),
            title,
        )
        .await
    }
}

/// Reconcile a route's settlement lock.
#[derive(Debug, Parser)]
pub struct ReconcileCmd {
    /// The route's bridge protocol
    #[arg(long)]
    adapter: String,
    /// The route's external chain
    #[arg(long)]
    chain: String,
    /// JSON file holding the entries the lock recorded since the last
    /// reconciliation, in order: `[{plan_id, leg_id, kind, amount}]`, kind
    /// one of locked, released, refunded
    #[arg(long)]
    entries: std::path::PathBuf,
    /// The route's proof of the lock's checkpoint, hex
    #[arg(long)]
    checkpoint: String,
    #[command(flatten)]
    signer: super::signer::Signer,
}

impl ReconcileCmd {
    async fn execute(&self) -> Result<()> {
        output::print_header("Settlement lock — Reconcile");
        let entries: serde_json::Value = serde_json::from_slice(
            &std::fs::read(&self.entries)
                .with_context(|| format!("reading {}", self.entries.display()))?,
        )?;
        let params = serde_json::json!({
            "adapter": self.adapter,
            "chain": self.chain,
            "entries": entries,
            "checkpoint": self.checkpoint,
        });
        let checked: serde_json::Value = RpcClient::new(self.signer.rpc_url())
            .call("tenzro_submitReconciliation", params)
            .await?;
        output::print_field("Reconciled", &checked["reconciled"].to_string());
        output::print_field("Checkpoint must prove count", &checked["count"].to_string());
        output::print_field(
            "Checkpoint must prove hash",
            checked["acc"].as_str().unwrap_or_default(),
        );
        let tx: TransactionType = serde_json::from_value(checked["tx_type"].clone())?;
        self.signer.send_tx(tx, "SettlementPlan").await
    }
}
