//! Network funding: requests, tranche releases, settled work reports,
//! reward claims and vesting releases.
//!
//! Each operation is a signed `Funding` transaction whose gas the treasury
//! pays, so an identity with no TNZO can take part. Requests go to the
//! governance vote.

use crate::output;
use crate::rpc::RpcClient;
use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use serde_json::{Value, json};

/// Gas limit of a funding operation (paid by the treasury).
const FUNDING_GAS: u64 = 80_000;

/// Network funding operations
#[derive(Debug, Subcommand)]
pub enum FundingCommand {
    /// Request a treasury grant (optionally in tranches) for a governance vote
    RequestGrant(RequestGrantCmd),
    /// Request the release of a grant's next tranche
    RequestTranche(RequestTrancheCmd),
    /// Record that a scheduled grant tranche's milestone is met (a named verifier)
    VerifyMilestone(MilestoneCmd),
    /// Release a scheduled grant's next tranche against its verified milestone
    ReleaseMilestone(MilestoneCmd),
    /// Record validator-signed settled receipts as reward work
    ReportWork(ReportWorkCmd),
    /// Claim your issued reward coupons (part liquid, the rest vests)
    ClaimRewards(AccountCmd),
    /// Release what your vesting schedules have accrued
    ReleaseVesting(AccountCmd),
    /// Show a funding proposal or grant
    Show(ShowCmd),
}

impl FundingCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::RequestGrant(c) => c.execute().await,
            Self::RequestTranche(c) => c.execute().await,
            Self::VerifyMilestone(c) => c.execute("verify_milestone").await,
            Self::ReleaseMilestone(c) => c.execute("release_milestone").await,
            Self::ReportWork(c) => c.execute().await,
            Self::ClaimRewards(c) => c.submit("claim_rewards").await,
            Self::ReleaseVesting(c) => c.submit("release_vesting").await,
            Self::Show(c) => c.execute().await,
        }
    }
}

/// Sign `op` as a `Funding` transaction with the client's hardware key and submit it.
async fn submit(rpc_url: &str, key_namespace: &str, op: Value) -> Result<()> {
    let rpc = RpcClient::new(rpc_url);
    let bytes = serde_json::to_vec(&op)?;
    let spinner = output::create_spinner("Submitting funding operation...");
    let result: Value = crate::keystore::send_as_client(
        &rpc,
        key_namespace,
        [0u8; 32],
        json!({ "Funding": { "op": bytes } }),
        FUNDING_GAS,
    )
    .await?;
    spinner.finish_and_clear();
    let tx_hash = result
        .get("tx_hash")
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .or_else(|| result.as_str().map(str::to_string))
        .unwrap_or_default();
    output::print_success(&format!(
        "{} submitted",
        op.get("op")
            .and_then(|v| v.as_str())
            .unwrap_or("funding operation")
    ));
    output::print_field("Transaction Hash", &tx_hash);
    Ok(())
}

fn address32(hex_addr: &str) -> Result<Vec<u8>> {
    let raw = hex::decode(hex_addr.trim_start_matches("0x")).context("address is not hex")?;
    if raw.len() > 32 {
        anyhow::bail!("address longer than 32 bytes");
    }
    let mut a = raw;
    a.resize(32, 0);
    Ok(a)
}

#[derive(Debug, Parser)]
pub struct RequestGrantCmd {
    /// Hardware key namespace of the signing account
    #[arg(long, default_value = "client")]
    key_namespace: String,
    /// Who is paid (a registered identity's account); defaults to --from
    #[arg(long)]
    recipient: Option<String>,
    /// Total amount in wei
    #[arg(long)]
    amount: u128,
    /// Free category label: development, research, audit, infrastructure, community, events, operators, ...
    #[arg(long, default_value = "")]
    category: String,
    /// Link to the public write-up
    #[arg(long, default_value = "")]
    link: String,
    /// Why
    #[arg(long, default_value = "")]
    memo: String,
    /// Tranche amounts in wei, comma separated; they must sum to --amount
    #[arg(long, value_delimiter = ',')]
    tranches: Vec<u128>,
    /// The milestone each payment is for, one per tranche (one without
    /// tranches); separate them with a semicolon
    #[arg(long, value_delimiter = ';', required = true)]
    milestones: Vec<String>,
    /// How each payment vests: liquid, grant (6 months linear) or
    /// contributor (12-month cliff, then 36 months linear)
    #[arg(long, default_value = "grant", value_parser = ["liquid", "grant", "contributor"])]
    vesting: String,
    /// Pay in a USD stable asset instead of TNZO: its token id (0x and 64
    /// hex). Amounts are then in the asset's smallest unit and the grant
    /// vests liquid
    #[arg(long)]
    asset: Option<String>,
    /// How later tranches are released: governed (a proposal each) or
    /// scheduled (against milestones the verifiers record)
    #[arg(long, default_value = "governed", value_parser = ["governed", "scheduled"])]
    release: String,
    /// Accounts that record milestones (64 hex), comma separated; with
    /// --release scheduled
    #[arg(long, value_delimiter = ',')]
    verifiers: Vec<String>,
    /// Distinct verifiers needed per milestone; with --release scheduled
    #[arg(long, default_value_t = 1)]
    threshold: u32,
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl RequestGrantCmd {
    async fn execute(&self) -> Result<()> {
        let recipient = address32(self.recipient.as_deref().unwrap_or(&self.key_namespace))?;
        let mut action = json!({
            "action": "treasury_grant",
            "recipient": recipient,
            "amount": self.amount.to_string(),
            "memo": self.memo,
            "category": self.category,
            "link": self.link,
            "tranches": self.tranches,
            "milestones": self.milestones,
            "vesting": self.vesting,
        });
        if let Some(asset) = &self.asset {
            action["asset"] = json!(asset);
        }
        if self.release == "scheduled" {
            let verifiers = self
                .verifiers
                .iter()
                .map(|v| address32(v))
                .collect::<Result<Vec<_>>>()?;
            action["release"] = json!({
                "mode": "scheduled",
                "verifiers": verifiers,
                "threshold": self.threshold,
            });
        } else if !self.verifiers.is_empty() {
            anyhow::bail!("--verifiers needs --release scheduled");
        }
        submit(
            &self.rpc,
            &self.key_namespace,
            json!({ "op": "request", "action": action }),
        )
        .await
    }
}

#[derive(Debug, Parser)]
pub struct RequestTrancheCmd {
    /// Hardware key namespace of the signing account
    #[arg(long, default_value = "client")]
    key_namespace: String,
    /// Id of the enacted grant proposal (64 hex)
    #[arg(long)]
    grant_id: String,
    /// Tranche index (the next unpaid one; 1 is the second tranche)
    #[arg(long)]
    index: u32,
    /// Milestone evidence
    #[arg(long, default_value = "")]
    memo: String,
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl RequestTrancheCmd {
    async fn execute(&self) -> Result<()> {
        submit(
            &self.rpc,
            &self.key_namespace,
            json!({
                "op": "request",
                "action": {
                    "action": "release_grant_tranche",
                    "grant_id": self.grant_id.trim_start_matches("0x"),
                    "index": self.index,
                    "memo": self.memo,
                }
            }),
        )
        .await
    }
}

#[derive(Debug, Parser)]
pub struct MilestoneCmd {
    /// Hardware key namespace of the signing account
    #[arg(long, default_value = "client")]
    key_namespace: String,
    /// Id of the enacted grant proposal (64 hex)
    #[arg(long)]
    grant_id: String,
    /// Tranche index (1 is the second tranche)
    #[arg(long)]
    index: u32,
    /// What was delivered, recorded with the verification (verify only)
    #[arg(long, default_value = "")]
    evidence: String,
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl MilestoneCmd {
    async fn execute(&self, op: &str) -> Result<()> {
        let mut body = json!({
            "op": op,
            "grant_id": self.grant_id.trim_start_matches("0x"),
            "index": self.index,
        });
        if op == "verify_milestone" {
            body["evidence"] = json!(self.evidence);
        }
        submit(&self.rpc, &self.key_namespace, body).await
    }
}

fn leg_ids(legs: &[String]) -> Vec<&str> {
    legs.iter().map(|l| l.trim_start_matches("0x")).collect()
}

#[derive(Debug, Parser)]
pub struct ReportWorkCmd {
    /// Hardware key namespace of the signing account
    #[arg(long, default_value = "client")]
    key_namespace: String,
    /// Leg ids (hex) of committed settlement plans that paid you
    #[arg(long, value_delimiter = ',', required = true)]
    legs: Vec<String>,
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ReportWorkCmd {
    async fn execute(&self) -> Result<()> {
        submit(
            &self.rpc,
            &self.key_namespace,
            json!({ "op": "report_settled_work", "legs": leg_ids(&self.legs) }),
        )
        .await
    }
}

#[derive(Debug, Parser)]
pub struct AccountCmd {
    /// Hardware key namespace of the signing account
    #[arg(long, default_value = "client")]
    key_namespace: String,
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl AccountCmd {
    async fn submit(&self, op: &str) -> Result<()> {
        submit(&self.rpc, &self.key_namespace, json!({ "op": op })).await
    }
}

#[derive(Debug, Parser)]
pub struct ShowCmd {
    /// proposal | grant
    #[arg(value_parser = ["proposal", "grant"])]
    kind: String,
    /// Proposal or grant id
    id: String,
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ShowCmd {
    async fn execute(&self) -> Result<()> {
        let rpc = RpcClient::new(&self.rpc);
        let id = self.id.trim_start_matches("0x");
        let (method, params) = match self.kind.as_str() {
            "proposal" => ("tenzro_getProposal", json!({ "proposal_id": id })),
            _ => ("tenzro_getGrant", json!({ "grant_id": id })),
        };
        let result: Value = rpc.call(method, params).await?;
        if result.is_null() {
            output::print_warning("not found");
        } else {
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        Ok(())
    }
}
