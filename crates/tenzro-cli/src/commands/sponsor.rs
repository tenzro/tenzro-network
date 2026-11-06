//! `tenzro sponsor`: where this operator stands against sponsorship.
//!
//! Sponsorship pays what the treasury already holds, one governance proposal
//! at a time (docs/SPONSORSHIP-AND-GRANTS.md). The gate is an approved
//! operator: an enacted `ApproveOperator` proposal, which the chain only
//! passes for an account whose machine identity has a TPM endorsement
//! chaining to a recognised root and at least one verified-available hour.
//! A new operator cannot file that proposal themselves, so these commands do
//! the two things within reach: show exactly where the operator stands, and
//! prepare what a proposer needs to file it.
//!
//! Everything here is read from existing node RPCs:
//!
//! - `tenzro_getNodeStatus` for the machine DID and the node's account.
//! - `tenzro_slaVerdict` per hourly epoch for verified-available hours.
//! - `tenzro_getTreasuryPayouts` for the approval record, the amount paid and
//!   the governed caps.
//! - `tenzro_getSponsoredBond` for governance-sponsored validator stake.
//! - `tenzro_listProposals` for an `approve_operator` proposal in flight.
//!
//! The node exposes no read for the endorsement chain itself: the chain
//! checks it when a proposal is enacted. The check says so, states what the
//! platform makes of it, and prints the governance step that settles it.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use serde_json::{Value, json};

use crate::commands::preflight::Level;
use crate::output;
use crate::rpc::{RpcClient, format_tnzo};

/// Hours in one verification epoch's span: epochs are hours since the Unix
/// epoch.
const EPOCH_SECS: u64 = 3600;

/// How many `tenzro_slaVerdict` reads run at once.
const VERDICT_BATCH: usize = 12;

/// Sponsorship: eligibility, application and status
#[derive(Debug, Subcommand)]
pub enum SponsorCommand {
    /// Report whether this operator qualifies for sponsorship (read-only)
    Check(SponsorCheckCmd),
    /// Prepare a sponsorship application: the proposal a proposer files and
    /// the grant request you can file yourself
    Apply(SponsorApplyCmd),
    /// Show the approval record, what sponsorship has paid, and any proposal in flight (read-only)
    Status(SponsorStatusCmd),
}

impl SponsorCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Check(c) => c.execute().await,
            Self::Apply(c) => c.execute().await,
            Self::Status(c) => c.execute().await,
        }
    }
}

/// What every sponsor command needs to find the operator.
#[derive(Debug, Parser)]
pub struct Target {
    /// The node's RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,

    /// Operator account (64 hex). Defaults to the node's own account.
    #[arg(long)]
    account: Option<String>,

    /// Machine identity (did:tenzro:machine:...). Defaults to the node's.
    #[arg(long)]
    did: Option<String>,

    /// How many past hours of availability to count
    #[arg(long, default_value_t = 168)]
    hours: u64,

    /// Print the gathered facts as JSON instead of the readout
    #[arg(long)]
    json: bool,
}

/// Report whether this operator qualifies for sponsorship
#[derive(Debug, Parser)]
pub struct SponsorCheckCmd {
    #[command(flatten)]
    target: Target,
}

/// Prepare a sponsorship application
#[derive(Debug, Parser)]
pub struct SponsorApplyCmd {
    #[command(flatten)]
    target: Target,

    /// Where the operator runs (shown to voters)
    #[arg(long, default_value = "<region>")]
    region: String,

    /// The operator's independence declaration, or a link to it
    #[arg(long, default_value = "<independence-statement-or-link>")]
    independence: String,

    /// Stake the grant request asks for: TNZO (`10000`) or wei with its suffix
    #[arg(long, default_value = "10000", value_parser = crate::units::parse_amount_wei)]
    grant_amount: u128,

    /// Write the application summary here instead of ~/.tenzro/sponsor-application.json
    #[arg(long)]
    out: Option<PathBuf>,
}

/// Show the approval record and what sponsorship has paid
#[derive(Debug, Parser)]
pub struct SponsorStatusCmd {
    #[command(flatten)]
    target: Target,
}

/// The kind of machine root the operator's node has, as it bears on the
/// endorsement check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    /// A TPM 2.0 whose endorsement certificate the chain can check.
    Tpm,
    /// A Mac's Secure Enclave, which has no TPM endorsement certificate.
    SecureEnclave,
    /// An NVIDIA Jetson, whose firmware TPM has no recognised root seeded.
    Jetson,
    Unknown,
}

impl Platform {
    /// The platform of the machine this command runs on.
    pub fn detect() -> Self {
        if cfg!(target_os = "macos") {
            return Self::SecureEnclave;
        }
        if cfg!(target_os = "linux") {
            let jetson = std::fs::read_to_string("/proc/device-tree/model")
                .is_ok_and(|m| m.contains("Jetson"))
                || std::path::Path::new("/etc/nv_tegra_release").exists();
            return if jetson { Self::Jetson } else { Self::Tpm };
        }
        Self::Unknown
    }
}

/// The governed caps that decide whether an approval pays anything.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Caps {
    pub sponsorship_yearly_max_tnzo: String,
    pub running_cost_per_verified_epoch_wei: String,
    pub per_grantee_yearly_max_tnzo: String,
    pub combined_yearly_max_tnzo: String,
}

impl Caps {
    /// Whether governance has opened sponsorship at all.
    pub fn open(&self) -> bool {
        [
            &self.sponsorship_yearly_max_tnzo,
            &self.running_cost_per_verified_epoch_wei,
            &self.combined_yearly_max_tnzo,
        ]
        .iter()
        .any(|v| v.parse::<u128>().is_ok_and(|n| n > 0))
    }
}

/// An `approve_operator` proposal naming this account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProposalLine {
    pub id: String,
    pub status: String,
}

/// Everything read from the node, with the reads that failed left empty.
#[derive(Debug, Clone)]
pub struct Inputs {
    pub account: Option<String>,
    pub machine_did: Option<String>,
    pub node_reachable: bool,
    pub platform: Platform,
    pub window_hours: u64,
    /// Epochs in the window with a verified-available verdict. `None` when
    /// the verdict reads failed.
    pub verified_epochs: Option<Vec<u64>>,
    /// The operator's stored approval, when there is one.
    pub approval: Option<Value>,
    pub received_wei: u128,
    pub caps: Option<Caps>,
    pub sponsored_bonded_wei: u128,
    pub proposals: Vec<ProposalLine>,
    pub pending_stake: Option<crate::config::PendingStake>,
}

/// One line of the verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Item {
    pub label: &'static str,
    pub level: Level,
    pub detail: String,
}

/// The verdict: each criterion, and the one thing to do next.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assessment {
    pub items: Vec<Item>,
    /// Whether a proposer can file `ApproveOperator` for this operator now.
    pub ready_to_apply: bool,
    pub approved: bool,
}

fn item(label: &'static str, level: Level, detail: impl Into<String>) -> Item {
    Item {
        label,
        level,
        detail: detail.into(),
    }
}

/// Judge the inputs against what `ApproveOperator` enacts on. Pure.
pub fn assess(i: &Inputs) -> Assessment {
    let mut items = Vec::new();

    items.push(match (&i.machine_did, &i.account) {
        (Some(did), Some(acct)) => item("Identity", Level::Pass, format!("{did}, account {acct}")),
        _ if !i.node_reachable => item(
            "Identity",
            Level::Fail,
            "the node did not answer; start it, or pass --rpc, --account and --did",
        ),
        _ => item(
            "Identity",
            Level::Fail,
            "the node reports no machine identity or account; pass --account and --did",
        ),
    });

    items.push(match i.platform {
        Platform::SecureEnclave => item(
            "Hardware endorsement",
            Level::Fail,
            "a Secure Enclave has no TPM endorsement certificate, and ApproveOperator requires \
             one that chains to a recognised root. A Mac cannot be approved today.",
        ),
        Platform::Jetson => item(
            "Hardware endorsement",
            Level::Fail,
            "the NVIDIA Jetson firmware TPM has no recognised root seeded. Governance must \
             recognise one before a Jetson can be approved (docs/tpm-endorsement-roots.md).",
        ),
        Platform::Tpm => item(
            "Hardware endorsement",
            Level::Warn,
            "checked by the chain when the proposal is enacted; the node exposes no read for it. \
             Roots recognised: Infineon, STMicroelectronics, Nuvoton, Intel PTT, AMD fTPM \
             (docs/tpm-endorsement-roots.md). A discrete or firmware TPM from those vendors qualifies.",
        ),
        Platform::Unknown => item(
            "Hardware endorsement",
            Level::Warn,
            "this platform's endorsement cannot be judged from here; the chain checks it when the \
             proposal is enacted",
        ),
    });

    items.push(match &i.verified_epochs {
        Some(e) if !e.is_empty() => item(
            "Verified-available hours",
            Level::Pass,
            format!(
                "{} in the last {} hours (epochs {} to {})",
                e.len(),
                i.window_hours,
                e.iter().min().copied().unwrap_or(0),
                e.iter().max().copied().unwrap_or(0)
            ),
        ),
        Some(_) => item(
            "Verified-available hours",
            Level::Fail,
            format!(
                "none in the last {} hours. Keep the node running and reachable; validators attest \
                 each hour and at least one verified hour is required.",
                i.window_hours
            ),
        ),
        None => item(
            "Verified-available hours",
            Level::Warn,
            "could not be read (tenzro_slaVerdict failed); the requirement is at least one verified hour",
        ),
    });

    let approved = i
        .approval
        .as_ref()
        .is_some_and(|a| !a.get("revoked").and_then(Value::as_bool).unwrap_or(false));
    items.push(match &i.approval {
        Some(a) if approved => item(
            "Governance approval",
            Level::Pass,
            format!(
                "approved as {} by proposal {}",
                a.get("class").and_then(Value::as_str).unwrap_or("operator"),
                a.get("proposal_id").and_then(Value::as_str).unwrap_or("?")
            ),
        ),
        Some(_) => item(
            "Governance approval",
            Level::Fail,
            "was approved and then revoked by governance",
        ),
        None => match i.proposals.first() {
            Some(p) => item(
                "Governance approval",
                Level::Todo,
                format!("proposal {} is {}", p.id, p.status),
            ),
            None => item(
                "Governance approval",
                Level::Todo,
                "not approved, and no approve_operator proposal names this account. A proposer \
                 with stake files it: `tenzro sponsor apply` prepares the command.",
            ),
        },
    });

    items.push(match &i.caps {
        Some(c) if c.open() => item(
            "Sponsorship caps",
            Level::Pass,
            format!(
                "open: {} TNZO a year, {} wei per verified hour",
                c.sponsorship_yearly_max_tnzo, c.running_cost_per_verified_epoch_wei
            ),
        ),
        Some(_) => item(
            "Sponsorship caps",
            Level::Warn,
            "all zero. Approval pays nothing until governance sets sponsorship.yearly_max_tnzo \
             and the per-hour rate (docs/GOVERNANCE_PARAMS.md).",
        ),
        None => item(
            "Sponsorship caps",
            Level::Warn,
            "could not be read (tenzro_getTreasuryPayouts failed)",
        ),
    });

    let blocked = items.iter().any(|x| x.level == Level::Fail);
    Assessment {
        ready_to_apply: !blocked && !approved && i.proposals.is_empty(),
        approved,
        items,
    }
}

/// The governance command a proposer runs to approve this operator. Pure.
pub fn approve_command(i: &Inputs, region: &str, independence: &str) -> String {
    let (from, to) = match &i.verified_epochs {
        Some(e) if !e.is_empty() => (
            e.iter().min().copied().unwrap_or(0),
            e.iter().max().copied().unwrap_or(0),
        ),
        _ => (0, 0),
    };
    format!(
        "tenzro governance propose-approve-operator --operator {} --class validator \
         --provider-did {} --region {} --history-from-epoch {} --history-to-epoch {} \
         --independence {} --memo {}",
        i.account.as_deref().unwrap_or("<account>"),
        i.machine_did.as_deref().unwrap_or("<machine-did>"),
        region,
        from,
        to,
        independence,
        "<why-this-operator>"
    )
}

/// The grant request an operator can file themselves; the treasury pays its
/// gas, so a zero-balance account can file it. Pure.
pub fn grant_command(account: Option<&str>, amount_wei: u128) -> String {
    format!(
        "tenzro funding request-grant --recipient {} --amount {} --milestones <what-the-grant-delivers>",
        account.unwrap_or("<account>"),
        amount_wei
    )
}

/// The `tenzro ...` commands the application prints, with placeholders
/// replaced by single-token values, for the parse-every-printed-command test.
pub fn sample_commands() -> Vec<String> {
    let i = Inputs {
        account: Some(format!("0x{}", "ab".repeat(32))),
        machine_did: Some("did:tenzro:machine:abc".into()),
        node_reachable: true,
        platform: Platform::Tpm,
        window_hours: 168,
        verified_epochs: Some(vec![10, 11]),
        approval: None,
        received_wei: 0,
        caps: None,
        sponsored_bonded_wei: 0,
        proposals: Vec::new(),
        pending_stake: None,
    };
    vec![
        approve_command(&i, "<region>", "<independence-statement-or-link>"),
        grant_command(i.account.as_deref(), 10_000_000_000_000_000_000_000),
        "tenzro sponsor check".into(),
        "tenzro sponsor status".into(),
    ]
}

// ----------------------------------------------------------------------
// Reading the node
// ----------------------------------------------------------------------

fn now_epoch() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() / EPOCH_SECS)
        .unwrap_or(0)
}

/// Epochs in `from..=to` that the chain holds an available verdict for.
/// `None` when no read succeeded at all.
async fn verified_epochs(url: &str, did: &str, from: u64, to: u64) -> Option<Vec<u64>> {
    let epochs: Vec<u64> = (from..=to).collect();
    let mut verified = Vec::new();
    let mut any_read = false;
    for batch in epochs.chunks(VERDICT_BATCH) {
        let mut set = tokio::task::JoinSet::new();
        for &epoch in batch {
            let url = url.to_string();
            let did = did.to_string();
            set.spawn(async move {
                let rpc = RpcClient::new(&url);
                let v: Result<Value> = rpc
                    .call(
                        "tenzro_slaVerdict",
                        json!({ "provider_did": did, "epoch": epoch }),
                    )
                    .await;
                (epoch, v)
            });
        }
        while let Some(done) = set.join_next().await {
            if let Ok((epoch, Ok(v))) = done {
                any_read = true;
                if v.get("available").and_then(Value::as_bool) == Some(true) {
                    verified.push(epoch);
                }
            }
        }
    }
    verified.sort_unstable();
    any_read.then_some(verified)
}

fn caps_of(v: &Value) -> Option<Caps> {
    let c = v.get("caps")?;
    let s = |k: &str| {
        c.get(k)
            .map(|x| x.as_str().map(str::to_string).unwrap_or_else(|| x.to_string()))
            .unwrap_or_else(|| "0".into())
    };
    Some(Caps {
        sponsorship_yearly_max_tnzo: s("sponsorship_yearly_max_tnzo"),
        running_cost_per_verified_epoch_wei: s("running_cost_per_verified_epoch_wei"),
        per_grantee_yearly_max_tnzo: s("per_grantee_yearly_max_tnzo"),
        combined_yearly_max_tnzo: s("combined_yearly_max_tnzo"),
    })
}

/// The operator hex an `approve_operator` proposal names, whether the node
/// serialised the address as bytes or as hex.
fn proposal_operator_hex(action: &Value) -> Option<String> {
    let op = action.get("operator")?;
    if let Some(s) = op.as_str() {
        return Some(s.trim_start_matches("0x").to_ascii_lowercase());
    }
    let bytes: Option<Vec<u8>> = op
        .as_array()?
        .iter()
        .map(|b| b.as_u64().and_then(|n| u8::try_from(n).ok()))
        .collect();
    bytes.map(hex::encode)
}

fn proposals_for(list: &Value, account: &str) -> Vec<ProposalLine> {
    let want = account.trim_start_matches("0x").to_ascii_lowercase();
    list.get("proposals")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|entry| {
            let p = entry.get("proposal")?;
            if proposal_operator_hex(p.get("action")?)? != want {
                return None;
            }
            let status = p.get("status")?;
            Some(ProposalLine {
                id: p.get("id")?.as_str()?.to_string(),
                status: status
                    .as_str()
                    .map(str::to_string)
                    .unwrap_or_else(|| status.to_string()),
            })
        })
        .collect()
}

fn wei_of(v: &Value, key: &str) -> u128 {
    v.get(key)
        .and_then(|x| x.as_str())
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

impl Target {
    /// Read everything the verdict needs. A read that fails is recorded as
    /// absent, so a half-up node still yields the half that works.
    pub async fn gather(&self) -> Inputs {
        let rpc = RpcClient::new(&self.rpc);
        let status: Option<Value> = rpc.call("tenzro_getNodeStatus", json!([])).await.ok();
        let node_reachable = status.is_some();
        let account = self.account.clone().or_else(|| {
            status
                .as_ref()
                .and_then(|s| s.get("payee"))
                .and_then(Value::as_str)
                .map(str::to_string)
        });
        let machine_did = self.did.clone().or_else(|| {
            status
                .as_ref()
                .and_then(|s| s.get("machine_did"))
                .and_then(Value::as_str)
                .map(str::to_string)
        });

        let to = now_epoch();
        let from = to.saturating_sub(self.hours.saturating_sub(1));
        let verified = match &machine_did {
            Some(did) => verified_epochs(&self.rpc, did, from, to).await,
            None => None,
        };

        let mut approval = None;
        let mut received_wei = 0;
        let mut caps = None;
        let mut sponsored_bonded_wei = 0;
        let mut proposals = Vec::new();
        if let Some(acct) = &account {
            if let Ok(p) = rpc
                .call::<Value>(
                    "tenzro_getTreasuryPayouts",
                    json!({ "address": acct, "limit": 1 }),
                )
                .await
            {
                caps = caps_of(&p);
                if let Some(a) = p.get("address") {
                    received_wei = wei_of(a, "total_received");
                    approval = a.get("operator").filter(|o| !o.is_null()).cloned();
                }
            }
            if let Ok(b) = rpc
                .call::<Value>("tenzro_getSponsoredBond", json!({ "address": acct }))
                .await
            {
                sponsored_bonded_wei = wei_of(&b, "sponsored_bonded");
            }
            if let Ok(list) = rpc
                .call::<Value>(
                    "tenzro_listProposals",
                    json!({ "kind": "approve_operator", "limit": 50 }),
                )
                .await
            {
                proposals = proposals_for(&list, acct);
            }
        }

        Inputs {
            account,
            machine_did,
            node_reachable,
            platform: Platform::detect(),
            window_hours: self.hours,
            verified_epochs: verified,
            approval,
            received_wei,
            caps,
            sponsored_bonded_wei,
            proposals,
            pending_stake: crate::config::load_config().pending_stake,
        }
    }
}

// ----------------------------------------------------------------------
// Rendering
// ----------------------------------------------------------------------

fn print_item(it: &Item) {
    let mark = match it.level {
        Level::Pass => "ok  ",
        Level::Fail => "FAIL",
        Level::Warn => "note",
        Level::Todo => "todo",
    };
    output::print_field(&format!("[{mark}] {}", it.label), &it.detail);
}

fn print_assessment(a: &Assessment) {
    for it in &a.items {
        print_item(it);
    }
    println!();
    if a.approved {
        output::print_success("This operator is approved for sponsorship.");
    } else if a.ready_to_apply {
        output::print_info(
            "Nothing known blocks approval. `tenzro sponsor apply` prepares the proposal a proposer files.",
        );
    } else if a.items.iter().any(|x| x.level == Level::Fail) {
        output::print_warning("Something above blocks approval; fix the FAIL lines first.");
    }
}

fn json_of(i: &Inputs, a: &Assessment) -> Value {
    json!({
        "account": i.account,
        "machine_did": i.machine_did,
        "node_reachable": i.node_reachable,
        "platform": format!("{:?}", i.platform),
        "window_hours": i.window_hours,
        "verified_epochs": i.verified_epochs,
        "approval": i.approval,
        "received_wei": i.received_wei.to_string(),
        "sponsored_bonded_wei": i.sponsored_bonded_wei.to_string(),
        "proposals": i.proposals.iter().map(|p| json!({"id": p.id, "status": p.status})).collect::<Vec<_>>(),
        "caps": i.caps.as_ref().map(|c| json!({
            "sponsorship_yearly_max_tnzo": c.sponsorship_yearly_max_tnzo,
            "running_cost_per_verified_epoch_wei": c.running_cost_per_verified_epoch_wei,
            "per_grantee_yearly_max_tnzo": c.per_grantee_yearly_max_tnzo,
            "combined_yearly_max_tnzo": c.combined_yearly_max_tnzo,
        })),
        "criteria": a.items.iter().map(|x| json!({
            "label": x.label,
            "level": format!("{:?}", x.level),
            "detail": x.detail,
        })).collect::<Vec<_>>(),
        "ready_to_apply": a.ready_to_apply,
        "approved": a.approved,
    })
}

impl SponsorCheckCmd {
    pub async fn execute(&self) -> Result<()> {
        let inputs = self.target.gather().await;
        let a = assess(&inputs);
        if self.target.json {
            return output::print_json(&json_of(&inputs, &a));
        }
        output::print_header("Sponsorship Eligibility");
        print_assessment(&a);
        Ok(())
    }
}

impl SponsorStatusCmd {
    pub async fn execute(&self) -> Result<()> {
        let inputs = self.target.gather().await;
        let a = assess(&inputs);
        if self.target.json {
            return output::print_json(&json_of(&inputs, &a));
        }
        output::print_header("Sponsorship Status");
        if let Some(acct) = &inputs.account {
            output::print_field("Account", acct);
        }
        match &inputs.approval {
            Some(ap) => {
                output::print_field(
                    "Approval",
                    &format!(
                        "{}{}",
                        ap.get("class").and_then(Value::as_str).unwrap_or("operator"),
                        if ap.get("revoked").and_then(Value::as_bool).unwrap_or(false) {
                            " (revoked)"
                        } else {
                            ""
                        }
                    ),
                );
                output::print_field(
                    "Verified hours counted",
                    &ap.get("verified_epochs")
                        .and_then(Value::as_u64)
                        .unwrap_or(0)
                        .to_string(),
                );
            }
            None => output::print_field("Approval", "none"),
        }
        output::print_field("Paid so far", &format_tnzo(inputs.received_wei));
        output::print_field(
            "Sponsored validator bond",
            &format_tnzo(inputs.sponsored_bonded_wei),
        );
        for p in &inputs.proposals {
            output::print_field("Proposal", &format!("{} is {}", p.id, p.status));
        }
        if let Some(c) = &inputs.caps {
            output::print_field(
                "Caps",
                &format!(
                    "{} TNZO a year, {} wei per verified hour, {} TNZO per grantee a year",
                    c.sponsorship_yearly_max_tnzo,
                    c.running_cost_per_verified_epoch_wei,
                    c.per_grantee_yearly_max_tnzo
                ),
            );
        }
        if let Some(p) = &inputs.pending_stake {
            output::print_field(
                "Waiting for stake",
                &format!(
                    "{} needs {} at {}",
                    p.role,
                    format_tnzo(p.required_wei.parse().unwrap_or(0)),
                    p.account
                ),
            );
        }
        println!();
        print_assessment(&a);
        Ok(())
    }
}

fn default_application_path() -> PathBuf {
    tenzro_types::paths::tenzro_home().join("sponsor-application.json")
}

impl SponsorApplyCmd {
    pub async fn execute(&self) -> Result<()> {
        let inputs = self.target.gather().await;
        let a = assess(&inputs);
        let approve = approve_command(&inputs, &self.region, &self.independence);
        let grant = grant_command(inputs.account.as_deref(), self.grant_amount);

        let path = self.out.clone().unwrap_or_else(default_application_path);
        let mut summary = json_of(&inputs, &a);
        summary["region"] = json!(self.region);
        summary["independence"] = json!(self.independence);
        summary["approve_command"] = json!(approve);
        summary["generated_ms"] = json!(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0)
        );
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
        }
        std::fs::write(&path, serde_json::to_string_pretty(&summary)?)
            .with_context(|| format!("write {}", path.display()))?;

        if self.target.json {
            return output::print_json(&summary);
        }

        output::print_header("Sponsorship Application");
        print_assessment(&a);
        println!();
        if a.approved {
            output::print_success("Already approved; there is nothing to apply for.");
            return Ok(());
        }
        output::print_field("Application summary", &path.display().to_string());
        println!();
        output::print_info(
            "1. Operator approval. Approval is a governance proposal, and filing one needs 1% \
             of the bonded stake, so a proposer files it for you. Send them the summary above; \
             they run:",
        );
        println!("     {approve}");
        output::print_info(
            "   Voting takes 72 hours on the standard track. A separate proposal then funds \
             the validator bond and the running cost, and pays only once governance has set \
             the sponsorship caps.",
        );
        println!();
        output::print_info(
            "2. A grant you file yourself. A treasury grant request needs no balance; the \
             treasury pays its gas. It asks governance to fund the stake directly:",
        );
        println!("     {grant}");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> Inputs {
        Inputs {
            account: Some(format!("0x{}", "ab".repeat(32))),
            machine_did: Some("did:tenzro:machine:abc".into()),
            node_reachable: true,
            platform: Platform::Tpm,
            window_hours: 168,
            verified_epochs: Some(vec![100, 101, 105]),
            approval: None,
            received_wei: 0,
            caps: Some(Caps::default()),
            sponsored_bonded_wei: 0,
            proposals: Vec::new(),
            pending_stake: None,
        }
    }

    fn level(a: &Assessment, label: &str) -> Level {
        a.items.iter().find(|i| i.label == label).unwrap().level
    }

    #[test]
    fn a_tpm_machine_with_hours_and_no_proposal_is_ready_to_apply() {
        let a = assess(&base());
        assert!(a.ready_to_apply);
        assert!(!a.approved);
        assert_eq!(level(&a, "Verified-available hours"), Level::Pass);
        assert_eq!(level(&a, "Governance approval"), Level::Todo);
    }

    #[test]
    fn zero_caps_are_called_out_as_paying_nothing() {
        let a = assess(&base());
        let caps = a.items.iter().find(|i| i.label == "Sponsorship caps").unwrap();
        assert_eq!(caps.level, Level::Warn);
        assert!(caps.detail.contains("pays nothing"));
    }

    #[test]
    fn open_caps_pass() {
        let mut i = base();
        i.caps = Some(Caps {
            sponsorship_yearly_max_tnzo: "50000".into(),
            ..Caps::default()
        });
        assert_eq!(level(&assess(&i), "Sponsorship caps"), Level::Pass);
    }

    #[test]
    fn no_verified_hour_blocks() {
        let mut i = base();
        i.verified_epochs = Some(Vec::new());
        let a = assess(&i);
        assert!(!a.ready_to_apply);
        assert_eq!(level(&a, "Verified-available hours"), Level::Fail);
    }

    #[test]
    fn unreadable_hours_are_not_a_failure() {
        let mut i = base();
        i.verified_epochs = None;
        let a = assess(&i);
        assert_eq!(level(&a, "Verified-available hours"), Level::Warn);
        assert!(a.ready_to_apply);
    }

    #[test]
    fn a_mac_and_a_jetson_are_told_they_cannot_be_approved() {
        for p in [Platform::SecureEnclave, Platform::Jetson] {
            let mut i = base();
            i.platform = p;
            let a = assess(&i);
            assert_eq!(level(&a, "Hardware endorsement"), Level::Fail);
            assert!(!a.ready_to_apply);
        }
    }

    #[test]
    fn an_existing_approval_is_reported_and_a_revoked_one_blocks() {
        let mut i = base();
        i.approval = Some(json!({"class": "validator", "proposal_id": "p1", "revoked": false}));
        let a = assess(&i);
        assert!(a.approved);
        assert!(!a.ready_to_apply);
        i.approval = Some(json!({"class": "validator", "proposal_id": "p1", "revoked": true}));
        let a = assess(&i);
        assert!(!a.approved);
        assert_eq!(level(&a, "Governance approval"), Level::Fail);
    }

    #[test]
    fn a_proposal_in_flight_is_named_and_stops_a_second_application() {
        let mut i = base();
        i.proposals = vec![ProposalLine {
            id: "p9".into(),
            status: "Voting".into(),
        }];
        let a = assess(&i);
        assert!(!a.ready_to_apply);
        let g = a.items.iter().find(|x| x.label == "Governance approval").unwrap();
        assert!(g.detail.contains("p9") && g.detail.contains("Voting"));
    }

    #[test]
    fn an_unreachable_node_says_how_to_continue() {
        let mut i = base();
        i.node_reachable = false;
        i.account = None;
        i.machine_did = None;
        let a = assess(&i);
        assert_eq!(level(&a, "Identity"), Level::Fail);
        assert!(a.items[0].detail.contains("--rpc"));
    }

    #[test]
    fn the_proposal_command_spans_the_verified_epochs() {
        let cmd = approve_command(&base(), "eu-west", "self-declared");
        assert!(cmd.contains("--history-from-epoch 100"));
        assert!(cmd.contains("--history-to-epoch 105"));
        assert!(cmd.contains("did:tenzro:machine:abc"));
    }

    #[test]
    fn proposals_are_matched_by_operator_whether_bytes_or_hex() {
        let acct = format!("0x{}", "ab".repeat(32));
        let as_bytes: Vec<u8> = vec![0xab; 32];
        let list = json!({"proposals": [
            {"proposal": {"id": "a", "status": "Voting", "action": {"action": "approve_operator", "operator": as_bytes}}},
            {"proposal": {"id": "b", "status": "Passed", "action": {"action": "approve_operator", "operator": "0x".to_string() + &"cd".repeat(32)}}},
            {"proposal": {"id": "c", "status": "Queued", "action": {"action": "approve_operator", "operator": "ab".repeat(32)}}},
        ]});
        let ids: Vec<String> = proposals_for(&list, &acct).into_iter().map(|p| p.id).collect();
        assert_eq!(ids, vec!["a", "c"]);
    }

    #[test]
    fn caps_read_from_the_payout_report() {
        let v = json!({"caps": {"sponsorship_yearly_max_tnzo": "0", "running_cost_per_verified_epoch_wei": "7",
            "per_grantee_yearly_max_tnzo": "0", "combined_yearly_max_tnzo": "0"}});
        let c = caps_of(&v).unwrap();
        assert!(c.open());
        assert_eq!(c.running_cost_per_verified_epoch_wei, "7");
    }
}
