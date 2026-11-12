//! Governance commands for the Tenzro CLI.
//!
//! Proposals, votes, enactment and vetoes are signed transactions decided in
//! consensus; the read commands show what consensus holds.

use crate::output;
use crate::rpc::RpcClient;
use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use serde_json::{Value, json};

/// Gas limit of a proposal transaction.
const PROPOSE_GAS: u64 = 100_000;
/// Gas limit of a vote transaction.
const VOTE_GAS: u64 = 30_000;
/// Gas limit of an enactment or veto transaction.
const EXECUTE_GAS: u64 = 120_000;
/// Gas for a sponsored-bond release, as the node charges it.
const SPONSORED_BOND_GAS: u64 = 60_000;
/// Gas for a veto signal, a veto withdrawal or a concern.
const HOLDER_GAS: u64 = 60_000;

/// Governance commands
#[derive(Debug, Subcommand)]
pub enum GovernanceCommand {
    #[command(flatten)]
    Rpc(GovernanceRpcCommand),
    /// List proposals, newest first
    List(GovernanceListCmd),
    /// Show one proposal and its tally
    Show(GovernanceShowCmd),
    /// Open a proposal (needs bonded stake)
    Propose(GovernanceProposeCmd),
    /// Vote on an open proposal, weighted by bonded stake
    Vote(GovernanceVoteCmd),
    /// Enact a proposal that passed, once its timelock has run
    Execute(GovernanceIdCmd),
    /// Veto a proposal during its timelock (governance guardians, or
    /// Foundation stewards on a treasury or expedited proposal; takes effect
    /// once the guardian threshold of distinct seats of the role has signed)
    Veto(GovernanceIdCmd),
    /// Lock TNZO against a treasury, sanction or protocol upgrade proposal:
    /// past 1% of supply (governed) its timelock stretches, at 10% it is
    /// voted again on the Ratify track
    #[command(name = "veto-signal")]
    VetoSignal(VetoSignalCmd),
    /// Take back a veto lock once its proposal is decided
    #[command(name = "veto-withdraw")]
    VetoWithdraw(VetoWithdrawCmd),
    /// Raise your human root's concern on a queued proposal; past the quorum
    /// its timelock doubles, once
    Concern(GovernanceIdCmd),
    /// Fetch a proposal's governance receipt (its records with state proofs
    /// under a certified checkpoint) and, with --verify, check it offline
    /// against the genesis anchor
    Receipt(ReceiptCmd),
    /// Show which validators' machines have quoted a binary, against the
    /// share a protocol upgrade needs before it enacts
    Readiness(ReadinessCmd),
    /// Quote the binary staged in this node's data directory (upgrade/staged)
    /// with its TPM and signal readiness from the validator account
    #[command(name = "upgrade-ready")]
    UpgradeReady(UpgradeReadyCmd),
    /// Settle a security fix's vulnerability commitment: reveal the
    /// disclosure, or with no file claim the lapse past the deadline, which
    /// slashes the proposer
    Disclose(DiscloseCmd),
    /// Signal a pause (or with --resume a resume): a protocol guardian's holds
    /// all enactment, a Foundation steward's holds treasury and expedited
    /// enactment; takes effect at the guardian threshold
    Pause(PauseCmd),
    /// Show every seat, the pauses, the threshold and the steward sunset
    Guardians(GuardianStateCmd),
    /// Show the treasury's keyless accounts on other chains and their last grants
    Treasury(TreasuryAccountsCmd),
    /// Show the bonded stake an address votes with
    #[command(name = "voting-power")]
    VotingPower(VotingPowerCmd),
    /// Show the last enacted change of a network policy
    Policy(PolicyCmd),
    /// Show the economic policy this node is applying
    #[command(name = "economic-policy")]
    EconomicPolicy(EconomicPolicyCmd),
    /// Show the governed network parameters: value, bounds, genesis value
    /// and any enacted change waiting for its epoch
    Params(ParamsCmd),
    /// List every governed lever: its kind (status, switch or value), the
    /// value or status in force, its bounds and any change waiting for its
    /// epoch, plus the mode every bridge route is left in
    Levers(LeversCmd),
    /// Propose changing one governed network parameter. A change that only
    /// pauses a status lever (value 1) is decided on the expedited track
    #[command(name = "propose-param")]
    ProposeParam(ProposeParamCmd),
    /// Show the governance-sponsored part of a validator's stake and the caps
    #[command(name = "sponsored-bond")]
    SponsoredBond(SponsoredBondCmd),
    /// Propose bonding existing treasury TNZO on a validator's behalf
    #[command(name = "propose-sponsor-bond")]
    ProposeSponsorBond(ProposeSponsoredBondCmd),
    /// Propose recalling a validator's sponsored bond to the treasury
    #[command(name = "propose-recall-sponsored-bond")]
    ProposeRecallSponsoredBond(ProposeSponsoredBondCmd),
    /// Return a validator's matured unbonding sponsored stake to the treasury
    #[command(name = "release-sponsored-bond")]
    ReleaseSponsoredBond(ReleaseSponsoredBondCmd),
    /// List every sponsorship and grant disbursement by recipient and class,
    /// the governed caps, and the approval status of one address
    #[command(name = "payouts")]
    Payouts(PayoutsCmd),
    /// Propose approving an operator (validator or provider) for sponsorship
    #[command(name = "propose-approve-operator")]
    ProposeApproveOperator(ProposeApproveOperatorCmd),
    /// Propose returning a jailed validator to candidacy at the next epoch,
    /// ahead of the end of its jail term (slashing is not undone)
    #[command(name = "propose-reinstate-validator")]
    ProposeReinstateValidator(ProposeRevokeCmd),
    /// Propose revoking an operator's approval
    #[command(name = "propose-revoke-operator")]
    ProposeRevokeOperator(ProposeRevokeCmd),
    /// Propose approving a grantee (developer, contributor or community)
    #[command(name = "propose-approve-grantee")]
    ProposeApproveGrantee(ProposeApproveGranteeCmd),
    /// Propose revoking a grantee's approval
    #[command(name = "propose-revoke-grantee")]
    ProposeRevokeGrantee(ProposeRevokeCmd),
    /// Propose paying an approved operator's running cost for verified hours
    #[command(name = "propose-operator-running-cost")]
    ProposeOperatorRunningCost(ProposeOperatorRunningCostCmd),
    /// Propose paying an approved operator's running cost in a USD stable asset
    ProposeOperatorStable(ProposeOperatorStableCmd),
}

impl GovernanceCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Rpc(cmd) => cmd.execute().await,
            Self::List(cmd) => cmd.execute().await,
            Self::Show(cmd) => cmd.execute().await,
            Self::Propose(cmd) => cmd.execute().await,
            Self::Vote(cmd) => cmd.execute().await,
            Self::Execute(cmd) => cmd.submit("GovernanceExecute").await,
            Self::Veto(cmd) => cmd.submit("GovernanceVeto").await,
            Self::VetoSignal(cmd) => cmd.execute().await,
            Self::VetoWithdraw(cmd) => cmd.execute().await,
            Self::Concern(cmd) => cmd.submit("GovernanceConcern").await,
            Self::Receipt(cmd) => cmd.execute().await,
            Self::Readiness(cmd) => cmd.execute().await,
            Self::UpgradeReady(cmd) => cmd.execute().await,
            Self::Disclose(cmd) => cmd.execute().await,
            Self::Pause(cmd) => cmd.execute().await,
            Self::Guardians(cmd) => cmd.execute().await,
            Self::Treasury(cmd) => cmd.execute().await,
            Self::VotingPower(cmd) => cmd.execute().await,
            Self::Policy(cmd) => cmd.execute().await,
            Self::EconomicPolicy(cmd) => cmd.execute().await,
            Self::Params(cmd) => cmd.execute().await,
            Self::Levers(cmd) => cmd.execute().await,
            Self::ProposeParam(cmd) => cmd.execute().await,
            Self::SponsoredBond(cmd) => cmd.execute().await,
            Self::ProposeSponsorBond(cmd) => cmd.execute("sponsor_validator_bond").await,
            Self::ProposeRecallSponsoredBond(cmd) => cmd.execute("recall_sponsored_bond").await,
            Self::ReleaseSponsoredBond(cmd) => cmd.execute().await,
            Self::Payouts(cmd) => cmd.execute().await,
            Self::ProposeApproveOperator(cmd) => cmd.execute().await,
            Self::ProposeReinstateValidator(cmd) => {
                cmd.execute("reinstate_validator", "validator").await
            }
            Self::ProposeRevokeOperator(cmd) => cmd.execute("revoke_operator", "operator").await,
            Self::ProposeApproveGrantee(cmd) => cmd.execute().await,
            Self::ProposeRevokeGrantee(cmd) => cmd.execute("revoke_grantee", "grantee").await,
            Self::ProposeOperatorRunningCost(cmd) => cmd.execute().await,
            Self::ProposeOperatorStable(cmd) => cmd.execute().await,
        }
    }
}

/// Sign `tx_type` with the client's hardware key and submit it.
async fn submit(
    rpc_url: &str,
    key_namespace: &str,
    tx_type: Value,
    gas: u64,
    what: &str,
) -> Result<()> {
    let rpc = RpcClient::new(rpc_url);
    let spinner = output::create_spinner(&format!("Submitting {what}..."));
    let result: Value =
        crate::keystore::send_as_client(&rpc, key_namespace, [0u8; 32], tx_type, gas).await?;
    spinner.finish_and_clear();
    let tx_hash = result
        .get("tx_hash")
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .or_else(|| result.as_str().map(str::to_string))
        .unwrap_or_default();
    output::print_success(&format!("{what} submitted"));
    output::print_field("Transaction Hash", &tx_hash);
    Ok(())
}

/// A 32-byte account in the JSON shape a transaction carries it.
fn address_bytes(raw: &str) -> Result<Vec<u8>> {
    let bytes = hex::decode(raw.trim_start_matches("0x"))?;
    if bytes.len() != 32 {
        bail!("an account is 32 bytes (64 hex characters)");
    }
    Ok(bytes)
}

fn proposal_id(raw: &str) -> Result<String> {
    let id = raw.trim_start_matches("0x");
    if id.len() != 64 || hex::decode(id).is_err() {
        bail!("a proposal id is 64 hex characters");
    }
    Ok(id.to_string())
}

/// Show the live economic policy — the rates this node applies to every
/// settlement, and how a payment divides under each of its capabilities.
#[derive(Debug, Parser)]
pub struct EconomicPolicyCmd {
    /// Emit the raw JSON the node returned.
    #[arg(long)]
    json: bool,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl EconomicPolicyCmd {
    pub async fn execute(&self) -> Result<()> {
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call("tenzro_getEconomicPolicy", serde_json::json!([]))
            .await?;

        if self.json {
            println!("{}", serde_json::to_string_pretty(&result)?);
            return Ok(());
        }

        output::print_header("Economic Policy");
        let policy = &result["policy"];
        println!();
        output::print_field(
            "Validating split",
            &format!(
                "operator {} bps / treasury {} bps",
                policy["validating"]["operator_bps"], policy["validating"]["treasury_bps"]
            ),
        );
        output::print_field(
            "Delegated split",
            &format!(
                "operator {} bps / rpc provider {} bps / treasury {} bps",
                policy["delegated"]["operator_bps"],
                policy["delegated"]["rpc_provider_bps"],
                policy["delegated"]["treasury_bps"]
            ),
        );
        output::print_field(
            "Marketplace commission",
            "none taken by the network; a reseller is paid its commission as a declared leg of each payment it sells",
        );
        output::print_field(
            "Default settlement",
            policy["default_conversion"].as_str().unwrap_or("unknown"),
        );
        output::print_field(
            "Micro-settlement floor",
            &policy["micro_settlement_floor"].to_string(),
        );
        output::print_field(
            "Validating",
            if result["validating"].as_bool().unwrap_or(false) {
                "yes"
            } else {
                "no"
            },
        );
        match result["rpc_provider_payee"].as_str() {
            Some(addr) => output::print_field("RPC provider payee", addr),
            None => output::print_field("RPC provider payee", "unset"),
        }

        output::print_field("Visibility", result["visibility"].as_str().unwrap_or("?"));
        let shares: Vec<String> = result["shares"]
            .as_array()
            .map(|v| {
                v.iter()
                    .map(|s| format!("{} {}bps", s["role"].as_str().unwrap_or("?"), s["bps"]))
                    .collect()
            })
            .unwrap_or_default();
        output::print_field(
            "Mode",
            &format!(
                "{} — {}",
                result["mode"].as_str().unwrap_or("?"),
                shares.join(", ")
            ),
        );

        println!();
        output::print_warning(
            "A private node keeps the whole payment. Rates are governance-set: propose a \
             change with `tenzro governance propose` and a policy_update action.",
        );
        Ok(())
    }
}

/// List governance proposals
#[derive(Debug, Parser)]
pub struct GovernanceListCmd {
    /// Keep only one action kind (policy_update, parameter_change, treasury_grant, ...)
    #[arg(long)]
    kind: Option<String>,
    /// How many to show (1-100)
    #[arg(long, default_value_t = 20)]
    limit: u64,
    /// Continue from a previous page's `next`
    #[arg(long)]
    before: Option<u64>,
    /// Emit the raw JSON
    #[arg(long)]
    json: bool,
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl GovernanceListCmd {
    pub async fn execute(&self) -> Result<()> {
        let rpc = RpcClient::new(&self.rpc);
        let result: Value = rpc
            .call(
                "tenzro_listProposals",
                json!({ "limit": self.limit, "before": self.before, "kind": self.kind }),
            )
            .await?;
        if self.json {
            println!("{}", serde_json::to_string_pretty(&result)?);
            return Ok(());
        }
        let proposals = result["proposals"].as_array().cloned().unwrap_or_default();
        output::print_header(&format!(
            "Proposals ({} of {})",
            proposals.len(),
            result["total"]
        ));
        for p in &proposals {
            let proposal = &p["proposal"];
            println!();
            output::print_field("Id", proposal["id"].as_str().unwrap_or_default());
            output::print_field("Kind", p["kind"].as_str().unwrap_or_default());
            output::print_field("Track", &proposal["track"].to_string());
            output::print_field("Status", &proposal["status"].to_string());
            output::print_field(
                "Tally",
                &format!(
                    "yes {} / no {} of {}",
                    p["tally"]["yes"].as_str().unwrap_or("0"),
                    p["tally"]["no"].as_str().unwrap_or("0"),
                    p["tally"]["total_eligible"].as_str().unwrap_or("0"),
                ),
            );
            output::print_field("Veto locked", p["veto_locked"].as_str().unwrap_or("0"));
            output::print_field("Concerns", &proposal["concerns"].to_string());
        }
        if let Some(next) = result["next"].as_u64() {
            println!();
            output::print_info(&format!("More: --before {next}"));
        }
        Ok(())
    }
}

/// Show one proposal
#[derive(Debug, Parser)]
pub struct GovernanceShowCmd {
    /// Proposal id (64 hex)
    proposal_id: String,
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl GovernanceShowCmd {
    pub async fn execute(&self) -> Result<()> {
        let rpc = RpcClient::new(&self.rpc);
        let result: Value = rpc
            .call(
                "tenzro_getProposal",
                json!({ "proposal_id": proposal_id(&self.proposal_id)? }),
            )
            .await?;
        if result.is_null() {
            bail!("no proposal {}", self.proposal_id);
        }
        println!("{}", serde_json::to_string_pretty(&result)?);
        Ok(())
    }
}

/// Open a governance proposal
#[derive(Debug, Parser)]
pub struct GovernanceProposeCmd {
    /// Hardware key namespace of the signing account; with --node-account,
    /// the node's `hardware_key_namespace` (omit for the machine's default
    /// node)
    #[arg(long)]
    key_namespace: Option<String>,
    /// Propose from this machine's node account, the validator account its
    /// genesis entry or registration bonded, instead of a client account
    #[arg(long)]
    node_account: bool,
    /// The proposal action as JSON, tagged by "action", e.g.
    /// '{"action":"parameter_change","key":"...","value":1,"memo":"..."}' or
    /// '{"action":"policy_update","update":{...},"memo":"...","track":{"kind":"standard"}}';
    /// a security fix is '"track":{"kind":"security_fix","basis":{"kind":"vulnerability","commitment":"<hex sha256>"}}'
    #[arg(long, conflicts_with = "file")]
    action: Option<String>,
    /// Read the proposal action from a JSON file
    #[arg(long)]
    file: Option<std::path::PathBuf>,
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl GovernanceProposeCmd {
    pub async fn execute(&self) -> Result<()> {
        let text = match (&self.action, &self.file) {
            (Some(a), None) => a.clone(),
            (None, Some(f)) => {
                std::fs::read_to_string(f).with_context(|| format!("reading {}", f.display()))?
            }
            _ => bail!("give the proposal action with --action or --file"),
        };
        let action: Value = serde_json::from_str(&text).context("the action is not JSON")?;
        if action.get("action").and_then(|v| v.as_str()).is_none() {
            bail!("the action names its kind in an \"action\" field");
        }
        let proposal = serde_json::to_vec(&action)?;
        let tx_type = json!({ "GovernancePropose": { "proposal": proposal } });
        if !self.node_account {
            let namespace = self.key_namespace.as_deref().unwrap_or("client");
            return submit(&self.rpc, namespace, tx_type, PROPOSE_GAS, "proposal").await;
        }
        let rpc = RpcClient::new(&self.rpc);
        let (result, from) = crate::keystore::send_as_node(
            &rpc,
            self.key_namespace.as_deref(),
            [0u8; 32],
            tx_type,
            PROPOSE_GAS,
        )
        .await?;
        output::print_success("proposal submitted");
        output::print_field("Proposer", &from);
        let tx_hash = result
            .get("tx_hash")
            .and_then(Value::as_str)
            .or_else(|| result.as_str());
        output::print_field("Transaction Hash", tx_hash.unwrap_or_default());
        Ok(())
    }
}

/// Show the governed network parameters from chain state.
#[derive(Debug, Parser)]
pub struct ParamsCmd {
    /// Show one parameter only
    #[arg(long)]
    key: Option<String>,
    /// Emit the raw JSON the node returned
    #[arg(long)]
    json: bool,
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ParamsCmd {
    pub async fn execute(&self) -> Result<()> {
        let rpc = RpcClient::new(&self.rpc);
        let params = match &self.key {
            Some(key) => json!({ "key": key }),
            None => json!({}),
        };
        let result: Value = rpc.call("tenzro_getNetworkParams", params).await?;
        if self.json {
            println!("{}", serde_json::to_string_pretty(&result)?);
            return Ok(());
        }
        let rows: Vec<Value> = match result.get("params").and_then(Value::as_array) {
            Some(all) => {
                output::print_header("Network Parameters");
                output::print_field("Epoch", &result["epoch"].to_string());
                all.clone()
            }
            None => vec![result],
        };
        for p in rows {
            println!();
            output::print_field("Key", p["key"].as_str().unwrap_or_default());
            output::print_field("Value", &p["value"].to_string());
            output::print_field("Bounds", &format!("{}..={}", p["min"], p["max"]));
            output::print_field("Genesis", &p["genesis"].to_string());
            if let Some(dir) = p.get("capture_guard").and_then(Value::as_str) {
                output::print_field(
                    "Capture guard",
                    &format!(
                        "tightens {dir}; a loosening moves one step and waits the guard grace"
                    ),
                );
            }
            if let Some(pending) = p.get("pending").filter(|v| !v.is_null()) {
                output::print_field(
                    "Pending",
                    &format!(
                        "{} from epoch {}",
                        pending["value"], pending["activates_epoch"]
                    ),
                );
            }
        }
        Ok(())
    }
}

/// List the governed levers from chain state.
#[derive(Debug, Parser)]
pub struct LeversCmd {
    /// Only the levers of one area, the first part of their key (`bridge`,
    /// `roles`, `zk`, `fees`, ...)
    #[arg(long)]
    area: Option<String>,
    /// Emit the raw JSON the node returned
    #[arg(long)]
    json: bool,
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl LeversCmd {
    pub async fn execute(&self) -> Result<()> {
        let rpc = RpcClient::new(&self.rpc);
        let params = match &self.area {
            Some(area) => json!({ "area": area }),
            None => json!({}),
        };
        let result: Value = rpc.call("tenzro_listLevers", params).await?;
        if self.json {
            println!("{}", serde_json::to_string_pretty(&result)?);
            return Ok(());
        }
        output::print_header("Governed Levers");
        output::print_field("Epoch", &result["epoch"].to_string());
        output::print_field("Total", &result["total"].to_string());
        let text = |v: &Value| v.as_str().map_or_else(|| v.to_string(), str::to_owned);
        let rows: Vec<Vec<String>> = result["levers"]
            .as_array()
            .map(Vec::as_slice)
            .unwrap_or_default()
            .iter()
            .map(|l| {
                let pending =
                    l.get("pending")
                        .filter(|p| !p.is_null())
                        .map_or_else(String::new, |p| {
                            let to = p
                                .get("status")
                                .filter(|s| !s.is_null())
                                .unwrap_or(&p["value"]);
                            format!("{} from epoch {}", text(to), p["activates_epoch"])
                        });
                let pending = match l.get("guardian_pause_until_epoch").filter(|e| !e.is_null()) {
                    Some(until) if pending.is_empty() => {
                        format!("guardian pause until epoch {until}")
                    }
                    Some(until) => format!("{pending}; guardian pause until epoch {until}"),
                    None => pending,
                };
                let now = l
                    .get("status")
                    .filter(|s| !s.is_null())
                    .unwrap_or(&l["value"]);
                vec![
                    text(&l["key"]),
                    text(&l["kind"]),
                    text(now),
                    format!("{}..={}", text(&l["min"]), text(&l["max"])),
                    pending,
                ]
            })
            .collect();
        output::print_table(&["Key", "Kind", "Now", "Bounds", "Pending"], &rows);
        let routes: Vec<Vec<String>> = result["bridge_routes"]
            .as_array()
            .map(Vec::as_slice)
            .unwrap_or_default()
            .iter()
            .map(|r| {
                vec![
                    text(&r["adapter"]),
                    text(&r["source_chain"]),
                    text(&r["mode"]),
                    r.get("reason")
                        .filter(|v| !v.is_null())
                        .map(text)
                        .unwrap_or_default(),
                ]
            })
            .collect();
        if !routes.is_empty() {
            println!();
            output::print_table(&["Transport", "Source Chain", "Mode", "Reason"], &routes);
        }
        Ok(())
    }
}

/// Propose a new value for one governed network parameter. It is checked
/// against the parameter's bounds when submitted, and if the proposal is
/// enacted the value applies from the next epoch (after the tightening grace
/// window when it raises a bond, slash or fee, or shortens a window). Setting
/// a status lever to paused (1) only stops a feature and runs on the
/// expedited track: a short vote and timelock, open to a guardian or steward
/// veto. Resuming (0) and retiring (2) run on the standard track.
#[derive(Debug, Parser)]
pub struct ProposeParamCmd {
    /// Parameter key, as `tenzro governance params` lists it
    #[arg(long)]
    key: String,
    /// The proposed value
    #[arg(long)]
    value: u64,
    /// Why, shown to voters
    #[arg(long)]
    memo: String,
    /// Hardware key namespace of the signing account
    #[arg(long)]
    key_namespace: Option<String>,
    /// Propose from this machine's node account
    #[arg(long)]
    node_account: bool,
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ProposeParamCmd {
    pub async fn execute(&self) -> Result<()> {
        let action = json!({
            "action": "parameter_change",
            "key": self.key,
            "value": self.value,
            "memo": self.memo,
        });
        GovernanceProposeCmd {
            key_namespace: self.key_namespace.clone(),
            node_account: self.node_account,
            action: Some(action.to_string()),
            file: None,
            rpc: self.rpc.clone(),
        }
        .execute()
        .await
    }
}

fn validator_bytes(validator: &str) -> Result<Vec<u8>> {
    let bytes = hex::decode(validator.trim_start_matches("0x"))
        .map_err(|e| anyhow::anyhow!("validator is not hex: {e}"))?;
    if bytes.len() != 32 {
        bail!("validator must be 32 bytes, got {}", bytes.len());
    }
    Ok(bytes)
}

/// Show the governance-sponsored part of a validator's stake: existing
/// treasury TNZO bonded on its behalf, which counts toward the bond and is
/// slashable, never votes, earns nothing and returns to the treasury.
#[derive(Debug, Parser)]
pub struct SponsoredBondCmd {
    /// Validator address (hex)
    address: String,
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl SponsoredBondCmd {
    pub async fn execute(&self) -> Result<()> {
        let rpc = RpcClient::new(&self.rpc);
        let result: Value = rpc
            .call(
                "tenzro_getSponsoredBond",
                json!({ "address": self.address }),
            )
            .await?;
        output::print_header("Sponsored Bond");
        output::print_field("Address", &self.address);
        for (label, field) in [
            ("Bond", "bonded"),
            ("Own bond (votes)", "own_bonded"),
            ("Sponsored, bonded", "sponsored_bonded"),
            ("Sponsored, unbonding", "sponsored_unbonding"),
            ("Sponsored out, network", "sponsored_outstanding_total"),
        ] {
            output::print_field(label, result[field].as_str().unwrap_or("0"));
        }
        for (label, field) in [
            ("Cap per validator (TNZO)", "max_per_validator_tnzo"),
            ("Cap network-wide (TNZO)", "max_total_tnzo"),
        ] {
            output::print_field(label, &result[field].as_u64().unwrap_or(0).to_string());
        }
        Ok(())
    }
}

/// Propose sponsoring or recalling a validator's bond. Amount in the
/// smallest unit; refused while the governed caps are zero.
#[derive(Debug, Parser)]
pub struct ProposeSponsoredBondCmd {
    /// Validator address (64 hex)
    #[arg(long)]
    validator: String,
    /// Amount, smallest unit
    #[arg(long)]
    amount: u128,
    /// Why, shown to voters
    #[arg(long)]
    memo: String,
    /// Hardware key namespace of the signing account
    #[arg(long)]
    key_namespace: Option<String>,
    /// Propose from this machine's node account
    #[arg(long)]
    node_account: bool,
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ProposeSponsoredBondCmd {
    pub async fn execute(&self, action: &str) -> Result<()> {
        let action = json!({
            "action": action,
            "validator": validator_bytes(&self.validator)?,
            "amount": self.amount.to_string(),
            "memo": self.memo,
        });
        GovernanceProposeCmd {
            key_namespace: self.key_namespace.clone(),
            node_account: self.node_account,
            action: Some(action.to_string()),
            file: None,
            rpc: self.rpc.clone(),
        }
        .execute()
        .await
    }
}

/// Return a validator's matured unbonding sponsored stake to the treasury.
/// Anyone may send it.
#[derive(Debug, Parser)]
pub struct ReleaseSponsoredBondCmd {
    /// Validator address (64 hex)
    validator: String,
    /// Hardware key namespace of the signing account
    #[arg(long, default_value = "client")]
    key_namespace: String,
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ReleaseSponsoredBondCmd {
    pub async fn execute(&self) -> Result<()> {
        let tx_type = json!({
            "SponsoredBond": {
                "op": { "release": { "validator": validator_bytes(&self.validator)? } }
            }
        });
        submit(
            &self.rpc,
            &self.key_namespace,
            tx_type,
            SPONSORED_BOND_GAS,
            "sponsored bond release",
        )
        .await
    }
}

/// List the disbursements of treasury sponsorship and grants, oldest first,
/// each with its recipient, amount and class, the total per class and the
/// governed caps. With --address, also whether it is an approved operator or
/// grantee and what it has been paid.
#[derive(Debug, Parser)]
pub struct PayoutsCmd {
    /// Address (hex) to show the approval status of
    #[arg(long)]
    address: Option<String>,
    /// Disbursements to skip
    #[arg(long, default_value_t = 0)]
    offset: u64,
    /// Most disbursements to show
    #[arg(long, default_value_t = 100)]
    limit: u64,
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl PayoutsCmd {
    pub async fn execute(&self) -> Result<()> {
        let rpc = RpcClient::new(&self.rpc);
        let result: Value = rpc
            .call(
                "tenzro_getTreasuryPayouts",
                json!({ "address": self.address, "offset": self.offset, "limit": self.limit }),
            )
            .await?;
        output::print_header("Treasury Payouts");
        output::print_field("Disbursements", &result["count"].to_string());
        if let Some(classes) = result["by_class"].as_object() {
            for (class, total) in classes {
                output::print_field(
                    &format!("Paid, {class} (wei)"),
                    total.as_str().unwrap_or("0"),
                );
            }
        }
        for (label, field) in [
            (
                "Sponsorship cap a year (TNZO)",
                "sponsorship_yearly_max_tnzo",
            ),
            (
                "Running cost per verified hour (wei)",
                "running_cost_per_verified_epoch_wei",
            ),
            ("Grantee cap a year (TNZO)", "per_grantee_yearly_max_tnzo"),
            (
                "Sponsorship and grants cap a year (TNZO)",
                "combined_yearly_max_tnzo",
            ),
        ] {
            output::print_field(
                label,
                &result["caps"][field].as_u64().unwrap_or(0).to_string(),
            );
        }
        if let Some(records) = result["records"].as_array() {
            for r in records {
                output::print_field(
                    &format!("#{} {}", r["n"], r["kind"].as_str().unwrap_or("")),
                    &format!(
                        "{} wei to {} ({}) by {}: {}",
                        r["amount"].as_str().unwrap_or("0"),
                        r["recipient"].as_str().unwrap_or(""),
                        r["class"].as_str().unwrap_or(""),
                        r["proposal_id"].as_str().unwrap_or(""),
                        r["milestone"].as_str().unwrap_or("")
                    ),
                );
            }
        }
        if !result["address"].is_null() {
            output::print_field(
                "Received by address (wei)",
                result["address"]["total_received"].as_str().unwrap_or("0"),
            );
            for (label, field) in [("Operator", "operator"), ("Grantee", "grantee")] {
                let a = &result["address"][field];
                if a.is_null() {
                    output::print_field(label, "not approved");
                } else {
                    output::print_field(
                        label,
                        &format!(
                            "{}{}",
                            a["class"].as_str().unwrap_or(""),
                            if a["revoked"].as_bool().unwrap_or(false) {
                                " (revoked)"
                            } else {
                                ""
                            }
                        ),
                    );
                }
            }
        }
        Ok(())
    }
}

/// Propose a governance action with the shared signing options.
async fn propose_action(
    action: Value,
    key_namespace: &Option<String>,
    node_account: bool,
    rpc: &str,
) -> Result<()> {
    GovernanceProposeCmd {
        key_namespace: key_namespace.clone(),
        node_account,
        action: Some(action.to_string()),
        file: None,
        rpc: rpc.to_string(),
    }
    .execute()
    .await
}

/// Propose approving an operator for sponsorship. The chain checks the
/// machine identity holds a recognised TPM endorsement and counts its
/// verified-available hours in the history named.
#[derive(Debug, Parser)]
pub struct ProposeApproveOperatorCmd {
    /// Operator account (64 hex)
    #[arg(long)]
    operator: String,
    /// validator or provider
    #[arg(long, value_parser = ["validator", "provider"])]
    class: String,
    /// The operator's machine identity (did:tenzro:machine:...)
    #[arg(long)]
    provider_did: String,
    /// Where the operator runs
    #[arg(long)]
    region: String,
    /// First hourly epoch of the availability history counted
    #[arg(long)]
    history_from_epoch: u64,
    /// Last hourly epoch of the availability history counted
    #[arg(long)]
    history_to_epoch: u64,
    /// The operator's independence declaration, or a link to it
    #[arg(long)]
    independence: String,
    /// Link to the public statement of the criteria
    #[arg(long, default_value = "")]
    link: String,
    /// Why, shown to voters
    #[arg(long)]
    memo: String,
    /// Hardware key namespace of the signing account
    #[arg(long)]
    key_namespace: Option<String>,
    /// Propose from this machine's node account
    #[arg(long)]
    node_account: bool,
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ProposeApproveOperatorCmd {
    pub async fn execute(&self) -> Result<()> {
        let action = json!({
            "action": "approve_operator",
            "operator": validator_bytes(&self.operator)?,
            "class": self.class,
            "criteria": {
                "provider_did": self.provider_did,
                "region": self.region,
                "history_from_epoch": self.history_from_epoch,
                "history_to_epoch": self.history_to_epoch,
                "independence": self.independence,
                "link": self.link,
            },
            "memo": self.memo,
        });
        propose_action(action, &self.key_namespace, self.node_account, &self.rpc).await
    }
}

/// Propose approving a grantee. The grantee must hold a registered identity.
#[derive(Debug, Parser)]
pub struct ProposeApproveGranteeCmd {
    /// Grantee account (64 hex)
    #[arg(long)]
    grantee: String,
    /// developer, contributor or community
    #[arg(long, value_parser = ["developer", "contributor", "community"])]
    class: String,
    /// What the grantee builds or does
    #[arg(long)]
    summary: String,
    /// Link to the public statement of the criteria
    #[arg(long, default_value = "")]
    link: String,
    /// Why, shown to voters
    #[arg(long)]
    memo: String,
    /// Hardware key namespace of the signing account
    #[arg(long)]
    key_namespace: Option<String>,
    /// Propose from this machine's node account
    #[arg(long)]
    node_account: bool,
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ProposeApproveGranteeCmd {
    pub async fn execute(&self) -> Result<()> {
        let action = json!({
            "action": "approve_grantee",
            "grantee": validator_bytes(&self.grantee)?,
            "class": self.class,
            "criteria": { "summary": self.summary, "link": self.link },
            "memo": self.memo,
        });
        propose_action(action, &self.key_namespace, self.node_account, &self.rpc).await
    }
}

/// Propose revoking an operator's or a grantee's approval. Every later
/// payment is refused once it is enacted.
#[derive(Debug, Parser)]
pub struct ProposeRevokeCmd {
    /// Account (64 hex): the operator, grantee or jailed validator
    #[arg(long)]
    account: String,
    /// Why, shown to voters
    #[arg(long)]
    memo: String,
    /// Hardware key namespace of the signing account
    #[arg(long)]
    key_namespace: Option<String>,
    /// Propose from this machine's node account
    #[arg(long)]
    node_account: bool,
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ProposeRevokeCmd {
    pub async fn execute(&self, action: &str, field: &str) -> Result<()> {
        let action = json!({
            "action": action,
            field: validator_bytes(&self.account)?,
            "memo": self.memo,
        });
        propose_action(action, &self.key_namespace, self.node_account, &self.rpc).await
    }
}

/// Propose paying an approved operator part of its running cost out of the
/// treasury, against its verified-available hours in the range. Each
/// verified hour backs one payment; refused while the governed caps are zero.
#[derive(Debug, Parser)]
pub struct ProposeOperatorRunningCostCmd {
    /// Approved operator account (64 hex)
    #[arg(long)]
    operator: String,
    /// First hourly epoch claimed
    #[arg(long)]
    from_epoch: u64,
    /// Last hourly epoch claimed
    #[arg(long)]
    to_epoch: u64,
    /// Amount, smallest unit
    #[arg(long)]
    amount: u128,
    /// Why, shown to voters
    #[arg(long)]
    memo: String,
    /// Hardware key namespace of the signing account
    #[arg(long)]
    key_namespace: Option<String>,
    /// Propose from this machine's node account
    #[arg(long)]
    node_account: bool,
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ProposeOperatorRunningCostCmd {
    pub async fn execute(&self) -> Result<()> {
        let action = json!({
            "action": "sponsor_operator_running_cost",
            "operator": validator_bytes(&self.operator)?,
            "from_epoch": self.from_epoch,
            "to_epoch": self.to_epoch,
            "amount": self.amount.to_string(),
            "memo": self.memo,
        });
        propose_action(action, &self.key_namespace, self.node_account, &self.rpc).await
    }
}

/// Propose paying an approved operator's running cost in a USD stable asset
/// the treasury holds, sized in dollars, against its verified-available
/// hours. Each verified hour backs one payment only; refused while the
/// governed USD caps are zero.
#[derive(Debug, Parser)]
pub struct ProposeOperatorStableCmd {
    /// Approved operator account (64 hex)
    #[arg(long)]
    operator: String,
    /// First hourly epoch claimed
    #[arg(long)]
    from_epoch: u64,
    /// Last hourly epoch claimed
    #[arg(long)]
    to_epoch: u64,
    /// The settlement asset: its token id (0x and 64 hex)
    #[arg(long)]
    token_id: String,
    /// Amount, the asset's smallest unit
    #[arg(long)]
    amount: u128,
    /// Use the governed per-payment headroom above the period limit
    #[arg(long)]
    period_exception: bool,
    /// Why, shown to voters
    #[arg(long)]
    memo: String,
    /// Hardware key namespace of the signing account
    #[arg(long)]
    key_namespace: Option<String>,
    /// Propose from this machine's node account
    #[arg(long)]
    node_account: bool,
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ProposeOperatorStableCmd {
    pub async fn execute(&self) -> Result<()> {
        let action = json!({
            "action": "sponsor_operator_stable",
            "operator": validator_bytes(&self.operator)?,
            "from_epoch": self.from_epoch,
            "to_epoch": self.to_epoch,
            "token_id": self.token_id,
            "amount": self.amount.to_string(),
            "period_exception": self.period_exception,
            "memo": self.memo,
        });
        propose_action(action, &self.key_namespace, self.node_account, &self.rpc).await
    }
}

/// Vote on a proposal
#[derive(Debug, Parser)]
pub struct GovernanceVoteCmd {
    /// Proposal id (64 hex)
    proposal_id: String,
    /// Hardware key namespace: the signing client account's (default
    /// `client`), or with --machine-root the node's `hardware_key_namespace`
    /// (default: the machine's default node)
    #[arg(long)]
    key_namespace: Option<String>,
    /// Validator account whose bond the ballot carries (64 hex). The ballot
    /// is cast by the validator's root: its operator's passkey identity
    /// signs it, or, with --machine-root, the autonomous machine that is the
    /// validator approves it.
    #[arg(long)]
    validator: String,
    /// Cast the ballot as the validator's machine root: this machine's
    /// identity key (the key its machine DID derives from) approves it and
    /// the node account submits it. For a validator whose identity is this
    /// autonomous machine.
    #[arg(long)]
    machine_root: bool,
    /// Vote yes
    #[arg(long, conflicts_with = "no", required_unless_present = "no")]
    yes: bool,
    /// Vote no
    #[arg(long)]
    no: bool,
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl GovernanceVoteCmd {
    pub async fn execute(&self) -> Result<()> {
        let id = proposal_id(&self.proposal_id)?;
        let validator = address_bytes(&self.validator)?;
        if !self.machine_root {
            return submit(
                &self.rpc,
                self.key_namespace.as_deref().unwrap_or("client"),
                json!({ "GovernanceVote": { "proposal_id": id, "vote": self.yes, "validator": validator } }),
                VOTE_GAS,
                "vote",
            )
            .await;
        }
        let id_bytes: [u8; 32] = hex::decode(&id)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("proposal id is 32 bytes"))?;
        let rpc = RpcClient::new(&self.rpc);
        let chain_id = crate::rpc::fetch_chain_id(&rpc).await?;
        let approval = crate::keystore::machine_root_ballot(
            self.key_namespace.as_deref(),
            chain_id,
            &id_bytes,
            self.yes,
            &validator,
        )?;
        let tx_type = json!({ "GovernanceVote": {
            "proposal_id": id,
            "vote": self.yes,
            "validator": validator,
            "root_approval": approval,
        } });
        let (result, from) = crate::keystore::send_as_node(
            &rpc,
            self.key_namespace.as_deref(),
            [0u8; 32],
            tx_type,
            VOTE_GAS,
        )
        .await?;
        output::print_success("vote submitted with the machine root's approval");
        output::print_field("Submitted by", &from);
        let tx_hash = result
            .get("tx_hash")
            .and_then(Value::as_str)
            .or_else(|| result.as_str());
        output::print_field("Transaction Hash", tx_hash.unwrap_or_default());
        Ok(())
    }
}

/// Enact or veto a proposal
#[derive(Debug, Parser)]
pub struct GovernanceIdCmd {
    /// Proposal id (64 hex)
    proposal_id: String,
    /// Hardware key namespace of the signing account
    #[arg(long, default_value = "client")]
    key_namespace: String,
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl GovernanceIdCmd {
    async fn submit(&self, tx: &str) -> Result<()> {
        let (what, gas) = match tx {
            "GovernanceVeto" => ("veto", EXECUTE_GAS),
            "GovernanceConcern" => ("concern", HOLDER_GAS),
            _ => ("enactment", EXECUTE_GAS),
        };
        let mut tx_type = serde_json::Map::new();
        tx_type.insert(
            tx.to_string(),
            json!({ "proposal_id": proposal_id(&self.proposal_id)? }),
        );
        submit(
            &self.rpc,
            &self.key_namespace,
            Value::Object(tx_type),
            gas,
            what,
        )
        .await
    }
}

/// A proposal's governance receipt
#[derive(Debug, Parser)]
pub struct ReceiptCmd {
    /// Proposal id (64 hex)
    proposal_id: String,
    /// Read the receipt from this file instead of the node
    #[arg(long)]
    file: Option<std::path::PathBuf>,
    /// Write the receipt fetched from the node to this file
    #[arg(long)]
    out: Option<std::path::PathBuf>,
    /// Verify it offline against the genesis anchor
    #[arg(long, requires_all = ["chain_id", "genesis_hash", "genesis_committee_root"])]
    verify: bool,
    /// Chain id, from the genesis file
    #[arg(long)]
    chain_id: Option<u64>,
    /// Genesis block hash, hex
    #[arg(long)]
    genesis_hash: Option<String>,
    /// Root of the genesis committee, hex
    #[arg(long)]
    genesis_committee_root: Option<String>,
    /// Image id of the handover program, hex, from the chain's governance:
    /// needed when the receipt's checkpoint is certified from a handover
    /// chain proof
    #[arg(long)]
    handover_program: Option<String>,
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ReceiptCmd {
    async fn execute(&self) -> Result<()> {
        use crate::commands::evidence::{hex32, verify_governance_receipt};
        let raw: Value = match &self.file {
            Some(path) => serde_json::from_slice(&std::fs::read(path)?)?,
            None => {
                RpcClient::new(&self.rpc)
                    .call(
                        "tenzro_getGovernanceReceipt",
                        json!({ "proposal_id": proposal_id(&self.proposal_id)? }),
                    )
                    .await?
            }
        };
        if let Some(out) = &self.out {
            std::fs::write(out, serde_json::to_vec_pretty(&raw)?)?;
        }
        let receipt: tenzro_types::evidence_pack::GovernanceReceipt = serde_json::from_value(raw)?;
        if receipt.proposal_id != proposal_id(&self.proposal_id)? {
            bail!("the receipt is of proposal {}", receipt.proposal_id);
        }
        output::print_header("Governance receipt");
        output::print_field("Proposal", &receipt.proposal_id);
        output::print_field("State height", &receipt.state_height.to_string());
        if !self.verify {
            output::print_field("Records", &receipt.records.len().to_string());
            return Ok(());
        }
        let anchor = tenzro_consensus::light_client::GenesisAnchor {
            chain_id: self.chain_id.unwrap_or_default(),
            genesis_hash: hex32(
                self.genesis_hash.as_deref().unwrap_or_default(),
                "--genesis-hash",
            )?,
            committee_root: hex32(
                self.genesis_committee_root.as_deref().unwrap_or_default(),
                "--genesis-committee-root",
            )?,
        };
        let program = self
            .handover_program
            .as_deref()
            .map(|h| hex32(h, "--handover-program"))
            .transpose()?;
        let report = verify_governance_receipt(&receipt, &anchor, program)?;
        output::print_success("Verified from the genesis anchor");
        output::print_field("Certified checkpoint", &report.checkpoint.to_string());
        output::print_field("Status", report.proposal["status"].as_str().unwrap_or(""));
        output::print_field("Track", report.proposal["track"].as_str().unwrap_or(""));
        if let Some(t) = &report.tally {
            output::print_field("Yes", &t["yes"].to_string());
            output::print_field("No", &t["no"].to_string());
        }
        output::print_field("Veto escrow", &report.veto_locked.to_string());
        if let Some(h) = report.executed_height {
            output::print_field("Executed at height", &h.to_string());
        }
        if let Some(a) = &report.activation {
            output::print_field("Activation height", &a["activation_height"].to_string());
        }
        Ok(())
    }
}

/// A binary's readiness
#[derive(Debug, Parser)]
pub struct ReadinessCmd {
    /// Hex SHA-256 of the binary
    code_hash: String,
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ReadinessCmd {
    async fn execute(&self) -> Result<()> {
        let rpc = RpcClient::new(&self.rpc);
        let r: Value = rpc
            .call(
                "tenzro_getUpgradeReadiness",
                json!({ "code_hash": self.code_hash }),
            )
            .await?;
        output::print_header("Upgrade readiness");
        output::print_field("Code hash", r["code_hash"].as_str().unwrap_or(""));
        output::print_field("Ready (bps)", &r["ready_bps"].to_string());
        output::print_field("Required (bps)", &r["required_bps"].to_string());
        output::print_field("Met", &r["met"].to_string());
        output::print_field("This node runs it", &r["this_node_runs_it"].to_string());
        for s in r["signals"].as_array().into_iter().flatten() {
            output::print_field(
                s["validator"].as_str().unwrap_or(""),
                &format!(
                    "{} at height {}",
                    s["machine_did"].as_str().unwrap_or(""),
                    s["height"]
                ),
            );
        }
        if let Some(a) = r.get("scheduled").filter(|a| !a.is_null()) {
            output::print_field("Scheduled version", a["version"].as_str().unwrap_or(""));
            output::print_field("Scheduled binary", a["code_hash"].as_str().unwrap_or(""));
            output::print_field("Activation height", &a["activation_height"].to_string());
        }
        Ok(())
    }
}

/// Signal this validator's readiness for a staged binary
#[derive(Debug, Parser)]
pub struct UpgradeReadyCmd {
    /// Hex SHA-256 of the binary the protocol upgrade names
    code_hash: String,
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl UpgradeReadyCmd {
    async fn execute(&self) -> Result<()> {
        let rpc = RpcClient::new(&self.rpc);
        let r: Value = rpc
            .call(
                "tenzro_signalUpgradeReady",
                json!({ "code_hash": self.code_hash }),
            )
            .await?;
        output::print_success("Readiness signalled");
        output::print_field("Transaction", r["tx_hash"].as_str().unwrap_or(""));
        output::print_field("Validator", r["from"].as_str().unwrap_or(""));
        Ok(())
    }
}

/// Reveal or lapse a security fix's vulnerability commitment
#[derive(Debug, Parser)]
pub struct DiscloseCmd {
    /// Proposal id (64 hex)
    proposal_id: String,
    /// File holding the disclosure; omit to claim the lapse
    #[arg(long)]
    file: Option<std::path::PathBuf>,
    /// Hardware key namespace of the signing account
    #[arg(long, default_value = "client")]
    key_namespace: String,
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl DiscloseCmd {
    async fn execute(&self) -> Result<()> {
        let disclosure = match &self.file {
            Some(path) => std::fs::read(path)?,
            None => Vec::new(),
        };
        submit(
            &self.rpc,
            &self.key_namespace,
            json!({ "GovernanceSecurityDisclosure": {
                "proposal_id": proposal_id(&self.proposal_id)?,
                "disclosure": disclosure,
            } }),
            HOLDER_GAS,
            if self.file.is_some() {
                "disclosure"
            } else {
                "lapse claim"
            },
        )
        .await
    }
}

/// Lock TNZO against a proposal in its veto escrow
#[derive(Debug, Parser)]
pub struct VetoSignalCmd {
    /// Proposal id (64 hex)
    proposal_id: String,
    /// TNZO to lock, in base units; it returns in full once the proposal is decided
    amount: u128,
    /// Hardware key namespace of the signing account
    #[arg(long, default_value = "client")]
    key_namespace: String,
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl VetoSignalCmd {
    async fn execute(&self) -> Result<()> {
        submit(
            &self.rpc,
            &self.key_namespace,
            json!({ "GovernanceVetoSignal": {
                "proposal_id": proposal_id(&self.proposal_id)?,
                "amount": self.amount.to_string(),
            } }),
            HOLDER_GAS,
            "veto signal",
        )
        .await
    }
}

/// Return a veto lock to its holder once the proposal is decided
#[derive(Debug, Parser)]
pub struct VetoWithdrawCmd {
    /// Proposal id (64 hex)
    proposal_id: String,
    /// The account that locked it (64 hex); defaults to the signing account
    #[arg(long)]
    holder: Option<String>,
    /// Hardware key namespace of the signing account
    #[arg(long, default_value = "client")]
    key_namespace: String,
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl VetoWithdrawCmd {
    async fn execute(&self) -> Result<()> {
        let holder = match &self.holder {
            Some(h) => address_bytes(h)?,
            None => crate::keystore::client_account(&self.key_namespace)?
                .1
                .account_slot()
                .to_vec(),
        };
        submit(
            &self.rpc,
            &self.key_namespace,
            json!({ "GovernanceVetoWithdraw": {
                "proposal_id": proposal_id(&self.proposal_id)?,
                "holder": holder,
            } }),
            HOLDER_GAS,
            "veto withdrawal",
        )
        .await
    }
}

/// Signal a pause or resume of governance enactment
#[derive(Debug, Parser)]
pub struct PauseCmd {
    /// Signal a resume instead of a pause
    #[arg(long)]
    resume: bool,
    /// Hardware key namespace of the protocol guardian or Foundation steward account signing
    #[arg(long, default_value = "client")]
    key_namespace: String,
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl PauseCmd {
    async fn execute(&self) -> Result<()> {
        let what = if self.resume {
            "resume signal"
        } else {
            "pause signal"
        };
        submit(
            &self.rpc,
            &self.key_namespace,
            json!({ "GovernancePause": { "paused": !self.resume } }),
            EXECUTE_GAS,
            what,
        )
        .await
    }
}

/// Show guardian state
#[derive(Debug, Parser)]
pub struct GuardianStateCmd {
    /// Account whose guardian seat to show (hex)
    #[arg(long)]
    address: Option<String>,
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl GuardianStateCmd {
    async fn execute(&self) -> Result<()> {
        let rpc = RpcClient::new(&self.rpc);
        let params = match &self.address {
            Some(a) => json!({ "address": a }),
            None => json!({}),
        };
        let result: Value = rpc.call("tenzro_getGuardianState", params).await?;
        output::print_header("Guardians");
        output::print_field("Enactment paused", &result["paused"].to_string());
        output::print_field(
            "Paused until (ms)",
            &result["pause"]["paused_until_ms"].to_string(),
        );
        output::print_field(
            "Cool-off until (ms)",
            &result["pause"]["cooloff_until_ms"].to_string(),
        );
        output::print_field("Treasury held", &result["treasury_held"].to_string());
        output::print_field(
            "Hold until (ms)",
            &result["treasury_hold"]["paused_until_ms"].to_string(),
        );
        output::print_field("Threshold", &result["threshold"].to_string());
        output::print_field(
            "Steward sunset (ms)",
            &result["steward_sunset_ms"].to_string(),
        );
        output::print_field("Steward seat cap", &result["steward_max_seats"].to_string());
        for s in result["seats"].as_array().into_iter().flatten() {
            output::print_field(
                s["address"].as_str().unwrap_or(""),
                &format!(
                    "{} {} until {}{}",
                    s["seat"]["role"].as_str().unwrap_or(""),
                    s["seat"]["did"].as_str().unwrap_or(""),
                    s["seat"]["term_ends_ms"],
                    if s["active"].as_bool() == Some(true) {
                        ""
                    } else {
                        " (lapsed)"
                    }
                ),
            );
        }
        if let Some(seat) = result.get("seat").filter(|s| !s.is_null()) {
            output::print_field("Seat DID", seat["did"].as_str().unwrap_or(""));
            output::print_field("Seat role", seat["role"].as_str().unwrap_or(""));
            output::print_field("Term ends (ms)", &seat["term_ends_ms"].to_string());
            output::print_field("Live", &result["active"].to_string());
        }
        Ok(())
    }
}

/// Show the treasury's accounts on other chains
#[derive(Debug, Parser)]
pub struct TreasuryAccountsCmd {
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl TreasuryAccountsCmd {
    async fn execute(&self) -> Result<()> {
        let rpc = RpcClient::new(&self.rpc);
        let result: Value = rpc.call("tenzro_getTreasuryAccounts", json!({})).await?;
        output::print_header("Treasury accounts");
        output::print_field("Identity", result["did"].as_str().unwrap_or(""));
        output::print_field("Tenzro", result["tenzro"].as_str().unwrap_or(""));
        for a in result["accounts"].as_array().into_iter().flatten() {
            let line = match a.get("address").and_then(Value::as_str) {
                Some(addr) => match a.get("grant").filter(|g| !g.is_null()) {
                    Some(g) => format!(
                        "{addr} (grant {} for {}, until {})",
                        g["seq"], g["amount"], g["not_after_ms"]
                    ),
                    None => addr.to_string(),
                },
                None => a["error"].as_str().unwrap_or("").to_string(),
            };
            output::print_field(a["caip2"].as_str().unwrap_or(""), &line);
        }
        output::print_field("Bitcoin", result["bitcoin"].as_str().unwrap_or(""));
        Ok(())
    }
}

/// Show voting power
#[derive(Debug, Parser)]
pub struct VotingPowerCmd {
    /// Account address (hex)
    address: String,
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl VotingPowerCmd {
    pub async fn execute(&self) -> Result<()> {
        let rpc = RpcClient::new(&self.rpc);
        let result: Value = rpc
            .call("tenzro_getVotingPower", json!({ "address": self.address }))
            .await?;
        output::print_header("Voting Power");
        output::print_field("Address", &self.address);
        output::print_field(
            "Bonded stake",
            result["voting_power"].as_str().unwrap_or("0"),
        );
        output::print_field(
            "Network total",
            result["total_bonded"].as_str().unwrap_or("0"),
        );
        Ok(())
    }
}

/// Show an enacted policy
#[derive(Debug, Parser)]
pub struct PolicyCmd {
    /// economic_policy | adaptive_burn_config | supply_targets | protocol_upgrade
    #[arg(value_parser = [
        "economic_policy", "adaptive_burn_config", "supply_targets", "protocol_upgrade",
    ])]
    kind: String,
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl PolicyCmd {
    pub async fn execute(&self) -> Result<()> {
        let rpc = RpcClient::new(&self.rpc);
        let result: Value = rpc
            .call("tenzro_getPolicy", json!({ "kind": self.kind }))
            .await?;
        if result.is_null() {
            output::print_info(&format!(
                "No {} change has been enacted; the genesis setting stands.",
                self.kind
            ));
            return Ok(());
        }
        println!("{}", serde_json::to_string_pretty(&result)?);
        Ok(())
    }
}

/// Governance commands that call one node RPC each and print its answer
#[derive(Debug, clap::Subcommand)]
pub enum GovernanceRpcCommand {
    /// Call tenzro_decodeAction (decode action) and print the node's answer
    DecodeAction(GovernanceDecodeActionRpcCmd),
}

impl GovernanceRpcCommand {
    pub async fn execute(&self) -> anyhow::Result<()> {
        match self {
            Self::DecodeAction(cmd) => cmd.execute().await,
        }
    }
}

/// Call tenzro_decodeAction (decode action)
#[derive(Debug, clap::Parser)]
pub struct GovernanceDecodeActionRpcCmd {
    /// transaction
    #[arg(long)]
    transaction: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl GovernanceDecodeActionRpcCmd {
    pub async fn execute(&self) -> anyhow::Result<()> {
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_decodeAction",
                serde_json::json!([{ "transaction": self.transaction }]),
            )
            .await?;
        crate::output::print_json(&result)
    }
}

#[cfg(test)]
mod tests {
    /// Every `policy["a"]["b"]` path the economic-policy view reads, taken
    /// from this file's own source so a newly printed field is covered too.
    fn printed_policy_paths() -> Vec<Vec<String>> {
        let source = include_str!("governance.rs");
        let start = source
            .find("impl EconomicPolicyCmd")
            .expect("the economic-policy view is in this file");
        let end = start
            + source[start..]
                .find("\n}\n")
                .expect("the economic-policy view has an end");
        let body = &source[start..end];

        let mut paths = Vec::new();
        let mut rest = body;
        while let Some(at) = rest.find("policy[\"") {
            let mut cursor = &rest[at + "policy".len()..];
            let mut path = Vec::new();
            while let Some(after) = cursor.strip_prefix("[\"") {
                let close = after.find("\"]").expect("an index is closed");
                path.push(after[..close].to_string());
                cursor = &after[close + 2..];
            }
            paths.push(path);
            rest = cursor;
        }
        paths
    }

    #[test]
    fn every_printed_policy_field_exists_in_the_policy() {
        let policy = serde_json::to_value(tenzro_types::economics::EconomicPolicy::default())
            .expect("the policy serializes");
        let paths = printed_policy_paths();
        assert!(
            paths.len() >= 5,
            "the guard found the printed fields ({paths:?})"
        );
        let missing: Vec<String> = paths
            .iter()
            .filter(|path| {
                let mut node = &policy;
                for key in path.iter() {
                    match node.get(key.as_str()) {
                        Some(next) => node = next,
                        None => return true,
                    }
                }
                false
            })
            .map(|path| path.join("."))
            .collect();
        assert!(
            missing.is_empty(),
            "the CLI prints governed parameters the policy does not define: {missing:?}"
        );
    }
}
