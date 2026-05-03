//! Governance commands for the Tenzro CLI

use clap::{Parser, Subcommand};
use anyhow::Result;
use crate::output;

/// Governance commands
#[derive(Debug, Subcommand)]
pub enum GovernanceCommand {
    /// List active proposals
    List(GovernanceListCmd),
    /// Create a new proposal
    Propose(GovernanceProposeCmd),
    /// Vote on a proposal
    Vote(GovernanceVoteCmd),
    /// Vote on a proposal (alias)
    #[command(name = "vote-on")]
    VoteOn(GovernanceVoteCmd),
}

impl GovernanceCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::List(cmd) => cmd.execute().await,
            Self::Propose(cmd) => cmd.execute().await,
            Self::Vote(cmd) => cmd.execute().await,
            Self::VoteOn(cmd) => cmd.execute().await,
        }
    }
}

/// List governance proposals
#[derive(Debug, Parser)]
pub struct GovernanceListCmd {
    /// Show only active proposals
    #[arg(long)]
    active: bool,

    /// Show detailed information
    #[arg(long)]
    detailed: bool,

    /// Output format (table, json)
    #[arg(long, default_value = "table")]
    format: String,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl GovernanceListCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Governance Proposals");

        let spinner = output::create_spinner("Fetching proposals...");

        let rpc = RpcClient::new(&self.rpc);
        let proposals: Vec<serde_json::Value> = rpc.call("tenzro_listProposals", serde_json::json!([{}])).await?;

        spinner.finish_and_clear();

        if self.format == "json" {
            output::print_json(&proposals)?;
        } else if self.detailed && !proposals.is_empty() {
            // Detailed view
            for proposal in &proposals {
                println!();
                if let Some(id) = proposal.get("proposal_id").and_then(|v| v.as_str()) {
                    output::print_field("ID", id);
                }
                if let Some(title) = proposal.get("title").and_then(|v| v.as_str()) {
                    output::print_field("Title", title);
                }
                if let Some(prop_type) = proposal.get("type").and_then(|v| v.as_str()) {
                    output::print_field("Type", prop_type);
                }
                if let Some(proposer) = proposal.get("proposer").and_then(|v| v.as_str()) {
                    output::print_field("Proposer", &output::format_address(proposer));
                }
                if let Some(status) = proposal.get("status").and_then(|v| v.as_str()) {
                    let is_active = status.contains("Active") || status.contains("Pending");
                    output::print_status("Status", status, is_active);
                }
                println!();
                if let Some(votes_for) = proposal.get("votes_for").and_then(|v| v.as_u64().map(|n| n as u128).or_else(|| v.as_str().and_then(|s| s.parse::<u128>().ok()))) {
                    output::print_field("Votes For", &format!("{} TNZO", votes_for));
                }
                if let Some(votes_against) = proposal.get("votes_against").and_then(|v| v.as_u64().map(|n| n as u128).or_else(|| v.as_str().and_then(|s| s.parse::<u128>().ok()))) {
                    output::print_field("Votes Against", &format!("{} TNZO", votes_against));
                }
                if let Some(ends_at) = proposal.get("ends_at").and_then(|v| v.as_str()) {
                    output::print_field("Ends", ends_at);
                }
                println!();
            }
        } else {
            // Table view
            let headers = vec!["ID", "Title", "Type", "Status", "For %", "Ends"];
            let mut rows = Vec::new();

            for proposal in &proposals {
                let id = proposal.get("proposal_id").and_then(|v| v.as_str()).unwrap_or("unknown");
                let title = proposal.get("title").and_then(|v| v.as_str()).unwrap_or("unknown");
                let prop_type = proposal.get("type").and_then(|v| v.as_str()).unwrap_or("unknown");
                let status = proposal.get("status").and_then(|v| v.as_str()).unwrap_or("unknown");
                let votes_for = proposal.get("votes_for").and_then(|v| v.as_u64().map(|n| n as u128).or_else(|| v.as_str().and_then(|s| s.parse::<u128>().ok()))).unwrap_or(0);
                let votes_against = proposal.get("votes_against").and_then(|v| v.as_u64().map(|n| n as u128).or_else(|| v.as_str().and_then(|s| s.parse::<u128>().ok()))).unwrap_or(0);
                let total_votes = votes_for + votes_against;
                let for_pct = if total_votes > 0 {
                    format!("{:.1}%", (votes_for as f64 / total_votes as f64) * 100.0)
                } else {
                    "N/A".to_string()
                };
                let ends_at = proposal.get("ends_at").and_then(|v| v.as_str()).unwrap_or("N/A");

                // Truncate title if too long
                let title_short = if title.len() > 30 {
                    format!("{}...", &title[..27])
                } else {
                    title.to_string()
                };

                rows.push(vec![
                    id.to_string(),
                    title_short,
                    prop_type.to_string(),
                    status.to_string(),
                    for_pct,
                    ends_at.to_string(),
                ]);
            }

            if rows.is_empty() {
                output::print_info("No proposals found");
            } else {
                output::print_table(&headers, &rows);
            }
        }

        Ok(())
    }
}

/// Create a new governance proposal
#[derive(Debug, Parser)]
pub struct GovernanceProposeCmd {
    /// Proposal title
    title: String,

    /// Proposal description
    description: String,

    /// Proposal type (parameter, treasury, upgrade)
    #[arg(long, default_value = "parameter")]
    r#type: String,

    /// Voting duration in days
    #[arg(long, default_value = "14")]
    duration_days: u32,

    /// Minimum proposal deposit (TNZO)
    #[arg(long, default_value = "10000")]
    deposit: String,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl GovernanceProposeCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Create Governance Proposal");

        // Parse deposit
        let deposit_float: f64 = self.deposit.parse()?;
        let minimum_deposit = 10000.0;

        if deposit_float < minimum_deposit {
            return Err(anyhow::anyhow!(
                "Minimum proposal deposit is {} TNZO",
                minimum_deposit
            ));
        }

        // Show proposal details
        println!();
        output::print_field("Title", &self.title);
        output::print_field("Description", &self.description);
        output::print_field("Type", &self.r#type);
        output::print_field("Voting Duration", &format!("{} days", self.duration_days));
        output::print_field("Deposit Required", &format!("{} TNZO", self.deposit));
        println!();

        output::print_warning("Your deposit will be returned if the proposal passes or is rejected.");
        output::print_warning("It will be slashed if the proposal is deemed spam or malicious.");
        println!();

        // Confirm with user
        use dialoguer::Confirm;
        let confirmed = Confirm::new()
            .with_prompt("Submit this proposal?")
            .default(false)
            .interact()?;

        if !confirmed {
            output::print_warning("Proposal cancelled");
            return Ok(());
        }

        let spinner = output::create_spinner("Creating proposal transaction...");

        use crate::rpc::RpcClient;
        let rpc = RpcClient::new(&self.rpc);

        spinner.set_message("Locking deposit...");

        let result: serde_json::Value = rpc.call("tenzro_createProposal", serde_json::json!([{
            "title": self.title,
            "description": self.description,
            "proposal_type": self.r#type,
            "duration_days": self.duration_days,
            "deposit": self.deposit
        }])).await?;

        spinner.set_message("Broadcasting proposal...");

        spinner.finish_and_clear();

        output::print_success("Proposal created successfully!");
        println!();

        if let Some(proposal_id) = result.get("proposal_id").and_then(|v| v.as_str()) {
            output::print_field("Proposal ID", proposal_id);
        }
        if let Some(tx_hash) = result.get("transaction_hash").and_then(|v| v.as_str()) {
            output::print_field("Transaction Hash", tx_hash);
        }
        if let Some(status) = result.get("status").and_then(|v| v.as_str()) {
            output::print_field("Status", status);
        }
        output::print_field("Voting Starts", "Now");
        output::print_field("Voting Ends", &format!("{} days from now", self.duration_days));

        Ok(())
    }
}

/// Vote on a governance proposal
#[derive(Debug, Parser)]
pub struct GovernanceVoteCmd {
    /// Proposal ID
    proposal_id: String,

    /// Vote choice (yes, no, abstain)
    vote: String,

    /// Reason for vote (optional)
    #[arg(long)]
    reason: Option<String>,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl GovernanceVoteCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Cast Governance Vote");

        // Parse vote
        let vote_choice = match self.vote.to_lowercase().as_str() {
            "yes" | "for" | "y" => "For",
            "no" | "against" | "n" => "Against",
            "abstain" | "a" => "Abstain",
            _ => {
                return Err(anyhow::anyhow!(
                    "Invalid vote: {}. Must be one of: yes, no, abstain",
                    self.vote
                ));
            }
        };

        // Query actual voting power from the node
        use crate::rpc::RpcClient;
        let rpc = RpcClient::new(&self.rpc);

        // Fetch voting power using the wallet address from persisted config
        let cfg = crate::config::load_config();
        let from_address = cfg.wallet_address
            .ok_or_else(|| anyhow::anyhow!(
                "No wallet address found. Run `tenzro-cli wallet create` or `tenzro-cli wallet import` first."
            ))?;
        let vp_result = rpc.call::<serde_json::Value>("tenzro_getVotingPower", serde_json::json!([from_address])).await;
        let voting_power: f64 = match vp_result {
            Ok(val) => val.as_str()
                .and_then(|s| s.parse::<f64>().ok())
                .unwrap_or(0.0),
            Err(_) => 0.0,
        };

        if voting_power == 0.0 {
            output::print_warning("Warning: Your voting power is 0. Stake TNZO to participate in governance.");
        }

        println!();
        output::print_field("Proposal ID", &self.proposal_id);
        output::print_field("Your Vote", vote_choice);
        output::print_field("Voting Power", &format!("{} TNZO", voting_power));

        if let Some(reason) = &self.reason {
            output::print_field("Reason", reason);
        }

        println!();

        // Confirm with user
        use dialoguer::Confirm;
        let confirmed = Confirm::new()
            .with_prompt(format!("Cast your vote '{}' on proposal {}?", vote_choice, self.proposal_id))
            .default(false)
            .interact()?;

        if !confirmed {
            output::print_warning("Vote cancelled");
            return Ok(());
        }

        let spinner = output::create_spinner("Creating vote transaction...");

        spinner.set_message("Broadcasting vote...");

        let result: serde_json::Value = rpc.call("tenzro_vote", serde_json::json!([{
            "proposal_id": self.proposal_id,
            "vote": vote_choice,
            "reason": self.reason.as_deref()
        }])).await?;

        spinner.finish_and_clear();

        output::print_success("Vote cast successfully!");
        println!();

        if let Some(vote_id) = result.get("vote_id").and_then(|v| v.as_str()) {
            output::print_field("Vote ID", vote_id);
        }
        if let Some(tx_hash) = result.get("transaction_hash").and_then(|v| v.as_str()) {
            output::print_field("Transaction Hash", tx_hash);
        }
        if let Some(power) = result.get("voting_power").and_then(|v| v.as_u64().map(|n| n as u128).or_else(|| v.as_str().and_then(|s| s.parse::<u128>().ok()))) {
            output::print_field("Voting Power Used", &format!("{} TNZO", power));
        } else {
            output::print_field("Voting Power Used", &format!("{} TNZO", voting_power));
        }

        Ok(())
    }
}
