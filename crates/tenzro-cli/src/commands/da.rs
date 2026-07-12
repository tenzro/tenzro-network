//! Committee data-availability commands for the Tenzro CLI.
//!
//! - `tenzro da challenge`  — challenge a member's sliver custody (`tenzro_daChallenge`)
//! - `tenzro da challenges` — list resolved challenge records (`tenzro_daListChallenges`)
//! - `tenzro da availability` — rolling availability scores (`tenzro_daAvailability`)
//! - `tenzro da committee`  — committee roster with per-member scores (`tenzro_daCommittee`)
//! - `tenzro da blobs`      — locally-known blob commitments (`tenzro_daListBlobs`)
//!
//! A possession challenge sends a random 32-byte nonce to the target member,
//! which must return its full Red Stuff sliver plus an Ed25519 signature
//! binding the nonce. The challenger re-verifies the sliver against the blob
//! commitment, so a member cannot pass with cached metadata. Outcomes feed a
//! 0-1000 availability score (+1 pass, -5 silence or honest not-held,
//! -25 bad proof). Only validator nodes with committee-DA wired serve these
//! RPCs.

use anyhow::Result;
use clap::{Parser, Subcommand};

use crate::output;

/// Committee data-availability commands
#[derive(Debug, Subcommand)]
pub enum DaCommand {
    /// Challenge a committee member to prove sliver possession
    Challenge(DaChallengeCmd),
    /// List resolved possession-challenge records, newest-first
    Challenges(DaChallengesCmd),
    /// Show availability scores (one member or all, lowest first)
    Availability(DaAvailabilityCmd),
    /// Show the committee roster with per-member availability
    Committee(DaCommitteeCmd),
    /// List blob commitments held in the local committee store
    Blobs(DaBlobsCmd),
}

impl DaCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Challenge(cmd) => cmd.execute().await,
            Self::Challenges(cmd) => cmd.execute().await,
            Self::Availability(cmd) => cmd.execute().await,
            Self::Committee(cmd) => cmd.execute().await,
            Self::Blobs(cmd) => cmd.execute().await,
        }
    }
}

fn print_object(value: &serde_json::Value) {
    for (key, val) in value.as_object().unwrap_or(&serde_json::Map::new()) {
        output::print_field(key, val.to_string().trim_matches('"'));
    }
}

/// Challenge a committee member to prove current possession of its sliver.
#[derive(Debug, Parser)]
pub struct DaChallengeCmd {
    /// 0x-prefixed 32-byte blob commitment
    #[arg(long)]
    commitment: String,

    /// Committee index of the member to challenge
    #[arg(long)]
    target_index: u64,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl DaChallengeCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("DA Possession Challenge");

        let rpc = RpcClient::new(&self.rpc);
        let spinner = output::create_spinner("Challenging...");
        let result: serde_json::Value = rpc
            .call(
                "tenzro_daChallenge",
                serde_json::json!({
                    "commitment": self.commitment,
                    "target_index": self.target_index,
                }),
            )
            .await?;
        spinner.finish_and_clear();

        let outcome = result
            .get("outcome")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        if outcome == "passed" {
            output::print_success("Challenge passed — member proved possession");
        } else {
            output::print_warning(&format!("Challenge outcome: {outcome}"));
        }
        println!();
        print_object(&result);
        Ok(())
    }
}

/// List resolved possession-challenge records.
#[derive(Debug, Parser)]
pub struct DaChallengesCmd {
    /// Maximum records to return, newest-first
    #[arg(long, default_value = "100")]
    limit: u32,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl DaChallengesCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("DA Possession Challenges");

        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_daListChallenges",
                serde_json::json!({ "limit": self.limit }),
            )
            .await?;

        let count = result.get("count").and_then(|v| v.as_u64()).unwrap_or(0);
        output::print_field("Total", &count.to_string());
        println!();

        let challenges = result
            .get("challenges")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        if challenges.is_empty() {
            output::print_warning("No challenges recorded.");
            return Ok(());
        }

        for (i, rec) in challenges.iter().enumerate() {
            println!("Challenge #{}", i + 1);
            print_object(rec);
            println!();
        }
        Ok(())
    }
}

/// Show availability scores.
#[derive(Debug, Parser)]
pub struct DaAvailabilityCmd {
    /// Optional 0x-prefixed member address; omit for all scored members
    #[arg(long)]
    address: Option<String>,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl DaAvailabilityCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("DA Availability Scores");

        let rpc = RpcClient::new(&self.rpc);
        let params = match &self.address {
            Some(addr) => serde_json::json!({ "address": addr }),
            None => serde_json::json!({}),
        };
        let result: serde_json::Value = rpc.call("tenzro_daAvailability", params).await?;

        if self.address.is_some() {
            print_object(&result);
            return Ok(());
        }

        let count = result.get("count").and_then(|v| v.as_u64()).unwrap_or(0);
        output::print_field("Scored members", &count.to_string());
        println!();

        let scores = result
            .get("scores")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        if scores.is_empty() {
            output::print_warning("No members scored yet (no challenges resolved).");
            return Ok(());
        }

        for (i, score) in scores.iter().enumerate() {
            println!("Member #{}", i + 1);
            print_object(score);
            println!();
        }
        Ok(())
    }
}

/// Show the committee roster with per-member availability.
#[derive(Debug, Parser)]
pub struct DaCommitteeCmd {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl DaCommitteeCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("DA Committee");

        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call("tenzro_daCommittee", serde_json::json!({}))
            .await?;

        if let Some(local) = result.get("local_address").and_then(|v| v.as_str()) {
            output::print_field("Local address", local);
        }
        let count = result.get("count").and_then(|v| v.as_u64()).unwrap_or(0);
        output::print_field("Members", &count.to_string());
        println!();

        let members = result
            .get("members")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        for member in &members {
            print_object(member);
            println!();
        }
        Ok(())
    }
}

/// List blob commitments held in the local committee store.
#[derive(Debug, Parser)]
pub struct DaBlobsCmd {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl DaBlobsCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("DA Blob Commitments");

        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call("tenzro_daListBlobs", serde_json::json!({}))
            .await?;

        let count = result.get("count").and_then(|v| v.as_u64()).unwrap_or(0);
        output::print_field("Known blobs", &count.to_string());
        println!();

        let blobs = result
            .get("blobs")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        if blobs.is_empty() {
            output::print_warning("No blob commitments in the local store.");
            return Ok(());
        }

        for (i, blob) in blobs.iter().enumerate() {
            println!("Blob #{}", i + 1);
            print_object(blob);
            println!();
        }
        Ok(())
    }
}
