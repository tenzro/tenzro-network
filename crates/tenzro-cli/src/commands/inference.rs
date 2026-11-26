//! Inference request commands for the Tenzro CLI

use crate::output;
use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

/// Inference commands
#[derive(Debug, Subcommand)]
pub enum InferenceCommand {
    #[command(flatten)]
    Rpc(InferenceRpcCommand),
    /// Submit an inference request
    Request(InferenceRequestCmd),
    /// Run a short inference a sponsoring agent pays for, on a node that
    /// offers it
    Sponsored(SponsoredInferenceCmd),
    /// Read the inference router's live metrics (requests routed, hedges
    /// dispatched, hedges won, deadline-exceeded requests).
    RouterMetrics(RouterMetricsCmd),
    /// Check a jurisdiction receipt's signature and the key that made it
    #[command(name = "verify-jurisdiction-receipt")]
    VerifyJurisdictionReceipt(VerifyJurisdictionReceiptCmd),
    /// Fetch a stored TOPLOC inference commitment by hash.
    GetCommitment(GetCommitmentCmd),
    /// Re-execute a prompt against a stored commitment and report the
    /// per-step verification outcome.
    VerifyCommitment(VerifyCommitmentCmd),
    /// File a challenge against a stored inference commitment.
    FileChallenge(FileChallengeCmd),
    /// Fetch an inference challenge by id.
    GetChallenge(GetChallengeCmd),
    /// List inference challenges, optionally filtered by status or provider.
    ListChallenges(ListChallengesCmd),
    /// The challenges this node holds a committee seat on.
    SeatDuties(SeatDutiesCmd),
    /// Re-execute a challenged reply as a committee seat and record the
    /// verdict.
    Reexecute(ReexecuteCmd),
    /// Commit this node's seat to its recorded verdict (hidden); the verdict
    /// and salt stay on this machine until the reveal.
    CommitVote(CommitVoteCmd),
    /// Reveal the vote committed from this machine.
    RevealVote(RevealVoteCmd),
    /// Finalize an inference challenge by tallying revealed committee
    /// votes. Upheld verdicts decrement the provider's reputation and
    /// record a compute-bond failure.
    FinalizeChallenge(FinalizeChallengeCmd),
    /// Take a challenge its committee upheld to the chain as an inference
    /// fault against the provider's bond (operator only).
    FileChallengeFault(FileChallengeFaultCmd),
}

/// Run a short inference a sponsoring agent pays for
#[derive(Debug, Parser)]
pub struct SponsoredInferenceCmd {
    /// Model id
    #[arg(long)]
    model: String,
    /// Prompt (at most 4096 bytes)
    input: String,
    /// The sponsoring agent's DID
    #[arg(long)]
    sponsor: String,
    /// Most output tokens (up to the node's cap)
    #[arg(long)]
    max_tokens: Option<u32>,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl SponsoredInferenceCmd {
    pub async fn execute(&self) -> Result<()> {
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_sponsoredInference",
                serde_json::json!({
                    "model": self.model, "input": self.input,
                    "sponsor": self.sponsor, "max_tokens": self.max_tokens,
                }),
            )
            .await?;
        output::print_json(&result)
    }
}

impl InferenceCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Rpc(cmd) => cmd.execute().await,
            Self::Request(cmd) => cmd.execute().await,
            Self::Sponsored(cmd) => cmd.execute().await,
            Self::RouterMetrics(cmd) => cmd.execute().await,
            Self::VerifyJurisdictionReceipt(cmd) => cmd.execute().await,
            Self::GetCommitment(cmd) => cmd.execute().await,
            Self::VerifyCommitment(cmd) => cmd.execute().await,
            Self::FileChallenge(cmd) => cmd.execute().await,
            Self::GetChallenge(cmd) => cmd.execute().await,
            Self::ListChallenges(cmd) => cmd.execute().await,
            Self::SeatDuties(cmd) => cmd.execute().await,
            Self::Reexecute(cmd) => cmd.execute().await,
            Self::CommitVote(cmd) => cmd.execute().await,
            Self::RevealVote(cmd) => cmd.execute().await,
            Self::FinalizeChallenge(cmd) => cmd.execute().await,
            Self::FileChallengeFault(cmd) => cmd.execute().await,
        }
    }
}

fn print_challenge(challenge: &serde_json::Value) {
    for key in [
        "challenge_id",
        "commitment_hash",
        "model_id",
        "provider",
        "challenger",
        "reason",
        "status",
        "filed_at",
        "resolved_at",
    ] {
        if let Some(v) = challenge.get(key)
            && !v.is_null()
        {
            let rendered = match v.as_str() {
                Some(s) => s.to_string(),
                None => v.to_string(),
            };
            output::print_field(key, &rendered);
        }
    }
}

/// `tenzro inference get-commitment <hash>`
#[derive(Debug, Parser)]
pub struct GetCommitmentCmd {
    /// Commitment hash (hex, with or without 0x prefix).
    commitment_hash: String,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl GetCommitmentCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_getInferenceCommitment",
                serde_json::json!({ "commitment_hash": self.commitment_hash }),
            )
            .await?;

        if result.is_null() {
            output::print_warning("No commitment stored under that hash");
            return Ok(());
        }
        println!("{}", serde_json::to_string_pretty(&result)?);
        Ok(())
    }
}

/// `tenzro inference verify-commitment <hash> <prompt>`
///
/// The prompt is never stored with the commitment — the verifier must
/// supply the exact prompt that produced the output. Verification
/// requires the node to have the model loaded in serial (llama.cpp) mode.
/// A node that did not serve the response needs `--envelope` and `--receipt`.
#[derive(Debug, Parser)]
pub struct VerifyCommitmentCmd {
    /// Commitment hash (hex, with or without 0x prefix).
    commitment_hash: String,

    /// The exact prompt the committed response was generated from.
    prompt: String,

    /// File holding the output of `get-commitment` run against the node that
    /// served the response, for checking on a node that holds no copy.
    /// Needs `--receipt`.
    #[arg(long, requires = "receipt")]
    envelope: Option<std::path::PathBuf>,

    /// File holding the receipt the provider signed for the response. It
    /// checks the decode, and names the model and provider of an envelope.
    #[arg(long)]
    receipt: Option<std::path::PathBuf>,

    /// Output format (text, json)
    #[arg(long, default_value = "text")]
    format: String,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl VerifyCommitmentCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        let read = |path: &Option<std::path::PathBuf>| -> Result<Option<serde_json::Value>> {
            match path {
                Some(path) => Ok(Some(serde_json::from_slice(&std::fs::read(path)?)?)),
                None => Ok(None),
            }
        };
        // Only the commitment itself is sent: model and provider are taken
        // from the receipt it is checked with.
        let commitment = read(&self.envelope)?.and_then(|e| e.get("commitment").cloned());
        let receipt = read(&self.receipt)?;
        let spinner = output::create_spinner("Re-executing prompt against the commitment...");
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_verifyInferenceCommitment",
                serde_json::json!({
                    "commitment_hash": self.commitment_hash,
                    "prompt": self.prompt,
                    "commitment": commitment,
                    "receipt": receipt,
                }),
            )
            .await?;
        spinner.finish_and_clear();

        if self.format == "json" {
            println!("{}", serde_json::to_string_pretty(&result)?);
            return Ok(());
        }

        output::print_header("Commitment Verification");
        for key in ["commitment_hash", "model_id", "provider"] {
            if let Some(v) = result.get(key).and_then(|v| v.as_str()) {
                output::print_field(key, v);
            }
        }
        let steps_total = result
            .get("steps_total")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let steps_passed = result
            .get("steps_passed")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        output::print_field("steps", &format!("{steps_passed}/{steps_total} passed"));
        if result
            .get("pass")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            output::print_success("Commitment verified: provider output matches re-execution");
        } else {
            output::print_warning("Commitment FAILED verification");
            if let Some(failing) = result.get("failing_steps")
                && !failing.is_null()
            {
                output::print_field("failing_steps", &failing.to_string());
            }
        }
        Ok(())
    }
}

/// `tenzro inference file-challenge <hash> <challenger> --receipt <file>
/// --inputs <file> [--envelope <file>] [--reason ...]`
///
/// The challenge goes to every validator; the inputs are served only to the
/// drawn seats, which re-execute them before voting.
#[derive(Debug, Parser)]
pub struct FileChallengeCmd {
    /// Commitment hash being disputed (hex, with or without 0x prefix).
    commitment_hash: String,

    /// Challenger identity (DID or address).
    challenger: String,

    /// Optional free-text reason for the dispute.
    #[arg(long)]
    reason: Option<String>,

    /// File holding the receipt the provider signed for the response.
    #[arg(long)]
    receipt: std::path::PathBuf,

    /// File holding what the engine was given, as JSON: `{"kind": "prompt",
    /// "prompt": ...}` for a raw completion or `{"kind": "chat", "messages":
    /// [...], "render": {"tools": [...], "enable_thinking": ..,
    /// "reasoning_effort": ..}, "media": [...]}` for a chat turn. It must be
    /// what the receipt commits to.
    #[arg(long)]
    inputs: std::path::PathBuf,

    /// File holding the commitment envelope, when the node filed on did not
    /// serve the response.
    #[arg(long)]
    envelope: Option<std::path::PathBuf>,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl FileChallengeCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        let read = |path: &std::path::Path| -> Result<serde_json::Value> {
            Ok(serde_json::from_slice(&std::fs::read(path)?)?)
        };
        let commitment = match &self.envelope {
            Some(path) => read(path)?.get("commitment").cloned(),
            None => None,
        };
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_fileInferenceChallenge",
                serde_json::json!({
                    "commitment_hash": self.commitment_hash,
                    "challenger": self.challenger,
                    "reason": self.reason,
                    "receipt": read(&self.receipt)?,
                    "inputs": read(&self.inputs)?,
                    "commitment": commitment,
                }),
            )
            .await?;

        output::print_success("Challenge filed");
        print_challenge(&result);
        Ok(())
    }
}

/// `tenzro inference get-challenge <challenge_id>`
#[derive(Debug, Parser)]
pub struct GetChallengeCmd {
    /// Challenge id (UUID).
    challenge_id: String,

    /// Output format (text, json)
    #[arg(long, default_value = "text")]
    format: String,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl GetChallengeCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_getInferenceChallenge",
                serde_json::json!({ "challenge_id": self.challenge_id }),
            )
            .await?;

        if result.is_null() {
            output::print_warning("No challenge with that id");
            return Ok(());
        }
        if self.format == "json" {
            println!("{}", serde_json::to_string_pretty(&result)?);
            return Ok(());
        }
        output::print_header("Inference Challenge");
        print_challenge(&result);
        if let Some(verification) = result.get("verification")
            && !verification.is_null()
        {
            println!();
            output::print_header("Verification");
            output::print_json(verification)?;
        }
        Ok(())
    }
}

/// `tenzro inference list-challenges [--status voting_commit|voting_reveal|upheld|dismissed] [--provider 0x..]`
#[derive(Debug, Parser)]
pub struct ListChallengesCmd {
    /// Filter by status (voting_commit, voting_reveal, upheld, dismissed).
    #[arg(long)]
    status: Option<String>,

    /// Filter by provider (announce-signer pubkey hex).
    #[arg(long)]
    provider: Option<String>,

    /// Output format (text, json)
    #[arg(long, default_value = "text")]
    format: String,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ListChallengesCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_listInferenceChallenges",
                serde_json::json!({
                    "status": self.status,
                    "provider": self.provider,
                }),
            )
            .await?;

        if self.format == "json" {
            println!("{}", serde_json::to_string_pretty(&result)?);
            return Ok(());
        }

        let count = result.get("count").and_then(|v| v.as_u64()).unwrap_or(0);
        output::print_header(&format!("Inference Challenges ({count})"));
        if let Some(challenges) = result.get("challenges").and_then(|v| v.as_array()) {
            for (i, challenge) in challenges.iter().enumerate() {
                if i > 0 {
                    println!();
                }
                print_challenge(challenge);
            }
        }
        Ok(())
    }
}

/// A committed vote kept until its reveal: the verdict and salt stay on this
/// machine, with the reveal signature made at commit time.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct SealedVote {
    challenge_id: String,
    voter: String,
    verdict: bool,
    salt: String,
    reveal_signature: String,
}

/// Where the sealed vote for a challenge is kept. The id must be a UUID, so
/// it can never name a path outside the folder.
fn sealed_vote_path(data_dir: &std::path::Path, challenge_id: &str) -> Result<std::path::PathBuf> {
    let id = uuid::Uuid::parse_str(challenge_id)
        .with_context(|| format!("{challenge_id} is not a challenge id"))?;
    Ok(data_dir
        .join("challenge-votes")
        .join(format!("{}.json", id.hyphenated())))
}

fn keep_sealed_vote(data_dir: &std::path::Path, vote: &SealedVote) -> Result<()> {
    let path = sealed_vote_path(data_dir, &vote.challenge_id)?;
    let dir = path.parent().expect("the path has a folder");
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    // A fresh file, so the mode below always applies.
    let partial = path.with_extension("partial");
    let _ = std::fs::remove_file(&partial);
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut file = options
        .open(&partial)
        .with_context(|| format!("writing {}", partial.display()))?;
    std::io::Write::write_all(&mut file, &serde_json::to_vec_pretty(vote)?)?;
    file.sync_all()?;
    std::fs::rename(&partial, &path).with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

fn sealed_vote(data_dir: &std::path::Path, challenge_id: &str) -> Result<SealedVote> {
    let path = sealed_vote_path(data_dir, challenge_id)?;
    let bytes = std::fs::read(&path).with_context(|| {
        format!(
            "no vote committed from this machine for {challenge_id} ({})",
            path.display()
        )
    })?;
    serde_json::from_slice(&bytes).with_context(|| format!("reading {}", path.display()))
}

/// The verdict this node's re-execution recorded for a challenge it holds a
/// seat on, read from the `tenzro_listSeatDuties` reply. `true` upholds.
fn recorded_verdict(seats: &serde_json::Value, challenge_id: &str) -> Result<bool> {
    let duty = seats["duties"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|d| d["challenge_id"].as_str() == Some(challenge_id))
        .with_context(|| format!("this node holds no seat on challenge {challenge_id}"))?;
    if duty["committed"].as_bool() == Some(true) {
        anyhow::bail!("this node's seat on {challenge_id} has already committed");
    }
    duty["verdict"].as_bool().with_context(|| {
        format!(
            "challenge {challenge_id} is not re-executed yet: run `tenzro inference reexecute {challenge_id}` first"
        )
    })
}

fn verdict_word(upholds: bool) -> &'static str {
    if upholds { "upheld" } else { "dismissed" }
}

/// `tenzro inference seat-duties [--rpc URL]`
///
/// The challenges this node's key holds a committee seat on, with their
/// deadlines and how far the seat has got: re-executed, committed, revealed.
#[derive(Debug, Parser)]
pub struct SeatDutiesCmd {
    /// Output format (text, json)
    #[arg(long, default_value = "text")]
    format: String,

    /// This node's RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl SeatDutiesCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        let reply: serde_json::Value = RpcClient::new(&self.rpc)
            .call("tenzro_listSeatDuties", serde_json::json!({}))
            .await?;
        if self.format == "json" {
            println!("{}", serde_json::to_string_pretty(&reply)?);
            return Ok(());
        }
        let seats = reply["duties"]
            .as_array()
            .map(Vec::as_slice)
            .unwrap_or_default();
        if seats.is_empty() {
            output::print_success("This node holds no committee seat");
            return Ok(());
        }
        for d in seats {
            let step = match (
                d["revealed"].as_bool(),
                d["committed"].as_bool(),
                d["verdict"].as_bool(),
            ) {
                (Some(true), _, _) => "revealed".to_string(),
                (_, Some(true), _) => "committed, reveal next".to_string(),
                (_, _, Some(v)) => format!("re-executed ({}), commit next", verdict_word(v)),
                _ => "re-execute next".to_string(),
            };
            println!(
                "{}  {}  {}  commit by {}  reveal by {}  {}",
                d["challenge_id"].as_str().unwrap_or("?"),
                d["model_id"].as_str().unwrap_or("?"),
                d["status"].as_str().unwrap_or("?"),
                d["commit_deadline"],
                d["reveal_deadline"],
                step
            );
        }
        Ok(())
    }
}

/// `tenzro inference reexecute <challenge_id> [--rpc URL]`
///
/// This node, as a committee seat, fetches the challenged reply's inputs from
/// the node holding the challenge, re-executes them and records its verdict.
/// The verdict a seat may commit is the one recorded here.
#[derive(Debug, Parser)]
pub struct ReexecuteCmd {
    /// Challenge id (UUID).
    challenge_id: String,

    /// Output format (text, json)
    #[arg(long, default_value = "text")]
    format: String,

    /// This node's RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ReexecuteCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        let spinner = output::create_spinner("Re-executing the challenged reply...");
        let result: serde_json::Value = RpcClient::new(&self.rpc)
            .call(
                "tenzro_reexecuteChallenge",
                serde_json::json!({ "challenge_id": self.challenge_id }),
            )
            .await?;
        spinner.finish_and_clear();
        if self.format == "json" {
            println!("{}", serde_json::to_string_pretty(&result)?);
            return Ok(());
        }
        let upholds = result["verdict"]
            .as_bool()
            .context("the node recorded no verdict")?;
        let scored = &result["scored"];
        output::print_success(&format!(
            "Recorded verdict: {} ({} of {} steps matched)",
            verdict_word(upholds),
            scored["steps_passed"],
            scored["steps_total"]
        ));
        Ok(())
    }
}

/// `tenzro inference commit-vote <challenge_id> [--rpc URL]`
///
/// Commits this node's seat to the verdict its re-execution recorded. The
/// salt is drawn here; the node signs the reveal and the commit with its
/// validator key, and the verdict, salt and reveal signature are kept in this
/// machine's data directory until `reveal-vote`. Submitted to this node,
/// which passes the commit on to every node holding the challenge.
#[derive(Debug, Parser)]
pub struct CommitVoteCmd {
    /// Challenge id (UUID).
    challenge_id: String,

    /// Output format (text, json)
    #[arg(long, default_value = "text")]
    format: String,

    /// This node's RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl CommitVoteCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        let data_dir = crate::commands::update::notice::data_dir();
        // Checked before anything is signed or kept.
        sealed_vote_path(&data_dir, &self.challenge_id)?;
        let node = RpcClient::new(&self.rpc);
        let seats: serde_json::Value = node
            .call("tenzro_listSeatDuties", serde_json::json!({}))
            .await?;
        let verdict = recorded_verdict(&seats, &self.challenge_id)?;
        let salt = hex::encode(rand::random::<[u8; 32]>());
        let sign = |phase: &str| {
            node.call::<serde_json::Value>(
                "tenzro_signChallengeVote",
                serde_json::json!({
                    "phase": phase,
                    "challenge_id": self.challenge_id,
                    "verdict": verdict,
                    "salt": salt,
                }),
            )
        };
        let reveal = sign("reveal").await?;
        let sealed = SealedVote {
            challenge_id: self.challenge_id.clone(),
            voter: reveal["voter"]
                .as_str()
                .context("the node named no voter")?
                .to_string(),
            verdict,
            salt: salt.clone(),
            reveal_signature: reveal["signature"]
                .as_str()
                .context("the node returned no reveal signature")?
                .to_string(),
        };
        // Kept before the commit is sent, so a commit that lands can always
        // be revealed.
        keep_sealed_vote(&data_dir, &sealed)?;
        let commit = sign("commit").await?;
        let result: serde_json::Value = node
            .call(
                "tenzro_commitChallengeVote",
                serde_json::json!({
                    "challenge_id": self.challenge_id,
                    "voter": commit["voter"],
                    "commit_hash": commit["commit_hash"],
                    "signature": commit["signature"],
                }),
            )
            .await?;
        if self.format == "json" {
            println!("{}", serde_json::to_string_pretty(&result)?);
            return Ok(());
        }
        output::print_success("Vote committed");
        print_challenge(&result);
        Ok(())
    }
}

/// `tenzro inference reveal-vote <challenge_id> [--rpc URL]`
///
/// Reveals the vote `commit-vote` committed from this machine: the verdict,
/// salt and reveal signature kept then are submitted to the node holding the
/// dispute, and the kept copy is removed once the reveal is accepted.
#[derive(Debug, Parser)]
pub struct RevealVoteCmd {
    /// Challenge id (UUID).
    challenge_id: String,

    /// Output format (text, json)
    #[arg(long, default_value = "text")]
    format: String,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl RevealVoteCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        let data_dir = crate::commands::update::notice::data_dir();
        let sealed = sealed_vote(&data_dir, &self.challenge_id)?;
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_revealChallengeVote",
                serde_json::json!({
                    "challenge_id": sealed.challenge_id,
                    "voter": sealed.voter,
                    "verdict": sealed.verdict,
                    "salt": sealed.salt,
                    "signature": sealed.reveal_signature,
                }),
            )
            .await?;
        std::fs::remove_file(sealed_vote_path(&data_dir, &self.challenge_id)?)?;
        if self.format == "json" {
            println!("{}", serde_json::to_string_pretty(&result)?);
            return Ok(());
        }
        output::print_success("Vote revealed");
        print_challenge(&result);
        Ok(())
    }
}

/// `tenzro inference finalize-challenge <challenge_id>`
///
/// Tallies the committee's revealed votes weighted by stake. No admin
/// token — the verdict is the committee's. Idempotent. A challenge with no
/// quorum closes as dismissed once its reveal window has passed.
#[derive(Debug, Parser)]
pub struct FinalizeChallengeCmd {
    /// Challenge id (UUID).
    challenge_id: String,

    /// Output format (text, json)
    #[arg(long, default_value = "text")]
    format: String,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl FinalizeChallengeCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        let rpc = RpcClient::new(&self.rpc);
        let spinner = output::create_spinner("Finalizing challenge...");
        let result: serde_json::Value = rpc
            .call(
                "tenzro_finalizeChallenge",
                serde_json::json!({
                    "challenge_id": self.challenge_id,
                }),
            )
            .await?;
        spinner.finish_and_clear();

        if self.format == "json" {
            println!("{}", serde_json::to_string_pretty(&result)?);
            return Ok(());
        }

        let status = result.get("status").and_then(|v| v.as_str()).unwrap_or("");
        if status == "upheld" {
            output::print_warning("Challenge UPHELD — provider penalties applied");
        } else if status == "dismissed" {
            output::print_success("Challenge dismissed");
        } else {
            output::print_warning(&format!("Challenge status: {status}"));
        }
        print_challenge(&result);
        if let Some(v) = result.get("reputation_penalized").and_then(|v| v.as_bool()) {
            output::print_field("reputation_penalized", if v { "yes" } else { "no" });
        }
        if let Some(verification) = result.get("verification")
            && !verification.is_null()
        {
            println!();
            output::print_header("Tally");
            output::print_json(verification)?;
        }
        Ok(())
    }
}

/// `tenzro inference file-challenge-fault <challenge_id> <dispute file>`
///
/// Takes a challenge its committee upheld to the chain: the node files the
/// inference fault for the answer the challenged commitment was signed into,
/// from its own validator account, once. Operator only.
#[derive(Debug, Parser)]
pub struct FileChallengeFaultCmd {
    /// Challenge id (UUID).
    challenge_id: String,

    /// File holding the answer the challenged commitment was signed into, as
    /// JSON {receipt, request, output}.
    dispute: std::path::PathBuf,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl FileChallengeFaultCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        let dispute: serde_json::Value = serde_json::from_slice(&std::fs::read(&self.dispute)?)?;
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_fileChallengeFault",
                serde_json::json!({
                    "challenge_id": self.challenge_id,
                    "dispute": dispute,
                }),
            )
            .await?;
        if let Some(fault) = result.get("fault_id").and_then(|v| v.as_str()) {
            output::print_success("Inference fault filed");
            output::print_field("fault_id", fault);
        }
        Ok(())
    }
}

/// Read the inference router's live metrics snapshot.
#[derive(Debug, Parser)]
pub struct RouterMetricsCmd {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,

    /// Output format (text, json)
    #[arg(long, default_value = "text")]
    format: String,
}

impl RouterMetricsCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call("tenzro_getRouterMetrics", serde_json::json!({}))
            .await?;

        if self.format == "json" {
            println!("{}", serde_json::to_string_pretty(&result)?);
            return Ok(());
        }

        output::print_header("Inference Router Metrics");
        if let Some(obj) = result.as_object() {
            for (k, v) in obj {
                output::print_field(k, &v.to_string());
            }
        } else {
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        Ok(())
    }
}

/// Submit an inference request
#[derive(Debug, Parser)]
pub struct InferenceRequestCmd {
    /// Model ID to use
    model_id: String,

    /// Input text, file path, or URL
    input: String,

    /// Maximum price willing to pay (TNZO)
    #[arg(long, default_value = "1.0")]
    max_price: String,

    /// Verification the answer must carry: none, receipt, optimistic or tee
    #[arg(long, default_value = "none", value_parser = ["none", "receipt", "optimistic", "tee"])]
    verification: String,

    /// Temperature (0.0-2.0, for text models)
    #[arg(long)]
    temperature: Option<f32>,

    /// Maximum output tokens (for text models)
    #[arg(long)]
    max_tokens: Option<u32>,

    /// Save output to file
    #[arg(long)]
    output_file: Option<String>,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl InferenceRequestCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Inference Request");

        // Parse max price
        let _max_price_float: f64 = self.max_price.parse()?;

        // Determine if input is a file or direct text
        let input_preview = if std::path::Path::new(&self.input).exists() {
            format!("File: {}", self.input)
        } else if self.input.starts_with("http://") || self.input.starts_with("https://") {
            format!("URL: {}", self.input)
        } else {
            // Direct text input
            if self.input.len() > 100 {
                format!("{}...", &self.input[..97])
            } else {
                self.input.clone()
            }
        };

        // Show request details
        println!();
        output::print_field("Model", &self.model_id);
        output::print_field("Input", &input_preview);
        output::print_field("Max Price", &format!("{} TNZO", self.max_price));

        if self.verification != "none" {
            output::print_field("Verification", &self.verification);
        }

        if let Some(temp) = self.temperature {
            output::print_field("Temperature", &format!("{:.2}", temp));
        }

        if let Some(max_tokens) = self.max_tokens {
            output::print_field("Max Tokens", &max_tokens.to_string());
        }

        println!();

        // Confirm with user
        use dialoguer::Confirm;
        let confirmed = Confirm::new()
            .with_prompt("Submit inference request?")
            .default(true)
            .interact()?;

        if !confirmed {
            output::print_warning("Request cancelled");
            return Ok(());
        }

        let spinner = output::create_spinner("Creating inference request...");

        use crate::rpc::RpcClient;
        let rpc = RpcClient::new(&self.rpc);

        spinner.set_message("Finding available provider...");

        // Submit inference request
        let result: serde_json::Value = rpc
            .call(
                "tenzro_inferenceRequest",
                serde_json::json!([{
                    "model_id": self.model_id,
                    "input": self.input,
                    "max_price": self.max_price,
                    "verification": self.verification,
                    "temperature": self.temperature,
                    "max_tokens": self.max_tokens
                }]),
            )
            .await?;

        spinner.set_message("Receiving response...");

        spinner.finish_and_clear();

        output::print_success("Inference completed successfully!");

        // Display response
        println!();
        output::print_header("Response");
        println!();

        if let Some(response_text) = result.get("response").and_then(|v| v.as_str()) {
            println!("{}", response_text);
        } else if let Some(output) = result.get("output") {
            println!("{}", serde_json::to_string_pretty(&output)?);
        } else {
            println!("Model inference completed. Response data received.");
        }

        println!();

        // Show metadata
        output::print_header("Metadata");
        println!();

        if let Some(request_id) = result.get("request_id").and_then(|v| v.as_str()) {
            output::print_field("Request ID", request_id);
        }
        if let Some(provider) = result.get("provider").and_then(|v| v.as_str()) {
            output::print_field("Provider", &output::format_address(provider));
        }
        if let Some(latency) = result.get("latency").and_then(|v| v.as_f64()) {
            output::print_field("Latency", &format!("{:.2} seconds", latency));
        }
        if let Some(input_tokens) = result.get("input_tokens").and_then(|v| v.as_u64()) {
            output::print_field("Input Tokens", &input_tokens.to_string());
        }
        if let Some(output_tokens) = result.get("output_tokens").and_then(|v| v.as_u64()) {
            output::print_field("Output Tokens", &output_tokens.to_string());
        }
        if let Some(price) = result.get("actual_price").and_then(|v| v.as_str()) {
            output::print_field("Actual Price", price);
        }

        if let Some(receipt) = result.get("tenzro_receipt").filter(|r| !r.is_null()) {
            println!();
            if let Some(hash) = receipt.get("model_hash").and_then(|v| v.as_str()) {
                output::print_field("Model Hash", hash);
            }
            if let Some(machine) = receipt.get("machine_did").and_then(|v| v.as_str()) {
                output::print_field("Machine", machine);
            }
            if let Some(vendor) = receipt
                .get("tee")
                .and_then(|t| t.get("report"))
                .and_then(|r| r.get("vendor"))
                .and_then(|v| v.as_str())
            {
                output::print_field("TEE Report", vendor);
            }
            output::print_info("Check the receipt with tenzro_verifyInferenceReceipt");
        }

        // Save to file if requested
        if let Some(output_file) = &self.output_file
            && let Some(response_text) = result.get("response").and_then(|v| v.as_str())
        {
            std::fs::write(output_file, response_text)?;
            println!();
            output::print_success(&format!("Response saved to: {}", output_file));
        }

        Ok(())
    }
}

/// Inference commands that call one node RPC each and print its answer
#[derive(Debug, clap::Subcommand)]
pub enum InferenceRpcCommand {
    /// Call tenzro_getGeneration (get generation) and print the node's answer
    Generation(InferenceGenerationRpcCmd),
    /// Call tenzro_listInferenceUsage (list inference usage) and print the node's answer
    Usage(InferenceUsageRpcCmd),
    /// Call tenzro_auditInferenceChallenge (audit inference challenge) and print the node's answer
    AuditChallenge(InferenceAuditChallengeRpcCmd),
    /// Call tenzro_verifyInferenceReceipt (verify inference receipt) and print the node's answer
    VerifyReceipt(InferenceVerifyReceiptRpcCmd),
    /// Call tenzro_prefixProbe (prefix probe) and print the node's answer
    PrefixProbe(InferencePrefixProbeRpcCmd),
    /// Call tenzro_moeRoute (moe route) and print the node's answer
    MoeRoute(InferenceMoeRouteRpcCmd),
    /// Call tenzro_moeExecute (moe execute) and print the node's answer
    MoeExecute(InferenceMoeExecuteRpcCmd),
    /// Re-execute a stored expert receipt and dispute it if it does not match (tenzro_moeDisputeReceipt)
    MoeDisputeReceipt(InferenceMoeDisputeReceiptRpcCmd),
    /// Live operators holding a model on standby in a jurisdiction, cheapest first, with the account a reservation escrow must pay and the hourly fee each one advertises (tenzro_standbyQuote)
    StandbyQuote(InferenceStandbyQuoteRpcCmd),
}

impl InferenceRpcCommand {
    pub async fn execute(&self) -> anyhow::Result<()> {
        match self {
            Self::Generation(cmd) => cmd.execute().await,
            Self::Usage(cmd) => cmd.execute().await,
            Self::AuditChallenge(cmd) => cmd.execute().await,
            Self::VerifyReceipt(cmd) => cmd.execute().await,
            Self::PrefixProbe(cmd) => cmd.execute().await,
            Self::MoeRoute(cmd) => cmd.execute().await,
            Self::MoeExecute(cmd) => cmd.execute().await,
            Self::MoeDisputeReceipt(cmd) => cmd.execute().await,
            Self::StandbyQuote(cmd) => cmd.execute().await,
        }
    }
}

/// Call tenzro_standbyQuote: who would hold a session on standby, and for what fee
#[derive(Debug, clap::Parser)]
pub struct InferenceStandbyQuoteRpcCmd {
    /// The model the standby holder must have staged
    #[arg(long)]
    model_id: String,
    /// The jurisdiction the session is pinned to (an operator outside it can never succeed the session)
    #[arg(long)]
    jurisdiction: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl InferenceStandbyQuoteRpcCmd {
    pub async fn execute(&self) -> anyhow::Result<()> {
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_standbyQuote",
                serde_json::json!({ "model_id": self.model_id, "jurisdiction": self.jurisdiction }),
            )
            .await?;
        crate::output::print_json(&result)
    }
}

/// Call tenzro_getGeneration (get generation)
#[derive(Debug, clap::Parser)]
pub struct InferenceGenerationRpcCmd {
    /// id
    #[arg(long)]
    id: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl InferenceGenerationRpcCmd {
    pub async fn execute(&self) -> anyhow::Result<()> {
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call("tenzro_getGeneration", serde_json::json!({ "id": self.id }))
            .await?;
        crate::output::print_json(&result)
    }
}

/// Call tenzro_listInferenceUsage (list inference usage)
#[derive(Debug, clap::Parser)]
pub struct InferenceUsageRpcCmd {
    /// model id
    #[arg(long)]
    model_id: Option<String>,
    /// provider
    #[arg(long)]
    provider: Option<String>,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl InferenceUsageRpcCmd {
    pub async fn execute(&self) -> anyhow::Result<()> {
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_listInferenceUsage",
                serde_json::json!({ "model_id": self.model_id, "provider": self.provider }),
            )
            .await?;
        crate::output::print_json(&result)
    }
}

/// Call tenzro_auditInferenceChallenge (audit inference challenge)
#[derive(Debug, clap::Parser)]
pub struct InferenceAuditChallengeRpcCmd {
    /// challenge id
    #[arg(long)]
    challenge_id: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl InferenceAuditChallengeRpcCmd {
    pub async fn execute(&self) -> anyhow::Result<()> {
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_auditInferenceChallenge",
                serde_json::json!({ "challenge_id": self.challenge_id }),
            )
            .await?;
        crate::output::print_json(&result)
    }
}

/// Call tenzro_verifyInferenceReceipt (verify inference receipt)
#[derive(Debug, clap::Parser)]
pub struct InferenceVerifyReceiptRpcCmd {
    /// level
    #[arg(long)]
    level: String,
    /// receipt (JSON)
    #[arg(long)]
    receipt: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl InferenceVerifyReceiptRpcCmd {
    pub async fn execute(&self) -> anyhow::Result<()> {
        let receipt: serde_json::Value =
            serde_json::from_str(&self.receipt).context("--receipt is not JSON")?;
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_verifyInferenceReceipt",
                serde_json::json!({ "level": self.level, "receipt": receipt }),
            )
            .await?;
        crate::output::print_json(&result)
    }
}

/// Call tenzro_prefixProbe (prefix probe)
#[derive(Debug, clap::Parser)]
pub struct InferencePrefixProbeRpcCmd {
    /// digests
    #[arg(long)]
    digests: Vec<String>,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl InferencePrefixProbeRpcCmd {
    pub async fn execute(&self) -> anyhow::Result<()> {
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_prefixProbe",
                serde_json::json!({ "digests": self.digests }),
            )
            .await?;
        crate::output::print_json(&result)
    }
}

/// Call tenzro_moeRoute (moe route)
#[derive(Debug, clap::Parser)]
pub struct InferenceMoeRouteRpcCmd {
    /// model id
    #[arg(long)]
    model_id: String,
    /// hidden states (JSON)
    #[arg(long)]
    hidden_states: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl InferenceMoeRouteRpcCmd {
    pub async fn execute(&self) -> anyhow::Result<()> {
        let hidden_states: serde_json::Value =
            serde_json::from_str(&self.hidden_states).context("--hidden-states is not JSON")?;
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_moeRoute",
                serde_json::json!({ "model_id": self.model_id, "hidden_states": hidden_states }),
            )
            .await?;
        crate::output::print_json(&result)
    }
}

/// Call tenzro_moeExecute (moe execute)
#[derive(Debug, clap::Parser)]
pub struct InferenceMoeExecuteRpcCmd {
    /// request (JSON)
    #[arg(long)]
    request: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl InferenceMoeExecuteRpcCmd {
    pub async fn execute(&self) -> anyhow::Result<()> {
        let request: serde_json::Value =
            serde_json::from_str(&self.request).context("--request is not JSON")?;
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc.call("tenzro_moeExecute", request).await?;
        crate::output::print_json(&result)
    }
}

/// Re-execute a stored expert receipt against this node's copy of the expert;
/// a mismatch is a fraud proof against the receipt's signer.
#[derive(Debug, clap::Parser)]
pub struct InferenceMoeDisputeReceiptRpcCmd {
    /// Storage key of the receipt
    #[arg(long)]
    key: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl InferenceMoeDisputeReceiptRpcCmd {
    pub async fn execute(&self) -> anyhow::Result<()> {
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_moeDisputeReceipt",
                serde_json::json!({ "key": self.key }),
            )
            .await?;
        crate::output::print_json(&result)
    }
}

/// Check a jurisdiction receipt against this node's chain state.
#[derive(Debug, Parser)]
pub struct VerifyJurisdictionReceiptCmd {
    /// File holding the receipt as JSON
    #[arg(long)]
    file: std::path::PathBuf,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl VerifyJurisdictionReceiptCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        let text = std::fs::read_to_string(&self.file)
            .with_context(|| format!("reading {}", self.file.display()))?;
        let receipt: serde_json::Value = serde_json::from_str(&text)?;
        let verdict: serde_json::Value = RpcClient::new(&self.rpc)
            .call(
                "tenzro_verifyJurisdictionReceipt",
                serde_json::json!({ "receipt": receipt }),
            )
            .await?;
        output::print_header("Jurisdiction Receipt");
        output::print_json(&verdict)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHALLENGE: &str = "6f1c2a8e-3b4d-4e5f-9a0b-1c2d3e4f5a6b";

    #[test]
    fn a_committed_vote_is_kept_until_its_reveal_and_only_under_a_challenge_id() {
        let dir = tempfile::tempdir().unwrap();
        let vote = SealedVote {
            challenge_id: CHALLENGE.to_string(),
            voter: "0xabcd".to_string(),
            verdict: true,
            salt: hex::encode([7u8; 32]),
            reveal_signature: "aa".to_string(),
        };
        assert!(sealed_vote(dir.path(), CHALLENGE).is_err());
        keep_sealed_vote(dir.path(), &vote).unwrap();
        assert_eq!(sealed_vote(dir.path(), CHALLENGE).unwrap(), vote);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let path = sealed_vote_path(dir.path(), CHALLENGE).unwrap();
            let mode = std::fs::metadata(path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        for id in ["../escape", "a/b", ""] {
            assert!(sealed_vote_path(dir.path(), id).is_err());
        }
    }

    #[test]
    fn a_seat_commits_only_the_verdict_its_re_execution_recorded() {
        let duties = serde_json::json!({ "voter": "0xabcd", "duties": [
            { "challenge_id": "a", "verdict": true, "committed": false },
            { "challenge_id": "b", "verdict": null, "committed": false },
            { "challenge_id": "c", "verdict": false, "committed": true },
            { "challenge_id": CHALLENGE, "verdict": false, "committed": false },
        ]});
        assert!(recorded_verdict(&duties, "a").unwrap());
        assert!(!recorded_verdict(&duties, CHALLENGE).unwrap());
        let not_run = recorded_verdict(&duties, "b").unwrap_err().to_string();
        assert!(
            not_run.contains("tenzro inference reexecute b"),
            "{not_run}"
        );
        assert!(recorded_verdict(&duties, "c").is_err());
        assert!(recorded_verdict(&duties, "d").is_err());
        assert!(recorded_verdict(&serde_json::Value::Null, "a").is_err());
    }

    #[test]
    fn a_seat_names_no_verdict_salt_or_hash() {
        assert!(CommitVoteCmd::try_parse_from(["commit-vote", CHALLENGE]).is_ok());
        for flag in ["--verdict", "--commit-hash", "--voter-rpc"] {
            assert!(
                CommitVoteCmd::try_parse_from(["commit-vote", CHALLENGE, flag, "x"]).is_err(),
                "{flag}"
            );
        }
        assert!(RevealVoteCmd::try_parse_from(["reveal-vote", CHALLENGE]).is_ok());
        assert!(RevealVoteCmd::try_parse_from(["reveal-vote", CHALLENGE, "--salt", "00"]).is_err());
        assert!(ReexecuteCmd::try_parse_from(["reexecute", CHALLENGE]).is_ok());
        assert!(SeatDutiesCmd::try_parse_from(["seat-duties"]).is_ok());
    }
}
