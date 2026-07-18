//! Inference request commands for the Tenzro CLI

use clap::{Parser, Subcommand};
use anyhow::{Context, Result};
use crate::output;

/// Inference commands
#[derive(Debug, Subcommand)]
pub enum InferenceCommand {
    /// Submit an inference request
    Request(InferenceRequestCmd),
    /// Stream a chat completion, optionally billed against a payment channel.
    Stream(InferenceStreamCmd),
    /// Read the inference router's live metrics (requests routed, hedges
    /// dispatched, hedges won, deadline-exceeded requests).
    RouterMetrics(RouterMetricsCmd),
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
    /// Commit a committee vote (hidden) on an inference challenge.
    CommitVote(CommitVoteCmd),
    /// Reveal a previously committed committee vote.
    RevealVote(RevealVoteCmd),
    /// Finalize an inference challenge by tallying revealed committee
    /// votes. Upheld verdicts decrement the provider's reputation and
    /// record a compute-bond failure.
    FinalizeChallenge(FinalizeChallengeCmd),
    /// Select a model for an intent (use case + budget + quality floor +
    /// cost-quality knob) without naming one. Discovery only — dispatches
    /// nothing. With `--message`, discovers and runs in one call.
    Route(RouteCmd),
}

impl InferenceCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Request(cmd) => cmd.execute().await,
            Self::Stream(cmd) => cmd.execute().await,
            Self::RouterMetrics(cmd) => cmd.execute().await,
            Self::GetCommitment(cmd) => cmd.execute().await,
            Self::VerifyCommitment(cmd) => cmd.execute().await,
            Self::FileChallenge(cmd) => cmd.execute().await,
            Self::GetChallenge(cmd) => cmd.execute().await,
            Self::ListChallenges(cmd) => cmd.execute().await,
            Self::CommitVote(cmd) => cmd.execute().await,
            Self::RevealVote(cmd) => cmd.execute().await,
            Self::FinalizeChallenge(cmd) => cmd.execute().await,
            Self::Route(cmd) => cmd.execute().await,
        }
    }
}

/// `tenzro inference route --use-case <u> [--budget <b>] [--optimize <f>]
///   [--quality-floor cheap|strong] [--message <m>]`
///
/// Runs the model-selection pipeline. Without `--message`, calls
/// `tenzro_routeIntent` and prints the chosen model, tier, estimated cost,
/// and fallback chain (discovery only). With `--message`, calls
/// `tenzro_chatByIntent`, which discovers a model then dispatches it.
#[derive(Debug, Parser)]
pub struct RouteCmd {
    /// Use case: chat, code, reasoning, summarize, extract, or embed.
    #[arg(long)]
    use_case: String,

    /// Per-request cost cap in smallest TNZO unit (decimal string).
    #[arg(long)]
    budget: Option<String>,

    /// Cost-quality knob in [0.0, 1.0]: 0.0 cheapest acceptable, 1.0 strongest.
    #[arg(long)]
    optimize: Option<f32>,

    /// Reject any model below this tier: cheap or strong.
    #[arg(long)]
    quality_floor: Option<String>,

    /// Estimated input tokens for cost estimation.
    #[arg(long)]
    est_input_tokens: Option<u64>,

    /// Estimated output tokens for cost estimation.
    #[arg(long)]
    est_output_tokens: Option<u64>,

    /// Payer DID — enables the per-DID rolling-window budget gate.
    #[arg(long)]
    payer_did: Option<String>,

    /// When set, discover a model and run this prompt in one call.
    #[arg(long)]
    message: Option<String>,

    /// Maximum output tokens (only used with --message).
    #[arg(long, default_value_t = 256)]
    max_tokens: u64,

    /// Output format (text, json)
    #[arg(long, default_value = "text")]
    format: String,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl RouteCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        let mut params = serde_json::Map::new();
        params.insert(
            "use_case".to_string(),
            serde_json::Value::String(self.use_case.clone()),
        );
        if let Some(b) = &self.budget {
            params.insert("budget".to_string(), serde_json::Value::String(b.clone()));
        }
        if let Some(o) = self.optimize {
            params.insert(
                "optimize".to_string(),
                serde_json::json!(o),
            );
        }
        if let Some(q) = &self.quality_floor {
            params.insert(
                "quality_floor".to_string(),
                serde_json::Value::String(q.clone()),
            );
        }
        if let Some(n) = self.est_input_tokens {
            params.insert("est_input_tokens".to_string(), serde_json::json!(n));
        }
        if let Some(n) = self.est_output_tokens {
            params.insert("est_output_tokens".to_string(), serde_json::json!(n));
        }
        if let Some(did) = &self.payer_did {
            params.insert(
                "payer_did".to_string(),
                serde_json::Value::String(did.clone()),
            );
        }

        let rpc = RpcClient::new(&self.rpc);

        // With a message, discover + dispatch; otherwise discovery only.
        if let Some(message) = &self.message {
            params.insert(
                "message".to_string(),
                serde_json::Value::String(message.clone()),
            );
            params.insert("max_tokens".to_string(), serde_json::json!(self.max_tokens));

            let spinner = output::create_spinner("Routing intent and dispatching...");
            let result: serde_json::Value = rpc
                .call("tenzro_chatByIntent", serde_json::Value::Object(params))
                .await
                .context("calling tenzro_chatByIntent")?;
            spinner.finish_and_clear();

            if self.format == "json" {
                println!("{}", serde_json::to_string_pretty(&result)?);
                return Ok(());
            }

            if let Some(route) = result.get("route") {
                output::print_header("Selected Model");
                print_route(route);
                println!();
            }
            let response_text = result
                .get("response")
                .or_else(|| result.get("result").and_then(|r| r.get("response")))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if !response_text.is_empty() {
                output::print_header("Response");
                println!(
                    "{}",
                    tenzro_node::eu_ai_disclosure::render_cli_chat_chunk(response_text)
                );
            }
            return Ok(());
        }

        let spinner = output::create_spinner("Selecting a model for the intent...");
        let result: serde_json::Value = rpc
            .call("tenzro_routeIntent", serde_json::Value::Object(params))
            .await
            .context("calling tenzro_routeIntent")?;
        spinner.finish_and_clear();

        if self.format == "json" {
            println!("{}", serde_json::to_string_pretty(&result)?);
            return Ok(());
        }
        output::print_header("Selected Model");
        print_route(&result);
        Ok(())
    }
}

fn print_route(route: &serde_json::Value) {
    for key in ["model_id", "tier", "estimated_cost", "reason"] {
        if let Some(v) = route.get(key)
            && !v.is_null()
        {
            let rendered = match v.as_str() {
                Some(s) => s.to_string(),
                None => v.to_string(),
            };
            output::print_field(key, &rendered);
        }
    }
    if let Some(chain) = route.get("fallback_chain").and_then(|v| v.as_array())
        && !chain.is_empty()
    {
        let joined: Vec<String> = chain
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect();
        output::print_field("fallback_chain", &joined.join(" → "));
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
#[derive(Debug, Parser)]
pub struct VerifyCommitmentCmd {
    /// Commitment hash (hex, with or without 0x prefix).
    commitment_hash: String,

    /// The exact prompt the committed response was generated from.
    prompt: String,

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
        let spinner = output::create_spinner("Re-executing prompt against stored commitment...");
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_verifyInferenceCommitment",
                serde_json::json!({
                    "commitment_hash": self.commitment_hash,
                    "prompt": self.prompt,
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
        let steps_total = result.get("steps_total").and_then(|v| v.as_u64()).unwrap_or(0);
        let steps_passed = result.get("steps_passed").and_then(|v| v.as_u64()).unwrap_or(0);
        output::print_field("steps", &format!("{steps_passed}/{steps_total} passed"));
        if result.get("pass").and_then(|v| v.as_bool()).unwrap_or(false) {
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

/// `tenzro inference file-challenge <hash> <challenger> [--reason ...]`
#[derive(Debug, Parser)]
pub struct FileChallengeCmd {
    /// Commitment hash being disputed (hex, with or without 0x prefix).
    commitment_hash: String,

    /// Challenger identity (DID or address).
    challenger: String,

    /// Optional free-text reason for the dispute.
    #[arg(long)]
    reason: Option<String>,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl FileChallengeCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_fileInferenceChallenge",
                serde_json::json!({
                    "commitment_hash": self.commitment_hash,
                    "challenger": self.challenger,
                    "reason": self.reason,
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

/// `tenzro inference commit-vote <challenge_id> --voter 0x.. --commit-hash <hex>`
///
/// A drawn committee member records the hidden commit
/// `H(verdict||salt||challenge_id||voter)`. The verdict stays sealed until
/// `reveal-vote`.
#[derive(Debug, Parser)]
pub struct CommitVoteCmd {
    /// Challenge id (UUID).
    challenge_id: String,

    /// Committee-member identity (validator address, hex).
    #[arg(long)]
    voter: String,

    /// Vote commitment hash (hex).
    #[arg(long)]
    commit_hash: String,

    /// Output format (text, json)
    #[arg(long, default_value = "text")]
    format: String,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl CommitVoteCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_commitChallengeVote",
                serde_json::json!({
                    "challenge_id": self.challenge_id,
                    "voter": self.voter,
                    "commit_hash": self.commit_hash,
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

/// `tenzro inference reveal-vote <challenge_id> --voter 0x.. --verdict <bool> --salt <hex>`
///
/// Reveals a committed vote. `(verdict, salt)` must reproduce the commit
/// hash. `--verdict true` means the commitment did not verify (upholds).
#[derive(Debug, Parser)]
pub struct RevealVoteCmd {
    /// Challenge id (UUID).
    challenge_id: String,

    /// Committee-member identity (validator address, hex).
    #[arg(long)]
    voter: String,

    /// Revealed verdict (true = did-not-verify / upholds).
    #[arg(long)]
    verdict: bool,

    /// Reveal salt (hex) — must reproduce the earlier commit hash.
    #[arg(long)]
    salt: String,

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
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_revealChallengeVote",
                serde_json::json!({
                    "challenge_id": self.challenge_id,
                    "voter": self.voter,
                    "verdict": self.verdict,
                    "salt": self.salt,
                }),
            )
            .await?;
        if self.format == "json" {
            println!("{}", serde_json::to_string_pretty(&result)?);
            return Ok(());
        }
        output::print_success("Vote revealed");
        print_challenge(&result);
        Ok(())
    }
}

/// `tenzro inference finalize-challenge <challenge_id> [--force]`
///
/// Tallies the committee's revealed votes weighted by stake. No admin
/// token — the verdict is the committee's. Idempotent. `--force` closes a
/// challenge after the reveal window with no uphold quorum (provider
/// prevails).
#[derive(Debug, Parser)]
pub struct FinalizeChallengeCmd {
    /// Challenge id (UUID).
    challenge_id: String,

    /// Close the challenge after the reveal window even without an
    /// uphold quorum.
    #[arg(long)]
    force: bool,

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
                    "force": self.force,
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
        for key in ["reputation_penalized", "bond_failure_recorded"] {
            if let Some(v) = result.get(key).and_then(|v| v.as_bool()) {
                output::print_field(key, if v { "yes" } else { "no" });
            }
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

    /// Require TEE attestation
    #[arg(long)]
    require_tee: bool,

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

        if self.require_tee {
            output::print_field("TEE Required", "Yes");
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
        let result: serde_json::Value = rpc.call("tenzro_inferenceRequest", serde_json::json!([{
            "model_id": self.model_id,
            "input": self.input,
            "max_price": self.max_price,
            "require_tee": self.require_tee,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens
        }])).await?;

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

        if self.require_tee
            && let Some(attestation) = result.get("attestation") {
                println!();
                output::print_success("TEE Attestation verified");
                if let Some(vendor) = attestation.get("vendor").and_then(|v| v.as_str()) {
                    output::print_field("Vendor", vendor);
                }
                if let Some(enclave_id) = attestation.get("enclave_id").and_then(|v| v.as_str()) {
                    output::print_field("Enclave ID", enclave_id);
                }
            }

        // Save to file if requested
        if let Some(output_file) = &self.output_file
            && let Some(response_text) = result.get("response").and_then(|v| v.as_str()) {
                std::fs::write(output_file, response_text)?;
                println!();
                output::print_success(&format!("Response saved to: {}", output_file));
            }

        Ok(())
    }
}

/// `tenzro inference stream <model_id> <message> [--channel <id>]`
///
/// Stream a chat completion via `tenzro_chatStream`. When `--channel` is
/// supplied, the channel id is forwarded so the node can bill the
/// streamed tokens against that micropayment channel; without it, the
/// node falls back to whatever billing default is configured.
///
/// The streaming JSON-RPC method currently returns a single envelope
/// with the full result plus token-usage metadata; this command prints
/// the response text inline (with the EU AI Act §50(1) `[AI]` prefix —
/// see `main.rs` for the rationale) and the usage block separately.
#[derive(Debug, Parser)]
pub struct InferenceStreamCmd {
    /// Model ID to use.
    model_id: String,

    /// Prompt text.
    message: String,

    /// Optional micropayment channel id to bill streamed tokens against.
    #[arg(long)]
    channel: Option<String>,

    /// Maximum output tokens.
    #[arg(long, default_value_t = 1024)]
    max_tokens: u64,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl InferenceStreamCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Streaming Inference");
        output::print_field("Model", &self.model_id);
        if let Some(ch) = &self.channel {
            output::print_field("Channel", ch);
        }

        let mut params = serde_json::Map::new();
        params.insert(
            "model_id".to_string(),
            serde_json::Value::String(self.model_id.clone()),
        );
        params.insert(
            "message".to_string(),
            serde_json::Value::String(self.message.clone()),
        );
        params.insert(
            "max_tokens".to_string(),
            serde_json::Value::Number(self.max_tokens.into()),
        );
        if let Some(ch) = &self.channel {
            params.insert(
                "channel_id".to_string(),
                serde_json::Value::String(ch.clone()),
            );
        }

        let spinner = output::create_spinner("Streaming...");
        use crate::rpc::RpcClient;
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call("tenzro_chatStream", serde_json::Value::Object(params))
            .await
            .context("calling tenzro_chatStream")?;
        spinner.finish_and_clear();

        // Per EU AI Act Article 50(1): mark machine-generated text.
        // Single source of truth lives in
        // `tenzro_node::eu_ai_disclosure::render_cli_chat_chunk` so the
        // workspace can audit the literal in one place.
        let response_text = result
            .get("result")
            .and_then(|r| r.get("response"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if !response_text.is_empty() {
            println!();
            println!("{}", tenzro_node::eu_ai_disclosure::render_cli_chat_chunk(response_text));
        }

        if let Some(usage) = result.get("usage") {
            println!();
            output::print_header("Usage");
            output::print_json(usage)?;
        }

        Ok(())
    }
}
