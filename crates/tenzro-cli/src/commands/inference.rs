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
    /// Report how a routed call turned out, so the router's per-cluster
    /// error rates reflect what happened rather than only what the catalog
    /// declares.
    RecordOutcome(RecordOutcomeCmd),
    /// Read the node's difficulty index: cluster sizes, and per-cluster
    /// outcome counters for a model when one is named.
    DifficultyStats(DifficultyStatsCmd),
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
            Self::GetCommitment(cmd) => cmd.execute().await,
            Self::VerifyCommitment(cmd) => cmd.execute().await,
            Self::FileChallenge(cmd) => cmd.execute().await,
            Self::GetChallenge(cmd) => cmd.execute().await,
            Self::ListChallenges(cmd) => cmd.execute().await,
            Self::CommitVote(cmd) => cmd.execute().await,
            Self::RevealVote(cmd) => cmd.execute().await,
            Self::FinalizeChallenge(cmd) => cmd.execute().await,
            Self::Route(cmd) => cmd.execute().await,
            Self::RecordOutcome(cmd) => cmd.execute().await,
            Self::DifficultyStats(cmd) => cmd.execute().await,
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

    /// Payer wallet address (hex) — the payer's on-chain TNZO balance
    /// becomes a hard ceiling, so unaffordable models are dropped.
    #[arg(long)]
    payer_address: Option<String>,

    /// Text the model would answer. Used only to place the request in a
    /// difficulty cluster, so selection accounts for how hard the prompt is;
    /// it is not sent to any provider. Redundant with --message, which the
    /// node reads for the same purpose.
    #[arg(long)]
    prompt: Option<String>,

    /// When set, discover a model and run this prompt in one call.
    #[arg(long)]
    message: Option<String>,

    /// Maximum output tokens (only used with --message).
    #[arg(long, default_value_t = 256)]
    max_tokens: u64,

    /// Comma-separated jurisdiction pin: ISO 3166-1 alpha-2 country codes
    /// and/or bloc tokens (e.g. "DE,EU"), case-insensitive. The serving
    /// node must declare a matching attestation-bound locality claim or
    /// the request is refused. Only used with --message.
    #[arg(long)]
    jurisdiction: Option<String>,

    /// Fail the request unless the response carries a verifiable signed
    /// jurisdiction receipt. Only used with --message.
    #[arg(long)]
    require_jurisdiction_receipt: bool,

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
            params.insert("optimize".to_string(), serde_json::json!(o));
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
        if let Some(addr) = &self.payer_address {
            params.insert(
                "payer_address".to_string(),
                serde_json::Value::String(addr.clone()),
            );
        }
        if let Some(p) = &self.prompt {
            params.insert("prompt".to_string(), serde_json::Value::String(p.clone()));
        }

        let rpc = RpcClient::new(&self.rpc);

        // With a message, discover + dispatch; otherwise discovery only.
        if let Some(message) = &self.message {
            params.insert(
                "message".to_string(),
                serde_json::Value::String(message.clone()),
            );
            params.insert("max_tokens".to_string(), serde_json::json!(self.max_tokens));
            if let Some(pin) = &self.jurisdiction {
                params.insert(
                    "jurisdiction".to_string(),
                    serde_json::Value::String(pin.clone()),
                );
            }
            if self.require_jurisdiction_receipt {
                params.insert(
                    "jurisdiction_receipt".to_string(),
                    serde_json::Value::String("required".to_string()),
                );
            }

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
                    tenzro_types::eu_ai_disclosure::render_cli_chat_chunk(response_text)
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
    for key in [
        "model_id",
        "tier",
        "estimated_cost",
        "cluster",
        "expected_error",
        "provider",
        "endpoint",
        "reason",
    ] {
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
    if let Some(chain) = route.get("alternates").and_then(|v| v.as_array())
        && !chain.is_empty()
    {
        let joined: Vec<String> = chain
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect();
        output::print_field("alternates", &joined.join(" → "));
    }
}

/// `tenzro inference record-outcome --model-id <m> --cluster <c> --outcome <o>`
///
/// Reports how a routed call turned out. In practice this carries
/// `escalated` — the outcome only the caller knows, because it means the
/// caller took the answer to a stronger model. `resolved` and `failed` are
/// already recorded by `tenzro_chatByIntent` from the dispatch itself.
///
/// `retained: false` means the node has no difficulty index wired, so the
/// feedback was accepted and discarded. Reporting is advisory.
#[derive(Debug, Parser)]
pub struct RecordOutcomeCmd {
    /// The model that served the call — the routing decision's model_id.
    #[arg(long)]
    model_id: String,

    /// The difficulty cluster the request landed in — the routing decision's
    /// `cluster`.
    #[arg(long)]
    cluster: u32,

    /// How the call turned out: resolved, escalated, or failed.
    #[arg(long)]
    outcome: String,

    /// Output format (text, json)
    #[arg(long, default_value = "text")]
    format: String,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl RecordOutcomeCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_recordRouteOutcome",
                serde_json::json!({
                    "model_id": self.model_id,
                    "cluster": self.cluster,
                    "outcome": self.outcome,
                }),
            )
            .await
            .context("calling tenzro_recordRouteOutcome")?;

        if self.format == "json" {
            println!("{}", serde_json::to_string_pretty(&result)?);
            return Ok(());
        }

        output::print_header("Route Outcome Recorded");
        for key in ["model_id", "cluster", "outcome", "retained"] {
            if let Some(v) = result.get(key)
                && !v.is_null()
            {
                let rendered = match v.as_str() {
                    Some(s) => s.to_string(),
                    None => v.to_string(),
                };
                output::print_field(key, &rendered);
            }
        }
        if result.get("retained").and_then(|v| v.as_bool()) == Some(false) {
            println!();
            println!("This node has no difficulty index, so the report was discarded.");
        }
        Ok(())
    }
}

/// `tenzro inference difficulty-stats [--model-id <m>]`
///
/// Reads the node's difficulty index: how many prompt clusters it has
/// discovered and how many prompts landed in each. With `--model-id`, also
/// prints that model's per-cluster outcome counters and error rate.
#[derive(Debug, Parser)]
pub struct DifficultyStatsCmd {
    /// Report per-cluster outcome counters and error rate for this model.
    #[arg(long)]
    model_id: Option<String>,

    /// Output format (text, json)
    #[arg(long, default_value = "text")]
    format: String,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl DifficultyStatsCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        let mut params = serde_json::Map::new();
        if let Some(id) = &self.model_id {
            params.insert(
                "model_id".to_string(),
                serde_json::Value::String(id.clone()),
            );
        }

        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_routeDifficultyStats",
                serde_json::Value::Object(params),
            )
            .await
            .context("calling tenzro_routeDifficultyStats")?;

        if self.format == "json" {
            println!("{}", serde_json::to_string_pretty(&result)?);
            return Ok(());
        }

        output::print_header("Difficulty Index");
        if result.get("enabled").and_then(|v| v.as_bool()) != Some(true) {
            println!("No embedding model is loaded — this node routes on declared metadata alone.");
            return Ok(());
        }
        for key in [
            "cluster_count",
            "capacity",
            "embedding_dim",
            "split_threshold",
        ] {
            if let Some(v) = result.get(key)
                && !v.is_null()
            {
                output::print_field(key, &v.to_string());
            }
        }
        if let Some(clusters) = result.get("clusters").and_then(|v| v.as_array())
            && !clusters.is_empty()
        {
            println!();
            output::print_header("Prompts per Cluster");
            for c in clusters {
                let id = c.get("cluster").map(|v| v.to_string()).unwrap_or_default();
                let n = c.get("prompts").map(|v| v.to_string()).unwrap_or_default();
                output::print_field(&format!("cluster {id}"), &n);
            }
        }
        if let Some(per_model) = result.get("model_clusters").and_then(|v| v.as_array()) {
            println!();
            let model = result
                .get("model_id")
                .and_then(|v| v.as_str())
                .unwrap_or("model");
            output::print_header(&format!("Outcomes for {model}"));
            if per_model.is_empty() {
                println!("No observations yet — selection rests on declared metadata.");
            }
            for c in per_model {
                let id = c.get("cluster").map(|v| v.to_string()).unwrap_or_default();
                let resolved = c.get("resolved").map(|v| v.to_string()).unwrap_or_default();
                let escalated = c
                    .get("escalated")
                    .map(|v| v.to_string())
                    .unwrap_or_default();
                let failed = c.get("failed").map(|v| v.to_string()).unwrap_or_default();
                let rate = c
                    .get("error_rate")
                    .map(|v| v.to_string())
                    .unwrap_or_default();
                output::print_field(
                    &format!("cluster {id}"),
                    &format!(
                        "resolved {resolved}, escalated {escalated}, failed {failed}, error rate {rate}"
                    ),
                );
            }
        }
        Ok(())
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

/// `tenzro inference commit-vote <challenge_id> --commit-hash <hex> [--voter-rpc URL] [--rpc URL]`
///
/// A drawn committee member records the hidden commit
/// `H(verdict||salt||challenge_id||voter)`. The verdict stays sealed until
/// `reveal-vote`. The commit is signed by the validator key of the node at
/// `--voter-rpc` (as an administrator of that node), then submitted to the node
/// holding the dispute at `--rpc`.
#[derive(Debug, Parser)]
pub struct CommitVoteCmd {
    /// Challenge id (UUID).
    challenge_id: String,

    /// Vote commitment hash (hex).
    #[arg(long)]
    commit_hash: String,

    /// The voting validator's own node, which signs the commit.
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    voter_rpc: String,

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
        let signed: serde_json::Value = RpcClient::new(&self.voter_rpc)
            .call(
                "tenzro_signChallengeVote",
                serde_json::json!({
                    "challenge_id": self.challenge_id,
                    "commit_hash": self.commit_hash,
                }),
            )
            .await?;
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_commitChallengeVote",
                serde_json::json!({
                    "challenge_id": self.challenge_id,
                    "voter": signed["voter"],
                    "commit_hash": self.commit_hash,
                    "signature": signed["signature"],
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

/// `tenzro inference reveal-vote <challenge_id> --verdict <bool> --salt <hex> [--voter-rpc URL] [--rpc URL]`
///
/// Reveals a committed vote. `(verdict, salt)` must reproduce the commit
/// hash. `--verdict true` means the commitment did not verify (upholds).
/// Signed by the validator key of the node at `--voter-rpc`.
#[derive(Debug, Parser)]
pub struct RevealVoteCmd {
    /// Challenge id (UUID).
    challenge_id: String,

    /// The voting validator's own node, which signs the reveal.
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    voter_rpc: String,

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
        let signed: serde_json::Value = RpcClient::new(&self.voter_rpc)
            .call(
                "tenzro_signChallengeVote",
                serde_json::json!({
                    "challenge_id": self.challenge_id,
                    "verdict": self.verdict,
                    "salt": self.salt,
                }),
            )
            .await?;
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_revealChallengeVote",
                serde_json::json!({
                    "challenge_id": self.challenge_id,
                    "voter": signed["voter"],
                    "verdict": self.verdict,
                    "salt": self.salt,
                    "signature": signed["signature"],
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
