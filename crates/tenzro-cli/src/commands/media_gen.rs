//! Tenzro Media Gen commands for the Tenzro CLI.
//!
//! Decentralized generative image and video. The node owns the job queue,
//! worker registry, pricing, and receipts; the denoising loop runs in the
//! Python reference worker at `integrations/media_gen/`.
//!
//! Subcommands wrap `tenzro_mediaGen_*` JSON-RPC methods exposed by the node.
//! See `AI.md` for the architecture.

use crate::output;
use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};

const DEFAULT_RPC: &str = "http://127.0.0.1:8545";

/// Tenzro Media Gen operations
#[derive(Debug, Subcommand)]
pub enum MediaGenCommand {
    /// List the curated generative-media model catalog
    Catalog(MediaGenCatalogCmd),
    /// Price a job before posting it
    Quote(MediaGenQuoteCmd),
    /// Post a generation job (requester flow)
    PostJob(MediaGenPostJobCmd),
    /// List jobs this node holds, optionally filtered by status
    ListJobs(MediaGenListJobsCmd),
    /// Look up a single job by id
    GetJob(MediaGenGetJobCmd),
    /// Withdraw a job before a worker claims it
    CancelJob(MediaGenCancelJobCmd),
    /// Enroll a local worker's capability (worker flow)
    EnrollWorker(MediaGenEnrollWorkerCmd),
    /// List workers enrolled on this node
    ListWorkers(MediaGenListWorkersCmd),
    /// Claim a job, or one half of a split job
    ClaimJob(MediaGenClaimJobCmd),
    /// Report that the pipeline started
    MarkRunning(MediaGenMarkRunningCmd),
    /// Report that the job cannot be finished
    FailJob(MediaGenFailJobCmd),
    /// Put rendered bytes into the content-addressed store
    PublishOutput(MediaGenPublishOutputCmd),
    /// Record the intermediate latent handed to the low-noise expert
    RecordHandoff(MediaGenRecordHandoffCmd),
    /// Seal a finished job with a signed receipt
    SubmitReceipt(MediaGenSubmitReceiptCmd),
    /// Look up a completed job's receipt
    GetReceipt(MediaGenGetReceiptCmd),
    /// Download a completed job's rendered bytes
    FetchOutput(MediaGenFetchOutputCmd),
    /// Download a split job's intermediate latent
    FetchLatent(MediaGenFetchLatentCmd),
    /// Download the conditioning image an image-conditioned job names
    FetchInput(MediaGenFetchInputCmd),
}

impl MediaGenCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Catalog(c) => c.execute().await,
            Self::Quote(c) => c.execute().await,
            Self::PostJob(c) => c.execute().await,
            Self::ListJobs(c) => c.execute().await,
            Self::GetJob(c) => c.execute().await,
            Self::CancelJob(c) => c.execute().await,
            Self::EnrollWorker(c) => c.execute().await,
            Self::ListWorkers(c) => c.execute().await,
            Self::ClaimJob(c) => c.execute().await,
            Self::MarkRunning(c) => c.execute().await,
            Self::FailJob(c) => c.execute().await,
            Self::PublishOutput(c) => c.execute().await,
            Self::RecordHandoff(c) => c.execute().await,
            Self::SubmitReceipt(c) => c.execute().await,
            Self::GetReceipt(c) => c.execute().await,
            Self::FetchOutput(c) => c.execute().await,
            Self::FetchLatent(c) => c.execute().await,
            Self::FetchInput(c) => c.execute().await,
        }
    }
}

/// Read a JSON file into a `Value`, reporting the path on failure.
fn read_json(path: &str, what: &str) -> Result<serde_json::Value> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| anyhow!("read {} file '{}': {}", what, path, e))?;
    serde_json::from_str(&text).map_err(|e| anyhow!("parse {} JSON: {}", what, e))
}

// ---------------------------------------------------------------------------
// Catalog
// ---------------------------------------------------------------------------

#[derive(Debug, Parser)]
pub struct MediaGenCatalogCmd {
    /// Only entries serving this kind (text2image, image2image, text2video, image2video)
    #[arg(long)]
    kind: Option<String>,

    /// RPC endpoint
    #[arg(long, default_value = DEFAULT_RPC)]
    rpc: String,

    /// Output format (text, json)
    #[arg(long, default_value = "text")]
    format: String,
}

impl MediaGenCatalogCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call("tenzro_mediaGen_listCatalog", serde_json::json!({}))
            .await?;

        let models: Vec<serde_json::Value> = result
            .get("models")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .filter(|m| match &self.kind {
                Some(k) => m
                    .get("kinds")
                    .and_then(|v| v.as_array())
                    .map(|a| a.iter().any(|x| x.as_str() == Some(k.as_str())))
                    .unwrap_or(false),
                None => true,
            })
            .collect();

        if self.format == "json" {
            println!("{}", serde_json::to_string_pretty(&models)?);
            return Ok(());
        }

        output::print_header("Media Gen Catalog");
        if models.is_empty() {
            output::print_info("No matching models.");
            return Ok(());
        }
        for m in &models {
            let id = m.get("id").and_then(|v| v.as_str()).unwrap_or("?");
            let kinds = m
                .get("kinds")
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str())
                        .collect::<Vec<_>>()
                        .join(",")
                })
                .unwrap_or_default();
            // An expert pair means the denoising schedule splits across two
            // machines, which is the only reason a claim needs a role.
            let split = if m.get("expert_pair").map(|v| !v.is_null()).unwrap_or(false) {
                " [split]"
            } else {
                ""
            };
            output::print_field(id, &format!("{}{}", kinds, split));
        }
        output::print_info(&format!("{} model(s)", models.len()));
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Quote
// ---------------------------------------------------------------------------

/// Price a job from the same figures the runtime charges against, so the
/// requester can set `max_price` without guessing.
#[derive(Debug, Parser)]
pub struct MediaGenQuoteCmd {
    /// Media kind (text2image, image2image, text2video, image2video)
    #[arg(long)]
    kind: String,

    /// Path to a JSON file containing `MediaGenParams`
    #[arg(long)]
    params: String,

    /// RPC endpoint
    #[arg(long, default_value = DEFAULT_RPC)]
    rpc: String,
}

impl MediaGenQuoteCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        let params = read_json(&self.params, "params")?;
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_mediaGen_quote",
                serde_json::json!({ "kind": self.kind, "params": params }),
            )
            .await?;

        output::print_header("Media Gen Quote");
        for key in ["kind", "pixel_steps", "per_pixel_step", "base_fee", "quote"] {
            if let Some(v) = result.get(key).and_then(|v| v.as_str()) {
                output::print_field(key, v);
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Post job
// ---------------------------------------------------------------------------

/// Post a generation job. The full spec is loaded from a JSON file.
///
/// Whether the job splits across two experts is decided by the node from the
/// catalog, not by this command: the spec carries no role list.
#[derive(Debug, Parser)]
pub struct MediaGenPostJobCmd {
    /// Path to a JSON file containing a `MediaGenTaskSpec`
    #[arg(long)]
    spec: String,

    /// RPC endpoint
    #[arg(long, default_value = DEFAULT_RPC)]
    rpc: String,
}

impl MediaGenPostJobCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        let spec = read_json(&self.spec, "spec")?;

        output::print_header("Post Media Gen Job");
        let spinner = output::create_spinner("Submitting...");
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_mediaGen_postJob",
                serde_json::json!({ "task_spec": spec }),
            )
            .await;
        spinner.finish_and_clear();
        let result = result?;

        output::print_success("Job posted!");
        print_job_summary(&result);
        Ok(())
    }
}

/// Print the fields of a job that matter at a glance, including the roles a
/// split job still has open.
fn print_job_summary(job: &serde_json::Value) {
    output::print_field(
        "Job ID",
        job.get("job_id").and_then(|v| v.as_str()).unwrap_or(""),
    );
    output::print_field(
        "Status",
        job.get("status").and_then(|v| v.as_str()).unwrap_or(""),
    );
    let roles = job
        .get("required_roles")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    if !roles.is_empty() {
        let claimed: Vec<&str> = job
            .get("assignments")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.get("role").and_then(|r| r.as_str()))
                    .collect()
            })
            .unwrap_or_default();
        let open: Vec<&str> = roles
            .iter()
            .filter_map(|r| r.as_str())
            .filter(|r| !claimed.contains(r))
            .collect();
        output::print_field(
            "Roles",
            &format!(
                "required=[{}], unclaimed=[{}]",
                roles
                    .iter()
                    .filter_map(|r| r.as_str())
                    .collect::<Vec<_>>()
                    .join(","),
                open.join(",")
            ),
        );
    }
    if let Some(s) = job.get("settlement") {
        output::print_field(
            "Paid",
            s.get("price_paid").and_then(|v| v.as_str()).unwrap_or("0"),
        );
        output::print_field(
            "Commission",
            s.get("commission_wei")
                .and_then(|v| v.as_str())
                .unwrap_or("0"),
        );
        for p in s
            .get("payouts")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default()
        {
            let who = p
                .get("role")
                .and_then(|v| v.as_str())
                .or_else(|| p.get("worker_did").and_then(|v| v.as_str()))
                .unwrap_or("worker");
            output::print_field(
                &format!("  {}", who),
                &format!(
                    "{} ({} bps)",
                    p.get("amount").and_then(|v| v.as_str()).unwrap_or("0"),
                    p.get("share_bps").and_then(|v| v.as_u64()).unwrap_or(0)
                ),
            );
        }
    }
}

// ---------------------------------------------------------------------------
// List jobs
// ---------------------------------------------------------------------------

#[derive(Debug, Parser)]
pub struct MediaGenListJobsCmd {
    /// Only jobs in this status (pending, claimed, running, completed, failed, cancelled)
    #[arg(long)]
    status: Option<String>,

    /// RPC endpoint
    #[arg(long, default_value = DEFAULT_RPC)]
    rpc: String,

    /// Output format (text, json)
    #[arg(long, default_value = "text")]
    format: String,
}

impl MediaGenListJobsCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        let mut params = serde_json::json!({});
        if let Some(s) = &self.status {
            params["status"] = serde_json::Value::String(s.clone());
        }

        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc.call("tenzro_mediaGen_listJobs", params).await?;

        if self.format == "json" {
            println!("{}", serde_json::to_string_pretty(&result)?);
            return Ok(());
        }

        output::print_header("Media Gen Jobs");
        let jobs = result
            .get("jobs")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        if jobs.is_empty() {
            output::print_info("No jobs.");
            return Ok(());
        }
        for job in &jobs {
            let job_id = job.get("job_id").and_then(|v| v.as_str()).unwrap_or("?");
            let status = job.get("status").and_then(|v| v.as_str()).unwrap_or("?");
            let model = job
                .get("task_spec")
                .and_then(|s| s.get("model_id"))
                .and_then(|v| v.as_str())
                .unwrap_or("?");
            let assigned = job
                .get("assignments")
                .and_then(|v| v.as_array())
                .map(|a| a.len())
                .unwrap_or(0);
            let required = job
                .get("required_roles")
                .and_then(|v| v.as_array())
                .map(|a| a.len())
                .unwrap_or(0);
            output::print_field(
                job_id,
                &format!(
                    "status={}, model={}, workers={}/{}",
                    status,
                    model,
                    assigned,
                    required.max(1)
                ),
            );
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Get job
// ---------------------------------------------------------------------------

#[derive(Debug, Parser)]
pub struct MediaGenGetJobCmd {
    /// Job ID to look up
    #[arg(long)]
    job_id: String,

    /// RPC endpoint
    #[arg(long, default_value = DEFAULT_RPC)]
    rpc: String,
}

impl MediaGenGetJobCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_mediaGen_getJob",
                serde_json::json!({ "job_id": self.job_id }),
            )
            .await?;
        println!("{}", serde_json::to_string_pretty(&result)?);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Cancel job
// ---------------------------------------------------------------------------

#[derive(Debug, Parser)]
pub struct MediaGenCancelJobCmd {
    /// Job ID to cancel
    #[arg(long)]
    job_id: String,

    /// DID of the requester that posted the job
    #[arg(long)]
    requester_did: String,

    /// RPC endpoint
    #[arg(long, default_value = DEFAULT_RPC)]
    rpc: String,
}

impl MediaGenCancelJobCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_mediaGen_cancelJob",
                serde_json::json!({
                    "job_id": self.job_id,
                    "requester_did": self.requester_did,
                }),
            )
            .await?;
        output::print_success("Job cancelled.");
        print_job_summary(&result);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Enroll worker
// ---------------------------------------------------------------------------

/// Enroll a worker capability. A worker that holds only one half of a split
/// model declares that half in `expert_holdings`; a worker holding the whole
/// model qualifies for either half and can claim both.
#[derive(Debug, Parser)]
pub struct MediaGenEnrollWorkerCmd {
    /// Path to a JSON file containing a `MediaGenWorkerCapability`
    #[arg(long)]
    capability: String,

    /// RPC endpoint
    #[arg(long, default_value = DEFAULT_RPC)]
    rpc: String,
}

impl MediaGenEnrollWorkerCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        let capability = read_json(&self.capability, "capability")?;
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_mediaGen_enrollWorker",
                serde_json::json!({ "capability": capability }),
            )
            .await?;

        output::print_success("Worker enrolled.");
        output::print_field(
            "Worker DID",
            result
                .get("worker_did")
                .and_then(|v| v.as_str())
                .unwrap_or(""),
        );
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// List workers
// ---------------------------------------------------------------------------

#[derive(Debug, Parser)]
pub struct MediaGenListWorkersCmd {
    /// RPC endpoint
    #[arg(long, default_value = DEFAULT_RPC)]
    rpc: String,

    /// Output format (text, json)
    #[arg(long, default_value = "text")]
    format: String,
}

impl MediaGenListWorkersCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call("tenzro_mediaGen_listWorkers", serde_json::json!({}))
            .await?;

        if self.format == "json" {
            println!("{}", serde_json::to_string_pretty(&result)?);
            return Ok(());
        }

        output::print_header("Media Gen Workers");
        let workers = result
            .get("workers")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        if workers.is_empty() {
            output::print_info("No workers enrolled.");
            return Ok(());
        }
        for w in &workers {
            let did = w.get("worker_did").and_then(|v| v.as_str()).unwrap_or("?");
            let models = w
                .get("supported_models")
                .and_then(|v| v.as_array())
                .map(|a| a.len())
                .unwrap_or(0);
            let halves = w
                .get("expert_holdings")
                .and_then(|v| v.as_array())
                .map(|a| a.len())
                .unwrap_or(0);
            let vram = w.get("gpu_vram_gb").and_then(|v| v.as_f64()).unwrap_or(0.0);
            output::print_field(
                did,
                &format!(
                    "models={}, expert_halves={}, vram={}GB",
                    models, halves, vram
                ),
            );
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Claim job
// ---------------------------------------------------------------------------

/// Claim a job. `--role` is required on a split job and rejected on a whole
/// one; the catalog decides which a job is.
#[derive(Debug, Parser)]
pub struct MediaGenClaimJobCmd {
    /// Job ID to claim
    #[arg(long)]
    job_id: String,

    /// DID of an enrolled worker
    #[arg(long)]
    worker_did: String,

    /// Half of the denoising schedule to run (high-noise, low-noise)
    #[arg(long)]
    role: Option<String>,

    /// RPC endpoint
    #[arg(long, default_value = DEFAULT_RPC)]
    rpc: String,
}

impl MediaGenClaimJobCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        let mut params = serde_json::json!({
            "job_id": self.job_id,
            "worker_did": self.worker_did,
        });
        if let Some(role) = &self.role {
            params["role"] = serde_json::Value::String(role.clone());
        }

        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc.call("tenzro_mediaGen_claimJob", params).await?;
        output::print_success("Job claimed.");
        print_job_summary(&result);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Mark running
// ---------------------------------------------------------------------------

#[derive(Debug, Parser)]
pub struct MediaGenMarkRunningCmd {
    /// Job ID
    #[arg(long)]
    job_id: String,

    /// DID of the worker holding the job
    #[arg(long)]
    worker_did: String,

    /// RPC endpoint
    #[arg(long, default_value = DEFAULT_RPC)]
    rpc: String,
}

impl MediaGenMarkRunningCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_mediaGen_markRunning",
                serde_json::json!({
                    "job_id": self.job_id,
                    "worker_did": self.worker_did,
                }),
            )
            .await?;
        print_job_summary(&result);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Fail job
// ---------------------------------------------------------------------------

#[derive(Debug, Parser)]
pub struct MediaGenFailJobCmd {
    /// Job ID
    #[arg(long)]
    job_id: String,

    /// DID of the worker holding the job
    #[arg(long)]
    worker_did: String,

    /// Why the job cannot be finished
    #[arg(long)]
    error: String,

    /// RPC endpoint
    #[arg(long, default_value = DEFAULT_RPC)]
    rpc: String,
}

impl MediaGenFailJobCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_mediaGen_failJob",
                serde_json::json!({
                    "job_id": self.job_id,
                    "worker_did": self.worker_did,
                    "error": self.error,
                }),
            )
            .await?;
        output::print_warning("Job failed.");
        print_job_summary(&result);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Publish output
// ---------------------------------------------------------------------------

/// Put bytes — a finished render or an intermediate latent — into the
/// content-addressed store.
///
/// Returns both addresses of the same bytes: `output_hash` is the canonical
/// SHA-256 a receipt or handoff commits to, `locator` is the BLAKE3 the blob
/// store indexes by. A worker publishes before building its commitment,
/// because the commitment names the hash.
#[derive(Debug, Parser)]
pub struct MediaGenPublishOutputCmd {
    /// Path to the file to publish
    #[arg(long)]
    file: String,

    /// RPC endpoint
    #[arg(long, default_value = DEFAULT_RPC)]
    rpc: String,
}

impl MediaGenPublishOutputCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        use base64::Engine as _;

        let bytes = std::fs::read(&self.file)
            .map_err(|e| anyhow!("read file '{}': {}", self.file, e))?;
        if bytes.is_empty() {
            return Err(anyhow!("file '{}' is empty", self.file));
        }
        let encoded = base64::engine::general_purpose::STANDARD.encode(&bytes);

        let spinner = output::create_spinner("Publishing...");
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_mediaGen_publishOutput",
                serde_json::json!({ "bytes": encoded }),
            )
            .await;
        spinner.finish_and_clear();
        let result = result?;

        output::print_success("Published.");
        output::print_field(
            "Output hash (SHA-256)",
            result
                .get("output_hash")
                .and_then(|v| v.as_str())
                .unwrap_or(""),
        );
        output::print_field(
            "Locator (BLAKE3)",
            result.get("locator").and_then(|v| v.as_str()).unwrap_or("-"),
        );
        output::print_field(
            "Bytes",
            &result
                .get("bytes")
                .and_then(|v| v.as_u64())
                .unwrap_or(0)
                .to_string(),
        );
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Record handoff
// ---------------------------------------------------------------------------

/// Record the intermediate latent the high-noise expert hands to the low-noise
/// expert. The latent must already be in the store — publish it first.
#[derive(Debug, Parser)]
pub struct MediaGenRecordHandoffCmd {
    /// Path to a JSON file containing a signed `MediaGenHandoff`
    #[arg(long)]
    handoff: String,

    /// RPC endpoint
    #[arg(long, default_value = DEFAULT_RPC)]
    rpc: String,
}

impl MediaGenRecordHandoffCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        let handoff = read_json(&self.handoff, "handoff")?;
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_mediaGen_recordHandoff",
                serde_json::json!({ "handoff": handoff }),
            )
            .await?;
        output::print_success("Handoff recorded.");
        print_job_summary(&result);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Submit receipt
// ---------------------------------------------------------------------------

/// Seal a finished job with a signed receipt. The output must already be in
/// the store — publish it first.
#[derive(Debug, Parser)]
pub struct MediaGenSubmitReceiptCmd {
    /// Path to a JSON file containing a signed `MediaGenReceipt`
    #[arg(long)]
    receipt: String,

    /// RPC endpoint
    #[arg(long, default_value = DEFAULT_RPC)]
    rpc: String,
}

impl MediaGenSubmitReceiptCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        let receipt = read_json(&self.receipt, "receipt")?;
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_mediaGen_submitReceipt",
                serde_json::json!({ "receipt": receipt }),
            )
            .await?;
        output::print_success("Receipt submitted.");
        print_job_summary(&result);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Get receipt
// ---------------------------------------------------------------------------

#[derive(Debug, Parser)]
pub struct MediaGenGetReceiptCmd {
    /// Job ID to look up
    #[arg(long)]
    job_id: String,

    /// RPC endpoint
    #[arg(long, default_value = DEFAULT_RPC)]
    rpc: String,
}

impl MediaGenGetReceiptCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_mediaGen_getReceipt",
                serde_json::json!({ "job_id": self.job_id }),
            )
            .await?;
        println!("{}", serde_json::to_string_pretty(&result)?);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Fetch output
// ---------------------------------------------------------------------------

/// Download a completed job's rendered bytes. The node checks them against the
/// hash and length the receipt committed to before returning them.
#[derive(Debug, Parser)]
pub struct MediaGenFetchOutputCmd {
    /// Job ID to fetch
    #[arg(long)]
    job_id: String,

    /// Where to write the bytes
    #[arg(long)]
    out: String,

    /// RPC endpoint
    #[arg(long, default_value = DEFAULT_RPC)]
    rpc: String,
}

impl MediaGenFetchOutputCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        let spinner = output::create_spinner("Fetching...");
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_mediaGen_fetchOutput",
                serde_json::json!({ "job_id": self.job_id }),
            )
            .await;
        spinner.finish_and_clear();
        let result = result?;

        let written = write_payload(&result, &self.out)?;
        output::print_success("Output fetched.");
        output::print_field(
            "Output hash",
            result
                .get("output_hash")
                .and_then(|v| v.as_str())
                .unwrap_or(""),
        );
        output::print_field(
            "MIME",
            result
                .get("output_mime")
                .and_then(|v| v.as_str())
                .unwrap_or(""),
        );
        output::print_field("Written", &format!("{} ({} bytes)", self.out, written));
        Ok(())
    }
}

/// Decode the base64 `data` field of a fetch response and write it out.
fn write_payload(result: &serde_json::Value, out: &str) -> Result<usize> {
    use base64::Engine as _;

    let data = result
        .get("data")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("response carried no 'data' field"))?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(data)
        .map_err(|e| anyhow!("decode payload: {}", e))?;
    std::fs::write(out, &bytes).map_err(|e| anyhow!("write '{}': {}", out, e))?;
    Ok(bytes.len())
}

// ---------------------------------------------------------------------------
// Fetch latent
// ---------------------------------------------------------------------------

/// Download a split job's intermediate latent. This is how the low-noise
/// expert picks up where the high-noise expert stopped.
#[derive(Debug, Parser)]
pub struct MediaGenFetchLatentCmd {
    /// Job ID to fetch the latent of
    #[arg(long)]
    job_id: String,

    /// Where to write the bytes
    #[arg(long)]
    out: String,

    /// RPC endpoint
    #[arg(long, default_value = DEFAULT_RPC)]
    rpc: String,
}

impl MediaGenFetchLatentCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        let spinner = output::create_spinner("Fetching latent...");
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_mediaGen_fetchLatent",
                serde_json::json!({ "job_id": self.job_id }),
            )
            .await;
        spinner.finish_and_clear();
        let result = result?;

        let written = write_payload(&result, &self.out)?;
        output::print_success("Latent fetched.");
        output::print_field("Written", &format!("{} ({} bytes)", self.out, written));
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Fetch input
// ---------------------------------------------------------------------------

/// Download the conditioning image an editing or image-conditioned job names.
/// The requester publishes it before posting the job, so the hash is already
/// bound into the job id by the time a worker claims it.
#[derive(Debug, Parser)]
pub struct MediaGenFetchInputCmd {
    /// Job ID to fetch the input image of
    #[arg(long)]
    job_id: String,

    /// Where to write the bytes
    #[arg(long)]
    out: String,

    /// RPC endpoint
    #[arg(long, default_value = DEFAULT_RPC)]
    rpc: String,
}

impl MediaGenFetchInputCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        let spinner = output::create_spinner("Fetching input image...");
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_mediaGen_fetchInput",
                serde_json::json!({ "job_id": self.job_id }),
            )
            .await;
        spinner.finish_and_clear();
        let result = result?;

        let written = write_payload(&result, &self.out)?;
        output::print_success("Input image fetched.");
        output::print_field("Written", &format!("{} ({} bytes)", self.out, written));
        Ok(())
    }
}
