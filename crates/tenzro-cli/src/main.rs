//! Tenzro Network CLI
//!
//! Command-line interface for operating Tenzro Network nodes, managing wallets,
//! models, staking, and governance.

use anyhow::Result;
use clap::{Parser, Subcommand};
use dialoguer::{Input, Select, theme::ColorfulTheme};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use tenzro_cli::{commands, output, rpc};

use commands::{
    AccessCommand, AdaptiveBurnCommand, AgentCommand, AuthCommand, BondCommand, BridgeCommand,
    CatalogCommand, ClusterCommand, ContractCommand, CryptoCommand, DaCommand, DecideCommand,
    DetectCommand,
    DiscoverCommand, DutyCommand, EmbedImageCommand, EmbedTextCommand, EmbedVideoCommand,
    EscrowCommand, EventsCommand, FinalityCommand, ForecastCommand, FundingCommand,
    GovernanceCommand, IdentityCommand, InferenceCommand, InsuranceCommand, IrohCommand, JoinCmd,
    MediaGenCommand, ModelCommand, NodeCommand, PaymentCommand, Permit2Command, PqHybridCommand,
    ProvenanceCommand, ProviderCommand, RegistryCommand, RerankCommand, ReserveCommand,
    ScheduleCommand, SegmentCommand, SettleCommand, SetupCmd, SpeechCommand, SponsorCommand, StakeCommand,
    TeeCommand, TextSegmentCommand, TokenCommand, TrainingCommand, TranscribeCommand, TrustCommand,
    TxCommand, ValidatorCommand, VrfCommand, WalletCommand, ZkCommand,
    bridge_fee::BridgeFeeCommand,
    device::DeviceCommand,
    machine_access::MachineAccessCommand,
    rails::{InteractionCommand, RailsCommand},
    rpc_cmd::RpcCommand,
    status_bar::StatusCmd,
    urwa::UrwaCommand,
    visibility::VisibilityCommand,
};

/// Tenzro Network CLI — node operation, wallet management, provider tools
#[derive(Debug, Parser)]
#[command(name = "tenzro")]
#[command(version)]
#[command(about = "Tenzro Network CLI — AI-Native, Agentic, Tokenized Settlement Layer", long_about = None)]
struct Cli {
    /// Enable verbose logging
    #[arg(short, long, global = true)]
    verbose: bool,

    /// Output format (text, json)
    #[arg(long, global = true, default_value = "text")]
    format: String,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Join the Tenzro Network (one-click participate)
    Join(JoinCmd),

    /// Guided setup — join the network, provide, validate, or bootstrap a private network
    Setup(SetupCmd),

    /// Node management commands
    #[command(subcommand)]
    Node(NodeCommand),

    /// Wallet management commands
    #[command(subcommand)]
    Wallet(WalletCommand),

    /// Model management commands
    #[command(subcommand)]
    Model(ModelCommand),

    /// Staking commands
    #[command(subcommand)]
    Stake(StakeCommand),

    /// Governance commands
    #[command(subcommand)]
    Governance(GovernanceCommand),

    /// Transaction inspection
    #[command(subcommand)]
    Tx(TxCommand),

    /// Network funding: grant and tranche requests, reward claims, vesting release
    #[command(subcommand)]
    Funding(FundingCommand),

    /// Sponsorship: check eligibility, prepare an application, see status
    #[command(subcommand)]
    Sponsor(SponsorCommand),

    /// Provider management commands
    #[command(subcommand)]
    Provider(ProviderCommand),

    /// Provider schedule management
    #[command(subcommand)]
    Schedule(ScheduleCommand),

    /// Inference commands
    #[command(subcommand)]
    Inference(InferenceCommand),

    /// Identity management commands (TDIP)
    #[command(subcommand)]
    Identity(IdentityCommand),

    /// Payment commands
    #[command(subcommand)]
    Payment(PaymentCommand),

    /// AI agent management commands
    #[command(subcommand)]
    Agent(AgentCommand),

    /// Escrow and payment channel commands
    #[command(subcommand)]
    Escrow(EscrowCommand),

    /// Network duties: work the chain pays the first prover for
    #[command(subcommand)]
    Duty(DutyCommand),

    /// Start a local single-validator chain for development, keys in this machine's hardware
    Dev(commands::dev::DevCmd),

    /// Token management commands (create, query, cross-VM transfers)
    #[command(subcommand)]
    Token(TokenCommand),

    /// Contract deployment commands
    #[command(subcommand)]
    Contract(ContractCommand),

    /// Cross-chain bridge commands (quote, execute, status, routes)
    #[command(subcommand)]
    Bridge(BridgeCommand),

    /// Relayer commands: deliver what other chains report to Tenzro
    #[command(subcommand)]
    Relay(RelayCommand),

    /// Event streaming commands (subscribe, history, webhooks)
    #[command(subcommand)]
    Events(EventsCommand),

    /// Cryptographic operations (sign, verify, encrypt, decrypt, hash, keygen)
    #[command(subcommand)]
    Crypto(CryptoCommand),

    /// TEE operations (detect, attest, challenge, verify, providers)
    #[command(subcommand)]
    Tee(TeeCommand),

    /// Zero-knowledge proof operations (prove, verify, circuits, fraud proofs)
    #[command(subcommand)]
    Zk(ZkCommand),

    /// VRF proof verification — RFC 9381 ECVRF-EDWARDS25519-SHA512-TAI
    #[command(subcommand)]
    Vrf(VrfCommand),

    /// Finality: verify the latest compact certificate from genesis as a light client
    #[command(subcommand)]
    Finality(FinalityCommand),

    /// Passkey-first wallet onboarding + custody (enrollment, recovery, session keys, hardware signers)
    #[command(subcommand)]
    Passkey(commands::passkey::PasskeyCommand),

    /// Owner-signed machine access for agents, tools and models (add, list, revoke)
    #[command(subcommand)]
    MachineAccess(MachineAccessCommand),

    /// Generative media: the media catalog and renders
    #[command(subcommand, name = "media-gen")]
    MediaGen(MediaGenCommand),

    /// Timeseries forecasting (TimesFM 2.5, Chronos-2, TiRex-2, Toto 2.0)
    #[command(subcommand)]
    Forecast(ForecastCommand),

    /// Text embeddings (Qwen3-Embedding, EmbeddingGemma, BGE-M3)
    #[command(subcommand, name = "embed-text")]
    EmbedText(EmbedTextCommand),

    /// Image embeddings (CLIP, SigLIP2, DINOv3)
    #[command(subcommand, name = "embed-image")]
    EmbedImage(EmbedImageCommand),

    /// Image segmentation (SAM 2, EdgeSAM, MobileSAM)
    #[command(subcommand)]
    Segment(SegmentCommand),

    /// Open-vocabulary text-promptable segmentation (SAM 3, SAM 3.1)
    #[command(subcommand, name = "text-segment")]
    TextSegment(TextSegmentCommand),

    /// Object detection (RF-DETR, D-FINE)
    #[command(subcommand)]
    Detect(DetectCommand),

    /// Decision models: answer typed questions about a text
    #[command(subcommand)]
    Decide(DecideCommand),

    /// Rerankers: score documents against a query
    #[command(subcommand)]
    Rerank(RerankCommand),

    /// Speech synthesis (text to speech)
    #[command(subcommand)]
    Speech(SpeechCommand),

    /// LoRA training on this node's CUDA device (operator only)
    #[command(subcommand)]
    Training(TrainingCommand),

    /// Audio transcription / ASR (Moonshine, Distil-Whisper, Parakeet, Canary)
    #[command(subcommand)]
    Transcribe(TranscribeCommand),

    /// Video embeddings (catalog scaffolding for V-JEPA / VideoMAE)
    #[command(subcommand, name = "embed-video")]
    EmbedVideo(EmbedVideoCommand),

    /// OAuth 2.1 + DPoP auth: refresh access tokens, link wallet for auth
    Auth(AuthCommand),

    /// Proof-of-Reserve attestations for tokenized assets
    #[command(subcommand)]
    Reserve(ReserveCommand),

    /// C2PA-style content provenance manifests (EU AI Act §50(2))
    #[command(subcommand)]
    Provenance(ProvenanceCommand),

    /// Certifications, operator policies and model provenance
    #[command(subcommand)]
    Trust(TrustCommand),

    /// The model catalog: what a node serves, and publishing entries to it
    #[command(subcommand)]
    Catalog(CatalogCommand),

    /// AgentBond surety primitive: post, increase, withdraw, get, list
    #[command(subcommand)]
    Bond(BondCommand),

    /// The network insurance pool: claim, list, get, pool
    #[command(subcommand)]
    Insurance(InsuranceCommand),

    /// The generic registry: list, get (read-only)
    #[command(subcommand)]
    Registry(RegistryCommand),

    /// Validator set (Dynamic Validator Set): register, exit, update-metadata, get, list
    #[command(subcommand)]
    Validator(ValidatorCommand),

    /// Committee data availability: challenge, challenges, availability, committee, blobs, object, retention
    #[command(subcommand)]
    Da(DaCommand),

    /// The chain's randomness beacon
    Beacon(commands::beacon::BeaconCmd),

    /// The base fee of every resource market: compute, state growth, bandwidth, proof
    FeeMarket(commands::fee_market::FeeMarketCmd),

    /// Iroh content-addressed transport: info, endpoint-id, alpns, publish, fetch
    #[command(subcommand)]
    Iroh(IrohCommand),

    /// Adaptive-burn governance dial: config, metrics, recommendation, proposals
    #[command(subcommand)]
    AdaptiveBurn(AdaptiveBurnCommand),

    /// Settlement plans: legs on several networks, one Commit-or-Abort decision, the split fixed by the quote
    #[command(subcommand)]
    Settle(SettleCommand),

    /// PQ-hybrid signing helper commands
    #[command(subcommand)]
    PqHybrid(PqHybridCommand),

    /// Node access: sign in for an access token; administer who may use a node
    #[command(subcommand)]
    Access(AccessCommand),

    /// Permit2 SignatureTransfer: domain-separator / digest / verify-and-consume / nonce-used
    #[command(subcommand)]
    Permit2(Permit2Command),

    /// ERC-7943 (uRWA) tokenized RWA compliance: kill-switch / freeze / forced-transfer
    #[command(subcommand)]
    Urwa(UrwaCommand),

    /// Bridge fee in TNZO: quote destination-native bridge fees in TNZO + list sponsorship pools
    #[command(name = "bridge-fee", subcommand)]
    BridgeFee(BridgeFeeCommand),

    /// Decentralized Mixture-of-Experts serving
    #[command(subcommand)]
    Moe(commands::moe::MoeCommand),

    /// Discovery: node hardware profile
    #[command(subcommand)]
    Discover(DiscoverCommand),

    /// Local-network cluster planning
    #[command(subcommand)]
    Cluster(ClusterCommand),

    /// Devices bound to an identity, and machine ownership
    #[command(subcommand)]
    Device(DeviceCommand),

    /// Settlement rails and micropayment routing
    #[command(subcommand)]
    Rails(RailsCommand),

    /// Interaction receipts: mirror a settlement to other chains
    #[command(subcommand)]
    Interaction(InteractionCommand),

    /// Live resource and traffic status for this node
    Status(StatusCmd),

    /// Discover and call any JSON-RPC method this node serves
    #[command(subcommand)]
    Rpc(RpcCommand),

    /// Show or set this node's visibility (public, gated or private)
    #[command(subcommand)]
    Visibility(VisibilityCommand),

    /// Interactive chat with AI models
    Chat(ChatCmd),

    /// Show hardware profile
    Hardware(HardwareCmd),

    /// Show network information
    Info(InfoCmd),

    /// Show version information
    Version(VersionCmd),
}

/// Show hardware profile
#[derive(Debug, Parser)]
struct HardwareCmd {
    /// Output format (text, json)
    #[arg(long, default_value = "text")]
    format: String,
}

/// Interactive chat with AI models
#[derive(Debug, Parser)]
struct ChatCmd {
    /// Model ID to use. Omit to select one from `--use-case` + `--budget`.
    model_id: Option<String>,

    /// Use case for intent selection when no model_id is given:
    /// chat, code, reasoning, summarize, extract, or embed.
    #[arg(long)]
    use_case: Option<String>,

    /// Per-request cost cap in smallest TNZO unit (decimal string) for
    /// intent selection. Only used when no model_id is given.
    #[arg(long)]
    budget: Option<String>,

    /// Cost-quality knob in [0.0, 1.0] for intent selection.
    #[arg(long)]
    optimize: Option<f32>,

    /// Reject models below this tier during intent selection: cheap or strong.
    #[arg(long)]
    quality_floor: Option<String>,

    /// Maximum tokens to generate
    #[arg(long, default_value = "512")]
    max_tokens: u32,

    /// Temperature (0.0-2.0)
    #[arg(long, default_value = "0.7")]
    temperature: f32,

    /// Enable Multi-Token Prediction with this draft count (1..=6).
    /// Only meaningful on models whose catalog entry declares a
    /// paired drafter (e.g. Gemma 4 12B / 31B via `gemma4-*-mtp-draft`).
    /// Unsloth recommends 2 as a starting point; optimal value is
    /// hardware-dependent.
    #[arg(long, value_parser = clap::value_parser!(u8).range(1..=6))]
    draft_n: Option<u8>,

    /// Comma-separated jurisdiction pin: ISO 3166-1 alpha-2 country codes
    /// and/or bloc tokens (e.g. "DE,EU"), case-insensitive. The serving
    /// node must declare a matching attestation-bound locality claim or
    /// the request is refused.
    #[arg(long)]
    jurisdiction: Option<String>,

    /// Fail the request unless the response carries a verifiable signed
    /// jurisdiction receipt.
    #[arg(long)]
    require_jurisdiction_receipt: bool,

    /// Path to a JSON escrow voucher (`escrow_id`, `cumulative_amount`,
    /// `public_key`, composite `signature`): the
    /// payer's next cumulative voucher on an open payment channel, paying
    /// for this turn.
    #[arg(long)]
    channel_voucher: Option<String>,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

/// Show network information
#[derive(Debug, Parser)]
struct InfoCmd {
    /// RPC endpoint to query
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

/// Show version information
#[derive(Debug, Parser)]
struct VersionCmd {
    /// Show detailed version information
    #[arg(long)]
    detailed: bool,
}

fn main() -> Result<()> {
    // A model file's header is parsed by this executable re-run as a
    // locked-down child, which must lock itself down before any thread:
    // so before the async runtime starts.
    tenzro_model::parse_jail::enter_if_requested();
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(cli_main())
}

async fn cli_main() -> Result<()> {
    // Check if running with no subcommand and stdout is a TTY — launch interactive mode
    use std::io::IsTerminal as _;
    if std::env::args().count() == 1 && std::io::stdout().is_terminal() {
        init_logging(false)?;
        return run_interactive_mode().await;
    }

    let cli = Cli::parse();

    // Initialize logging
    init_logging(cli.verbose)?;

    // Print banner for interactive commands only when stdout is a TTY
    // This prevents banner pollution in scripts, pipelines, and automated environments
    // Also respect TENZRO_NO_BANNER=1 environment variable
    let no_banner = std::env::var("TENZRO_NO_BANNER")
        .map(|v| v == "1")
        .unwrap_or(false);
    if !matches!(cli.command, Command::Version(_))
        && !cli.verbose
        && !no_banner
        && std::io::stdout().is_terminal()
    {
        output::print_banner();
    }

    // Execute command
    match cli.command {
        Command::Join(cmd) => cmd.execute().await?,
        Command::Setup(cmd) => cmd.execute().await?,
        Command::Node(cmd) => cmd.execute().await?,
        Command::Wallet(cmd) => cmd.execute().await?,
        Command::Model(cmd) => cmd.execute().await?,
        Command::Stake(cmd) => cmd.execute().await?,
        Command::Governance(cmd) => cmd.execute().await?,
        Command::Tx(cmd) => cmd.execute().await?,
        Command::Funding(cmd) => cmd.execute().await?,
        Command::Sponsor(cmd) => cmd.execute().await?,
        Command::Provider(cmd) => cmd.execute().await?,
        Command::Schedule(cmd) => cmd.execute().await?,
        Command::Inference(cmd) => cmd.execute().await?,
        Command::Identity(cmd) => cmd.execute().await?,
        Command::Payment(cmd) => cmd.execute().await?,
        Command::Agent(cmd) => cmd.execute().await?,
        Command::Escrow(cmd) => cmd.execute().await?,
        Command::Duty(cmd) => cmd.execute().await?,
        Command::Dev(cmd) => cmd.execute().await?,
        Command::Token(cmd) => cmd.execute().await?,
        Command::Contract(cmd) => cmd.execute().await?,
        Command::Bridge(cmd) => cmd.execute().await?,
        Command::Relay(RelayCommand::AgentAccount(cmd)) => cmd.execute().await?,
        Command::Events(cmd) => cmd.execute().await?,
        Command::Crypto(cmd) => cmd.execute().await?,
        Command::Tee(cmd) => cmd.execute().await?,
        Command::Zk(cmd) => cmd.execute().await?,
        Command::Vrf(cmd) => cmd.execute().await?,
        Command::Finality(cmd) => cmd.execute().await?,
        Command::Passkey(cmd) => cmd.execute(None).await?,
        Command::MachineAccess(cmd) => cmd.execute().await?,
        Command::MediaGen(cmd) => cmd.execute().await?,
        Command::Forecast(cmd) => cmd.execute().await?,
        Command::EmbedText(cmd) => cmd.execute().await?,
        Command::EmbedImage(cmd) => cmd.execute().await?,
        Command::Segment(cmd) => cmd.execute().await?,
        Command::TextSegment(cmd) => cmd.execute().await?,
        Command::Detect(cmd) => cmd.execute().await?,
        Command::Decide(cmd) => cmd.execute().await?,
        Command::Rerank(cmd) => cmd.execute().await?,
        Command::Speech(cmd) => cmd.execute().await?,
        Command::Training(cmd) => cmd.execute().await?,
        Command::Transcribe(cmd) => cmd.execute().await?,
        Command::EmbedVideo(cmd) => cmd.execute().await?,
        Command::Auth(cmd) => cmd.execute().await?,
        Command::Reserve(cmd) => cmd.execute().await?,
        Command::Provenance(cmd) => cmd.execute().await?,
        Command::Trust(cmd) => cmd.execute().await?,
        Command::Catalog(cmd) => cmd.execute().await?,
        Command::Bond(cmd) => cmd.execute().await?,
        Command::Insurance(cmd) => cmd.execute().await?,
        Command::Registry(cmd) => cmd.execute().await?,
        Command::Validator(cmd) => cmd.execute().await?,
        Command::Da(cmd) => cmd.execute().await?,
        Command::Beacon(cmd) => cmd.execute().await?,
        Command::FeeMarket(cmd) => cmd.execute().await?,
        Command::Iroh(cmd) => cmd.execute().await?,
        Command::AdaptiveBurn(cmd) => cmd.execute().await?,
        Command::Settle(cmd) => cmd.execute().await?,
        Command::PqHybrid(cmd) => cmd.execute().await?,
        Command::Access(cmd) => cmd.execute().await?,
        Command::Permit2(cmd) => cmd.execute().await?,
        Command::Urwa(cmd) => cmd.execute().await?,
        Command::BridgeFee(cmd) => cmd.execute().await?,
        Command::Moe(cmd) => cmd.execute().await?,
        Command::Discover(cmd) => cmd.execute().await?,
        Command::Cluster(cmd) => cmd.execute().await?,
        Command::Device(cmd) => cmd.execute().await?,
        Command::Rails(cmd) => cmd.execute().await?,
        Command::Interaction(cmd) => cmd.execute().await?,
        Command::Status(cmd) => cmd.execute().await?,
        Command::Rpc(cmd) => cmd.execute().await?,
        Command::Visibility(cmd) => cmd.execute().await?,
        Command::Chat(cmd) => execute_chat(cmd).await?,
        Command::Hardware(cmd) => commands::hardware::execute(&cmd.format).await?,
        Command::Info(cmd) => execute_info(cmd).await?,
        Command::Version(cmd) => execute_version(cmd)?,
    }

    Ok(())
}

/// Initialize logging based on verbosity.
///
/// # Logs go to stderr, and that is not a preference
///
/// Several commands here exist to emit a document an operator redirects into a
/// file — `node enroll controller-ref` prints a controller entry, `node enroll
/// authorize` prints a delegation, `identity enroll` prints an enrolment
/// record. On stdout, a single log line lands ahead of the JSON and the file is
/// unparseable:
///
/// ```text
/// $ tenzro node enroll controller-ref machine --did ... > controller.json
/// $ head -c 60 controller.json
/// [2m2026-09-13T10:27:09Z[0m [32m INFO[0m derived the node identity from the TPM
/// ```
///
/// That is exactly what happened while enrolling a machine under two
/// controllers: every entry had to be recovered by scanning forward to the
/// first `{`. The identity loader logs on the way past — correctly, it is worth
/// saying that a key came from a TPM — and the log had nowhere to go but into
/// the caller's document.
///
/// stderr is the conventional destination for exactly this reason: it keeps
/// diagnostics visible on a terminal while leaving stdout as the command's
/// actual output. A caller that wants the logs in the file can still ask for
/// them with `2>&1`; a caller that does not should not have to strip them.
fn init_logging(verbose: bool) -> Result<()> {
    let filter = if verbose {
        tracing_subscriber::EnvFilter::new("tenzro=debug,tenzro_cli=debug")
    } else {
        tracing_subscriber::EnvFilter::new("tenzro=info,tenzro_cli=info")
    };

    tracing_subscriber::registry()
        .with(filter)
        .with(
            tracing_subscriber::fmt::layer()
                .with_target(verbose)
                .with_writer(std::io::stderr),
        )
        .init();

    Ok(())
}

/// Identify an attached image's media type from its leading bytes.
///
/// A serving projector reads the format from the bytes themselves; this is the
/// wire label the rich chat shape requires alongside the base64 payload.
fn sniff_image_media_type(bytes: &[u8]) -> Result<&'static str> {
    if bytes.starts_with(&[0x89, b'P', b'N', b'G']) {
        Ok("image/png")
    } else if bytes.starts_with(&[0xFF, 0xD8, 0xFF]) {
        Ok("image/jpeg")
    } else if bytes.len() >= 12 && &bytes[0..4] == b"RIFF" && &bytes[8..12] == b"WEBP" {
        Ok("image/webp")
    } else if bytes.starts_with(b"GIF8") {
        Ok("image/gif")
    } else {
        anyhow::bail!("unrecognized image format — expected PNG, JPEG, WebP, or GIF")
    }
}

/// Execute chat command — uses local model inference with RPC fallback
async fn execute_chat(cmd: ChatCmd) -> Result<()> {
    use std::io::{self, Write};
    use std::sync::Arc;
    use tenzro_model::{
        ChatMessage as ModelChatMessage, GenerationConfig, HfDownloader, ModelRuntime,
        get_model_by_id,
    };

    // Initialize model runtime and downloader
    let models_dir = tenzro_types::paths::models_dir();
    let _ = std::fs::create_dir_all(&models_dir);

    // Initialize chat history directory
    // Chat transcripts belong to the identity that held the conversation, not
    // to the machine it happened on. Two people sharing a box do not share a
    // history, and one person on two boxes expects theirs to follow them.
    let history_dir =
        tenzro_types::paths::identity_chat_history_dir(&tenzro_cli::keystore::active_did());
    let _ = std::fs::create_dir_all(&history_dir);

    let runtime = Arc::new(ModelRuntime::new()?);
    let downloader = HfDownloader::new(models_dir);

    // Resolve the model: an explicit model_id wins; otherwise select one from
    // the stated intent (use_case + budget + quality_floor + optimize) via the
    // node's inference router, so callers can chat without naming a model.
    let model_id: String = match &cmd.model_id {
        Some(m) if !m.trim().is_empty() => m.clone(),
        _ => {
            let use_case = cmd.use_case.as_deref().ok_or_else(|| {
                anyhow::anyhow!(
                    "provide a model_id or --use-case (chat|code|reasoning|research|summarize|extract|embed)"
                )
            })?;
            let mut params = serde_json::Map::new();
            params.insert(
                "use_case".to_string(),
                serde_json::Value::String(use_case.to_string()),
            );
            if let Some(b) = &cmd.budget {
                params.insert("budget".to_string(), serde_json::Value::String(b.clone()));
            }
            if let Some(o) = cmd.optimize {
                params.insert("optimize".to_string(), serde_json::json!(o));
            }
            if let Some(q) = &cmd.quality_floor {
                params.insert(
                    "quality_floor".to_string(),
                    serde_json::Value::String(q.clone()),
                );
            }

            let rpc = rpc::RpcClient::new(&cmd.rpc);
            let spinner = output::create_spinner("Selecting a model for the intent...");
            let decision: serde_json::Value = rpc
                .call("tenzro_routeIntent", serde_json::Value::Object(params))
                .await
                .map_err(|e| anyhow::anyhow!("calling tenzro_routeIntent: {e}"))?;
            spinner.finish_and_clear();

            let selected = decision
                .get("model_id")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("intent router returned no model"))?
                .to_string();
            output::print_field("Selected model", &selected);
            if let Some(reason) = decision.get("reason").and_then(|v| v.as_str()) {
                output::print_field("Reason", reason);
            }
            selected
        }
    };

    // Determine inference source: local model or network.
    // Jurisdiction pins are enforced by the serving node against its
    // attestation-bound locality claim; the CLI's in-process llama.cpp
    // path has no claim, so pinned requests always go through RPC.
    let jurisdiction_pinned = cmd.jurisdiction.is_some() || cmd.require_jurisdiction_receipt;
    // Whether this machine can run the model locally is decided by the
    // catalog the node serves.
    commands::catalog::install_from(&cmd.rpc).await?;
    let use_local = if jurisdiction_pinned {
        false
    } else if let Some(entry) = get_model_by_id(&model_id) {
        let gguf_path = downloader.model_path(&model_id);
        /*
         * Does the NODE already hold this model? Then do not load a second copy.
         *
         * `runtime` here is this process's own ModelRuntime, so the `is_loaded` check below
         * asks an empty map and always answers no -- the CLI loaded its own copy of the
         * weights every time, even with the node serving that same model in the same
         * machine's VRAM.
         *
         * Measured: with the node holding qwen3.5-4b at 10.6 GB, `tenzro chat` tried to load
         * it again and died with `cudaMalloc failed ... failed to allocate buffer for kv
         * cache` on a 16 GB card. Two copies of one model is never what an operator wanted;
         * it is what happens when nobody asks.
         *
         * The network path this falls through to already exists -- the Err arm below says
         * "Falling back to network" -- so this is not a new mechanism, only one that was
         * never reached because the local attempt came first and usually succeeded.
         */
        let node_serves = {
            let probe = rpc::RpcClient::new(&cmd.rpc);
            match probe
                .call::<serde_json::Value>(
                    "tenzro_listModelEndpoints",
                    serde_json::Value::Object(serde_json::Map::new()),
                )
                .await
            {
                Ok(v) => serde_json::to_string(&v)
                    .map(|t| t.contains(&format!("\"{model_id}\"")))
                    .unwrap_or(false),
                // A node that cannot be reached is not a node that is serving it; falling
                // through to the local load is right here -- that is the standalone case.
                Err(_) => false,
            }
        };
        if node_serves {
            output::print_success(&format!(
                "{model_id} is already served by the node -- using it rather than loading a second copy"
            ));
            false
        } else if gguf_path.exists() || gguf_path.is_symlink() {
            // Auto-load model if downloaded but not yet loaded
            if !runtime.is_loaded(&model_id) {
                let spinner =
                    output::create_spinner(&format!("Loading {} into memory...", entry.name));
                match runtime
                    .load_model_with_context(&model_id, &gguf_path, Some(entry.context_length))
                    .await
                {
                    Ok(()) => {
                        spinner.finish_and_clear();
                        output::print_success(&format!("Model {} loaded", entry.name));
                    }
                    Err(e) => {
                        spinner.finish_and_clear();
                        output::print_warning(&format!(
                            "Failed to load locally: {}. Falling back to network.",
                            e
                        ));
                    }
                }
                runtime.is_loaded(&model_id)
            } else {
                true
            }
        } else {
            false
        }
    } else {
        false
    };

    let source_label = if use_local { "local" } else { "network" };

    output::print_header(&format!("Chat with {}", model_id));
    println!();
    output::print_field("Model", &model_id);
    output::print_field("Source", source_label);
    output::print_field("Max Tokens", &cmd.max_tokens.to_string());
    output::print_field("Temperature", &format!("{:.1}", cmd.temperature));
    if let Some(pin) = &cmd.jurisdiction {
        output::print_field("Jurisdiction", pin);
    }
    println!();
    output::print_info("Type '/exit' or '/quit' to end the conversation");
    output::print_info("Type '/history' to list recent sessions");
    output::print_info("Type '/load {session_id}' to load a previous session");
    output::print_info("Type '/image {path}' to attach an image to the next message");
    output::print_info("Press Ctrl+C to interrupt");
    println!();

    let rpc = rpc::RpcClient::new(&cmd.rpc);
    let mut history: Vec<serde_json::Value> = Vec::new();

    // Create new session ID (timestamp-based UUID)
    let session_id = format!("{}", chrono::Utc::now().format("%Y%m%d_%H%M%S_%f"));
    let mut session_file = history_dir.join(format!("{}.json", session_id));
    output::print_field("Session ID", &session_id);
    println!();

    let gen_config = GenerationConfig {
        temperature: cmd.temperature as f64,
        top_p: 0.9,
        max_tokens: cmd.max_tokens,
        repeat_penalty: 1.1,
        repeat_last_n: 64,
        seed: 42,
        draft_n: cmd.draft_n,
        commitment_k: None,
        ..Default::default()
    };

    // Images queued by `/image` and drained by the next real turn. Each entry
    // is (media_type, bytes) — the bytes go to a local runtime as-is, and the
    // media type labels the base64 block on the network path.
    let mut pending_media: Vec<(&'static str, Vec<u8>)> = Vec::new();

    loop {
        // Print prompt
        print!("{}> {}", output::colors::CYAN, output::colors::RESET);
        io::stdout().flush()?;

        /*
         * EOF ends the session. `read_line` returns Ok(0) at end of input and leaves the buffer
         * empty; discarding that count turned a closed stdin into an infinite loop that reprinted
         * the prompt as fast as it could. Piping a single prompt in -- `echo ... | tenzro chat` --
         * wrote 6.7 GB of `> ` to a log in about six minutes before anything noticed.
         *
         * Ctrl-D on a terminal and a closed pipe are the same condition, and both mean the same
         * thing: there are no more turns coming.
         */
        let mut input = String::new();
        if io::stdin().read_line(&mut input)? == 0 {
            println!();
            output::print_success("Goodbye!");
            break;
        }
        let input = input.trim();

        // Check for commands
        if input == "/exit" || input == "/quit" {
            println!();
            output::print_success("Goodbye!");
            break;
        }

        if input == "/history" {
            println!();
            output::print_header("Recent Chat Sessions");
            println!();

            let mut sessions: Vec<_> = std::fs::read_dir(&history_dir)?
                .filter_map(|entry| entry.ok())
                .filter(|e| {
                    e.path()
                        .extension()
                        .map(|ext| ext == "json")
                        .unwrap_or(false)
                })
                .collect();

            sessions.sort_by(|a, b| {
                let t_a = a.metadata().and_then(|m| m.modified()).ok();
                let t_b = b.metadata().and_then(|m| m.modified()).ok();
                t_b.cmp(&t_a)
            });

            for (i, entry) in sessions.iter().take(10).enumerate() {
                let filename = entry.file_name();
                let session_name = filename.to_string_lossy();
                let session_id = session_name.trim_end_matches(".json");

                // Try to read first user message
                let preview = if let Ok(content) = std::fs::read_to_string(entry.path()) {
                    if let Ok(msgs) = serde_json::from_str::<Vec<serde_json::Value>>(&content) {
                        msgs.iter()
                            .find(|m| m.get("role").and_then(|r| r.as_str()) == Some("user"))
                            .and_then(|m| m.get("content").and_then(|c| c.as_str()))
                            .map(|s| {
                                let preview = s.chars().take(60).collect::<String>();
                                if s.len() > 60 {
                                    format!("{}...", preview)
                                } else {
                                    preview
                                }
                            })
                            .unwrap_or_else(|| "(empty)".to_string())
                    } else {
                        "(invalid)".to_string()
                    }
                } else {
                    "(unreadable)".to_string()
                };

                println!("  {}. {} - {}", i + 1, session_id, preview);
            }

            println!();
            output::print_info("Use '/load {session_id}' to continue a session");
            println!();
            continue;
        }

        if input.starts_with("/load ") {
            let session_id_to_load = input.trim_start_matches("/load ").trim();
            let load_path = history_dir.join(format!("{}.json", session_id_to_load));

            if load_path.exists() {
                match std::fs::read_to_string(&load_path) {
                    Ok(content) => {
                        match serde_json::from_str::<Vec<serde_json::Value>>(&content) {
                            Ok(loaded_history) => {
                                history = loaded_history;
                                session_file = load_path;
                                println!();
                                output::print_success(&format!(
                                    "Loaded session {} ({} messages)",
                                    session_id_to_load,
                                    history.len()
                                ));
                                println!();

                                // Display conversation so far
                                for msg in &history {
                                    if let (Some(role), Some(content)) = (
                                        msg.get("role").and_then(|r| r.as_str()),
                                        msg.get("content").and_then(|c| c.as_str()),
                                    ) {
                                        if role == "user" {
                                            println!(
                                                "{}User:{} {}",
                                                output::colors::CYAN,
                                                output::colors::RESET,
                                                content
                                            );
                                        } else if role == "assistant" {
                                            println!(
                                                "{}Assistant:{} {}",
                                                output::colors::GREEN,
                                                output::colors::RESET,
                                                content
                                            );
                                        }
                                    }
                                }
                                println!();
                            }
                            Err(e) => {
                                output::print_warning(&format!("Failed to parse session: {}", e));
                            }
                        }
                    }
                    Err(e) => {
                        output::print_warning(&format!("Failed to read session: {}", e));
                    }
                }
            } else {
                output::print_warning(&format!("Session '{}' not found", session_id_to_load));
            }
            println!();
            continue;
        }

        if let Some(path) = input.strip_prefix("/image ") {
            let path = path.trim();
            match std::fs::read(path) {
                Ok(bytes) => match sniff_image_media_type(&bytes) {
                    Ok(media_type) => {
                        output::print_success(&format!(
                            "Attached {} ({}, {} bytes) — sent with your next message",
                            path,
                            media_type,
                            bytes.len()
                        ));
                        pending_media.push((media_type, bytes));
                    }
                    Err(e) => output::print_warning(&format!("{}: {}", path, e)),
                },
                Err(e) => output::print_warning(&format!("Failed to read {}: {}", path, e)),
            }
            println!();
            continue;
        }

        if input.is_empty() {
            continue;
        }

        let media = std::mem::take(&mut pending_media);

        // Refuse attachments before the turn joins the history, so a refused
        // request leaves the conversation exactly as it was.
        if use_local && !media.is_empty() && !runtime.supports_media(&model_id) {
            output::print_warning(&format!(
                "{} serves text only — it declares no multimodal projector, or the \
                 projector is not present locally. Attachments dropped.",
                model_id
            ));
            println!();
            continue;
        }

        // Add user message to history
        history.push(serde_json::json!({
            "role": "user",
            "content": input,
        }));

        let spinner = output::create_spinner("Thinking...");

        if use_local {
            // ── Local inference ──────────────────────────────────────
            // Build chat messages — llama.cpp applies the correct template
            // from GGUF metadata (Gemma, Qwen, Mistral, etc.)
            let mut messages = vec![ModelChatMessage::new(
                "system",
                "You are a helpful assistant.",
            )];
            for msg in &history {
                let role = msg
                    .get("role")
                    .and_then(|v| v.as_str())
                    .unwrap_or("user")
                    .to_string();
                let content = msg
                    .get("content")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                messages.push(ModelChatMessage::new(role, content));
            }

            // Both paths report the same four fields this REPL prints; the
            // multimodal result additionally carries tool calls, which the
            // chat REPL does not request.
            let generated = if media.is_empty() {
                runtime
                    .generate_chat(&model_id, &messages, &gen_config)
                    .await
                    .map(|r| (r.text, r.input_tokens, r.output_tokens, r.tokens_per_second))
            } else {
                let images: Vec<Vec<u8>> = media.iter().map(|(_, bytes)| bytes.clone()).collect();
                runtime
                    .generate_chat_multimodal(&model_id, &messages, &images, &[], &gen_config)
                    .await
                    .map(|r| (r.text, r.input_tokens, r.output_tokens, r.tokens_per_second))
            };

            match generated {
                Ok((text, input_tokens, output_tokens, tokens_per_second)) => {
                    spinner.finish_and_clear();

                    println!();
                    // EU AI Act Art. 50(1): every assistant chunk is labeled
                    // as AI-generated. Local-mode chat is end-user-facing, so
                    // the disclosure shows up directly in the terminal.
                    // Use the canonical helper so the prefix string lives in
                    // exactly one place across the workspace.
                    println!(
                        "{}",
                        tenzro_types::eu_ai_disclosure::render_cli_chat_chunk(&text)
                    );
                    println!();

                    output::print_field(
                        "",
                        &format!(
                            "{}[{} in, {} out tokens | {:.1} tok/s | Free (local)]{}",
                            output::colors::BOLD,
                            input_tokens,
                            output_tokens,
                            tokens_per_second,
                            output::colors::RESET
                        ),
                    );
                    println!();

                    history.push(serde_json::json!({
                        "role": "assistant",
                        "content": text,
                    }));

                    // Save history to session file
                    if let Err(e) =
                        std::fs::write(&session_file, serde_json::to_string_pretty(&history)?)
                    {
                        output::print_warning(&format!("Failed to save session: {}", e));
                    }
                }
                Err(e) => {
                    spinner.finish_and_clear();
                    output::print_warning(&format!("Inference error: {}", e));
                    println!();
                }
            }
        } else {
            // ── Network inference (RPC fallback) ─────────────────────
            #[derive(serde::Deserialize)]
            struct ChatResponse {
                output: String,
                input_tokens: u32,
                output_tokens: u32,
                cost_wei: String,
                #[serde(default)]
                load: Option<serde_json::Value>,
                #[serde(default)]
                tenzro_jurisdiction: Option<serde_json::Value>,
            }

            // The rich shape of the same method, used when the turn carries
            // attachments — only that shape has image content blocks.
            #[derive(serde::Deserialize)]
            struct RichChatResponse {
                content: Vec<serde_json::Value>,
                usage: RichUsage,
                cost_wei: String,
                #[serde(default)]
                load: Option<serde_json::Value>,
                #[serde(default)]
                tenzro_jurisdiction: Option<serde_json::Value>,
            }

            #[derive(serde::Deserialize)]
            struct RichUsage {
                input_tokens: u32,
                output_tokens: u32,
            }

            let mut request = if media.is_empty() {
                serde_json::json!({
                    "model_id": model_id,
                    "message": input,
                    "history": history,
                    "max_tokens": cmd.max_tokens,
                    "temperature": cmd.temperature,
                })
            } else {
                use base64::Engine as _;
                // Attachments ride on the current turn as image blocks ahead of
                // the text, matching the order the serving node binds them in.
                let mut blocks: Vec<serde_json::Value> = media
                    .iter()
                    .map(|(media_type, bytes)| {
                        serde_json::json!({
                            "type": "image",
                            "source": {
                                "type": "base64",
                                "media_type": media_type,
                                "data": base64::engine::general_purpose::STANDARD.encode(bytes),
                            }
                        })
                    })
                    .collect();
                blocks.push(serde_json::json!({ "type": "text", "text": input }));

                // `history` already ends with this turn as plain text; swap that
                // entry's content for the block list.
                let mut messages = history.clone();
                if let Some(last) = messages.last_mut() {
                    last["content"] = serde_json::Value::Array(blocks);
                }

                serde_json::json!({
                    "model_id": model_id,
                    "messages": messages,
                    "max_tokens": cmd.max_tokens,
                    "temperature": cmd.temperature,
                })
            };
            if let Some(n) = cmd.draft_n {
                request["draft_n"] = serde_json::json!(n);
            }
            if let Some(pin) = &cmd.jurisdiction {
                request["jurisdiction"] = serde_json::json!(pin);
            }
            if cmd.require_jurisdiction_receipt {
                request["jurisdiction_receipt"] = serde_json::json!("required");
            }
            if let Some(path) = &cmd.channel_voucher {
                let voucher: serde_json::Value =
                    serde_json::from_str(&std::fs::read_to_string(path)?)?;
                request["channel_voucher"] = voucher;
            }

            let response: Result<ChatResponse> = if media.is_empty() {
                rpc.call("tenzro_chat", request).await
            } else {
                rpc.call::<RichChatResponse>("tenzro_chat", request)
                    .await
                    .map(|r| ChatResponse {
                        output: r
                            .content
                            .iter()
                            .filter(|b| b.get("type").and_then(|t| t.as_str()) == Some("text"))
                            .filter_map(|b| b.get("text").and_then(|t| t.as_str()))
                            .collect::<Vec<_>>()
                            .join(""),
                        input_tokens: r.usage.input_tokens,
                        output_tokens: r.usage.output_tokens,
                        cost_wei: r.cost_wei,
                        load: r.load,
                        tenzro_jurisdiction: r.tenzro_jurisdiction,
                    })
            };

            spinner.finish_and_clear();

            match response {
                Ok(chat_response) => {
                    println!();
                    // EU AI Act Art. 50(1) — same disclosure prefix as
                    // local-mode. Network mode reaches the user through
                    // the same terminal surface, so the rule is identical.
                    println!(
                        "{}",
                        tenzro_types::eu_ai_disclosure::render_cli_chat_chunk(
                            &chat_response.output
                        )
                    );
                    println!();

                    let cost_wei: u128 = chat_response.cost_wei.parse().unwrap_or(0);
                    let cost_str = if cost_wei == 0 {
                        "Free".to_string()
                    } else {
                        format!("{} TNZO", output::format_balance(cost_wei, 18))
                    };

                    output::print_field(
                        "",
                        &format!(
                            "{}[{} in, {} out tokens | {}]{}",
                            output::colors::BOLD,
                            chat_response.input_tokens,
                            chat_response.output_tokens,
                            cost_str,
                            output::colors::RESET
                        ),
                    );
                    if let Some(ref load) = chat_response.load {
                        output::print_field(
                            "",
                            &format!("  Load: {}", output::format_load_info(load)),
                        );
                    }
                    if let Some(ref receipt) = chat_response.tenzro_jurisdiction {
                        let claim = receipt.get("jurisdiction");
                        let country = claim
                            .and_then(|c| c.get("country"))
                            .and_then(|v| v.as_str())
                            .unwrap_or("?");
                        let blocs = claim
                            .and_then(|c| c.get("blocs"))
                            .and_then(|v| v.as_array())
                            .map(|a| {
                                a.iter()
                                    .filter_map(|b| b.as_str())
                                    .collect::<Vec<_>>()
                                    .join(",")
                            })
                            .unwrap_or_default();
                        let attested = claim
                            .and_then(|c| c.get("attestation_hash"))
                            .is_some_and(|v| !v.is_null());
                        let label = if blocs.is_empty() {
                            country.to_string()
                        } else {
                            format!("{} ({})", country, blocs)
                        };
                        output::print_field(
                            "",
                            &format!(
                                "  Jurisdiction: {} — {} claim, signed receipt",
                                label,
                                if attested {
                                    "attestation-bound"
                                } else {
                                    "operator-asserted"
                                }
                            ),
                        );
                    }
                    println!();

                    history.push(serde_json::json!({
                        "role": "assistant",
                        "content": chat_response.output,
                    }));

                    // Save history to session file
                    if let Err(e) =
                        std::fs::write(&session_file, serde_json::to_string_pretty(&history)?)
                    {
                        output::print_warning(&format!("Failed to save session: {}", e));
                    }
                }
                Err(e) => {
                    output::print_warning(&format!("Error: {}", e));
                    println!();
                }
            }
        }
    }

    Ok(())
}

/// Execute info command
async fn execute_info(cmd: InfoCmd) -> Result<()> {
    output::print_header("Network Information");

    let spinner = output::create_spinner("Fetching network info...");

    let rpc = rpc::RpcClient::new(&cmd.rpc);

    // Fetch data from RPC
    let block_number_result: Result<String> =
        rpc.call("eth_blockNumber", serde_json::json!([])).await;
    let chain_id_result: Result<String> = rpc.call("eth_chainId", serde_json::json!([])).await;
    let peer_count_result: Result<String> = rpc.call("net_peerCount", serde_json::json!([])).await;
    let node_info_result: Result<serde_json::Value> = rpc
        .call("tenzro_getNodeStatus", serde_json::json!([]))
        .await;
    let total_supply_result: Result<String> =
        rpc.call("tenzro_totalSupply", serde_json::json!([])).await;

    spinner.finish_and_clear();

    println!();

    // Display network info
    if let Ok(chain_id_hex) = chain_id_result {
        let chain_id = rpc::parse_hex_u64(&chain_id_hex);
        output::print_field("Chain ID", &chain_id.to_string());
    } else {
        output::print_field("Chain ID", "unavailable");
    }

    output::print_field("Network", "Tenzro Network");
    output::print_field("Protocol Version", "1.0.0");
    println!();

    if let Ok(block_hex) = block_number_result {
        let block_num = rpc::parse_hex_u64(&block_hex);
        output::print_field("Best Block", &format!("#{}", block_num));

        // Try to query finalized block from RPC, fall back to block_num - 3
        let finalized = match rpc
            .call("tenzro_getFinalizedBlock", serde_json::json!([]))
            .await
        {
            Ok(val) => {
                let val: serde_json::Value = val;
                u64::from_str_radix(val.as_str().unwrap_or("0x0").trim_start_matches("0x"), 16)
                    .unwrap_or(block_num.saturating_sub(3))
            }
            Err(_) => block_num.saturating_sub(3),
        };
        output::print_field("Finalized Block", &format!("#{}", finalized));
    } else {
        output::print_field("Best Block", "unavailable");
        output::print_field("Finalized Block", "unavailable");
    }

    output::print_field("Block Time", "~6 seconds");

    println!();

    if let Ok(peer_hex) = peer_count_result {
        let peer_count = rpc::parse_hex_u64(&peer_hex);
        output::print_field("Connected Peers", &peer_count.to_string());
    } else {
        output::print_field("Connected Peers", "unavailable");
    }

    if let Ok(node_info) = node_info_result {
        if let Some(role) = node_info.get("role").and_then(|v| v.as_str()) {
            output::print_field("Node Role", role);
        }
        if let Some(version) = node_info.get("version").and_then(|v| v.as_str()) {
            output::print_field("Node Version", version);
        }
    }

    println!();

    if let Ok(supply_hex) = total_supply_result {
        let supply = rpc::parse_hex_u128(&supply_hex);
        output::print_field("TNZO Total Supply", &rpc::format_tnzo(supply));
    } else {
        output::print_field("TNZO Total Supply", "unavailable");
    }

    Ok(())
}

/// Execute version command
fn execute_version(cmd: VersionCmd) -> Result<()> {
    if cmd.detailed {
        output::print_header("Tenzro Network CLI");
        println!();
        output::print_field("Version", env!("CARGO_PKG_VERSION"));
        output::print_field("Git Commit", option_env!("GIT_HASH").unwrap_or("unknown"));
        output::print_field("Build Date", option_env!("BUILD_DATE").unwrap_or("unknown"));
        output::print_field(
            "Rust Version",
            option_env!("CARGO_PKG_RUST_VERSION").unwrap_or("unknown"),
        );
        println!();
        output::print_field("Authors", env!("CARGO_PKG_AUTHORS"));
        output::print_field(
            "Homepage",
            option_env!("CARGO_PKG_HOMEPAGE").unwrap_or("https://tenzro.com"),
        );
        output::print_field("Repository", env!("CARGO_PKG_REPOSITORY"));
        output::print_field("License", env!("CARGO_PKG_LICENSE"));
        println!();

        println!(
            "{}Components:{}",
            output::colors::BOLD,
            output::colors::RESET
        );
        output::print_field("  tenzro-types", env!("CARGO_PKG_VERSION"));
        output::print_field("  tenzro-crypto", env!("CARGO_PKG_VERSION"));
        output::print_field("  tenzro-wallet", env!("CARGO_PKG_VERSION"));
        output::print_field("  tenzro-node", env!("CARGO_PKG_VERSION"));
    } else {
        println!("tenzro {}", env!("CARGO_PKG_VERSION"));
    }

    Ok(())
}

/// Interactive mode — activated when `tenzro` is run with no arguments on a TTY
async fn run_interactive_mode() -> Result<()> {
    println!();
    println!(
        "  {}████████╗███████╗███╗   ██╗███████╗██████╗  ██████╗ {}",
        output::colors::CYAN,
        output::colors::RESET
    );
    println!(
        "  {}╚══██╔══╝██╔════╝████╗  ██║╚══███╔╝██╔══██╗██╔═══██╗{}",
        output::colors::CYAN,
        output::colors::RESET
    );
    println!(
        "  {}   ██║   █████╗  ██╔██╗ ██║  ███╔╝ ██████╔╝██║   ██║{}",
        output::colors::CYAN,
        output::colors::RESET
    );
    println!(
        "  {}   ██║   ██╔══╝  ██║╚██╗██║ ███╔╝  ██╔══██╗██║   ██║{}",
        output::colors::CYAN,
        output::colors::RESET
    );
    println!(
        "  {}   ██║   ███████╗██║ ╚████║███████╗██║  ██║╚██████╔╝{}",
        output::colors::CYAN,
        output::colors::RESET
    );
    println!(
        "  {}   ╚═╝   ╚══════╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ╚═════╝{}",
        output::colors::CYAN,
        output::colors::RESET
    );
    println!();

    // Determine RPC endpoint from config or default
    let cfg = tenzro_cli::config::load_config();
    let rpc_url = cfg
        .endpoint
        .unwrap_or_else(|| "http://127.0.0.1:8545".to_string());
    let rpc = rpc::RpcClient::new(&rpc_url);

    // Show connection status
    if let Ok(info) = rpc
        .call::<serde_json::Value>("tenzro_getNodeStatus", serde_json::json!([]))
        .await
    {
        let height = info
            .get("block_height")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let peers = info.get("peer_count").and_then(|v| v.as_u64()).unwrap_or(0);
        println!(
            "  {}Connected:{} {} | Block: {} | Peers: {}",
            output::colors::GREEN,
            output::colors::RESET,
            rpc.url(),
            height,
            peers
        );
    } else {
        println!(
            "  {}Not connected to a node{} ({})",
            output::colors::YELLOW,
            output::colors::RESET,
            rpc.url()
        );
    }
    println!();

    loop {
        let categories = vec![
            "Wallet & Tokens",
            "AI Models & Inference",
            "Bridge & Cross-Chain",
            "Identity & Credentials",
            "Payments & Settlement",
            "Security (Crypto, TEE, ZK)",
            "Developer (Contracts, Tasks)",
            "Network & Governance",
            "Exit",
        ];

        let selection = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("What would you like to do?")
            .items(&categories)
            .default(0)
            .interact()?;

        let result = match selection {
            0 => wallet_menu(&rpc).await,
            1 => models_menu(&rpc).await,
            2 => bridge_menu(&rpc).await,
            3 => identity_menu(&rpc).await,
            4 => payments_menu(&rpc).await,
            5 => security_menu(&rpc).await,
            6 => developer_menu(&rpc).await,
            7 => network_menu(&rpc).await,
            8 => break,
            _ => Ok(()),
        };

        if let Err(e) = result {
            output::print_error(&format!("{}", e));
        }
        println!();
    }

    println!();
    output::print_success("Goodbye!");
    Ok(())
}

async fn wallet_menu(rpc: &rpc::RpcClient) -> Result<()> {
    let options = vec![
        "Check balance",
        "Send TNZO",
        "Transaction history",
        "<- Back",
    ];
    let sel = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Wallet & Tokens")
        .items(&options)
        .default(0)
        .interact()?;
    match sel {
        0 => {
            let addr: String = Input::with_theme(&ColorfulTheme::default())
                .with_prompt("Address (hex)")
                .interact_text()?;
            let result: serde_json::Value = rpc
                .call("eth_getBalance", serde_json::json!([addr, "latest"]))
                .await?;
            let hex = result.as_str().unwrap_or("0x0");
            let wei = u128::from_str_radix(hex.trim_start_matches("0x"), 16).unwrap_or(0);
            println!();
            output::print_field("Balance", &rpc::format_tnzo(wei));
        }
        1 => {
            let to: String = Input::with_theme(&ColorfulTheme::default())
                .with_prompt("To address")
                .interact_text()?;
            let amount: String = Input::with_theme(&ColorfulTheme::default())
                .with_prompt("Amount (TNZO)")
                .interact_text()?;
            let amount_float: f64 = amount.parse().unwrap_or(0.0);
            let amount_wei = (amount_float * 1e18) as u128;
            // Signed in hardware as this machine's client account and
            // submitted pre-signed; the node never signs for it.
            let result = tenzro_cli::keystore::send_as_client(
                rpc,
                "client",
                tenzro_cli::keystore::address32(&to)?,
                serde_json::json!({ "Transfer": { "amount": amount_wei.to_string() } }),
                21_000,
            )
            .await?;
            output::print_success("Transaction sent!");
            output::print_field(
                "Tx Hash",
                &result
                    .as_str()
                    .map_or_else(|| result.to_string(), str::to_string),
            );
        }
        2 => {
            let addr: String = Input::with_theme(&ColorfulTheme::default())
                .with_prompt("Address")
                .interact_text()?;
            let result: serde_json::Value = rpc
                .call(
                    "tenzro_getTransactionHistory",
                    serde_json::json!({ "address": addr, "limit": 10 }),
                )
                .await?;
            if let Some(txs) = result.get("transactions").and_then(|v| v.as_array()) {
                for tx in txs {
                    let hash = tx.get("hash").and_then(|v| v.as_str()).unwrap_or("?");
                    let value = tx.get("value").and_then(|v| v.as_str()).unwrap_or("0");
                    println!("  {} -> {}", &hash[..18.min(hash.len())], value);
                }
            } else {
                output::print_info("No transactions found.");
            }
        }
        _ => {}
    }
    Ok(())
}

async fn models_menu(rpc: &rpc::RpcClient) -> Result<()> {
    let options = vec![
        "List available models",
        "Chat with a model",
        "Download a model",
        "List model endpoints",
        "Discover models on network",
        "<- Back",
    ];
    let sel = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("AI Models & Inference")
        .items(&options)
        .default(0)
        .interact()?;
    match sel {
        0 => {
            let result: serde_json::Value =
                rpc.call("tenzro_listModels", serde_json::json!({})).await?;
            if let Some(models) = result.as_array() {
                let headers = vec!["Model ID", "Name", "Status"];
                let mut rows = Vec::new();
                for m in models {
                    rows.push(vec![
                        m.get("model_id")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string(),
                        m.get("name")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string(),
                        m.get("status")
                            .and_then(|v| v.as_str())
                            .unwrap_or("available")
                            .to_string(),
                    ]);
                }
                output::print_table(&headers, &rows);
            } else {
                output::print_json(&result)?;
            }
        }
        1 => {
            let model_id: String = Input::with_theme(&ColorfulTheme::default())
                .with_prompt("Model ID")
                .interact_text()?;
            let message: String = Input::with_theme(&ColorfulTheme::default())
                .with_prompt("Message")
                .interact_text()?;
            let result: serde_json::Value = rpc.call("tenzro_chat", serde_json::json!({
                "model_id": model_id, "message": message, "history": [], "max_tokens": 512, "temperature": 0.7,
            })).await?;
            if let Some(output_text) = result.get("output").and_then(|v| v.as_str()) {
                println!();
                // EU AI Act Art. 50(1) — match the chat REPL's prefix.
                println!(
                    "{}",
                    tenzro_types::eu_ai_disclosure::render_cli_chat_chunk(output_text)
                );
            } else {
                output::print_json(&result)?;
            }
        }
        2 => {
            let model_id: String = Input::with_theme(&ColorfulTheme::default())
                .with_prompt("Model ID to fetch and serve")
                .interact_text()?;
            let result: serde_json::Value = rpc
                .call(
                    "tenzro_serveModel",
                    serde_json::json!([{ "model_id": model_id }]),
                )
                .await?;
            output::print_field(
                "Status",
                result
                    .get("status")
                    .and_then(|v| v.as_str())
                    .unwrap_or("requested"),
            );
        }
        3 => {
            let endpoints: Vec<serde_json::Value> = rpc
                .call("tenzro_listModelEndpoints", serde_json::json!([]))
                .await
                .unwrap_or_default();
            if endpoints.is_empty() {
                output::print_info("No endpoints registered.");
            } else {
                for ep in &endpoints {
                    output::print_field(
                        ep.get("model_name").and_then(|v| v.as_str()).unwrap_or("?"),
                        ep.get("iroh_endpoint_id")
                            .and_then(|v| v.as_str())
                            .unwrap_or(""),
                    );
                }
            }
        }
        4 => {
            let result: serde_json::Value = rpc
                .call("tenzro_discoverModels", serde_json::json!({ "limit": 10 }))
                .await?;
            if let Some(models) = result.as_array() {
                for m in models {
                    output::print_field(
                        m.get("model_id").and_then(|v| v.as_str()).unwrap_or("?"),
                        m.get("name").and_then(|v| v.as_str()).unwrap_or(""),
                    );
                }
            }
        }
        _ => {}
    }
    Ok(())
}

async fn bridge_menu(rpc: &rpc::RpcClient) -> Result<()> {
    let options = vec![
        "List bridge routes",
        "Send TNZO to another chain",
        "<- Back",
    ];
    let sel = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Bridge & Cross-Chain")
        .items(&options)
        .default(0)
        .interact()?;
    match sel {
        0 => {
            let result: serde_json::Value = rpc
                .call("tenzro_listBridgeRoutes", serde_json::json!({}))
                .await?;
            for route in result["routes"].as_array().cloned().unwrap_or_default() {
                output::print_field(
                    route["key"].as_str().unwrap_or(""),
                    route["mode"].as_str().unwrap_or(""),
                );
            }
        }
        1 => {
            output::print_info(
                "Sending is holder-signed: use `tenzro bridge send --request-out <file> ...`",
            );
        }
        _ => {}
    }
    Ok(())
}

async fn identity_menu(rpc: &rpc::RpcClient) -> Result<()> {
    let options = vec![
        "Register identity",
        "Resolve DID",
        "List identities",
        "Set delegation scope",
        "<- Back",
    ];
    let sel = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Identity & Credentials")
        .items(&options)
        .default(0)
        .interact()?;
    match sel {
        0 => {
            let name: String = Input::with_theme(&ColorfulTheme::default())
                .with_prompt("Display name")
                .interact_text()?;
            commands::identity::register_human(rpc.url(), &name).await?;
        }
        1 => {
            let did: String = Input::with_theme(&ColorfulTheme::default())
                .with_prompt("DID to resolve")
                .interact_text()?;
            let result: serde_json::Value = rpc
                .call("tenzro_resolveIdentity", serde_json::json!({"did": did}))
                .await?;
            if let Some(name) = result.get("display_name").and_then(|v| v.as_str()) {
                output::print_field("Name", name);
            }
            if let Some(t) = result.get("identity_type").and_then(|v| v.as_str()) {
                output::print_field("Type", t);
            }
            if let Some(s) = result.get("status").and_then(|v| v.as_str()) {
                output::print_field("Status", s);
            }
        }
        2 => {
            let ids: Vec<serde_json::Value> = rpc
                .call("tenzro_listIdentities", serde_json::json!([{}]))
                .await?;
            if ids.is_empty() {
                output::print_info("No identities found.");
            } else {
                for id in &ids {
                    output::print_field(
                        id.get("did").and_then(|v| v.as_str()).unwrap_or("?"),
                        id.get("display_name")
                            .and_then(|v| v.as_str())
                            .unwrap_or(""),
                    );
                }
            }
        }
        3 => {
            output::print_info(
                "Use the full CLI: tenzro identity set-delegation <DID> --max-tx-value <V>",
            );
        }
        _ => {}
    }
    Ok(())
}

async fn payments_menu(rpc: &rpc::RpcClient) -> Result<()> {
    let options = vec!["Create payment challenge", "<- Back"];
    let sel = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Payments & Settlement")
        .items(&options)
        .default(0)
        .interact()?;
    if sel == 0 {
        let resource: String = Input::with_theme(&ColorfulTheme::default())
            .with_prompt("Resource URI")
            .interact_text()?;
        let amount: String = Input::with_theme(&ColorfulTheme::default())
            .with_prompt("Amount")
            .interact_text()?;
        let result: serde_json::Value = rpc.call("tenzro_createPaymentChallenge", serde_json::json!({
            "resource": resource, "amount": amount.trim(), "asset": "USDC", "protocol": "mpp",
        })).await?;
        output::print_success("Challenge created!");
        output::print_field(
            "Challenge ID",
            result
                .get("challenge_id")
                .and_then(|v| v.as_str())
                .unwrap_or(""),
        );
    }
    Ok(())
}

async fn security_menu(rpc: &rpc::RpcClient) -> Result<()> {
    let options = vec![
        "Verify signature",
        "Detect TEE hardware",
        "Create ZK proof",
        "<- Back",
    ];
    let sel = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Security (Crypto, TEE, ZK)")
        .items(&options)
        .default(0)
        .interact()?;
    match sel {
        0 => {
            output::print_info("Use the full CLI: tenzro crypto verify");
        }
        1 => {
            let result: serde_json::Value =
                rpc.call("tenzro_detectTee", serde_json::json!([])).await?;
            let available = result
                .get("available")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            if available {
                output::print_success("TEE hardware detected!");
                output::print_field(
                    "Provider",
                    result
                        .get("provider")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown"),
                );
            } else {
                output::print_info("No TEE hardware detected.");
            }
        }
        2 => {
            output::print_info(
                "Use the full CLI: tenzro zk prove --circuit <name> --inputs <json>",
            );
        }
        _ => {}
    }
    Ok(())
}

async fn developer_menu(rpc: &rpc::RpcClient) -> Result<()> {
    let options = vec!["Deploy contract", "Open network duties", "<- Back"];
    let sel = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Developer")
        .items(&options)
        .default(0)
        .interact()?;
    match sel {
        0 => {
            output::print_info(
                "Use the full CLI: tenzro contract deploy --bytecode <hex> --key-namespace <ns>",
            );
        }
        1 => {
            let result: serde_json::Value =
                rpc.call("tenzro_listDuties", serde_json::json!({})).await?;
            let duties = result
                .get("duties")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            for d in &duties {
                output::print_field(
                    d.get("id").and_then(|v| v.as_str()).unwrap_or("?"),
                    &d.get("kind").map(|v| v.to_string()).unwrap_or_default(),
                );
            }
            if duties.is_empty() {
                output::print_info("No open duties.");
            }
        }
        _ => {}
    }
    Ok(())
}

async fn network_menu(rpc: &rpc::RpcClient) -> Result<()> {
    let options = vec![
        "Node status",
        "Network info",
        "List proposals",
        "Staking info",
        "Peer count",
        "<- Back",
    ];
    let sel = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Network & Governance")
        .items(&options)
        .default(0)
        .interact()?;
    match sel {
        0 => {
            let info: serde_json::Value = rpc
                .call("tenzro_getNodeStatus", serde_json::json!([]))
                .await?;
            output::print_success("Node is running");
            if let Some(v) = info.get("role").and_then(|v| v.as_str()) {
                output::print_field("Role", v);
            }
            if let Some(v) = info.get("version").and_then(|v| v.as_str()) {
                output::print_field("Version", v);
            }
            if let Some(v) = info.get("block_height").and_then(|v| v.as_u64()) {
                output::print_field("Block", &v.to_string());
            }
            if let Some(v) = info.get("peer_count").and_then(|v| v.as_u64()) {
                output::print_field("Peers", &v.to_string());
            }
        }
        1 => {
            let block: String = rpc.call("eth_blockNumber", serde_json::json!([])).await?;
            let chain_id = rpc::fetch_chain_id(rpc).await?;
            output::print_field("Block", &rpc::parse_hex_u64(&block).to_string());
            output::print_field("Chain ID", &chain_id.to_string());
        }
        2 => {
            let proposals: Vec<serde_json::Value> = rpc
                .call("tenzro_listProposals", serde_json::json!([{}]))
                .await
                .unwrap_or_default();
            if proposals.is_empty() {
                output::print_info("No proposals.");
            } else {
                for p in &proposals {
                    output::print_field(
                        p.get("title").and_then(|v| v.as_str()).unwrap_or("?"),
                        p.get("status").and_then(|v| v.as_str()).unwrap_or(""),
                    );
                }
            }
        }
        3 => {
            output::print_info("Use the full CLI: tenzro stake bond/info");
        }
        4 => {
            let count: String = rpc.call("net_peerCount", serde_json::json!([])).await?;
            output::print_field("Peer Count", &rpc::parse_hex_u64(&count).to_string());
        }
        _ => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_cli() {
        use clap::CommandFactory;
        Cli::command().debug_assert();
    }

    /// The commands the sponsorship application prints are real subcommands
    /// with real flags.
    #[test]
    fn every_command_sponsor_prints_parses() {
        use clap::Parser;
        for line in commands::sponsor::sample_commands() {
            let argv: Vec<&str> = line.split_whitespace().collect();
            Cli::try_parse_from(&argv)
                .unwrap_or_else(|e| panic!("sponsor prints `{line}`, which does not parse:\n{e}"));
        }
    }

    /// Every `tenzro ...` command the setup wizard prints must parse under
    /// the CLI's own parser. A printed command that does not exist sends a
    /// new operator to an error at the moment they trust the wizard most.
    #[test]
    fn every_command_the_wizard_prints_parses() {
        use clap::Parser;
        let steps = commands::setup::validator_next_steps(
            std::path::Path::new("/var/lib/tenzro"),
            std::path::Path::new("/var/lib/tenzro/tenzro-node.service"),
            &format!("0x{}", "ab".repeat(32)),
            10_000_000_000_000_000_000_000,
            false,
        );
        let mut printed = commands::setup::printed_tenzro_commands(&steps);
        printed.extend(commands::stake_options::printed_tenzro_commands(
            &commands::stake_options::StakeNeed {
                role: "validator".into(),
                required_wei: 10_000_000_000_000_000_000_000,
                balance_wei: Some(0),
                account: format!("0x{}", "ab".repeat(32)),
            },
        ));
        assert!(!printed.is_empty(), "the wizard prints no tenzro command");
        for line in printed {
            let argv: Vec<&str> = line.split_whitespace().collect();
            Cli::try_parse_from(&argv)
                .unwrap_or_else(|e| panic!("the wizard prints `{line}`, which does not parse:\n{e}"));
        }
    }
}

#[cfg(test)]
mod cli_documentation_tests {
    use super::Cli;
    use clap::CommandFactory;

    /// Where the generated reference lives, relative to the crate.
    const REFERENCE: &str = "../../docs/CLI.md";

    /// Every command group in the binary, as clap sees it.
    fn command_groups() -> Vec<String> {
        Cli::command()
            .get_subcommands()
            .map(|c| c.get_name().to_string())
            .collect()
    }

    /// **Documentation drift, caught by the compiler's test run rather than by
    /// a user.**
    ///
    /// This CLI grew to 124 command groups against a README that named 26 and
    /// a guide that named 9. Nothing was wrong with any individual commit —
    /// each added a command and moved on — and there was no point at which
    /// anybody was told the reference had fallen behind.
    ///
    /// So the reference is generated from the binary (`scripts/gen-cli-docs.sh`)
    /// and this fails when the two disagree. A new command group is then a
    /// choice between regenerating the docs and explaining why it is hidden,
    /// rather than something that silently goes unmentioned.
    #[test]
    fn every_command_group_appears_in_the_reference() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(REFERENCE);
        let Ok(doc) = std::fs::read_to_string(&path) else {
            panic!(
                "no CLI reference at {}. Generate it with scripts/gen-cli-docs.sh",
                path.display()
            );
        };

        let missing: Vec<String> = command_groups()
            .into_iter()
            // `help` is clap's own and has nothing to document.
            .filter(|name| name != "help")
            .filter(|name| !doc.contains(&format!("## `tenzro {name}`")))
            .collect();

        assert!(
            missing.is_empty(),
            "{} command group(s) are in the binary but not in docs/CLI.md:\n  {}\n\
             Regenerate with scripts/gen-cli-docs.sh",
            missing.len(),
            missing.join("\n  ")
        );
    }

    /// And the reverse: a documented command that no longer exists sends a
    /// reader to a command that will not run, which is worse than silence.
    #[test]
    fn the_reference_documents_nothing_that_was_removed() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(REFERENCE);
        let Ok(doc) = std::fs::read_to_string(&path) else {
            return; // covered by the test above
        };

        let real: std::collections::HashSet<String> = command_groups().into_iter().collect();
        let documented: Vec<String> = doc
            .lines()
            .filter_map(|l| l.strip_prefix("## `tenzro "))
            .filter_map(|l| l.strip_suffix('`'))
            .map(str::to_string)
            .collect();

        let stale: Vec<&String> = documented.iter().filter(|n| !real.contains(*n)).collect();
        assert!(
            stale.is_empty(),
            "docs/CLI.md documents {} command(s) the binary no longer has:\n  {:?}",
            stale.len(),
            stale
        );
    }

    /// Every command path in the binary at every depth (`provider pricing set`),
    /// not just the groups.
    fn command_paths() -> std::collections::BTreeSet<String> {
        fn walk(cmd: &clap::Command, prefix: &str, out: &mut std::collections::BTreeSet<String>) {
            for sub in cmd
                .get_subcommands()
                .filter(|c| c.get_name() != "help" && !c.is_hide_set())
            {
                let path = format!("{prefix}{}", sub.get_name());
                out.insert(path.clone());
                walk(sub, &format!("{path} "), out);
            }
        }
        let mut out = std::collections::BTreeSet::new();
        walk(&Cli::command(), "", &mut out);
        out
    }

    /// The paths documented as headings (`## ... ######`), whatever the depth.
    fn documented_paths(doc: &str) -> std::collections::BTreeSet<String> {
        doc.lines()
            .filter_map(|l| l.trim_start_matches('#').strip_prefix(" `tenzro "))
            .filter_map(|l| l.strip_suffix('`'))
            .map(str::to_string)
            .collect()
    }

    /// Each subcommand at every depth has its own entry with its flags, and no
    /// entry names a path the binary does not have.
    #[test]
    fn every_command_path_at_every_depth_is_in_the_reference() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(REFERENCE);
        let doc = std::fs::read_to_string(&path).expect("docs/CLI.md");
        let real = command_paths();
        let documented = documented_paths(&doc);
        let missing: Vec<_> = real.difference(&documented).collect();
        let stale: Vec<_> = documented.difference(&real).collect();
        assert!(
            missing.is_empty() && stale.is_empty(),
            "docs/CLI.md is out of date (regenerate with scripts/gen-cli-docs.sh): \
             {} path(s) undocumented {missing:?}; {} documented but gone {stale:?}",
            missing.len(),
            stale.len()
        );
    }
}

/// Relayer commands.
#[derive(Debug, clap::Subcommand)]
pub enum RelayCommand {
    /// Settle a report of an agent's account on another chain
    AgentAccount(commands::agent_accounts::RelayAgentAccountCmd),
}
