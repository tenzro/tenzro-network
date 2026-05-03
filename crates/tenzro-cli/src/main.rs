//! Tenzro Network CLI
//!
//! Command-line interface for operating Tenzro Network nodes, managing wallets,
//! models, staking, and governance.

use clap::{Parser, Subcommand};
use anyhow::Result;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use dialoguer::{Select, Input, theme::ColorfulTheme};

use tenzro_cli::{commands, output, rpc};

use commands::{
    NodeCommand, WalletCommand, ModelCommand, StakeCommand,
    GovernanceCommand, ProviderCommand, InferenceCommand,
    IdentityCommand, PaymentCommand, JoinCmd, ScheduleCommand,
    SetUsernameCmd, AgentCommand, CantonCommand,
    EscrowCommand, TaskCommand, MarketplaceCommand, SkillCommand,
    ToolCommand, TokenCommand, ContractCommand, BridgeCommand,
    DebridgeCommand, LifiCommand, NftCommand, ComplianceCommand,
    CrosschainCommand, EventsCommand, CryptoCommand, TeeCommand,
    ZkCommand, VrfCommand, CustodyCommand, AppCommand,
    CortexCommand, Ap2Command, Erc8004Command, WormholeCommand, CctCommand,
    TrainCommand,
    DetectCommand, EmbedTextCommand, EmbedVideoCommand, SegmentCommand, TranscribeCommand,
    AuthCommand,
    X402Command, ReputationCommand, ApprovalCommand, DisputeCommand, ProvenanceCommand,
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

    /// Provider management commands
    #[command(subcommand)]
    Provider(ProviderCommand),

    /// Provider schedule management
    #[command(subcommand)]
    Schedule(ScheduleCommand),

    /// Inference commands
    #[command(subcommand)]
    Inference(InferenceCommand),

    /// Identity management commands (TDIP + PDIS)
    #[command(subcommand)]
    Identity(IdentityCommand),

    /// Payment protocol commands (MPP / x402)
    #[command(subcommand)]
    Payment(PaymentCommand),

    /// AI agent management commands
    #[command(subcommand)]
    Agent(AgentCommand),

    /// Canton/DAML integration commands
    #[command(subcommand)]
    Canton(CantonCommand),

    /// Escrow and payment channel commands
    #[command(subcommand)]
    Escrow(EscrowCommand),

    /// Task marketplace commands
    #[command(subcommand)]
    Task(TaskCommand),

    /// Agent marketplace commands
    #[command(subcommand)]
    Marketplace(MarketplaceCommand),

    /// Skill registry commands
    #[command(subcommand)]
    Skill(SkillCommand),

    /// Tool registry commands (MCP server management)
    #[command(subcommand)]
    Tool(ToolCommand),

    /// Token management commands (create, query, cross-VM transfers)
    #[command(subcommand)]
    Token(TokenCommand),

    /// Contract deployment commands
    #[command(subcommand)]
    Contract(ContractCommand),

    /// Cross-chain bridge commands (quote, execute, status, routes)
    #[command(subcommand)]
    Bridge(BridgeCommand),

    /// deBridge cross-chain operations (search tokens, create tx, swap)
    #[command(subcommand)]
    Debridge(DebridgeCommand),

    /// LI.FI cross-chain aggregator (chains, tokens, routes, quotes, status)
    #[command(subcommand)]
    Lifi(LifiCommand),

    /// NFT collection and token commands (ERC-721/1155)
    #[command(subcommand)]
    Nft(NftCommand),

    /// ERC-3643 compliance commands (KYC, accreditation, freeze)
    #[command(subcommand)]
    Compliance(ComplianceCommand),

    /// ERC-7802 cross-chain token commands (mint/burn via authorized bridges)
    #[command(subcommand)]
    Crosschain(CrosschainCommand),

    /// Event streaming commands (subscribe, history, webhooks)
    #[command(subcommand)]
    Events(EventsCommand),

    /// Cryptographic operations (sign, verify, encrypt, decrypt, hash, keygen)
    #[command(subcommand)]
    Crypto(CryptoCommand),

    /// TEE operations (detect, attest, verify, seal, unseal, providers)
    #[command(subcommand)]
    Tee(TeeCommand),

    /// Zero-knowledge proof operations (prove, verify, keygen, circuits)
    #[command(subcommand)]
    Zk(ZkCommand),

    /// VRF operations (prove, verify, keygen) — RFC 9381 ECVRF-EDWARDS25519-SHA512-TAI
    #[command(subcommand)]
    Vrf(VrfCommand),

    /// Cortex recurrent-depth reasoning (register, list, reason) — priced, signed, settled
    #[command(subcommand)]
    Cortex(CortexCommand),

    /// Custody & MPC wallet operations (create, export, import, rotate, limits, session)
    #[command(subcommand)]
    Custody(CustodyCommand),

    /// Application management (register, users, funding, sponsoring, stats)
    #[command(subcommand)]
    App(AppCommand),

    /// AP2 (Agent Payments Protocol): mandate verify, validate, info
    #[command(subcommand)]
    Ap2(Ap2Command),

    /// ERC-8004 Trustless Agents Registry: derive-id, encode-register, feedback, validation
    #[command(subcommand)]
    Erc8004(Erc8004Command),

    /// Wormhole cross-chain: chain-id, parse-vaa, bridge
    #[command(subcommand)]
    Wormhole(WormholeCommand),

    /// TNZO CCT (Chainlink Cross-Chain Token) pool inspection: list-pools, get-pool
    #[command(subcommand)]
    Cct(CctCommand),

    /// Tenzro Train — decentralized verifiable foundation-model training
    #[command(subcommand)]
    Train(TrainCommand),

    /// Text embeddings (Qwen3-Embedding, EmbeddingGemma, BGE-M3)
    #[command(subcommand, name = "embed-text")]
    EmbedText(EmbedTextCommand),

    /// Image segmentation (SAM 3, SAM 2, EdgeSAM, MobileSAM)
    #[command(subcommand)]
    Segment(SegmentCommand),

    /// Object detection (RF-DETR, D-FINE)
    #[command(subcommand)]
    Detect(DetectCommand),

    /// Audio transcription / ASR (Moonshine, Distil-Whisper, Parakeet, Canary)
    #[command(subcommand)]
    Transcribe(TranscribeCommand),

    /// Video embeddings (catalog scaffolding for V-JEPA / VideoMAE)
    #[command(subcommand, name = "embed-video")]
    EmbedVideo(EmbedVideoCommand),

    /// OAuth 2.1 + DPoP auth: refresh access tokens, link wallet for auth
    Auth(AuthCommand),

    /// AAP (Agent Access Protocol) — alias for `auth`. AAP is the
    /// agent-facing layering on top of OAuth 2.1 + DPoP + RAR; the
    /// underlying RPCs are the same `tenzro_*Token*` / wallet-link
    /// methods exposed by `auth`.
    #[command(name = "aap")]
    Aap(AuthCommand),

    /// ERC-8004 Trustless Agents Registry — alias for `erc8004` with
    /// the canonical short name from EIP-8004.
    #[command(subcommand, name = "8004")]
    Eip8004(Erc8004Command),

    /// x402 (Coinbase HTTP-402 micropayment protocol): list-schemes, pay
    #[command(subcommand)]
    X402(X402Command),

    /// Provider reputation: get current score
    #[command(subcommand)]
    Reputation(ReputationCommand),

    /// Pending approvals from delegated machines: list, get, decide
    #[command(subcommand)]
    Approval(ApprovalCommand),

    /// Channel-dispute inspection: status by id, list-by-channel
    #[command(subcommand)]
    Dispute(DisputeCommand),

    /// C2PA-style content provenance manifests (EU AI Act §50(2))
    #[command(subcommand)]
    Provenance(ProvenanceCommand),

    /// Interactive chat with AI models
    Chat(ChatCmd),

    /// Show hardware profile
    Hardware(HardwareCmd),

    /// Set your Tenzro username
    SetUsername(SetUsernameCmd),

    /// Request testnet TNZO tokens from faucet
    Faucet(FaucetCmd),

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

/// Request testnet TNZO tokens from the faucet
#[derive(Debug, Parser)]
struct FaucetCmd {
    /// Your wallet address (hex, e.g. 0x...)
    address: String,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

/// Interactive chat with AI models
#[derive(Debug, Parser)]
struct ChatCmd {
    /// Model ID to use
    model_id: String,

    /// Maximum tokens to generate
    #[arg(long, default_value = "512")]
    max_tokens: u32,

    /// Temperature (0.0-2.0)
    #[arg(long, default_value = "0.7")]
    temperature: f32,

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

#[tokio::main]
async fn main() -> Result<()> {
    // Check if running with no subcommand and stdout is a TTY — launch interactive mode
    if std::env::args().count() == 1 && atty::is(atty::Stream::Stdout) {
        init_logging(false)?;
        return run_interactive_mode().await;
    }

    let cli = Cli::parse();

    // Initialize logging
    init_logging(cli.verbose)?;

    // Print banner for interactive commands only when stdout is a TTY
    // This prevents banner pollution in scripts, pipelines, and automated environments
    // Also respect TENZRO_NO_BANNER=1 environment variable
    let no_banner = std::env::var("TENZRO_NO_BANNER").map(|v| v == "1").unwrap_or(false);
    if !matches!(cli.command, Command::Version(_)) && !cli.verbose && !no_banner && atty::is(atty::Stream::Stdout) {
        output::print_banner();
    }

    // Execute command
    match cli.command {
        Command::Join(cmd) => cmd.execute().await?,
        Command::Node(cmd) => cmd.execute().await?,
        Command::Wallet(cmd) => cmd.execute().await?,
        Command::Model(cmd) => cmd.execute().await?,
        Command::Stake(cmd) => cmd.execute().await?,
        Command::Governance(cmd) => cmd.execute().await?,
        Command::Provider(cmd) => cmd.execute().await?,
        Command::Schedule(cmd) => cmd.execute().await?,
        Command::Inference(cmd) => cmd.execute().await?,
        Command::Identity(cmd) => cmd.execute().await?,
        Command::Payment(cmd) => cmd.execute().await?,
        Command::Agent(cmd) => cmd.execute().await?,
        Command::Canton(cmd) => cmd.execute().await?,
        Command::Escrow(cmd) => cmd.execute().await?,
        Command::Task(cmd) => cmd.execute().await?,
        Command::Marketplace(cmd) => cmd.execute().await?,
        Command::Skill(cmd) => cmd.execute().await?,
        Command::Tool(cmd) => cmd.execute().await?,
        Command::Token(cmd) => cmd.execute().await?,
        Command::Contract(cmd) => cmd.execute().await?,
        Command::Bridge(cmd) => cmd.execute().await?,
        Command::Debridge(cmd) => cmd.execute().await?,
        Command::Lifi(cmd) => cmd.execute().await?,
        Command::Nft(cmd) => cmd.execute().await?,
        Command::Compliance(cmd) => cmd.execute().await?,
        Command::Crosschain(cmd) => cmd.execute().await?,
        Command::Events(cmd) => cmd.execute().await?,
        Command::Crypto(cmd) => cmd.execute().await?,
        Command::Tee(cmd) => cmd.execute().await?,
        Command::Zk(cmd) => cmd.execute().await?,
        Command::Vrf(cmd) => cmd.execute().await?,
        Command::Cortex(cmd) => cmd.execute().await?,
        Command::Custody(cmd) => cmd.execute().await?,
        Command::App(cmd) => cmd.execute().await?,
        Command::Ap2(cmd) => cmd.execute().await?,
        Command::Erc8004(cmd) => cmd.execute().await?,
        Command::Wormhole(cmd) => cmd.execute().await?,
        Command::Cct(cmd) => cmd.execute().await?,
        Command::Train(cmd) => cmd.execute().await?,
        Command::EmbedText(cmd) => cmd.execute().await?,
        Command::Segment(cmd) => cmd.execute().await?,
        Command::Detect(cmd) => cmd.execute().await?,
        Command::Transcribe(cmd) => cmd.execute().await?,
        Command::EmbedVideo(cmd) => cmd.execute().await?,
        Command::Auth(cmd) => cmd.execute().await?,
        Command::Aap(cmd) => cmd.execute().await?,
        Command::Eip8004(cmd) => cmd.execute().await?,
        Command::X402(cmd) => cmd.execute().await?,
        Command::Reputation(cmd) => cmd.execute().await?,
        Command::Approval(cmd) => cmd.execute().await?,
        Command::Dispute(cmd) => cmd.execute().await?,
        Command::Provenance(cmd) => cmd.execute().await?,
        Command::Faucet(cmd) => execute_faucet(cmd).await?,
        Command::Chat(cmd) => execute_chat(cmd).await?,
        Command::Hardware(cmd) => commands::hardware::execute(&cmd.format).await?,
        Command::SetUsername(cmd) => cmd.execute().await?,
        Command::Info(cmd) => execute_info(cmd).await?,
        Command::Version(cmd) => execute_version(cmd)?,
    }

    Ok(())
}

/// Initialize logging based on verbosity
fn init_logging(verbose: bool) -> Result<()> {
    let filter = if verbose {
        tracing_subscriber::EnvFilter::new("tenzro=debug,tenzro_cli=debug")
    } else {
        tracing_subscriber::EnvFilter::new("tenzro=info,tenzro_cli=info")
    };

    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer().with_target(verbose))
        .init();

    Ok(())
}

/// Execute faucet command
async fn execute_faucet(cmd: FaucetCmd) -> Result<()> {
    output::print_header("Testnet Faucet");

    let spinner = output::create_spinner("Requesting TNZO tokens...");

    let rpc = rpc::RpcClient::new(&cmd.rpc);

    let result: Result<serde_json::Value> = rpc.call("tenzro_faucet", serde_json::json!({
        "address": cmd.address
    })).await;

    spinner.finish_and_clear();

    match result {
        Ok(resp) => {
            println!();
            output::print_success("Tokens received!");
            output::print_field("Address", &cmd.address);
            if let Some(amount) = resp.get("amount").and_then(|v| v.as_str()) {
                output::print_field("Amount", &format!("{} TNZO", amount));
            } else {
                output::print_field("Amount", "100 TNZO");
            }
            if let Some(tx) = resp.get("transaction_hash").and_then(|v| v.as_str()) {
                output::print_field("Transaction", tx);
            }
            if let Some(cooldown) = resp.get("next_available").and_then(|v| v.as_str()) {
                output::print_field("Next Available", cooldown);
            }
        }
        Err(e) => output::print_error(&format!("Faucet request failed: {}", e)),
    }

    Ok(())
}

/// Execute chat command — uses local model inference with RPC fallback
async fn execute_chat(cmd: ChatCmd) -> Result<()> {
    use std::io::{self, Write};
    use std::sync::Arc;
    use tenzro_model::{ModelRuntime, HfDownloader, GenerationConfig, ChatMessage as ModelChatMessage, get_model_by_id};

    // Initialize model runtime and downloader
    let models_dir = dirs::home_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join(".tenzro")
        .join("models");
    let _ = std::fs::create_dir_all(&models_dir);

    // Initialize chat history directory
    let history_dir = dirs::home_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join(".tenzro")
        .join("chat_history");
    let _ = std::fs::create_dir_all(&history_dir);

    let runtime = Arc::new(ModelRuntime::new());
    let downloader = HfDownloader::new(models_dir);

    // Determine inference source: local model or network
    let use_local = if let Some(entry) = get_model_by_id(&cmd.model_id) {
        let gguf_path = downloader.model_path(&cmd.model_id);
        if gguf_path.exists() || gguf_path.is_symlink() {
            // Auto-load model if downloaded but not yet loaded
            if !runtime.is_loaded(&cmd.model_id) {
                let spinner = output::create_spinner(&format!("Loading {} into memory...", entry.name));
                match runtime.load_model_with_context(&cmd.model_id, &gguf_path, entry.architecture, Some(entry.context_length)).await {
                    Ok(()) => {
                        spinner.finish_and_clear();
                        output::print_success(&format!("Model {} loaded", entry.name));
                    }
                    Err(e) => {
                        spinner.finish_and_clear();
                        output::print_warning(&format!("Failed to load locally: {}. Falling back to network.", e));
                    }
                }
                runtime.is_loaded(&cmd.model_id)
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

    output::print_header(&format!("Chat with {}", cmd.model_id));
    println!();
    output::print_field("Model", &cmd.model_id);
    output::print_field("Source", source_label);
    output::print_field("Max Tokens", &cmd.max_tokens.to_string());
    output::print_field("Temperature", &format!("{:.1}", cmd.temperature));
    println!();
    output::print_info("Type '/exit' or '/quit' to end the conversation");
    output::print_info("Type '/history' to list recent sessions");
    output::print_info("Type '/load {session_id}' to load a previous session");
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
    };

    loop {
        // Print prompt
        print!("{}> {}", output::colors::CYAN, output::colors::RESET);
        io::stdout().flush()?;

        // Read user input
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
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
                .filter(|e| e.path().extension().map(|ext| ext == "json").unwrap_or(false))
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
                                if s.len() > 60 { format!("{}...", preview) } else { preview }
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
                                output::print_success(&format!("Loaded session {} ({} messages)", session_id_to_load, history.len()));
                                println!();

                                // Display conversation so far
                                for msg in &history {
                                    if let (Some(role), Some(content)) = (
                                        msg.get("role").and_then(|r| r.as_str()),
                                        msg.get("content").and_then(|c| c.as_str())
                                    ) {
                                        if role == "user" {
                                            println!("{}User:{} {}", output::colors::CYAN, output::colors::RESET, content);
                                        } else if role == "assistant" {
                                            println!("{}Assistant:{} {}", output::colors::GREEN, output::colors::RESET, content);
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

        if input.is_empty() {
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
            let mut messages = vec![
                ModelChatMessage {
                    role: "system".to_string(),
                    content: "You are a helpful assistant.".to_string(),
                },
            ];
            for msg in &history {
                let role = msg.get("role").and_then(|v| v.as_str()).unwrap_or("user").to_string();
                let content = msg.get("content").and_then(|v| v.as_str()).unwrap_or("").to_string();
                messages.push(ModelChatMessage { role, content });
            }

            match runtime.generate_chat(&cmd.model_id, &messages, &gen_config).await {
                Ok(result) => {
                    spinner.finish_and_clear();

                    println!();
                    // EU AI Act Art. 50(1): every assistant chunk is labeled
                    // as AI-generated. Local-mode chat is end-user-facing, so
                    // the disclosure shows up directly in the terminal.
                    // Use the canonical helper so the prefix string lives in
                    // exactly one place across the workspace.
                    println!("{}", tenzro_node::eu_ai_disclosure::render_cli_chat_chunk(&result.text));
                    println!();

                    output::print_field(
                        "",
                        &format!("{}[{} in, {} out tokens | {:.1} tok/s | Free (local)]{}",
                            output::colors::BOLD,
                            result.input_tokens,
                            result.output_tokens,
                            result.tokens_per_second,
                            output::colors::RESET
                        )
                    );
                    println!();

                    history.push(serde_json::json!({
                        "role": "assistant",
                        "content": result.text,
                    }));

                    // Save history to session file
                    if let Err(e) = std::fs::write(&session_file, serde_json::to_string_pretty(&history)?) {
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
                cost: String,
                #[serde(default)]
                load: Option<serde_json::Value>,
            }

            let request = serde_json::json!({
                "model_id": cmd.model_id,
                "message": input,
                "history": history,
                "max_tokens": cmd.max_tokens,
                "temperature": cmd.temperature,
            });

            let response: Result<ChatResponse> = rpc.call("tenzro_chat", request).await;

            spinner.finish_and_clear();

            match response {
                Ok(chat_response) => {
                    println!();
                    // EU AI Act Art. 50(1) — same disclosure prefix as
                    // local-mode. Network mode reaches the user through
                    // the same terminal surface, so the rule is identical.
                    println!("{}", tenzro_node::eu_ai_disclosure::render_cli_chat_chunk(&chat_response.output));
                    println!();

                    let cost_str = if chat_response.cost != "0" {
                        format!("{} TNZO", chat_response.cost)
                    } else {
                        "Free".to_string()
                    };

                    output::print_field(
                        "",
                        &format!("{}[{} in, {} out tokens | {}]{}",
                            output::colors::BOLD,
                            chat_response.input_tokens,
                            chat_response.output_tokens,
                            cost_str,
                            output::colors::RESET
                        )
                    );
                    if let Some(ref load) = chat_response.load {
                        output::print_field("", &format!("  Load: {}", output::format_load_info(load)));
                    }
                    println!();

                    history.push(serde_json::json!({
                        "role": "assistant",
                        "content": chat_response.output,
                    }));

                    // Save history to session file
                    if let Err(e) = std::fs::write(&session_file, serde_json::to_string_pretty(&history)?) {
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
    let block_number_result: Result<String> = rpc.call("eth_blockNumber", serde_json::json!([])).await;
    let chain_id_result: Result<String> = rpc.call("eth_chainId", serde_json::json!([])).await;
    let peer_count_result: Result<String> = rpc.call("net_peerCount", serde_json::json!([])).await;
    let node_info_result: Result<serde_json::Value> = rpc.call("tenzro_nodeInfo", serde_json::json!([])).await;
    let total_supply_result: Result<String> = rpc.call("tenzro_totalSupply", serde_json::json!([])).await;

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
        let finalized = match rpc.call("tenzro_getFinalizedBlock", serde_json::json!([])).await {
            Ok(val) => {
                let val: serde_json::Value = val;
                u64::from_str_radix(
                    val.as_str().unwrap_or("0x0").trim_start_matches("0x"), 16
                ).unwrap_or(block_num.saturating_sub(3))
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
        output::print_field("Rust Version", option_env!("CARGO_PKG_RUST_VERSION").unwrap_or("unknown"));
        println!();
        output::print_field("Authors", env!("CARGO_PKG_AUTHORS"));
        output::print_field("Homepage", option_env!("CARGO_PKG_HOMEPAGE").unwrap_or("https://tenzro.com"));
        output::print_field("Repository", env!("CARGO_PKG_REPOSITORY"));
        output::print_field("License", env!("CARGO_PKG_LICENSE"));
        println!();

        println!("{}Components:{}", output::colors::BOLD, output::colors::RESET);
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
    println!("  {}████████╗███████╗███╗   ██╗███████╗██████╗  ██████╗ {}", output::colors::CYAN, output::colors::RESET);
    println!("  {}╚══██╔══╝██╔════╝████╗  ██║╚══███╔╝██╔══██╗██╔═══██╗{}", output::colors::CYAN, output::colors::RESET);
    println!("  {}   ██║   █████╗  ██╔██╗ ██║  ███╔╝ ██████╔╝██║   ██║{}", output::colors::CYAN, output::colors::RESET);
    println!("  {}   ██║   ██╔══╝  ██║╚██╗██║ ███╔╝  ██╔══██╗██║   ██║{}", output::colors::CYAN, output::colors::RESET);
    println!("  {}   ██║   ███████╗██║ ╚████║███████╗██║  ██║╚██████╔╝{}", output::colors::CYAN, output::colors::RESET);
    println!("  {}   ╚═╝   ╚══════╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ╚═════╝{}", output::colors::CYAN, output::colors::RESET);
    println!();

    // Determine RPC endpoint from config or default
    let cfg = tenzro_cli::config::load_config();
    let rpc_url = cfg.endpoint.unwrap_or_else(|| "http://127.0.0.1:8545".to_string());
    let rpc = rpc::RpcClient::new(&rpc_url);

    // Show connection status
    if let Ok(info) = rpc.call::<serde_json::Value>("tenzro_nodeInfo", serde_json::json!([])).await {
        let height = info.get("block_height").and_then(|v| v.as_u64()).unwrap_or(0);
        let peers = info.get("peer_count").and_then(|v| v.as_u64()).unwrap_or(0);
        println!("  {}Connected:{} {} | Block: {} | Peers: {}", output::colors::GREEN, output::colors::RESET, rpc.url(), height, peers);
    } else {
        println!("  {}Not connected to a node{} ({})", output::colors::YELLOW, output::colors::RESET, rpc.url());
    }
    println!();

    loop {
        let categories = vec![
            "Wallet & Tokens",
            "AI Models & Inference",
            "Agents & Swarms",
            "Bridge & Cross-Chain",
            "Identity & Credentials",
            "Payments & Settlement",
            "Security (Crypto, TEE, ZK)",
            "Developer (Contracts, Skills, Tools)",
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
            2 => agents_menu(&rpc).await,
            3 => bridge_menu(&rpc).await,
            4 => identity_menu(&rpc).await,
            5 => payments_menu(&rpc).await,
            6 => security_menu(&rpc).await,
            7 => developer_menu(&rpc).await,
            8 => network_menu(&rpc).await,
            9 => break,
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
        "Create wallet",
        "Check balance",
        "Send TNZO",
        "Request faucet tokens",
        "List accounts",
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
            let result: serde_json::Value = rpc.call("tenzro_createWallet", serde_json::json!(["ed25519"])).await?;
            output::print_success("Wallet created!");
            output::print_field("Address", result.get("address").and_then(|v| v.as_str()).unwrap_or(""));
            output::print_field("Type", result.get("key_type").and_then(|v| v.as_str()).unwrap_or("ed25519"));
        }
        1 => {
            let addr: String = Input::with_theme(&ColorfulTheme::default())
                .with_prompt("Address (hex)")
                .interact_text()?;
            let result: serde_json::Value = rpc.call("eth_getBalance", serde_json::json!([addr, "latest"])).await?;
            let hex = result.as_str().unwrap_or("0x0");
            let wei = u128::from_str_radix(hex.trim_start_matches("0x"), 16).unwrap_or(0);
            println!();
            output::print_field("Balance", &rpc::format_tnzo(wei));
        }
        2 => {
            let _from: String = Input::with_theme(&ColorfulTheme::default()).with_prompt("From address").interact_text()?;
            let to: String = Input::with_theme(&ColorfulTheme::default()).with_prompt("To address").interact_text()?;
            let amount: String = Input::with_theme(&ColorfulTheme::default()).with_prompt("Amount (TNZO)").interact_text()?;
            let amount_float: f64 = amount.parse().unwrap_or(0.0);
            let amount_wei = (amount_float * 1e18) as u64;
            let tx_json = serde_json::json!({
                "to": to, "value": format!("0x{:x}", amount_wei),
                "nonce": "0x0", "gas_limit": "0x5208", "gas_price": "0x3b9aca00",
                "chain_id": "0x539", "data": "0x"
            });
            let raw_tx = format!("0x{}", hex::encode(tx_json.to_string().as_bytes()));
            let tx_hash: String = rpc.call("eth_sendRawTransaction", serde_json::json!([raw_tx])).await?;
            output::print_success("Transaction sent!");
            output::print_field("Tx Hash", &tx_hash);
        }
        3 => {
            let addr: String = Input::with_theme(&ColorfulTheme::default()).with_prompt("Address").interact_text()?;
            let result: serde_json::Value = rpc.call("tenzro_faucet", serde_json::json!({ "address": addr })).await?;
            output::print_success("Tokens received!");
            output::print_field("Amount", result.get("amount").and_then(|v| v.as_str()).unwrap_or("100 TNZO"));
        }
        4 => {
            let accounts: Vec<serde_json::Value> = rpc.call("tenzro_listAccounts", serde_json::json!([])).await.unwrap_or_default();
            if accounts.is_empty() {
                output::print_info("No accounts found.");
            } else {
                for a in &accounts {
                    output::print_field(
                        a.get("address").and_then(|v| v.as_str()).unwrap_or("?"),
                        a.get("balance").and_then(|v| v.as_str()).unwrap_or(""),
                    );
                }
            }
        }
        5 => {
            let addr: String = Input::with_theme(&ColorfulTheme::default()).with_prompt("Address").interact_text()?;
            let result: serde_json::Value = rpc.call("tenzro_getTransactionHistory", serde_json::json!({ "address": addr, "limit": 10 })).await?;
            if let Some(txs) = result.get("transactions").and_then(|v| v.as_array()) {
                for tx in txs {
                    let hash = tx.get("hash").and_then(|v| v.as_str()).unwrap_or("?");
                    let value = tx.get("value").and_then(|v| v.as_str()).unwrap_or("0");
                    println!("  {} -> {}", &hash[..18.min(hash.len())], value);
                }
            } else { output::print_info("No transactions found."); }
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
            let result: serde_json::Value = rpc.call("tenzro_listModels", serde_json::json!({})).await?;
            if let Some(models) = result.as_array() {
                let headers = vec!["Model ID", "Name", "Status"];
                let mut rows = Vec::new();
                for m in models {
                    rows.push(vec![
                        m.get("model_id").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                        m.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                        m.get("status").and_then(|v| v.as_str()).unwrap_or("available").to_string(),
                    ]);
                }
                output::print_table(&headers, &rows);
            } else { output::print_json(&result)?; }
        }
        1 => {
            let model_id: String = Input::with_theme(&ColorfulTheme::default()).with_prompt("Model ID").interact_text()?;
            let message: String = Input::with_theme(&ColorfulTheme::default()).with_prompt("Message").interact_text()?;
            let result: serde_json::Value = rpc.call("tenzro_chat", serde_json::json!({
                "model_id": model_id, "message": message, "history": [], "max_tokens": 512, "temperature": 0.7,
            })).await?;
            if let Some(output_text) = result.get("output").and_then(|v| v.as_str()) {
                println!();
                // EU AI Act Art. 50(1) — match the chat REPL's prefix.
                println!("{}", tenzro_node::eu_ai_disclosure::render_cli_chat_chunk(output_text));
            } else { output::print_json(&result)?; }
        }
        2 => {
            let model_id: String = Input::with_theme(&ColorfulTheme::default()).with_prompt("Model ID to download").interact_text()?;
            let result: serde_json::Value = rpc.call("tenzro_downloadModel", serde_json::json!([{ "model_id": model_id }])).await?;
            output::print_field("Status", result.get("status").and_then(|v| v.as_str()).unwrap_or("requested"));
        }
        3 => {
            let endpoints: Vec<serde_json::Value> = rpc.call("tenzro_listModelEndpoints", serde_json::json!([])).await.unwrap_or_default();
            if endpoints.is_empty() { output::print_info("No endpoints registered."); }
            else {
                for ep in &endpoints {
                    output::print_field(
                        ep.get("model_name").and_then(|v| v.as_str()).unwrap_or("?"),
                        ep.get("api_endpoint").and_then(|v| v.as_str()).unwrap_or(""),
                    );
                }
            }
        }
        4 => {
            let result: serde_json::Value = rpc.call("tenzro_discoverModels", serde_json::json!({ "limit": 10 })).await?;
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

async fn agents_menu(rpc: &rpc::RpcClient) -> Result<()> {
    let options = vec![
        "Register an agent",
        "List agents",
        "Send message to agent",
        "Discover agents",
        "Create a swarm",
        "<- Back",
    ];
    let sel = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Agents & Swarms")
        .items(&options)
        .default(0)
        .interact()?;
    match sel {
        0 => {
            let name: String = Input::with_theme(&ColorfulTheme::default()).with_prompt("Agent name").interact_text()?;
            let creator: String = Input::with_theme(&ColorfulTheme::default()).with_prompt("Creator address").interact_text()?;
            let result: serde_json::Value = rpc.call("tenzro_registerAgent", serde_json::json!({
                "name": name, "creator": creator, "capabilities": ["general"],
            })).await?;
            output::print_success("Agent registered!");
            output::print_field("Agent ID", result.get("agent_id").and_then(|v| v.as_str()).unwrap_or(""));
        }
        1 => {
            let agents: Vec<serde_json::Value> = rpc.call("tenzro_listAgents", serde_json::json!([])).await.unwrap_or_default();
            if agents.is_empty() { output::print_info("No agents registered."); }
            else {
                let headers = vec!["Agent ID", "Name", "Status"];
                let mut rows = Vec::new();
                for a in &agents {
                    rows.push(vec![
                        a.get("agent_id").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                        a.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                        a.get("status").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                    ]);
                }
                output::print_table(&headers, &rows);
            }
        }
        2 => {
            let from: String = Input::with_theme(&ColorfulTheme::default()).with_prompt("From agent ID").interact_text()?;
            let to: String = Input::with_theme(&ColorfulTheme::default()).with_prompt("To agent ID").interact_text()?;
            let msg: String = Input::with_theme(&ColorfulTheme::default()).with_prompt("Message").interact_text()?;
            let result: serde_json::Value = rpc.call("tenzro_sendAgentMessage", serde_json::json!({
                "from": from, "to": to, "message": msg,
            })).await?;
            output::print_success("Message sent!");
            output::print_field("Message ID", result.get("message_id").and_then(|v| v.as_str()).unwrap_or(""));
        }
        3 => {
            let result: serde_json::Value = rpc.call("tenzro_discoverAgents", serde_json::json!({ "limit": 10 })).await?;
            if let Some(agents) = result.as_array() {
                for a in agents {
                    output::print_field(
                        a.get("agent_id").and_then(|v| v.as_str()).unwrap_or("?"),
                        a.get("name").and_then(|v| v.as_str()).unwrap_or(""),
                    );
                }
            }
        }
        4 => {
            let orch: String = Input::with_theme(&ColorfulTheme::default()).with_prompt("Orchestrator agent ID").interact_text()?;
            let result: serde_json::Value = rpc.call("tenzro_createSwarm", serde_json::json!([{
                "orchestrator_id": orch, "members": [],
            }])).await?;
            output::print_success("Swarm created!");
            output::print_field("Swarm ID", result.get("swarm_id").and_then(|v| v.as_str()).unwrap_or(""));
        }
        _ => {}
    }
    Ok(())
}

async fn bridge_menu(rpc: &rpc::RpcClient) -> Result<()> {
    let options = vec![
        "Get bridge quote",
        "Execute bridge transfer",
        "Check transfer status",
        "List bridge routes",
        "<- Back",
    ];
    let sel = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Bridge & Cross-Chain")
        .items(&options)
        .default(0)
        .interact()?;
    match sel {
        0 => {
            let from: String = Input::with_theme(&ColorfulTheme::default()).with_prompt("From chain").interact_text()?;
            let to: String = Input::with_theme(&ColorfulTheme::default()).with_prompt("To chain").interact_text()?;
            let token: String = Input::with_theme(&ColorfulTheme::default()).with_prompt("Token").interact_text()?;
            let amount: String = Input::with_theme(&ColorfulTheme::default()).with_prompt("Amount").interact_text()?;
            let result: serde_json::Value = rpc.call("tenzro_bridgeQuote", serde_json::json!({
                "from_chain": from, "to_chain": to, "token": token, "amount": amount,
            })).await?;
            output::print_field("Estimated Output", result.get("estimated_output").and_then(|v| v.as_str()).unwrap_or("N/A"));
            output::print_field("Fee", result.get("fee").and_then(|v| v.as_str()).unwrap_or("N/A"));
        }
        1..=3 => {
            output::print_info("Use the full CLI for this operation: tenzro bridge execute/status/routes");
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
            let name: String = Input::with_theme(&ColorfulTheme::default()).with_prompt("Display name").interact_text()?;
            let result: serde_json::Value = rpc.call("tenzro_registerIdentity", serde_json::json!([{
                "display_name": name, "identity_type": "human",
            }])).await?;
            output::print_success("Identity registered!");
            output::print_field("DID", result.get("did").and_then(|v| v.as_str()).unwrap_or(""));
        }
        1 => {
            let did: String = Input::with_theme(&ColorfulTheme::default()).with_prompt("DID to resolve").interact_text()?;
            let result: serde_json::Value = rpc.call("tenzro_resolveIdentity", serde_json::json!([did])).await?;
            if let Some(name) = result.get("display_name").and_then(|v| v.as_str()) { output::print_field("Name", name); }
            if let Some(t) = result.get("identity_type").and_then(|v| v.as_str()) { output::print_field("Type", t); }
            if let Some(s) = result.get("status").and_then(|v| v.as_str()) { output::print_field("Status", s); }
        }
        2 => {
            let ids: Vec<serde_json::Value> = rpc.call("tenzro_listIdentities", serde_json::json!([{}])).await.unwrap_or_default();
            if ids.is_empty() { output::print_info("No identities found."); }
            else {
                for id in &ids {
                    output::print_field(
                        id.get("did").and_then(|v| v.as_str()).unwrap_or("?"),
                        id.get("display_name").and_then(|v| v.as_str()).unwrap_or(""),
                    );
                }
            }
        }
        3 => {
            output::print_info("Use the full CLI: tenzro identity set-delegation <DID> --max-tx-value <V>");
        }
        _ => {}
    }
    Ok(())
}

async fn payments_menu(rpc: &rpc::RpcClient) -> Result<()> {
    let options = vec![
        "Create payment challenge",
        "Pay for a resource",
        "List payment sessions",
        "Payment gateway info",
        "<- Back",
    ];
    let sel = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Payments & Settlement")
        .items(&options)
        .default(0)
        .interact()?;
    match sel {
        0 => {
            let resource: String = Input::with_theme(&ColorfulTheme::default()).with_prompt("Resource URI").interact_text()?;
            let amount: String = Input::with_theme(&ColorfulTheme::default()).with_prompt("Amount").interact_text()?;
            let result: serde_json::Value = rpc.call("tenzro_createPaymentChallenge", serde_json::json!([{
                "resource": resource, "amount": amount.parse::<u64>().unwrap_or(0), "asset": "USDC", "protocol": "mpp",
            }])).await?;
            output::print_success("Challenge created!");
            output::print_field("Challenge ID", result.get("challenge_id").and_then(|v| v.as_str()).unwrap_or(""));
        }
        1 => {
            let url: String = Input::with_theme(&ColorfulTheme::default()).with_prompt("Resource URL").interact_text()?;
            let result: serde_json::Value = rpc.call("tenzro_payMpp", serde_json::json!([{ "url": url }])).await?;
            output::print_success("Payment successful!");
            output::print_field("Receipt", result.get("receipt_id").and_then(|v| v.as_str()).unwrap_or(""));
        }
        2 => {
            let sessions: Vec<serde_json::Value> = rpc.call("tenzro_listPaymentSessions", serde_json::json!([{}])).await.unwrap_or_default();
            if sessions.is_empty() { output::print_info("No sessions."); }
            else {
                for s in &sessions {
                    output::print_field(
                        s.get("session_id").and_then(|v| v.as_str()).unwrap_or("?"),
                        s.get("status").and_then(|v| v.as_str()).unwrap_or(""),
                    );
                }
            }
        }
        3 => {
            let info: serde_json::Value = rpc.call("tenzro_paymentGatewayInfo", serde_json::json!([])).await?;
            output::print_field("Status", info.get("status").and_then(|v| v.as_str()).unwrap_or("active"));
            output::print_info("Protocols: MPP, x402, Direct");
        }
        _ => {}
    }
    Ok(())
}

async fn security_menu(rpc: &rpc::RpcClient) -> Result<()> {
    let options = vec![
        "Generate keypair",
        "Sign message",
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
            let key_type = Select::with_theme(&ColorfulTheme::default())
                .with_prompt("Key type")
                .items(&["ed25519", "secp256k1"])
                .default(0)
                .interact()?;
            let kt = if key_type == 0 { "ed25519" } else { "secp256k1" };
            let result: serde_json::Value = rpc.call("tenzro_generateKeypair", serde_json::json!({ "key_type": kt })).await?;
            output::print_success(&format!("{} keypair generated!", kt));
            output::print_field("Public Key", result.get("public_key").and_then(|v| v.as_str()).unwrap_or(""));
            output::print_field("Address", result.get("address").and_then(|v| v.as_str()).unwrap_or(""));
        }
        1 | 2 => {
            output::print_info("Use the full CLI: tenzro crypto sign/verify");
        }
        3 => {
            let result: serde_json::Value = rpc.call("tenzro_detectTee", serde_json::json!([])).await?;
            let available = result.get("available").and_then(|v| v.as_bool()).unwrap_or(false);
            if available {
                output::print_success("TEE hardware detected!");
                output::print_field("Provider", result.get("provider").and_then(|v| v.as_str()).unwrap_or("unknown"));
            } else {
                output::print_info("No TEE hardware detected. Simulation mode available.");
            }
        }
        4 => {
            output::print_info("Use the full CLI: tenzro zk prove --circuit <name> --inputs <json>");
        }
        _ => {}
    }
    Ok(())
}

async fn developer_menu(rpc: &rpc::RpcClient) -> Result<()> {
    let options = vec![
        "Deploy contract",
        "List skills",
        "List tools",
        "Task marketplace",
        "Register a skill",
        "<- Back",
    ];
    let sel = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Developer")
        .items(&options)
        .default(0)
        .interact()?;
    match sel {
        0 => {
            output::print_info("Use the full CLI: tenzro contract deploy --vm evm --bytecode <hex> --deployer <addr>");
        }
        1 => {
            let result: serde_json::Value = rpc.call("tenzro_listSkills", serde_json::json!([{ "limit": 10 }])).await?;
            if let Some(skills) = result.as_array() {
                for s in skills {
                    output::print_field(
                        s.get("skill_id").and_then(|v| v.as_str()).unwrap_or("?"),
                        s.get("name").and_then(|v| v.as_str()).unwrap_or(""),
                    );
                }
                if skills.is_empty() { output::print_info("No skills registered."); }
            }
        }
        2 => {
            let result: serde_json::Value = rpc.call("tenzro_listTools", serde_json::json!([{ "limit": 10 }])).await?;
            if let Some(tools) = result.as_array() {
                for t in tools {
                    output::print_field(
                        t.get("tool_id").and_then(|v| v.as_str()).unwrap_or("?"),
                        t.get("name").and_then(|v| v.as_str()).unwrap_or(""),
                    );
                }
                if tools.is_empty() { output::print_info("No tools registered."); }
            }
        }
        3 => {
            let result: serde_json::Value = rpc.call("tenzro_listTasks", serde_json::json!([{ "limit": 10 }])).await?;
            if let Some(tasks) = result.as_array() {
                for t in tasks {
                    output::print_field(
                        t.get("title").and_then(|v| v.as_str()).unwrap_or("?"),
                        t.get("status").and_then(|v| v.as_str()).unwrap_or(""),
                    );
                }
                if tasks.is_empty() { output::print_info("No tasks in marketplace."); }
            }
        }
        4 => {
            output::print_info("Use the full CLI: tenzro skill register --name <name> --description <desc> --capabilities <caps>");
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
            let info: serde_json::Value = rpc.call("tenzro_nodeInfo", serde_json::json!([])).await?;
            output::print_success("Node is running");
            if let Some(v) = info.get("role").and_then(|v| v.as_str()) { output::print_field("Role", v); }
            if let Some(v) = info.get("version").and_then(|v| v.as_str()) { output::print_field("Version", v); }
            if let Some(v) = info.get("block_height").and_then(|v| v.as_u64()) { output::print_field("Block", &v.to_string()); }
            if let Some(v) = info.get("peer_count").and_then(|v| v.as_u64()) { output::print_field("Peers", &v.to_string()); }
        }
        1 => {
            let block: String = rpc.call("eth_blockNumber", serde_json::json!([])).await?;
            let chain_id: String = rpc.call("eth_chainId", serde_json::json!([])).await.unwrap_or_else(|_| "0x539".to_string());
            output::print_field("Block", &rpc::parse_hex_u64(&block).to_string());
            output::print_field("Chain ID", &rpc::parse_hex_u64(&chain_id).to_string());
        }
        2 => {
            let proposals: Vec<serde_json::Value> = rpc.call("tenzro_listProposals", serde_json::json!([{}])).await.unwrap_or_default();
            if proposals.is_empty() { output::print_info("No proposals."); }
            else {
                for p in &proposals {
                    output::print_field(
                        p.get("title").and_then(|v| v.as_str()).unwrap_or("?"),
                        p.get("status").and_then(|v| v.as_str()).unwrap_or(""),
                    );
                }
            }
        }
        3 => {
            output::print_info("Use the full CLI: tenzro stake deposit/info");
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
}
