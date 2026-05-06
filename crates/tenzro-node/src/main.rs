//! Tenzro Network Node - Full node binary

use clap::Parser;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::broadcast;
use tracing::{error, info, warn, Level};
use tracing_subscriber::EnvFilter;

use tenzro_node::config::{NodeConfig, GenesisConfig};
use tenzro_node::error::{self, Result};
use tenzro_node::node::TenzroNode;
use tenzro_node::rpc::RpcServer;
use tenzro_node::{a2a, event_loop, genesis, mcp, spending_policy_bridge, spt_ceiling_bridge, web};
use tenzro_storage::KvStore;

/// Tenzro Network Node CLI
#[derive(Parser, Debug)]
#[command(name = "tenzro-node")]
#[command(about = "Tenzro Network Full Node", long_about = None)]
#[command(version)]
struct Cli {
    /// Path to configuration file
    #[arg(short, long, value_name = "FILE")]
    config: Option<PathBuf>,

    /// Data directory
    #[arg(short, long, value_name = "DIR")]
    data_dir: Option<PathBuf>,

    /// Node role (validator, model-provider, tee-provider, user)
    #[arg(short, long, value_name = "ROLE")]
    role: Option<String>,

    /// Network listen address
    #[arg(short, long, value_name = "ADDR")]
    listen_addr: Option<String>,

    /// Bootstrap nodes (comma-separated multiaddrs)
    #[arg(short, long, value_name = "NODES")]
    boot_nodes: Option<String>,

    /// Log level (trace, debug, info, warn, error)
    #[arg(long, value_name = "LEVEL", default_value = "info")]
    log_level: String,

    /// Log format: "text" for human-readable, "json" for structured JSON
    #[arg(long, value_name = "FORMAT", default_value = "text")]
    log_format: String,

    /// RPC listen address
    #[arg(long, value_name = "ADDR", default_value = "127.0.0.1:8545")]
    rpc_addr: String,

    /// Web API listen address
    #[arg(long, value_name = "ADDR", default_value = "0.0.0.0:8080")]
    web_addr: String,

    /// Path to genesis configuration file
    #[arg(short, long, value_name = "FILE")]
    genesis: Option<PathBuf>,

    /// MCP server listen address
    #[arg(long, value_name = "ADDR", default_value = "0.0.0.0:3001")]
    mcp_addr: String,

    /// A2A protocol server listen address
    #[arg(long, value_name = "ADDR", default_value = "0.0.0.0:3002")]
    a2a_addr: String,

    /// Solana MCP server listen address
    #[arg(long, value_name = "ADDR", default_value = "0.0.0.0:3003")]
    solana_mcp_addr: String,

    /// Ethereum MCP server listen address
    #[arg(long, value_name = "ADDR", default_value = "0.0.0.0:3004")]
    ethereum_mcp_addr: String,

    /// Canton MCP server listen address
    #[arg(long, value_name = "ADDR", default_value = "0.0.0.0:3005")]
    canton_mcp_addr: String,

    /// LayerZero MCP server listen address
    #[arg(long, value_name = "ADDR", default_value = "0.0.0.0:3006")]
    layerzero_mcp_addr: String,

    /// Chainlink MCP server listen address
    #[arg(long, value_name = "ADDR", default_value = "0.0.0.0:3007")]
    chainlink_mcp_addr: String,

    /// LI.FI MCP server listen address
    #[arg(long, value_name = "ADDR", default_value = "0.0.0.0:3008")]
    lifi_mcp_addr: String,

    /// External (publicly-routable) RPC endpoint URL advertised to peers.
    /// Used in gossiped model registrations so other nodes can dial this
    /// service from outside its local network (bypasses the non-routable
    /// bind address like `0.0.0.0:8545`).
    /// Example: `--external-rpc-addr https://rpc.tenzro.network`
    #[arg(long, value_name = "URL")]
    external_rpc_addr: Option<String>,

    /// External (publicly-routable) MCP endpoint URL advertised to peers.
    /// Used in gossiped model registrations so other nodes can dial the
    /// MCP server from outside its local network.
    /// Example: `--external-mcp-addr https://mcp.tenzro.network/mcp`
    #[arg(long, value_name = "URL")]
    external_mcp_addr: Option<String>,
}

#[tokio::main(worker_threads = 2)]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    init_logging(&cli.log_level, &cli.log_format)?;

    // Install aws-lc-rs as the process-wide rustls CryptoProvider before any
    // TLS-using subsystem (reqwest, axum-rustls, libp2p TLS, hyper-rustls)
    // touches rustls. aws-lc-rs is the only mainstream rustls provider that
    // ships X25519MLKEM768 hybrid post-quantum key exchange (per the FIPS 203
    // ML-KEM-768 / IETF hybrid named-group spec).
    //
    // `install_default` returns `Err(_)` if a provider was already installed
    // earlier in the process. That is harmless for us — it means another
    // crate raced ahead and installed the same `aws-lc-rs` provider via its
    // own static init (we pin the same backend everywhere via
    // `default-features = false, features = ["aws-lc-rs"]`). We log the
    // outcome but do not fail node startup on it.
    match rustls::crypto::aws_lc_rs::default_provider().install_default() {
        Ok(()) => info!("Installed aws-lc-rs as rustls CryptoProvider (PQ-hybrid TLS enabled)"),
        Err(_) => tracing::debug!(
            "aws-lc-rs CryptoProvider was already installed by an earlier static init; \
             continuing"
        ),
    }

    // Print startup banner (skip in JSON log mode to avoid polluting structured output)
    if cli.log_format != "json" {
        print_banner();
    }

    // Load or create configuration
    let mut config = load_config(&cli)?;

    // Apply CLI overrides
    apply_cli_overrides(&mut config, &cli)?;

    // Validate configuration
    config.validate()?;

    // Print node info
    if cli.log_format != "json" {
        print_node_info(&config);
    } else {
        info!(
            role = ?config.role,
            data_dir = ?config.data_dir,
            rpc_addr = %config.rpc_addr,
            web_addr = %config.web_addr,
            mcp_addr = %config.mcp_addr,
            a2a_addr = %config.a2a_addr,
            solana_mcp = %config.solana_mcp_addr,
            ethereum_mcp = %config.ethereum_mcp_addr,
            canton_mcp = %config.canton_mcp_addr,
            layerzero_mcp = %config.layerzero_mcp_addr,
            chainlink_mcp = %config.chainlink_mcp_addr,
            lifi_mcp = %config.lifi_mcp_addr,
            "Node configuration loaded"
        );
    }

    // Create shutdown broadcast channel — all subsystems subscribe to this
    let (shutdown_tx, _) = broadcast::channel::<()>(1);

    // Create and start the node
    let mut node = TenzroNode::new(config.clone()).await?;
    node.start().await?;

    // Construct the Stripe SPT ceiling-resolver cache adapter once (if a
    // Stripe API key is configured) and register a typed handle on the
    // node BEFORE the Arc wrap. The same adapter Arc is later cloned
    // into the IdentityPaymentBinder as a `dyn SptCeilingResolver` and
    // also reachable via `node.spt_ceiling_cache()` for the SPT
    // revocation dispatcher's invalidate path. Constructing once,
    // sharing via Arc, guarantees the binder read path and the
    // dispatcher invalidate path see the same cache state.
    let spt_ceiling_cache: Option<
        std::sync::Arc<spt_ceiling_bridge::SptCeilingResolverAdapter>,
    > = config
        .payments
        .stripe_api_key
        .as_ref()
        .filter(|k| !k.trim().is_empty())
        .map(|api_key| {
            let mut stripe = tenzro_payments::mpp::StripeClient::new(api_key.clone());
            if let Some(api_base) = config
                .payments
                .stripe_api_base
                .as_ref()
                .filter(|b| !b.trim().is_empty())
            {
                stripe = stripe.with_api_base(api_base.clone());
            }
            std::sync::Arc::new(spt_ceiling_bridge::SptCeilingResolverAdapter::new(
                std::sync::Arc::new(stripe),
            ))
        });
    if let Some(ref cache) = spt_ceiling_cache {
        node.set_spt_ceiling_cache(cache.clone());
        tracing::info!("Stripe SPT ceiling-resolver cache registered on TenzroNode");
    }

    // Start RPC server
    let node_arc = Arc::new(node);
    let mut rpc_server = RpcServer::new(node_arc.clone(), config.rpc_addr.clone());

    // Wire HTTP 402 payment gate into RPC server for /v1/chat/completions
    // when payments are enabled. Uses the same gateway + challenge store as
    // the Web API so challenges are interchangeable between the two servers.
    // Build the optional identity binder for payer validation in HTTP 402 middleware.
    // When available, this validates that the payer's DID is active and that the
    // payment amount/protocol/chain are within the payer's delegation scope.
    let identity_binder: Option<std::sync::Arc<tenzro_payments::identity_binding::IdentityPaymentBinder>> =
        node_arc.identity_registry().map(|registry| {
            let mut binder = tenzro_payments::identity_binding::IdentityPaymentBinder::new(
                registry.clone(),
                std::sync::Arc::new(tenzro_identity::IdentityVerifier::new(registry.clone())),
            );
            // Phase C: bridge the per-machine SpendingPolicy registry on
            // AgentRuntime into the payment gate. With the resolver wired,
            // `validate_payer_for_protocol` enforces both the protocol-level
            // DelegationScope and the runtime-level SpendingPolicy on every
            // machine-DID-initiated payment.
            if let Some(agent_runtime) = node_arc.agent_runtime() {
                let resolver: std::sync::Arc<dyn tenzro_payments::SpendingPolicyResolver> =
                    std::sync::Arc::new(
                        spending_policy_bridge::AgentRuntimeSpendingPolicyResolver::new(
                            agent_runtime.clone(),
                        ),
                    );
                binder = binder.with_spending_policy_resolver(resolver);
            }
            // Phase D (Stripe SPT): consume the shared
            // `spt_ceiling_cache` Arc constructed and registered on the
            // node above. Reusing the same adapter Arc as the binder's
            // resolver and the dispatcher's invalidate handle is the
            // whole point — it guarantees cache state stays in lockstep
            // between payment-admission reads and revocation invalidates.
            // The four-ceiling enforcement path (`validate_payer_with_spt`)
            // consults the resolver to verify a granted-token is Active
            // and within `usage_limits` before admitting the payment.
            // Cache-first reads with `Ok(None)` fallback semantics — see
            // `spt_ceiling_bridge` module docs.
            if let Some(cache) = spt_ceiling_cache.clone() {
                let spt_resolver: std::sync::Arc<
                    dyn tenzro_payments::mpp::stripe_spt::SptCeilingResolver,
                > = cache;
                binder = binder.with_spt_ceiling_resolver(spt_resolver);
                tracing::info!("Stripe SPT ceiling resolver wired into IdentityPaymentBinder");
            }
            std::sync::Arc::new(binder)
        });

    if config.payments.enabled
        && let Some(gateway) = node_arc.payment_gateway() {
            let mut rpc_gate = tenzro_payments::middleware::PaymentGateMiddleware::new(
                gateway.clone(),
                tenzro_payments::middleware::PaymentGateConfig {
                    default_amount: config.payments.default_amount,
                    default_asset: config.payments.default_asset.clone(),
                    recipient: config.payments.recipient.clone(),
                    default_protocol: config.payments.default_protocol.clone(),
                },
                gateway.challenge_store(),
            );
            if let Some(ref binder) = identity_binder {
                rpc_gate = rpc_gate.with_identity_binder(binder.clone());
            }
            info!("HTTP 402 payment gate enabled for RPC /v1/chat/completions");
            rpc_server = rpc_server.with_payment_gate(rpc_gate);
        }

    // Spawn RPC server with graceful shutdown
    let rpc_shutdown_rx = shutdown_tx.subscribe();
    let mut rpc_handle = tokio::spawn(async move {
        if let Err(e) = rpc_server.start_with_shutdown(rpc_shutdown_rx).await {
            error!("RPC server error: {}", e);
        }
    });

    // Start Web Verification API
    let mut web_state = web::handlers::WebState::new()
        .with_node(node_arc.clone())
        .with_metrics((**node_arc.metrics()).clone());

    // If the P2P layer is initialised, wire its shared Prometheus registry
    // so the 15 `tenzro_network_*` metrics (gossipsub, dial rate limits,
    // peer counts, connection totals) are served from the same `/metrics`
    // endpoint as the node-level counters.
    if let Some(network) = node_arc.network() {
        web_state = web_state.with_network_metrics_registry(network.metrics_registry());
    }

    // Wire faucet if configured. The faucet's source address is the
    // runtime-provisioned signing-key address (see `provision_faucet_signing_key`
    // in `genesis.rs`), NOT the legacy sentinel `faucet.address` from the TOML.
    // The migration moves all balance from the legacy sentinel to the
    // keypair-derived address; the web `/faucet` endpoint must transfer
    // from the same address that holds the funds.
    if let Some(ref genesis) = config.genesis
        && let Some(ref faucet) = genesis.faucet
            && faucet.enabled {
                let runtime_faucet_address = node_arc
                    .storage()
                    .and_then(|s| s.get("metadata", genesis::FAUCET_SIGNING_KEY_ADDRESS).ok().flatten())
                    .and_then(|bytes| String::from_utf8(bytes).ok())
                    .map(|hex| format!("0x{}", hex))
                    .unwrap_or_else(|| {
                        warn!(
                            "Faucet signing-key address not found in CF_METADATA; \
                             falling back to legacy sentinel {}. /faucet will fail \
                             until provision_faucet_signing_key() runs.",
                            faucet.address
                        );
                        faucet.address.clone()
                    });
                web_state = web_state.with_faucet(
                    runtime_faucet_address,
                    faucet.amount_per_request,
                    faucet.cooldown_seconds,
                );
            }

    // Wire event sender if available
    if let Some(event_sender) = node_arc.event_sender() {
        web_state = web_state.with_event_sender(event_sender.clone());
    }

    // Wire the inference router so the `/chat` endpoint can route
    // OpenAI-compatible chat-completion requests to the correct
    // model provider. Without this, `/chat` returns
    // "no inference router configured".
    if let Some(router) = node_arc.inference_router() {
        web_state = web_state.with_inference_router(router.clone());
    }

    // Share web_state as Arc for both web server and MCP server
    let web_state = Arc::new(web_state);

    // Build the web server, optionally wiring the HTTP 402 payment gate.
    // The gate is constructed from `config.payments` together with the
    // `TenzroPaymentGateway` that the node already initialised in
    // `init_payments()`. Both share the same `ChallengeStore`, so a
    // challenge created by the middleware is later visible to the
    // gateway during verify-and-settle.
    let mut web_server = web::WebServer::new(config.web_addr.clone())
        .with_state_arc(web_state.clone());

    if config.payments.enabled {
        if let Some(gateway) = node_arc.payment_gateway() {
            let mut middleware = tenzro_payments::middleware::PaymentGateMiddleware::new(
                gateway.clone(),
                tenzro_payments::middleware::PaymentGateConfig {
                    default_amount: config.payments.default_amount,
                    default_asset: config.payments.default_asset.clone(),
                    recipient: config.payments.recipient.clone(),
                    default_protocol: config.payments.default_protocol.clone(),
                },
                gateway.challenge_store(),
            );
            if let Some(ref binder) = identity_binder {
                middleware = middleware.with_identity_binder(binder.clone());
            }
            let setup = web::server::PaymentGateSetup::new(
                middleware,
                config.payments.paid_routes.clone(),
            );
            info!(
                routes = ?config.payments.paid_routes,
                protocol = %config.payments.default_protocol,
                amount = %config.payments.default_amount,
                asset = %config.payments.default_asset,
                "HTTP 402 payment gate enabled for Web API",
            );
            web_server = web_server.with_payment_gate(setup);
        } else {
            tracing::warn!(
                "payments.enabled = true but TenzroPaymentGateway not initialised; \
                 HTTP 402 middleware will not be wired"
            );
        }
    }

    let web_shutdown_rx = shutdown_tx.subscribe();
    let mut web_handle = tokio::spawn(async move {
        if let Err(e) = web_server.start_with_shutdown(web_shutdown_rx).await {
            error!("Web server error: {}", e);
        }
    });

    // Start MCP server
    let mcp_addr = config.mcp_addr.clone();
    let mcp_node = node_arc.clone();
    let mcp_web_state = web_state.clone();
    let mut mcp_shutdown_rx = shutdown_tx.subscribe();
    let mut mcp_handle = tokio::spawn(async move {
        tokio::select! {
            result = mcp::server::start_mcp_server(mcp_addr, mcp_node, mcp_web_state) => {
                if let Err(e) = result { error!("MCP server error: {}", e); }
            }
            _ = async { let _ = mcp_shutdown_rx.recv().await; } => {
                info!("MCP server shutting down");
            }
        }
    });

    // Start A2A protocol server
    let a2a_addr = config.a2a_addr.clone();
    let a2a_node = node_arc.clone();
    let a2a_web_state = web_state;
    let mut a2a_shutdown_rx = shutdown_tx.subscribe();
    let mut a2a_handle = tokio::spawn(async move {
        tokio::select! {
            result = a2a::server::start_a2a_server(a2a_addr, a2a_node, a2a_web_state) => {
                if let Err(e) = result { error!("A2A server error: {}", e); }
            }
            _ = async { let _ = a2a_shutdown_rx.recv().await; } => {
                info!("A2A server shutting down");
            }
        }
    });

    // Start ecosystem MCP servers (Solana, Ethereum, Canton, LayerZero, Chainlink)
    let solana_addr = config.solana_mcp_addr.clone();
    let mut solana_shutdown_rx = shutdown_tx.subscribe();
    tokio::spawn(async move {
        tokio::select! {
            result = mcp::solana::start_solana_mcp_server(solana_addr) => {
                if let Err(e) = result { error!("Solana MCP server error: {}", e); }
            }
            _ = async { let _ = solana_shutdown_rx.recv().await; } => {
                info!("Solana MCP server shutting down");
            }
        }
    });

    let ethereum_addr = config.ethereum_mcp_addr.clone();
    let mut ethereum_shutdown_rx = shutdown_tx.subscribe();
    tokio::spawn(async move {
        tokio::select! {
            result = mcp::ethereum::start_ethereum_mcp_server(ethereum_addr) => {
                if let Err(e) = result { error!("Ethereum MCP server error: {}", e); }
            }
            _ = async { let _ = ethereum_shutdown_rx.recv().await; } => {
                info!("Ethereum MCP server shutting down");
            }
        }
    });

    let canton_addr = config.canton_mcp_addr.clone();
    // Pass Canton participant URLs + optional JWT into the Canton MCP server so
    // its tools talk to the right Canton node instead of always hitting the
    // hard-coded `localhost:7575/7576` defaults. Ledger and admin URLs are
    // derived from `config.canton.host`/`port` (the same source `init_vm()`
    // uses to wire the DamlExecutor); JWT is read from `CANTON_JWT_TOKEN` env
    // since it's a secret and intentionally not on the on-disk config.
    let canton_ledger_api_url =
        format!("http://{}:{}", config.canton.host, config.canton.port);
    let canton_admin_api_url = format!(
        "http://{}:{}",
        config.canton.host,
        config.canton.port.saturating_add(1),
    );
    let canton_jwt_token = std::env::var("CANTON_JWT_TOKEN").ok();
    let mut canton_shutdown_rx = shutdown_tx.subscribe();
    tokio::spawn(async move {
        tokio::select! {
            result = mcp::canton::start_canton_mcp_server(
                canton_addr,
                canton_ledger_api_url,
                canton_admin_api_url,
                canton_jwt_token,
            ) => {
                if let Err(e) = result { error!("Canton MCP server error: {}", e); }
            }
            _ = async { let _ = canton_shutdown_rx.recv().await; } => {
                info!("Canton MCP server shutting down");
            }
        }
    });

    let layerzero_addr = config.layerzero_mcp_addr.clone();
    let mut layerzero_shutdown_rx = shutdown_tx.subscribe();
    tokio::spawn(async move {
        tokio::select! {
            result = mcp::layerzero::start_layerzero_mcp_server(layerzero_addr) => {
                if let Err(e) = result { error!("LayerZero MCP server error: {}", e); }
            }
            _ = async { let _ = layerzero_shutdown_rx.recv().await; } => {
                info!("LayerZero MCP server shutting down");
            }
        }
    });

    let chainlink_addr = config.chainlink_mcp_addr.clone();
    let mut chainlink_shutdown_rx = shutdown_tx.subscribe();
    tokio::spawn(async move {
        tokio::select! {
            result = mcp::chainlink::start_chainlink_mcp_server(chainlink_addr) => {
                if let Err(e) = result { error!("Chainlink MCP server error: {}", e); }
            }
            _ = async { let _ = chainlink_shutdown_rx.recv().await; } => {
                info!("Chainlink MCP server shutting down");
            }
        }
    });

    let lifi_addr = config.lifi_mcp_addr.clone();
    let mut lifi_shutdown_rx = shutdown_tx.subscribe();
    tokio::spawn(async move {
        tokio::select! {
            result = mcp::lifi::start_lifi_mcp_server(lifi_addr) => {
                if let Err(e) = result { error!("LI.FI MCP server error: {}", e); }
            }
            _ = async { let _ = lifi_shutdown_rx.recv().await; } => {
                info!("LI.FI MCP server shutting down");
            }
        }
    });

    // Wait for shutdown signal (Ctrl+C or SIGTERM)
    info!("Node is running. Press Ctrl+C to stop.");
    let shutdown_signal = async {
        let ctrl_c = tokio::signal::ctrl_c();

        #[cfg(unix)]
        {
            let mut sigterm = tokio::signal::unix::signal(
                tokio::signal::unix::SignalKind::terminate(),
            ).expect("Failed to install SIGTERM handler");
            tokio::select! {
                _ = ctrl_c => info!("Received SIGINT (Ctrl+C)"),
                _ = sigterm.recv() => info!("Received SIGTERM"),
            }
        }

        #[cfg(not(unix))]
        {
            ctrl_c.await.ok();
            info!("Received shutdown signal");
        }
    };

    tokio::select! {
        _ = shutdown_signal => {},
        result = &mut rpc_handle => {
            if let Err(e) = result { error!(error = %e, "RPC server task panicked"); }
            else { error!("RPC server terminated unexpectedly"); }
        },
        result = &mut web_handle => {
            if let Err(e) = result { error!(error = %e, "Web server task panicked"); }
            else { error!("Web server terminated unexpectedly"); }
        },
        result = &mut mcp_handle => {
            if let Err(e) = result { error!(error = %e, "MCP server task panicked"); }
            else { error!("MCP server terminated unexpectedly"); }
        },
        result = &mut a2a_handle => {
            if let Err(e) = result { error!(error = %e, "A2A server task panicked"); }
            else { error!("A2A server terminated unexpectedly"); }
        },
    }

    info!("Initiating graceful shutdown...");

    // Broadcast shutdown to all servers — they will stop accepting new connections
    // and drain in-flight requests
    let _ = shutdown_tx.send(());

    // Signal the event loop to shut down
    if let Some(event_tx) = node_arc.event_sender() {
        info!("Sending shutdown event to event loop...");
        if let Err(e) = event_tx.try_send(event_loop::NodeEvent::Shutdown) {
            error!("Failed to send shutdown event: {}", e);
        }
    }

    // Give servers a grace period to drain in-flight requests
    info!("Waiting for servers to drain (5s grace period)...");
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;

    info!("Shutdown complete");

    Ok(())
}

/// Initialize logging with the specified level and format
fn init_logging(log_level: &str, log_format: &str) -> Result<()> {
    let level = match log_level.to_lowercase().as_str() {
        "trace" => Level::TRACE,
        "debug" => Level::DEBUG,
        "info" => Level::INFO,
        "warn" => Level::WARN,
        "error" => Level::ERROR,
        _ => {
            eprintln!("Invalid log level: {}, using INFO", log_level);
            Level::INFO
        }
    };

    let filter = EnvFilter::from_default_env()
        .add_directive(level.into())
        .add_directive("tenzro_node=trace".parse().unwrap())
        .add_directive("tenzro_network=debug".parse().unwrap())
        .add_directive("tenzro_consensus=debug".parse().unwrap());

    match log_format.to_lowercase().as_str() {
        "json" => {
            // Structured JSON logging — ideal for log aggregation (Loki, ELK, Datadog)
            tracing_subscriber::fmt()
                .with_env_filter(filter)
                .with_target(true)
                .with_thread_ids(true)
                .with_line_number(true)
                .json()
                .with_span_list(true)
                .with_current_span(true)
                .init();
        }
        _ => {
            // Human-readable text logging — default for development
            tracing_subscriber::fmt()
                .with_env_filter(filter)
                .with_target(true)
                .with_thread_ids(false)
                .with_line_number(true)
                .init();
        }
    }

    Ok(())
}

/// Load configuration from file or create default
fn load_config(cli: &Cli) -> Result<NodeConfig> {
    if let Some(config_path) = &cli.config {
        info!("Loading configuration from {:?}", config_path);
        NodeConfig::load_from_file(config_path)
    } else {
        info!("No configuration file specified, using defaults");
        Ok(NodeConfig::default())
    }
}

/// Apply CLI argument overrides to configuration
fn apply_cli_overrides(config: &mut NodeConfig, cli: &Cli) -> Result<()> {
    if let Some(data_dir) = &cli.data_dir {
        config.data_dir = data_dir.clone();
    }

    if let Some(role_str) = &cli.role {
        config.role = parse_role(role_str)?;
        // Auto-create consensus config for validators if not already set
        if config.role == tenzro_types::NetworkRole::Validator && config.consensus.is_none() {
            config.consensus = Some(tenzro_consensus::ConsensusConfig::default());
        }
        // Auto-create default genesis for validators/users if not already set
        if config.genesis.is_none() {
            config.genesis = Some(GenesisConfig::default_testnet());
        }
    }

    // Merge role-specific defaults when no config file was provided
    if cli.config.is_none() {
        match config.role {
            tenzro_types::NetworkRole::Validator => {
                let defaults = NodeConfig::default_validator();
                if config.consensus.is_none() {
                    config.consensus = defaults.consensus;
                }
            }
            tenzro_types::NetworkRole::ModelProvider => {
                let defaults = NodeConfig::default_provider();
                if config.models_dir.is_none() {
                    config.models_dir = defaults.models_dir;
                }
            }
            tenzro_types::NetworkRole::TeeProvider => {
                let defaults = NodeConfig::default_tee_provider();
                if config.models_dir.is_none() {
                    config.models_dir = defaults.models_dir;
                }
                config.tee_enabled = defaults.tee_enabled;
            }
            _ => {}
        }
    }

    if let Some(listen_addr) = &cli.listen_addr {
        if let Ok(addr) = listen_addr.parse::<libp2p::Multiaddr>() {
            config.network.listen_addresses = vec![addr];
            info!("Listen address override: {}", listen_addr);
        } else {
            // Try as host:port format
            let tcp_addr = format!("/ip4/{}/tcp/{}",
                listen_addr.split(':').next().unwrap_or("0.0.0.0"),
                listen_addr.split(':').nth(1).unwrap_or("9000")
            );
            if let Ok(addr) = tcp_addr.parse::<libp2p::Multiaddr>() {
                config.network.listen_addresses = vec![addr];
                info!("Listen address override: {}", tcp_addr);
            } else {
                return Err(error::NodeError::Config(format!("Invalid listen address: {}", listen_addr)));
            }
        }
    }

    if let Some(boot_nodes) = &cli.boot_nodes {
        let mut addrs = Vec::new();
        for node_addr in boot_nodes.split(',') {
            let trimmed = node_addr.trim();
            if !trimmed.is_empty() {
                match trimmed.parse::<libp2p::Multiaddr>() {
                    Ok(addr) => addrs.push(addr),
                    Err(e) => {
                        tracing::warn!("Skipping invalid boot node address '{}': {}", trimmed, e);
                    }
                }
            }
        }
        if !addrs.is_empty() {
            config.network.boot_nodes = addrs;
            info!("Boot nodes override: {} nodes", config.network.boot_nodes.len());
        }
    }

    if let Some(genesis_path) = &cli.genesis {
        let contents = std::fs::read_to_string(genesis_path)
            .map_err(|e| error::NodeError::Config(format!("Failed to read genesis file: {}", e)))?;
        let genesis: GenesisConfig = toml::from_str(&contents)
            .map_err(|e| error::NodeError::Config(format!("Failed to parse genesis config: {}", e)))?;
        config.genesis = Some(genesis);
    }

    config.log_level = cli.log_level.clone();
    config.rpc_addr = cli.rpc_addr.clone();
    config.web_addr = cli.web_addr.clone();
    config.mcp_addr = cli.mcp_addr.clone();
    config.a2a_addr = cli.a2a_addr.clone();
    config.solana_mcp_addr = cli.solana_mcp_addr.clone();
    config.ethereum_mcp_addr = cli.ethereum_mcp_addr.clone();
    config.canton_mcp_addr = cli.canton_mcp_addr.clone();
    config.layerzero_mcp_addr = cli.layerzero_mcp_addr.clone();
    config.chainlink_mcp_addr = cli.chainlink_mcp_addr.clone();
    config.lifi_mcp_addr = cli.lifi_mcp_addr.clone();

    // External (advertised) endpoint overrides — only set when supplied on
    // the CLI so that config-file values take precedence when no flag is
    // given. `None` at this layer leaves whatever was loaded from the
    // config file unchanged.
    if cli.external_rpc_addr.is_some() {
        config.external_rpc_addr = cli.external_rpc_addr.clone();
    }
    if cli.external_mcp_addr.is_some() {
        config.external_mcp_addr = cli.external_mcp_addr.clone();
    }

    Ok(())
}

/// Parse role string
fn parse_role(role: &str) -> Result<tenzro_types::NetworkRole> {
    use tenzro_types::NetworkRole;

    match role.to_lowercase().as_str() {
        "validator" => Ok(NetworkRole::Validator),
        "model-provider" => Ok(NetworkRole::ModelProvider),
        "tee-provider" => Ok(NetworkRole::TeeProvider),
        "user" | "light-client" => Ok(NetworkRole::LightClient),
        _ => Err(error::NodeError::Config(format!("Invalid role: {}", role))),
    }
}

/// Print startup banner
fn print_banner() {
    println!(r#"
╔════════════════════════════════════════════════════════════╗
║                                                            ║
║   ████████╗███████╗███╗   ██╗███████╗██████╗  ██████╗    ║
║   ╚══██╔══╝██╔════╝████╗  ██║╚══███╔╝██╔══██╗██╔═══██╗   ║
║      ██║   █████╗  ██╔██╗ ██║  ███╔╝ ██████╔╝██║   ██║   ║
║      ██║   ██╔══╝  ██║╚██╗██║ ███╔╝  ██╔══██╗██║   ██║   ║
║      ██║   ███████╗██║ ╚████║███████╗██║  ██║╚██████╔╝   ║
║      ╚═╝   ╚══════╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ╚═════╝    ║
║                                                            ║
║        AI-Native Agentic Tokenized Settlement Layer       ║
║                      Version 0.1.0                         ║
║                                                            ║
╚════════════════════════════════════════════════════════════╝
"#);
}

/// Print node information
fn print_node_info(config: &NodeConfig) {
    println!("\n{}", "=".repeat(60));
    println!("  Node Information");
    println!("{}", "=".repeat(60));
    println!("  Role:         {:?}", config.role);
    println!("  Data Dir:     {:?}", config.data_dir);
    println!("  RPC Address:  {}", config.rpc_addr);
    println!("  Web API:      {}", config.web_addr);
    println!("  MCP Server:   {}", config.mcp_addr);
    println!("  A2A Server:   {}", config.a2a_addr);
    println!("  Solana MCP:   {}", config.solana_mcp_addr);
    println!("  Ethereum MCP: {}", config.ethereum_mcp_addr);
    println!("  Canton MCP:   {}", config.canton_mcp_addr);
    println!("  LayerZero MCP:{}", config.layerzero_mcp_addr);
    println!("  Chainlink MCP:{}", config.chainlink_mcp_addr);
    println!("  LI.FI MCP:   {}", config.lifi_mcp_addr);
    println!("  Log Level:    {}", config.log_level);
    println!("  TEE Enabled:  {}", config.tee_enabled);

    if let Some(models_dir) = &config.models_dir {
        println!("  Models Dir:   {:?}", models_dir);
    }

    println!("{}\n", "=".repeat(60));
}
