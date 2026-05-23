//! Tenzro Network Node - Full node binary

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::broadcast;
use tracing::{error, info, warn, Level};
use tracing_subscriber::EnvFilter;

use tenzro_node::config::{NodeConfig, GenesisConfig};
use tenzro_node::error::{self, Result};
use tenzro_node::node::TenzroNode;
use tenzro_node::rpc::RpcServer;
use tenzro_node::{
    a2a, event_loop, genesis, lifecycle_state_bridge, mcp, spending_policy_bridge,
    spt_ceiling_bridge, web,
};
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

    /// libp2p multiaddrs to listen on. Comma-separated.
    /// When omitted, the node listens on BOTH `/ip4/0.0.0.0/tcp/9000` and
    /// `/ip4/0.0.0.0/udp/9000/quic-v1` — the universal default that lets any
    /// device (cloud VM, home WiFi, mobile, RasPi) reach this node over
    /// whichever transport NAT permits. QUIC also gives observed_addr a
    /// stable listening UDP port (structural port-reuse) which Identify
    /// then advertises correctly to peers.
    ///
    /// Pass explicit multiaddrs to override (e.g. when binding to a specific
    /// interface, using non-standard ports, or adding WebRTC/WebTransport).
    /// Only full libp2p multiaddrs are accepted — host:port shorthand is not
    /// supported.
    #[arg(short, long, value_name = "ADDRS", value_delimiter = ',')]
    listen_addr: Vec<String>,

    /// Public libp2p multiaddrs this node advertises to peers via Identify.
    /// Comma-separated. Required on cloud deployments that bind to `0.0.0.0`,
    /// where the network layer hides raw listen-addr enumeration to avoid
    /// leaking the docker0 bridge / private VPC interfaces. Validator nodes
    /// should pass their GCE-allocated external IP here, e.g.
    /// `/ip4/34.123.45.67/tcp/9000`. Multiple entries allow advertising both
    /// TCP and QUIC. Leave unset for nodes behind NAT; AutoNAT v2 will
    /// discover an external address dynamically once that path lands.
    #[arg(long, value_name = "ADDRS")]
    external_p2p_addr: Option<String>,

    /// Bootstrap nodes (comma-separated multiaddrs)
    #[arg(short, long, value_name = "NODES")]
    boot_nodes: Option<String>,

    /// Log level (trace, debug, info, warn, error)
    #[arg(long, value_name = "LEVEL", default_value = "info")]
    log_level: String,

    /// Log format: "text" for human-readable, "json" for structured JSON
    #[arg(long, value_name = "FORMAT", default_value = "text")]
    log_format: String,

    /// RPC listen address. Defaults to `0.0.0.0:8545` so that a freshly
    /// launched validator participates in the open RPC layer alongside its
    /// consensus role. Override with `--rpc-addr 127.0.0.1:8545` for a
    /// loopback-only node (typical for provider/TEE roles operated behind
    /// a trusted controller).
    #[arg(long, value_name = "ADDR", default_value = "0.0.0.0:8545")]
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

    /// Externally-reachable UDP socket address(es) for this node's iroh QUIC
    /// endpoint, as `IP:PORT` (comma-separated for multiple). On cloud
    /// deployments that bind iroh to `0.0.0.0` this is the routable public
    /// IP plus the iroh port (default `9001`) so that the Pkarr address
    /// record published for this node carries a sockaddr peers can actually
    /// dial. Without this flag, an endpoint built on `presets::Minimal`
    /// (relay-disabled) has no way to autodiscover its public address and
    /// publishes a signed-but-empty DNS body — cross-node fetches by
    /// `EndpointId` then fail with "Unable to download" because the
    /// downloader can't resolve any reachable sockaddr.
    ///
    /// Example: `--external-iroh-addr 35.184.63.8:9001`
    ///
    /// Home / mobile / corporate-NAT nodes leave this unset and rely on the
    /// (forthcoming) iroh relay path.
    #[arg(long, value_name = "ADDRS", value_delimiter = ',')]
    external_iroh_addr: Vec<String>,

    /// State-sync bootstrap: fetch the highest snapshot from the given
    /// peer's RPC endpoint, verify chunk hashes against the manifest, and
    /// commit it to the local KV store before starting consensus. Skips
    /// block replay from genesis. Used to bring a fresh / wedged validator
    /// online quickly. The caller is responsible for verifying the
    /// snapshot's `state_root_hex` against a trusted QC out of band.
    /// Example: `--state-sync-from https://rpc.tenzro.network`
    #[arg(long, value_name = "URL")]
    state_sync_from: Option<String>,

    /// Optional subcommand. When omitted, the binary runs as a full node
    /// using the top-level flags above. Subcommands are administrative
    /// helpers that talk to a *running* node over its JSON-RPC and exit.
    #[command(subcommand)]
    command: Option<Command>,
}

/// Administrative subcommands. Each subcommand either provisions
/// local state or talks to a running node over JSON-RPC.
#[derive(Debug, Subcommand)]
enum Command {
    /// Generate the validator's three signing keys (Ed25519 +
    /// ML-DSA-65 + BLS12-381) and persist them under `--data-dir`.
    ///
    /// This is the **only** path that creates validator key
    /// material — the running node binary on `start` strictly loads
    /// existing files and errors loud if any are missing. The reason
    /// is universal in 2026 production BFT: silent daemon-side
    /// auto-keygen on a misconfigured / empty / re-mounted volume
    /// silently forks a fresh validator identity, after which any
    /// bonded stake is bonded to a dead pubkey. Aptos, Sui, Cosmos /
    /// CometBFT, Solana, Monad, Ethereum CL clients (Lighthouse /
    /// Prysm / Teku), Celestia, Babylon, and Berachain all require
    /// an explicit operator-invoked keygen step for this reason.
    ///
    /// `init` writes three files under `--data-dir`, each `0o600` on
    /// Unix: `validator_key`, `validator_pq_key`, `validator_bls_key`.
    /// It then prints the three public keys in a ready-to-paste
    /// `[[validators]]` TOML stanza suitable for genesis v3 assembly.
    ///
    /// Refuses to overwrite existing key files. Pass `--force` to
    /// rotate; doing so abandons the previous validator identity and
    /// any bonded stake, so use it deliberately.
    #[command(name = "init")]
    Init {
        /// Data directory where the three validator key files are
        /// written. Defaults to `./data` to match the node's own
        /// default `data_dir`.
        #[arg(long, value_name = "DIR", default_value = "./data")]
        data_dir: PathBuf,

        /// Genesis stake to print in the emitted `[[validators]]`
        /// stanza. Does not write anything on-chain — this is purely
        /// a convenience for the operator assembling genesis.toml.
        #[arg(long, default_value_t = 1_000_000)]
        stake: u64,

        /// Overwrite existing validator key files if present. Rotating
        /// keys this way abandons the previous validator identity and
        /// any bonded stake; use only when you know what you're doing.
        #[arg(long, default_value_t = false)]
        force: bool,

        /// Output format for the generated pubkeys. `toml` (default)
        /// emits a ready-to-paste `[[validators]]` stanza; `json`
        /// emits a machine-readable object with the three pubkey
        /// fields and their hex encodings.
        #[arg(long, value_name = "FORMAT", default_value = "toml")]
        format: String,
    },

    /// Ask the running node to step down gracefully.
    ///
    /// Calls `tenzro_gracefulExit` on the local RPC. The node waits until
    /// it is **not** the elected HotStuff-2 leader for any of the next
    /// `--lookahead-views` views, then triggers its existing shutdown
    /// path (the in-process `NodeEvent::Shutdown` plus the 5-second
    /// drain in `main()`).
    ///
    /// Intended for K8s `preStop` hooks and systemd `ExecStop=` units —
    /// a 0 exit means the node accepted the request, not that the
    /// process has already died. Wait on the process or the pod
    /// terminationGracePeriodSeconds for the actual exit.
    #[command(name = "graceful-exit")]
    GracefulExit {
        /// JSON-RPC endpoint of the running node.
        #[arg(long, value_name = "URL", default_value = "http://127.0.0.1:8545")]
        rpc_url: String,

        /// How many forward views must clear of this node being leader
        /// before stand-down. 5 covers a full HotStuff-2 round of
        /// proposer rotation under normal conditions.
        #[arg(long, default_value_t = 5)]
        lookahead_views: u64,

        /// Cap on how long to wait for leader rotation. Defaults to
        /// 60s, which comfortably exceeds typical view durations even
        /// under timeout-driven view changes.
        #[arg(long, default_value_t = 60)]
        max_wait_secs: u64,

        /// Skip the leader-clearance check entirely and trigger
        /// shutdown immediately. Use only when you know the node is
        /// not currently producing or about to produce a block.
        #[arg(long, default_value_t = false)]
        force: bool,
    },
}

#[tokio::main(worker_threads = 2)]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    init_logging(&cli.log_level, &cli.log_format)?;

    // Administrative subcommands run as one-shot RPC clients against a
    // *running* node and exit — they do not boot a node themselves.
    if let Some(cmd) = cli.command {
        return run_subcommand(cmd).await;
    }

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
    if let Some(peer) = cli.state_sync_from.clone() {
        info!(peer = %peer, "State-sync requested via --state-sync-from");
        node.set_state_sync_peer(peer);
    }
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

                // Kill-switch lifecycle gate: bridge AgentRuntime's lifecycle
                // FSM into the payment binder so Paused / Quarantined /
                // Terminated agents are refused at the payment boundary
                // (separate axis from DelegationScope + SpendingPolicy; the
                // operational `Suspended` state stays Operational here).
                let lifecycle_resolver:
                    std::sync::Arc<dyn tenzro_payments::LifecycleStateResolver> =
                    std::sync::Arc::new(
                        lifecycle_state_bridge::AgentRuntimeLifecycleResolver::new(
                            agent_runtime.clone(),
                        ),
                    );
                binder = binder.with_lifecycle_resolver(lifecycle_resolver);
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

    // Build the shared A2A state once so the HTTPS axum surface and the
    // iroh-transport surface (Phase D2, #223) operate against the **same**
    // `TaskManager` — tasks created over either transport land in the same
    // table.
    let a2a_addr = config.a2a_addr.clone();
    let a2a_state = a2a::server::build_a2a_state(&a2a_addr, node_arc.clone(), web_state);

    // Phase D2 (#223): install the iroh-side A2A dispatcher. The iroh
    // router registered the `tenzro/a2a` ALPN at bind time backed by a
    // deferred dispatcher (see `init_ai_infrastructure`); now that we
    // have the shared `Arc<A2aState>`, swap the real one in. Peers that
    // connected before this point received `-32603` "dispatcher not yet
    // bound" envelopes — after this swap they get the full A2A surface.
    if let Some(deferred) = node_arc.iroh_a2a_dispatcher.as_ref() {
        let dispatcher: Arc<dyn tenzro_iroh::JsonRpcDispatcher> =
            Arc::new(a2a::iroh_transport::IrohA2aDispatcher::new(a2a_state.clone()));
        deferred.set(dispatcher);
        info!("A2A dispatcher installed on iroh transport (ALPN tenzro/a2a, Phase D2)");
    }

    let a2a_shutdown_rx = shutdown_tx.subscribe();
    let a2a_addr_https = a2a_addr.clone();
    let mut a2a_handle = tokio::spawn(async move {
        if let Err(e) = a2a::server::start_a2a_server_with_shutdown(
            a2a_addr_https,
            a2a_state,
            a2a_shutdown_rx,
        )
        .await
        {
            error!("A2A server error: {}", e);
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

/// Dispatch an administrative subcommand. Each variant is a one-shot
/// JSON-RPC call against a running node; the function returns the exit
/// status for the process.
async fn run_subcommand(cmd: Command) -> Result<()> {
    match cmd {
        Command::Init {
            data_dir,
            stake,
            force,
            format,
        } => run_init(data_dir, stake, force, format),
        Command::GracefulExit {
            rpc_url,
            lookahead_views,
            max_wait_secs,
            force,
        } => run_graceful_exit(rpc_url, lookahead_views, max_wait_secs, force).await,
    }
}

/// `tenzro-node init` — generate and persist the validator's three
/// signing keys (Ed25519 + ML-DSA-65 + BLS12-381) under `data_dir`,
/// then print the resulting public keys for genesis assembly.
///
/// This is the only path in the binary that creates validator key
/// material. The running node strictly loads and errors on missing
/// keys — see `keygen.rs` for the rationale.
fn run_init(
    data_dir: PathBuf,
    stake: u64,
    force: bool,
    format: String,
) -> Result<()> {
    info!(
        data_dir = %data_dir.display(),
        stake,
        force,
        format = %format,
        "Generating validator keyset"
    );

    let keyset = tenzro_node::keygen::generate_and_persist_keyset(&data_dir, force)?;
    let pubs = keyset.pubkeys();

    // Always log a short summary to stderr so operators see what was
    // written even if they pipe stdout into a genesis-builder script.
    info!(
        ed25519_pubkey_hex = %hex::encode(&pubs.ed25519),
        bls_pubkey_hex = %hex::encode(&pubs.bls12_381_g1),
        "Validator keyset generated; secret files written to {} with mode 0o600",
        data_dir.display(),
    );

    match format.to_lowercase().as_str() {
        "json" => {
            let v = serde_json::json!({
                "data_dir": data_dir.display().to_string(),
                "stake": stake,
                "validator": {
                    "public_key": format!("0x{}", hex::encode(&pubs.ed25519)),
                    "pq_public_key": format!("0x{}", hex::encode(&pubs.ml_dsa_65)),
                    "bls_public_key": format!("0x{}", hex::encode(&pubs.bls12_381_g1)),
                    "stake": stake,
                },
                "files": {
                    "ed25519": data_dir.join("validator_key").display().to_string(),
                    "ml_dsa_65": data_dir.join("validator_pq_key").display().to_string(),
                    "bls12_381": data_dir.join("validator_bls_key").display().to_string(),
                },
            });
            println!("{}", serde_json::to_string_pretty(&v).unwrap_or_default());
        }
        // Default: TOML stanza ready to paste into genesis.toml.
        _ => {
            println!("{}", pubs.to_genesis_toml(stake));
        }
    }

    Ok(())
}

/// `tenzro-node graceful-exit` — call `tenzro_gracefulExit` on the
/// running node's JSON-RPC. The RPC handler waits until this replica is
/// no longer the elected leader for the next `lookahead_views` views,
/// then triggers the in-process `NodeEvent::Shutdown`. We print the
/// JSON response and exit 0 if the call succeeded — actual process
/// termination on the server is asynchronous (5s drain in `main()`).
async fn run_graceful_exit(
    rpc_url: String,
    lookahead_views: u64,
    max_wait_secs: u64,
    force: bool,
) -> Result<()> {
    let req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tenzro_gracefulExit",
        "params": {
            "lookahead_views": lookahead_views,
            "max_wait_secs": max_wait_secs,
            "force": force,
        },
    });

    info!(
        rpc_url = %rpc_url,
        lookahead_views,
        max_wait_secs,
        force,
        "Sending graceful-exit request"
    );

    // The RPC handler blocks for up to `max_wait_secs` waiting for
    // leader rotation, so the HTTP timeout must comfortably exceed it.
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(max_wait_secs.saturating_add(30)))
        .build()
        .map_err(|e| error::NodeError::Other(format!("reqwest client build: {}", e)))?;

    let resp = client
        .post(&rpc_url)
        .json(&req)
        .send()
        .await
        .map_err(|e| error::NodeError::Other(format!("RPC POST {}: {}", rpc_url, e)))?;

    let status = resp.status();
    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| error::NodeError::Other(format!("RPC response decode: {}", e)))?;

    if !status.is_success() {
        error!(http_status = %status, body = %body, "graceful-exit RPC returned non-2xx");
        return Err(error::NodeError::Other(format!(
            "graceful-exit RPC HTTP {}: {}",
            status, body
        )));
    }
    if let Some(err) = body.get("error") {
        error!(error = %err, "graceful-exit RPC returned JSON-RPC error");
        return Err(error::NodeError::Other(format!(
            "graceful-exit RPC error: {}",
            err
        )));
    }

    let result = body.get("result").cloned().unwrap_or(serde_json::Value::Null);
    println!("{}", serde_json::to_string_pretty(&result).unwrap_or_default());
    info!("graceful-exit accepted by node; process will exit after server drain");
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

    // When --listen-addr is omitted, NetworkConfig::default() already provides
    // both TCP and QUIC on port 9000 (the universal default). Any explicit
    // entries replace that default wholesale — no merging, no shims.
    if !cli.listen_addr.is_empty() {
        let mut addrs = Vec::with_capacity(cli.listen_addr.len());
        for entry in &cli.listen_addr {
            let trimmed = entry.trim();
            if trimmed.is_empty() {
                continue;
            }
            let addr = trimmed.parse::<libp2p::Multiaddr>().map_err(|e| {
                error::NodeError::Config(format!(
                    "Invalid --listen-addr multiaddr '{}': {}",
                    trimmed, e
                ))
            })?;
            addrs.push(addr);
        }
        if !addrs.is_empty() {
            info!(
                "Listen addresses override: {} entries ({})",
                addrs.len(),
                addrs
                    .iter()
                    .map(|a| a.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            config.network.listen_addresses = addrs;
        }
    } else {
        info!(
            "Using default listen addresses (TCP+QUIC): {}",
            config
                .network
                .listen_addresses
                .iter()
                .map(|a| a.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        );
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

    // Public addresses this node advertises to peers via Identify. Each
    // entry is registered with the swarm via `add_external_address` and is
    // the only thing other peers see (the underlying listener enumeration is
    // hidden — see `tenzro-network/src/behaviour.rs::TenzroBehaviour::new`).
    if let Some(external_p2p_addr) = &cli.external_p2p_addr {
        let mut addrs = Vec::new();
        for entry in external_p2p_addr.split(',') {
            let trimmed = entry.trim();
            if trimmed.is_empty() {
                continue;
            }
            match trimmed.parse::<libp2p::Multiaddr>() {
                Ok(addr) => addrs.push(addr),
                Err(e) => {
                    tracing::warn!(
                        "Skipping invalid --external-p2p-addr entry '{}': {}",
                        trimmed,
                        e
                    );
                }
            }
        }
        if !addrs.is_empty() {
            info!(
                "External p2p addresses to advertise: {} entries",
                addrs.len()
            );
            config.network.external_addresses = addrs;
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

    // External iroh sockaddr(s). Plumbed into the iroh endpoint builder via
    // `Builder::external_addr` (so the magicsock state machine treats them
    // as known reachable addrs) and into the Pkarr publisher (which then
    // includes them in the published DNS record so peers can dial back).
    // Parse permissively: skip empty entries and log invalid ones rather
    // than failing the whole boot.
    if !cli.external_iroh_addr.is_empty() {
        let mut parsed = Vec::new();
        for entry in &cli.external_iroh_addr {
            let trimmed = entry.trim();
            if trimmed.is_empty() {
                continue;
            }
            match trimmed.parse::<std::net::SocketAddr>() {
                Ok(addr) => parsed.push(addr),
                Err(e) => {
                    tracing::warn!(
                        "Skipping invalid --external-iroh-addr entry '{}': {}",
                        trimmed,
                        e
                    );
                }
            }
        }
        if !parsed.is_empty() {
            info!(
                "External iroh addresses to advertise: {} entries",
                parsed.len()
            );
            config.iroh.external_addrs = parsed;
        }
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
