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
    a2a, event_loop, genesis, infer, ingress, lifecycle_state_bridge, mcp, spending_policy_bridge,
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

    /// Node roles, comma-separated (e.g. "validator,storage,ai"). A node may
    /// serve any combination of roles under a single stake. Aliases accepted:
    /// validator, model-provider/ai, tee-provider/tee, storage, edge/ingress,
    /// user/light.
    #[arg(short, long, value_name = "ROLES")]
    roles: Option<String>,

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

    /// Bootstrap discovery DNS name. The node resolves
    /// `_tenzro-boot._tcp.<NAME>` to a SRV record list of currently-healthy
    /// validator hostnames, then `_tenzro-id._txt.<NAME>` to per-host
    /// libp2p peer IDs. Resolved entries are appended to `boot_nodes`.
    ///
    /// This avoids the "rotate v0's key → break every other validator's
    /// hardcoded BOOT_PEER_ID" failure mode by externalising the
    /// bootstrap set to DNS. Operators rotate by editing the zone, not
    /// by shipping a new wrapper script to every VM.
    ///
    /// Example: `--bootstrap-dns boot.tenzro.xyz`
    #[arg(long, value_name = "NAME")]
    bootstrap_dns: Option<String>,

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
    /// Example: `--external-rpc-addr https://rpc.tenzro.xyz`
    #[arg(long, value_name = "URL")]
    external_rpc_addr: Option<String>,

    /// External (publicly-routable) MCP endpoint URL advertised to peers.
    /// Used in gossiped model registrations so other nodes can dial the
    /// MCP server from outside its local network.
    /// Example: `--external-mcp-addr https://mcp.tenzro.xyz/mcp`
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
    /// Example: `--external-iroh-addr 203.0.113.10:9001`
    ///
    /// Home / mobile / corporate-NAT nodes leave this unset and rely on the
    /// (forthcoming) iroh relay path.
    #[arg(long, value_name = "ADDRS", value_delimiter = ',')]
    external_iroh_addr: Vec<String>,

    /// State-sync bootstrap: fetch the highest snapshot from the given
    /// peer's RPC endpoint, verify chunk hashes against the manifest, and
    /// commit it to the local KV store before starting consensus. Skips
    /// block replay from genesis. Used to bring a fresh / wedged validator
    /// online quickly.
    ///
    /// MUST be combined with `--state-sync-anchor` (the operator-vetted
    /// state root at the snapshot height). Without an anchor the
    /// bootstrap refuses to apply chunks — a malicious peer could
    /// otherwise serve a forged manifest with any state.
    /// Example: `--state-sync-from https://rpc.tenzro.xyz`
    #[arg(long, value_name = "URL")]
    state_sync_from: Option<String>,

    /// Weak-subjectivity anchor for state-sync: the 32-byte state root
    /// (hex, with or without `0x`) the operator has verified out of band
    /// at the snapshot height the peer will serve. The snapshot's
    /// declared `state_root_hex` is matched bit-for-bit against this
    /// value before any chunk is applied. Required whenever
    /// `--state-sync-from` is set.
    ///
    /// Obtain this value from a trusted source: a known-good validator's
    /// signed gossip, a published weak-subjectivity checkpoint, or a
    /// personally-verified RPC's `tenzro_getSnapshotManifest` cross-checked
    /// against the network's finalized header.
    ///
    /// Example: `--state-sync-anchor 0xabc123...def`
    #[arg(long, value_name = "HEX", requires = "state_sync_from")]
    state_sync_anchor: Option<String>,

    /// Block height at which `--state-sync-anchor` is the trusted committed
    /// state root. When set, the block-sync import path also enforces the
    /// anchor: any block imported at this height whose committed state root
    /// differs from `--state-sync-anchor` is rejected, defeating a
    /// long-range fork that would otherwise pass commit-QC verification.
    /// When omitted, the anchor guards only snapshot bootstrap (the peer's
    /// manifest), and block-sync imports are accepted on QC verification
    /// alone — the historical behaviour. Auto state-sync via
    /// `--bootstrap-dns` derives this from the genesis
    /// `[weak_subjectivity]` block instead.
    #[arg(long, value_name = "HEIGHT", requires = "state_sync_anchor")]
    state_sync_height: Option<u64>,

    /// Admit NonCommercial-tier models. Off by default: a node refuses to
    /// load any model whose license forbids commercial use unless the
    /// operator opts in with this flag. Serving inference is a commercial
    /// act on a paid network, so the default is fail-closed.
    #[arg(long, default_value_t = false)]
    accept_non_commercial: bool,

    /// Admit a CommercialCustom-tier model family by its license id
    /// (repeatable / comma-separated), e.g. `--accept-license gemma
    /// --accept-license dinov3`. Custom-license families (Gemma Terms,
    /// DINOv3, Meta SAM) require the operator to have read and accepted the
    /// upstream terms; the node refuses to load them until their id appears
    /// here.
    #[arg(long, value_name = "ID", value_delimiter = ',')]
    accept_license: Vec<String>,

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
    /// bonded stake is bonded to a dead pubkey. Established production
    /// BFT stacks all require an explicit operator-invoked keygen step
    /// for this reason.
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

    // Apply CLI overrides (async because the bootstrap-DNS resolver
    // path makes live DNS queries before the swarm starts).
    apply_cli_overrides(&mut config, &cli).await?;

    // Validate configuration
    config.validate()?;

    // Print node info
    if cli.log_format != "json" {
        print_node_info(&config);
    } else {
        info!(
            roles = %config.roles,
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

    // State-sync wiring. Three input combinations supported:
    //
    // 1. Explicit `--state-sync-from <URL> --state-sync-anchor <HEX>`: the
    //    operator drives bootstrap manually. Highest precedence.
    // 2. `--bootstrap-dns <NAME>` + genesis `[weak_subjectivity]` block + a
    //    detectable-fresh data dir: the node auto-discovers a peer from the
    //    already-resolved bootstrap multiaddrs and derives the anchor from
    //    the genesis. This is the production "fresh validator joins the
    //    network without operator-supplied state-sync flags" path.
    // 3. Neither: legacy genesis-replay path (only viable when the chain is
    //    very young or the node has already bootstrapped).
    let explicit_peer = cli.state_sync_from.clone();
    let auto_state_sync = explicit_peer.is_none()
        && cli.bootstrap_dns.is_some()
        && config
            .genesis
            .as_ref()
            .and_then(|g| g.weak_subjectivity.as_ref())
            .is_some();

    if let Some(peer) = explicit_peer {
        info!(peer = %peer, "State-sync requested via --state-sync-from");
        node.set_state_sync_peer(peer);

        // Operator-supplied weak-subjectivity anchor is REQUIRED
        // alongside the peer URL — the snapshot manifest's declared
        // state_root must match this value bit-for-bit before any
        // chunk is applied. Without it the bootstrap is unauthenticated.
        let anchor_hex = cli
            .state_sync_anchor
            .clone()
            .ok_or_else(|| error::NodeError::Other(
                "--state-sync-from requires --state-sync-anchor (32-byte hex state \
                 root). The anchor is matched bit-for-bit against the snapshot \
                 manifest's declared state_root before any chunk is applied — \
                 without it the peer's RPC has no cryptographic authority to \
                 seed local state.".to_string()
            ))?;
        let cleaned = anchor_hex.trim_start_matches("0x");
        let anchor_bytes = hex::decode(cleaned).map_err(|e| error::NodeError::Other(
            format!("--state-sync-anchor is not valid hex: {e}")
        ))?;
        if anchor_bytes.len() != 32 {
            return Err(error::NodeError::Other(format!(
                "--state-sync-anchor must be exactly 32 bytes (got {})",
                anchor_bytes.len()
            )));
        }
        let mut anchor = [0u8; 32];
        anchor.copy_from_slice(&anchor_bytes);
        node.set_state_sync_anchor(anchor);
        info!(
            anchor = %format!("0x{}", hex::encode(anchor)),
            "State-sync anchor installed"
        );

        // If the operator also pinned the height, enforce the anchor on the
        // block-sync import path — not just the snapshot manifest. Without a
        // height the anchor cannot be located in the block stream, so
        // block-sync stays QC-only (historical behaviour).
        if let Some(height) = cli.state_sync_height {
            node.set_weak_subjectivity_anchor(height, anchor);
            info!(
                height = height,
                anchor = %format!("0x{}", hex::encode(anchor)),
                "Weak-subjectivity checkpoint installed for block-sync"
            );
        }
    } else if auto_state_sync {
        // Auto-derive (peer_url, anchor) for fresh-joiner catchup.
        //
        // Anchor source: genesis `[weak_subjectivity]` block (parsed and
        // validated as a 32-byte hex state root).
        //
        // Peer source: the first bootstrap multiaddr resolved by
        // `--bootstrap-dns`. We derive an HTTPS RPC URL by extracting the
        // /ip4 or /ip6 component from the multiaddr; libp2p ports map 1:1
        // to RPC ports in our deploy (the canonical fleet uses 9000/p2p
        // + 8545/RPC, and operators are free to use bootstrap-DNS
        // separately to advertise an explicit `_tenzro-rpc._tcp.<name>`
        // SRV in a later release if the mapping needs to be decoupled).
        //
        // If the multiaddr list is empty (DNS misconfig) the auto path
        // does nothing — same as a legacy boot without `--state-sync-from`
        // — and consensus will proceed via gossipsub block-fetch instead.
        let anchor_hex = config
            .genesis
            .as_ref()
            .and_then(|g| g.weak_subjectivity.as_ref())
            .map(|w| w.state_root_hex.clone())
            .expect("auto_state_sync guard ensured weak_subjectivity is set");
        let cleaned = anchor_hex.trim_start_matches("0x");
        let anchor_bytes = hex::decode(cleaned).map_err(|e| error::NodeError::Other(
            format!(
                "genesis weak_subjectivity.state_root_hex is not valid hex: {e}"
            ),
        ))?;
        if anchor_bytes.len() != 32 {
            return Err(error::NodeError::Other(format!(
                "genesis weak_subjectivity.state_root_hex must be exactly 32 \
                 bytes (got {})",
                anchor_bytes.len()
            )));
        }
        let mut anchor = [0u8; 32];
        anchor.copy_from_slice(&anchor_bytes);
        node.set_state_sync_anchor(anchor);

        // The genesis anchor carries a height, so the block-sync import path
        // enforces it too: a rejoining node that catches up by replaying
        // blocks (rather than snapshot bootstrap) rejects any fork whose
        // committed state root at the anchor height diverges from genesis.
        let anchor_height = config
            .genesis
            .as_ref()
            .and_then(|g| g.weak_subjectivity.as_ref())
            .map(|w| w.height)
            .expect("auto_state_sync guard ensured weak_subjectivity is set");
        node.set_weak_subjectivity_anchor(anchor_height, anchor);
        info!(
            height = anchor_height,
            anchor = %format!("0x{}", hex::encode(anchor)),
            "Weak-subjectivity checkpoint installed for block-sync (genesis)"
        );

        // Derive a peer RPC URL from the first usable bootstrap multiaddr.
        // The mapping is intentionally simple: `/ip4/<X>/...` → `http://<X>:8545`.
        // This holds for the canonical Tenzro fleet (RPC bound on every
        // validator). When operators decouple ports the same logic can
        // be extended to consume an explicit `_tenzro-rpc._tcp.<name>` SRV.
        let peer_url = config
            .network
            .boot_nodes
            .iter()
            .find_map(|ma| {
                let s = ma.to_string();
                // Multiaddrs look like `/ip4/203.0.113.10/tcp/9000/p2p/...`.
                // Pull the first /ip4 or /ip6 component.
                let mut parts = s.split('/').filter(|p| !p.is_empty());
                let proto = parts.next()?;
                let addr = parts.next()?;
                match proto {
                    "ip4" => Some(format!("http://{}:8545", addr)),
                    "ip6" => Some(format!("http://[{}]:8545", addr)),
                    _ => None,
                }
            });
        if let Some(url) = peer_url {
            info!(
                peer = %url,
                anchor = %format!("0x{}", hex::encode(anchor)),
                "Auto state-sync via bootstrap-DNS + genesis weak-subjectivity anchor"
            );
            node.set_state_sync_peer(url);
        } else {
            tracing::warn!(
                "Auto state-sync requested but no usable peer multiaddr in \
                 boot_nodes — node will fall back to gossipsub block-fetch"
            );
        }
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
    let mcp_shutdown_rx = shutdown_tx.subscribe();
    let mut mcp_handle = tokio::spawn(async move {
        if let Err(e) = mcp::server::start_mcp_server_with_shutdown(
            mcp_addr,
            mcp_node,
            mcp_web_state,
            mcp_shutdown_rx,
        )
        .await
        {
            error!("MCP server error: {}", e);
        }
    });

    // Build the shared A2A state once so the HTTPS axum surface and the
    // iroh-transport surface (Phase D2, #223) operate against the **same**
    // `TaskManager` — tasks created over either transport land in the same
    // table.
    let a2a_addr = config.a2a_addr.clone();
    let iroh_mcp_web_state = web_state.clone();
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

    // Phase D2 follow-up: install the iroh-side MCP handler. The iroh
    // router registered the `tenzro/mcp` ALPN at bind time backed by a
    // deferred handler (see `init_ai_infrastructure`); now that we have
    // `Arc<TenzroNode>` + `Arc<WebState>` we swap the real one in. Each
    // inbound bi-stream becomes a full rmcp session (`AsyncRwTransport`
    // line-delimited JSON-RPC — same wire format as stdio MCP).
    if let Some(deferred) = node_arc.iroh_mcp_handler.as_ref() {
        let handler: Arc<dyn tenzro_iroh::McpStreamHandler> = Arc::new(
            mcp::iroh_transport::IrohMcpHandler::new(node_arc.clone(), iroh_mcp_web_state),
        );
        deferred.set(handler);
        info!("MCP handler installed on iroh transport (ALPN tenzro/mcp, Phase D2)");
    }

    // Install the iroh-side inference dispatcher. The iroh router registered
    // the `tenzro/infer` ALPN at bind time backed by a deferred dispatcher
    // (see `init_ai_infrastructure`); now that we have `Arc<TenzroNode>` we
    // swap the real one in. Consumers dial a provider's `EndpointId` on this
    // ALPN and send a `tenzro_chat` frame — the NAT-agnostic path that
    // replaces HTTP-POSTing to a loopback `rpc_endpoint`.
    if let Some(deferred) = node_arc.iroh_infer_dispatcher.as_ref() {
        let dispatcher: Arc<dyn tenzro_iroh::JsonRpcDispatcher> =
            Arc::new(infer::IrohInferDispatcher::new(node_arc.clone()));
        deferred.set(dispatcher);
        info!("Inference dispatcher installed on iroh transport (ALPN tenzro/infer)");
    }

    // Install the iroh-side ingress handler. The iroh router registered the
    // `tenzro/http` ALPN at bind time backed by a deferred handler (see
    // `init_ai_infrastructure`); now that we have `Arc<TenzroNode>` we swap the
    // real one in. The edge dials a serving node's `EndpointId` on this ALPN,
    // writes a raw HTTP/1.1 request, and this handler renders the placed site
    // and writes the raw HTTP/1.1 response back.
    if let Some(deferred) = node_arc.iroh_http_handler.as_ref() {
        let handler: Arc<dyn tenzro_iroh::HttpForwardHandler> =
            Arc::new(ingress::IrohIngressHandler::new(node_arc.clone()));
        deferred.set(handler);
        info!("Ingress handler installed on iroh transport (ALPN tenzro/http)");
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

    // Start ecosystem MCP servers (Solana, Ethereum, Canton, LayerZero, Chainlink,
    // LI.FI). Each uses axum's `with_graceful_shutdown` plumbed through the
    // shared `shutdown_tx` broadcast — in-flight requests are allowed to drain
    // before the listener future resolves, instead of being torn down via
    // `tokio::select!` cancellation on the running future.
    let solana_addr = config.solana_mcp_addr.clone();
    let solana_shutdown_rx = shutdown_tx.subscribe();
    let solana_rpc_url = std::env::var("SOLANA_RPC_URL")
        .unwrap_or_else(|_| mcp::solana::default_solana_rpc_url());
    tokio::spawn(async move {
        if let Err(e) = mcp::solana::start_solana_mcp_server_with_rpc_and_shutdown(
            solana_addr,
            solana_rpc_url,
            solana_shutdown_rx,
        )
        .await
        {
            error!("Solana MCP server error: {}", e);
        }
    });

    let ethereum_addr = config.ethereum_mcp_addr.clone();
    let ethereum_shutdown_rx = shutdown_tx.subscribe();
    tokio::spawn(async move {
        if let Err(e) = mcp::ethereum::start_ethereum_mcp_server_with_shutdown(
            ethereum_addr,
            ethereum_shutdown_rx,
        )
        .await
        {
            error!("Ethereum MCP server error: {}", e);
        }
    });

    let canton_addr = config.canton_mcp_addr.clone();
    // Pass Canton participant URLs + optional JWT into the Canton MCP server so
    // its tools talk to the right Canton node instead of always hitting the
    // hard-coded `localhost:7575/7576` defaults. Ledger and admin URLs are
    // derived from `config.canton.host`/`port` (the same source `init_vm()`
    // uses to wire the DamlExecutor); JWT is read from `CANTON_JWT_TOKEN` env
    // since it's a secret and intentionally not on the on-disk config.
    // Canton MCP endpoint resolution honors the same three profiles as
    // `Node::init_bridge`:
    //  1. Devnet — fixed `json.devnet.tenzro.xyz` host, TLS, Auth0 bearer.
    //  2. Operator-run validator — operator's host:port (TLS per `canton.tls`),
    //     with EITHER operator OAuth2 (`canton.oauth`) OR static JWT
    //     (`canton.static_jwt`, set from `CANTON_JWT_TOKEN`).
    //  3. Local unauth — plaintext HTTP to localhost, no bearer.
    let (canton_ledger_api_url, canton_admin_api_url, canton_token_provider, canton_jwt_token) =
        if config.canton.devnet {
            let provider = config.canton.devnet_client_secret.clone().map(|secret| {
                let auth_cfg =
                    tenzro_bridge::canton_auth::CantonAuthConfig::devnet(secret);
                tenzro_bridge::canton_auth::CantonTokenProvider::new(auth_cfg)
            });
            // Base URL only — CantonMcpServer appends `/v2/...` itself
            // (mcp/canton.rs request paths); a `/v2` suffix here would
            // produce `/v2/v2/...` → 404.
            (
                "https://json.devnet.tenzro.xyz".to_string(),
                "https://admin.devnet.tenzro.xyz".to_string(),
                provider,
                None,
            )
        } else {
            let scheme = if config.canton.tls { "https" } else { "http" };
            let ledger = format!("{}://{}:{}", scheme, config.canton.host, config.canton.port);
            let admin = format!(
                "{}://{}:{}",
                scheme,
                config.canton.host,
                config.canton.port.saturating_add(1),
            );
            let provider = config.canton.oauth.as_ref().map(|oauth| {
                let auth_cfg = tenzro_bridge::canton_auth::CantonAuthConfig {
                    token_url: oauth.token_url.clone(),
                    client_id: oauth.client_id.clone(),
                    client_secret: oauth.client_secret.clone(),
                    audience: oauth.audience.clone(),
                    scope: oauth.scope.clone(),
                };
                tenzro_bridge::canton_auth::CantonTokenProvider::new(auth_cfg)
            });
            // Static JWT only takes effect if no OAuth2 provider is set.
            let jwt = if provider.is_none() {
                config.canton.static_jwt.clone()
            } else {
                None
            };
            (ledger, admin, provider, jwt)
        };
    let canton_shutdown_rx = shutdown_tx.subscribe();
    let canton_api_key_mgr = node_arc.api_key_manager().cloned();
    let canton_analytics_mgr = node_arc.canton_analytics().cloned();
    tokio::spawn(async move {
        if let Err(e) = mcp::canton::start_canton_mcp_server_with_shutdown(
            canton_addr,
            canton_ledger_api_url,
            canton_admin_api_url,
            canton_jwt_token,
            canton_token_provider,
            canton_api_key_mgr,
            canton_analytics_mgr,
            canton_shutdown_rx,
        )
        .await
        {
            error!("Canton MCP server error: {}", e);
        }
    });

    let layerzero_addr = config.layerzero_mcp_addr.clone();
    let layerzero_shutdown_rx = shutdown_tx.subscribe();
    tokio::spawn(async move {
        if let Err(e) = mcp::layerzero::start_layerzero_mcp_server_with_shutdown(
            layerzero_addr,
            layerzero_shutdown_rx,
        )
        .await
        {
            error!("LayerZero MCP server error: {}", e);
        }
    });

    let chainlink_addr = config.chainlink_mcp_addr.clone();
    let chainlink_shutdown_rx = shutdown_tx.subscribe();
    tokio::spawn(async move {
        if let Err(e) = mcp::chainlink::start_chainlink_mcp_server_with_shutdown(
            chainlink_addr,
            chainlink_shutdown_rx,
        )
        .await
        {
            error!("Chainlink MCP server error: {}", e);
        }
    });

    let lifi_addr = config.lifi_mcp_addr.clone();
    let lifi_shutdown_rx = shutdown_tx.subscribe();
    tokio::spawn(async move {
        if let Err(e) = mcp::lifi::start_lifi_mcp_server_with_shutdown(
            lifi_addr,
            lifi_shutdown_rx,
        )
        .await
        {
            error!("LI.FI MCP server error: {}", e);
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
async fn apply_cli_overrides(config: &mut NodeConfig, cli: &Cli) -> Result<()> {
    if let Some(data_dir) = &cli.data_dir {
        config.data_dir = data_dir.clone();
    }

    // Model-license acceptance. CLI flags are additive on top of any policy
    // set in the config file: `--accept-non-commercial` turns the flag on,
    // and each `--accept-license <id>` appends to the accepted set. Neither
    // flag can *revoke* a config-file acceptance — the operator drops those
    // by editing the config, not by omitting a flag.
    if cli.accept_non_commercial {
        config.model_licensing.accept_non_commercial = true;
    }
    for id in &cli.accept_license {
        let id = id.trim();
        if !id.is_empty() && !config.model_licensing.accepted_license_ids.iter().any(|a| a == id) {
            config.model_licensing.accepted_license_ids.push(id.to_string());
        }
    }

    if let Some(roles_str) = &cli.roles {
        config.roles = parse_roles(roles_str)?;
        // Auto-create consensus config for validators if not already set
        if config.roles.is_validator() && config.consensus.is_none() {
            config.consensus = Some(tenzro_consensus::ConsensusConfig::default());
        }
        // Auto-create default genesis if not already set
        if config.genesis.is_none() {
            config.genesis = Some(GenesisConfig::default_testnet());
        }
    }

    // Merge role-specific defaults per served role when no config file was
    // provided. A multi-role node accumulates the defaults of every role it
    // fills (e.g. validator+ai pulls both consensus and tee defaults). Weight
    // storage is left to NodeConfig::effective_models_dir, which roots under
    // the persistent data_dir when models_dir is unset.
    if cli.config.is_none() {
        if config.roles.is_validator() && config.consensus.is_none() {
            let vdef = NodeConfig::default_validator();
            config.consensus = vdef.consensus;
            // Validators are the relay-serving class — they run the relay-v2
            // server + AutoNAT-v2 server so NAT'd edge nodes can register a
            // reservation and become reachable via
            // `/p2p/<validator>/p2p-circuit/p2p/<edge>`. Without this, edge
            // nodes hang at "Peers 0" because `--roles validator` alone
            // previously only copied `consensus` from `default_validator`
            // and left `enable_relay=false` from `NetworkConfig::default()`.
            config.network.enable_relay = vdef.network.enable_relay;
        }
        if config.roles.serves_tee() {
            config.tee_enabled = NodeConfig::default_tee_provider().tee_enabled;
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

    // Env-supplied boot nodes (TENZRO_BOOT_NODES, comma-separated multiaddrs)
    // are the natural config surface for container / systemd deploys. Append
    // to whatever --boot-nodes set so env and CLI compose rather than clobber.
    {
        let env_boot = tenzro_network::BootstrapConfig::from_env();
        if !env_boot.boot_nodes.is_empty() {
            config.network.boot_nodes.extend(env_boot.boot_nodes.iter().cloned());
            info!(
                "TENZRO_BOOT_NODES appended: {} nodes (total {})",
                env_boot.boot_nodes.len(),
                config.network.boot_nodes.len()
            );
        }
    }

    // Bootstrap-DNS discovery: resolve `_tenzro-boot._tcp.<NAME>` SRV +
    // per-target `_tenzro-id._tcp.<TARGET>` TXT to derive a list of
    // /ip*/.../p2p/<PEER_ID> multiaddrs. Append (not overwrite) to the
    // existing boot_nodes list so operators can combine static + dynamic
    // discovery during a transition window.
    //
    // When the operator supplies neither --boot-nodes nor --bootstrap-dns and
    // the config file carries no boot nodes, fall back to the network
    // bootstrap name so a fresh install joins the network with zero flags.
    let bootstrap_dns_name = cli.bootstrap_dns.clone().or_else(|| {
        if config.network.boot_nodes.is_empty() {
            info!(
                "No boot nodes configured; using default bootstrap DNS name tenzro.xyz \
                 (override with --boot-nodes or --bootstrap-dns)"
            );
            Some("tenzro.xyz".to_string())
        } else {
            None
        }
    });
    if let Some(name) = &bootstrap_dns_name {
        match tenzro_node::bootstrap_dns::resolve_bootstrap_dns(name).await {
            Ok(resolved) => {
                if resolved.is_empty() {
                    tracing::warn!(
                        "Bootstrap DNS resolution returned no peers for {}; \
                         continuing with whatever was already in --boot-nodes",
                        name
                    );
                } else {
                    config.network.boot_nodes.extend(resolved.iter().cloned());
                    info!(
                        "Bootstrap DNS resolved {}: {} multiaddrs appended to boot_nodes (total {})",
                        name,
                        resolved.len(),
                        config.network.boot_nodes.len(),
                    );
                }
            }
            Err(e) => {
                // Fail loud but do not abort startup — operators using
                // bootstrap-DNS as a *supplement* to a static --boot-nodes
                // list should still come up if DNS is degraded. Operators
                // using bootstrap-DNS as the *only* boot path will see
                // an empty boot_nodes set and the node will sit isolated
                // until the next reachable peer dials it — that's the
                // explicit failure mode, not a silent hang.
                tracing::warn!(
                    "Bootstrap DNS resolution failed for {}: {}. \
                     Node will rely on whatever was in --boot-nodes (may be empty).",
                    name,
                    e
                );
            }
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

/// Parse a comma-separated roles string into a `RoleSet`.
fn parse_roles(roles: &str) -> Result<tenzro_types::RoleSet> {
    use std::str::FromStr;

    tenzro_types::RoleSet::from_str(roles)
        .map_err(|e| error::NodeError::Config(format!("Invalid roles '{}': {}", roles, e)))
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
    println!("  Roles:        {}", config.roles);
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

    if config.roles.serves_ai() {
        println!("  Models Dir:   {:?}", config.effective_models_dir());
        let lic = &config.model_licensing;
        let custom = if lic.accepted_license_ids.is_empty() {
            "none".to_string()
        } else {
            lic.accepted_license_ids.join(", ")
        };
        println!(
            "  Licenses:     open-weight always; non-commercial={}; custom=[{}]",
            lic.accept_non_commercial, custom
        );
    }

    println!("{}\n", "=".repeat(60));
}
