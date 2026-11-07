//! Tenzro Network Node - Full node binary

// The light build (no `inference` feature) leaves out the engine start-up;
// what only that uses is allowed to go unused there, as in the library.
#![cfg_attr(
    not(feature = "inference"),
    allow(dead_code, unused_imports, unused_variables, unused_mut)
)]

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::broadcast;
use tracing::{Level, error, info, warn};
use tracing_subscriber::EnvFilter;

use tenzro_node::config::{GenesisConfig, NodeConfig};
use tenzro_node::error::{self, Result};
#[cfg(feature = "inference")]
use tenzro_node::moe;
use tenzro_node::node::TenzroNode;
use tenzro_node::rpc::RpcServer;
use tenzro_node::{a2a, event_loop, infer, mcp, web};

/// Tenzro Network Node CLI
#[derive(Parser, Debug)]
#[command(name = "tenzro-node")]
#[command(about = "Tenzro Network Full Node", long_about = None)]
#[command(version)]
struct Cli {
    /// Path to configuration file
    #[arg(short, long, value_name = "FILE")]
    config: Option<PathBuf>,

    /// Data directory. Also settable via `$TENZRO_DATA_DIR` so an operator
    /// can pin it once — in the environment, a service unit, a shell
    /// profile — rather than repeating the flag on every start; the flag
    /// wins when both are given.
    #[arg(short, long, value_name = "DIR", env = "TENZRO_DATA_DIR")]
    data_dir: Option<PathBuf>,

    /// Hold this machine's identity key in another machine's TPM instead of a
    /// local one, through the key holder listening on this socket
    /// (`tenzro-node tpm key-holder`). The holder keeps this boot's transport
    /// key in memory and the operator passkey's grant for it.
    #[arg(long, value_name = "SOCKET", env = "TENZRO_TPM_KEY_HOLDER")]
    tpm_key_holder: Option<PathBuf>,

    /// The key label the provider enrolled for this machine.
    #[arg(long, value_name = "LABEL", env = "TENZRO_TPM_LABEL")]
    tpm_label: Option<String>,

    /// GiB held back from models for the OS, this process, RocksDB, iroh, and
    /// the service surfaces — never lent to a model at any load. Defaults to
    /// 16. Also settable via `$TENZRO_RESERVE_GB`; the flag wins when both
    /// are given. Lower it on a node that only serves models; raise it on one
    /// carrying a deep RocksDB working set or co-hosting other services.
    #[arg(long, value_name = "GB", env = "TENZRO_RESERVE_GB")]
    reserve_gb: Option<u32>,

    /// GiB ceiling for always-resident models (language models, embeddings,
    /// forecasting, ASR, TTS). Omit to use 60% of what remains after the
    /// reserve. Also settable via `$TENZRO_RESIDENT_CEILING_GB`; the flag
    /// wins when both are given.
    #[arg(long, value_name = "GB", env = "TENZRO_RESIDENT_CEILING_GB")]
    resident_ceiling_gb: Option<u32>,

    /// GiB ceiling for pipelines loaded per job and evicted afterwards —
    /// image and video generation. Omit to use whatever the resident tier
    /// does not take. Also settable via `$TENZRO_ON_DEMAND_CEILING_GB`; the
    /// flag wins when both are given. Separate from the resident ceiling on
    /// purpose: a chat model must not be able to crowd out the diffusion
    /// worker, and a video pipeline must not evict the model currently
    /// answering requests. On a memory-constrained box, the 60/40 default
    /// split can leave this tier too small for a single on-demand pipeline —
    /// raise it explicitly when that happens.
    #[arg(long, value_name = "GB", env = "TENZRO_ON_DEMAND_CEILING_GB")]
    on_demand_ceiling_gb: Option<u32>,

    /// Resource tier: `auto` (default), `edge`, `validator` or `provider`.
    /// Sets the defaults for the store's memory and background work and the
    /// runtime's threads; `auto` picks `provider` for roles that run models,
    /// `edge` on a machine with at most 8 GiB of memory, `validator`
    /// otherwise. Values set under `[storage]` win over the tier.
    #[arg(long, value_name = "TIER", env = "TENZRO_TIER")]
    tier: Option<String>,

    /// Async runtime worker threads. Omit for the tier's: 2, or 1 on a
    /// one-core edge device.
    #[arg(long, value_name = "N", env = "TENZRO_WORKER_THREADS")]
    worker_threads: Option<usize>,

    /// Node roles, comma-separated (e.g. "validator,storage,ai"). A node may
    /// serve any combination of roles under a single stake. Aliases accepted:
    /// validator, model-provider/ai, tee-provider/tee, storage, edge/ingress,
    /// user/light.
    #[arg(short, long, value_name = "ROLES")]
    roles: Option<String>,

    /// Self-stake in wei to auto-register this node as a validator on boot
    /// (permissionless / first-boot onboarding). Requires the validator role;
    /// the node's validator-derived account must hold this stake plus gas.
    /// Omit to disable self-registration.
    #[arg(long, value_name = "WEI")]
    validator_self_stake: Option<String>,

    /// Signature scheme of this node's consensus key:
    /// COMPSIG-MLDSA65-ECDSA-P256 (the default) or COMPSIG-MLDSA87-ECDSA-P384,
    /// which needs a TPM implementing ML-DSA and P-384. A validator
    /// registered under another scheme rotates to the key of this one.
    #[arg(long, value_name = "SCHEME")]
    consensus_key_scheme: Option<String>,

    /// Boot identities (comma-separated): machine identities, each optionally
    /// with the relay it is reachable through,
    /// `did:tenzro:machine:<id>[@<relay url>]`. Network addresses are
    /// refused. Also read, and appended, from `TENZRO_BOOT_NODES`.
    ///
    /// Omitting this joins the public network through its genesis
    /// validators' identities.
    ///
    /// Pass an explicitly empty value — `--boot-nodes ""` — to stay **isolated**:
    /// no dialling out. That is what a local or solo node wants, and it is
    /// distinct from omitting the flag.
    #[arg(short, long, value_name = "IDENTITIES")]
    boot_nodes: Option<String>,

    /// Serve the relay role: the address the relay's HTTP listener binds.
    /// Requires `--relay-url`.
    #[arg(long, value_name = "ADDR", requires = "relay_url")]
    relay_listen: Option<std::net::SocketAddr>,

    /// The URL peers reach this node's relay at, announced in its signed
    /// endpoint record. Exposing the listener at that URL, with TLS, is the
    /// operator's choice outside the node.
    #[arg(long, value_name = "URL", requires = "relay_listen")]
    relay_url: Option<url::Url>,

    /// UDP port this node's endpoint binds while it serves the relay role
    /// (default 443). Only for a host that runs several relays, such as a
    /// test cluster; one process per host can hold a port.
    #[arg(long, value_name = "PORT", requires = "relay_listen")]
    relay_udp_port: Option<u16>,

    /// Log level (trace, debug, info, warn, error)
    #[arg(long, value_name = "LEVEL", default_value = "info")]
    log_level: String,

    /// Log format: "text" for human-readable, "json" for structured JSON
    #[arg(long, value_name = "FORMAT", default_value = "text")]
    log_format: String,

    /// RPC listen address. Loopback only (default `127.0.0.1:8545`): the node
    /// never exposes its machine. To serve RPC publicly, put your own reverse
    /// proxy in front of this address and pass its URL as
    /// `--external-rpc-addr`.
    #[arg(long, value_name = "ADDR")]
    rpc_addr: Option<String>,

    /// Web API listen address. Loopback only (default `127.0.0.1:8080`).
    #[arg(long, value_name = "ADDR")]
    web_addr: Option<String>,

    /// Path to genesis configuration file
    #[arg(short, long, value_name = "FILE")]
    genesis: Option<PathBuf>,

    /// Run a self-contained solo chain: fabricate a single-validator genesis
    /// with this node as the only validator, and let it form quorum alone.
    ///
    /// This is for local development and isolated/sovereign bring-up ONLY. A
    /// validator meant to join the public network must NEVER run solo — doing
    /// so silently forks a private chain that only cosmetically resembles the
    /// real network (same chain_id), peers with it, and then
    /// diverges at QC verification. Requiring an explicit opt-in is what keeps
    /// "join the network" from degrading into "fork my own chain" when a
    /// genesis file is missing.
    ///
    /// Implied automatically by isolated mode (`--boot-nodes ""`). Rejected if
    /// combined with a real `--genesis` file or with configured boot peers.
    #[arg(long)]
    solo: bool,

    /// Run a local developer chain: a solo chain that dials no one, with
    /// one-minute epochs and quarter-second rounds, and the `--fund` accounts
    /// funded at genesis. Its validator and identity keys are this machine's
    /// TPM or Secure Enclave keys; a machine with neither is refused. Started
    /// by `tenzro dev`.
    #[arg(long, conflicts_with = "genesis")]
    dev: bool,

    /// An account funded with 1,000,000 TNZO at a developer chain's
    /// genesis, 32-byte hex. Repeatable. Only with `--dev`.
    #[arg(long = "fund", value_name = "ADDRESS", requires = "dev")]
    fund: Vec<String>,

    /// MCP server listen address. Loopback only (default `127.0.0.1:3001`).
    #[arg(long, value_name = "ADDR")]
    mcp_addr: Option<String>,

    /// A2A protocol server listen address. Loopback only (default
    /// `127.0.0.1:3002`).
    #[arg(long, value_name = "ADDR")]
    a2a_addr: Option<String>,

    /// Public https URL of your own edge (reverse proxy) in front of this
    /// node's loopback RPC listener, if you expose it. The only RPC URL the
    /// node publishes; without it none is published. Refused at startup when
    /// it is not https or names a loopback, private, CGNAT or link-local host.
    #[arg(long, value_name = "URL")]
    external_rpc_addr: Option<String>,

    /// Public https URL of your own edge in front of this node's loopback MCP
    /// listener, if you expose it. Same rules as `--external-rpc-addr`.
    #[arg(long, value_name = "URL")]
    external_mcp_addr: Option<String>,

    /// State sync: restore the committed state from these peers (their current
    /// iroh `EndpointId`s, as their signed announcements give them; repeat the flag
    /// for several) before starting consensus, instead of replaying blocks.
    /// `<EndpointId>@<ip:port>` dials that address directly, for a network with
    /// no discovery (repeat it to give several addresses of one peer); a bare
    /// id is found by discovery. Also settable as `state_sync_from` in the
    /// config file.
    /// The snapshot is fetched as BLAKE3-verified blobs from any peer that
    /// has them and checked bucket by bucket against the state root that the
    /// `--checkpoint-hash` block commits. The recovery after a corrupt store
    /// (`scripts/repair-validator-store.sh`, then restart with this flag)
    /// works on a fixed `bind_addr` too: the state-sync endpoint is released
    /// before the node's own endpoint binds.
    ///
    /// Requires `--checkpoint-height` and `--checkpoint-hash`.
    #[arg(long = "state-sync-from", value_name = "ENDPOINT_ID[@IP:PORT]")]
    state_sync_from: Vec<String>,

    /// Weak-subjectivity checkpoint: the hash (hex, with or without `0x`) of
    /// a finalized block the operator has verified out of band, at
    /// `--checkpoint-height`. Every import path refuses any other block at
    /// that height, which defeats a long-range fork that passes certificate
    /// verification, and state sync restores the state this block commits.
    #[arg(long, value_name = "HEX", requires = "checkpoint_height")]
    checkpoint_hash: Option<String>,

    /// Height of the `--checkpoint-hash` block.
    #[arg(long, value_name = "HEIGHT", requires = "checkpoint_hash")]
    checkpoint_height: Option<u64>,

    /// Recovery restart after a halt below quorum: the manifest file (JSON)
    /// that the surviving operators and the successor validators agreed on.
    /// Applied once at start, before consensus is seated, and only at the
    /// manifest's anchor block, so it does nothing on a chain that has moved
    /// on. Needs `--recovery-digest` and the anchor as `--checkpoint-height`
    /// and `--checkpoint-hash`. See docs/RECOVERY-BELOW-QUORUM.md.
    #[arg(
        long,
        value_name = "FILE",
        requires_all = ["recovery_digest", "checkpoint_height"]
    )]
    recovery_manifest: Option<PathBuf>,

    /// The manifest digest (hex) the operator compared with the one published
    /// on independent channels. The node refuses to start if the file's digest
    /// differs.
    #[arg(long, value_name = "HEX", requires = "recovery_manifest")]
    recovery_digest: Option<String>,

    /// The recovery root (hex) every member printed with `--recovery-check`.
    /// The node starts only if its own root equals it.
    #[arg(long, value_name = "HEX", requires = "recovery_manifest")]
    recovery_confirm: Option<String>,

    /// Run every recovery check, print the recovery root and exit without
    /// changing anything, so the members can compare roots before applying.
    #[arg(long, requires = "recovery_manifest")]
    recovery_check: bool,

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

    /// DID of a publisher this node serves catalog models from; repeat or
    /// comma-separate for several. Without any, every bonded publisher.
    #[arg(long, value_name = "DID", value_delimiter = ',')]
    catalog_publisher: Vec<String>,

    /// DID of a publisher whose engine releases this node reports as
    /// available; repeat or comma-separate for several.
    #[arg(long, value_name = "DID", value_delimiter = ',')]
    release_publisher: Vec<String>,

    /// Token id (hex) of an asset whose policy names the KYC issuers this
    /// node recognises; repeat or comma-separate for several. Without any,
    /// every identity's KYC tier is unverified.
    #[arg(long, value_name = "TOKEN_ID", value_delimiter = ',')]
    kyc_asset: Vec<String>,

    /// How to handle models whose licence restricts the territories they may be
    /// served to.
    ///
    /// Most licences carry no such term — seven of the eight custom licences in
    /// the catalog are unrestricted — so this affects only the few that do, and
    /// costs nothing for everything else.
    ///
    /// * `enforce` (default) — check the caller's territory per request.
    ///   Requires `--territory-db`.
    /// * `refuse-restricted` — do not serve territorially-restricted models at
    ///   all. Needs no database: it removes the obligation rather than the
    ///   enforcement of it, and is the right setting for an operator who does
    ///   not want these models.
    #[arg(long, value_name = "MODE", default_value = "enforce")]
    territory_mode: String,

    /// Path to an mmdb country database for territorial enforcement.
    ///
    /// Use a database you may redistribute: DB-IP Lite Country (CC BY 4.0) or
    /// sapics/ip-location-db `user-country` (PDDL-1.0, public domain). MaxMind
    /// GeoLite2 is **not** suitable — its EULA requires deleting superseded
    /// databases within 30 days of a release, which a distributed binary cannot
    /// honour, and redistribution needs a paid licence.
    ///
    /// Without one, `enforce` refuses territorially-restricted models — and
    /// only those. Every other model keeps serving.
    #[arg(long, value_name = "PATH")]
    territory_db: Option<std::path::PathBuf>,

    /// A label for the territory database, recorded on every decision (e.g.
    /// `dbip-country-lite-2026-08`).
    ///
    /// A decision has to stay interpretable after the database is updated
    /// underneath it: both a bloc's membership and an address's allocation can
    /// change, so "which data said so" is part of the record.
    #[arg(long, value_name = "LABEL")]
    territory_db_label: Option<String>,

    /// Reverse proxies whose `X-Forwarded-For` this node will believe.
    ///
    /// Without this, the header is ignored entirely and the socket address is
    /// used — which is correct: any client can set `X-Forwarded-For`, so
    /// trusting it unconditionally turns the whole check into a no-op.
    #[arg(long, value_name = "IP", value_delimiter = ',')]
    trusted_proxy: Vec<std::net::IpAddr>,

    /// Territory to record for callers on this machine or its private network
    /// (ISO 3166-1 alpha-2, e.g. `SG`).
    ///
    /// Local addresses cannot be geolocated. Absent this, they are treated like
    /// any other unresolvable caller and refused for restricted models. Setting
    /// it is an operator attestation about their own deployment, and is
    /// recorded as such rather than as a measurement.
    #[arg(long, value_name = "CC")]
    local_territory: Option<String>,

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
    /// Print this machine's validator public keys (Ed25519 + ML-DSA-65) for
    /// genesis assembly.
    ///
    /// Nothing is generated or written: the keys are derived on demand
    /// from this machine's TPM or Secure Enclave, and the same machine
    /// always derives the same keys. Refuses on a machine with neither.
    #[command(name = "init")]
    Init {
        /// The node's data directory. Also settable via
        /// `$TENZRO_DATA_DIR`.
        #[arg(long, value_name = "DIR", env = "TENZRO_DATA_DIR")]
        data_dir: Option<PathBuf>,

        /// Genesis stake to print in the emitted `[[validators]]`
        /// stanza. Does not write anything on-chain — this is purely
        /// a convenience for the operator assembling genesis.toml.
        #[arg(long, default_value_t = 1_000_000)]
        stake: u64,

        /// Output format. `toml` (default) emits a ready-to-paste
        /// `[[validators]]` stanza; `json` the same entry as an object.
        #[arg(long, value_name = "FORMAT", default_value = "toml")]
        format: String,
    },

    /// Print this machine's `[[validators]]` genesis entry, signed by its
    /// hardware consensus key. Refuses on a machine without one.
    #[command(name = "validator-entry")]
    ValidatorEntry {
        /// Data directory holding the node key.
        #[arg(long, value_name = "DIR", env = "TENZRO_DATA_DIR")]
        data_dir: Option<PathBuf>,

        /// Stake for the entry, in whole TNZO.
        #[arg(long)]
        stake: u64,

        /// URL of the relay this validator is reachable through (its own
        /// relay role's URL, or a relay it uses), so nodes can join through
        /// its identity.
        #[arg(long, value_name = "URL")]
        relay_url: Option<url::Url>,
    },

    /// Ask the running node to step down gracefully.
    ///
    /// Calls `tenzro_gracefulExit` on the local RPC. The node waits until
    /// it leads none of the next consensus rounds its schedule looks
    /// ahead over, then triggers its existing shutdown path (the
    /// in-process `NodeEvent::Shutdown` plus the 5-second drain in
    /// `main()`).
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

        /// Cap on how long to wait for leader rotation. Defaults to
        /// 60s, far longer than the rounds the schedule looks ahead
        /// over take even when leaders time out.
        #[arg(long, default_value_t = 60)]
        max_wait_secs: u64,

        /// Skip the leader-clearance check entirely and trigger
        /// shutdown immediately. Use only when you know the node is
        /// not currently producing or about to produce a block.
        #[arg(long, default_value_t = false)]
        force: bool,
    },

    /// Copy the node's newest epoch snapshot to DEST.
    ///
    /// Only SST files no earlier backup under DEST holds are copied; the
    /// rest are hardlinked from there, so every backup directory is a
    /// complete store. Runs at idle priority, paced to --rate-mb. The node
    /// never sends a backup anywhere itself: schedule this, and encrypt or
    /// ship DEST, however you choose. Safe while the node runs.
    #[command(name = "backup")]
    Backup {
        /// The node's data directory.
        #[arg(long, value_name = "DIR", env = "TENZRO_DATA_DIR")]
        data_dir: Option<PathBuf>,

        /// Destination directory for backups.
        #[arg(long, value_name = "DEST")]
        dest: PathBuf,

        /// Copy rate, MiB per second (0 for unpaced).
        #[arg(long, default_value_t = 64)]
        rate_mb: u64,
    },

    /// Set who may use this node: the access wizard.
    ///
    /// Writes `access.toml` in the data directory through the same store the
    /// running node and its admin page use: validated, versioned, logged,
    /// applied by a running node within seconds. With no options it asks.
    #[command(name = "access")]
    Access {
        /// The node's data directory.
        #[arg(long, value_name = "DIR", env = "TENZRO_DATA_DIR")]
        data_dir: Option<PathBuf>,

        /// Rule for every surface and class no other rule covers:
        /// open, closed, signed_in or agents_with_terms.
        #[arg(long)]
        preset: Option<String>,

        /// Add a DID that may administer this node besides its operator.
        #[arg(long = "admin", value_name = "DID")]
        admins: Vec<String>,

        /// Remove an administrator DID.
        #[arg(long = "remove-admin", value_name = "DID")]
        remove_admins: Vec<String>,

        /// Lifetime of issued access tokens, in seconds.
        #[arg(long)]
        token_ttl_secs: Option<u64>,

        /// Print the policy in force and change nothing.
        #[arg(long)]
        show: bool,

        /// Open the admin page: write a fifteen-minute ticket and print the
        /// page's address on this node's RPC listener.
        #[arg(long)]
        page: bool,

        /// This node's RPC listener, for --page.
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc_url: String,
    },

    /// Rebuild the node's store from an epoch snapshot or backup.
    ///
    /// The snapshot's checkpoint must be certified: a proof from genesis
    /// (the proof kept with the snapshot, one fetched from --proof-from, or
    /// one given with --proof) must verify every certificate's quorum
    /// signatures against the committee of its epoch, starting from the
    /// genesis committee, and the snapshot's state must rebuild the
    /// certified state root; otherwise nothing is restored. The node must be
    /// stopped and its store directory absent or empty.
    #[command(name = "restore")]
    Restore {
        /// The node's data directory.
        #[arg(long, value_name = "DIR", env = "TENZRO_DATA_DIR")]
        data_dir: Option<PathBuf>,

        /// The snapshot or backup directory to restore from.
        #[arg(long, value_name = "DIR")]
        snapshot: PathBuf,

        /// Chain id, from the genesis file.
        #[arg(long)]
        chain_id: u64,

        /// Genesis block hash (hex), from the genesis file.
        #[arg(long, value_name = "HEX")]
        genesis_hash: String,

        /// Root of the genesis committee (hex), from the genesis file.
        #[arg(long, value_name = "HEX")]
        genesis_committee_root: String,

        /// Fetch the checkpoint proof from this peer's RPC endpoint.
        #[arg(long, value_name = "URL", conflicts_with = "proof")]
        proof_from: Option<String>,

        /// Read the checkpoint proof (bincode) from this file.
        #[arg(long, value_name = "FILE")]
        proof: Option<PathBuf>,

        /// Image id (hex) of the handover program, from the chain's
        /// governance: needed when the proof builds on a handover chain
        /// proof rather than on every handover from genesis.
        #[arg(long, value_name = "HEX")]
        handover_program: Option<String>,
    },

    /// Write what a prover needs to extend the handover chain proof, as
    /// `tenzro-finality-prover handover` reads it: the node's newest chain
    /// proof receipt (`prev.bin`), the genesis committee root
    /// (`genesis-root`) and, per epoch since, the handover and the members of
    /// that epoch's committee (`<epoch>/handover.bin`, `<epoch>/members.bin`).
    #[command(name = "prover-inputs")]
    ProverInputs {
        /// The node's RPC endpoint.
        #[arg(long, value_name = "URL", default_value = "http://127.0.0.1:8545")]
        rpc_url: String,

        /// The directory to write into.
        #[arg(long, value_name = "DIR")]
        out: PathBuf,
    },

    /// This operator's own credentials: for model origins, and for the
    /// endpoint a connector forwards to. Optional: a node without one serves
    /// every open model and fetches gated weights from network peers. Run it
    /// on the node's own machine; the credential is sealed to this machine's
    /// TPM or Secure Enclave and never leaves it.
    #[command(name = "credentials")]
    Credentials {
        #[command(subcommand)]
        action: CredentialsAction,
    },

    /// This machine's TPM.
    ///
    /// The node account key is a P-256 key held in the TPM or Secure Enclave plus an ML-DSA-65 key: inside a TPM implementing library v1.85, otherwise derived on demand from the machine's hardware-held derivation root and never stored. The account's first transaction enrols the ML-DSA-65 key on chain.
    #[command(name = "tpm")]
    Tpm {
        #[command(subcommand)]
        action: TpmAction,
    },

    /// Report what this binary was built for and whether it can use this
    /// machine's accelerators, then exit: the same check the node runs at
    /// startup, without starting a node. Exits non-zero when the node would
    /// refuse to start here.
    #[command(name = "hardware")]
    Hardware,

    /// Report whether peers can reach this node, and how to fix it when they
    /// cannot: IPv4 and IPv6, the router's port mapping (UPnP, PCP,
    /// NAT-PMP), the host firewall, and, from the running node, the NAT in
    /// front of it, the addresses peers see it at and the relay it uses.
    /// Run it on the node's own machine.
    #[command(name = "doctor")]
    Doctor {
        /// Print the report as JSON.
        #[arg(long)]
        json: bool,

        /// Also let peers reach this node directly through the host
        /// firewall, with a rule scoped to this binary and its UDP port: on
        /// Windows an inbound rule for the private and public profiles (and
        /// removal of block rules a dismissed prompt left for this binary),
        /// on macOS an entry in the application firewall. Optional: the node
        /// works without it, through relays and hole punching. Needs an
        /// administrator PowerShell on Windows and sudo on macOS. On Linux
        /// it prints the command for your firewall.
        #[arg(long)]
        allow_inbound: bool,
    },
}

/// A credential the operator gives their node.
#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum CredentialOrigin {
    /// The Hugging Face Hub: an access token of the operator's own account,
    /// used only to fetch weights the origin gates behind it.
    Huggingface,
    /// The API key of the OpenAI-compatible endpoint the `[connector]`
    /// section names, sent only to that endpoint.
    Upstream,
}

impl CredentialOrigin {
    fn secret(self) -> tenzro_node::credentials::Secret {
        match self {
            CredentialOrigin::Huggingface => tenzro_node::credentials::Secret::Huggingface,
            CredentialOrigin::Upstream => tenzro_node::credentials::Secret::Upstream,
        }
    }

    fn name(self) -> &'static str {
        match self {
            CredentialOrigin::Huggingface => "Hugging Face credential",
            CredentialOrigin::Upstream => "upstream API key",
        }
    }
}

#[derive(Debug, Subcommand)]
enum CredentialsAction {
    /// Read the credential from stdin (one line) and seal it to this
    /// machine's TPM or Secure Enclave, replacing any set before. Restart the
    /// node to use it. A sealed credential is used first. Operators without
    /// a TPM or Secure Enclave can set TENZRO_HUGGINGFACE_CREDENTIAL or
    /// TENZRO_UPSTREAM_API_KEY in the node's environment, or put it in the
    /// configuration file, unsealed at their own risk.
    #[command(name = "set")]
    Set {
        origin: CredentialOrigin,
        /// Data directory (defaults to the configured one).
        #[arg(long)]
        data_dir: Option<PathBuf>,
    },
    /// Remove the stored credential.
    #[command(name = "clear")]
    Clear {
        origin: CredentialOrigin,
        #[arg(long)]
        data_dir: Option<PathBuf>,
    },
    /// Say whether a credential is set, without showing it.
    #[command(name = "status")]
    Status {
        #[arg(long)]
        data_dir: Option<PathBuf>,
    },
}

#[derive(Debug, Subcommand)]
enum TpmAction {
    /// Create this node's persistent TPM keys, once per machine: the storage
    /// root, the machine attestation key and the node identity key (under
    /// the configured key namespace). The node only reads them and refuses
    /// to start until they exist. Idempotent: keys already in place are kept.
    /// Run as a user that can open /dev/tpmrm0, with the node stopped.
    #[command(name = "provision")]
    Provision,
    /// Sign, with this machine's TPM, for the machines listed in the file:
    /// machines with no TPM of their own, enrolled by the operator.
    #[command(name = "serve")]
    Serve {
        #[arg(long, value_name = "FILE")]
        config: PathBuf,
    },
    /// Run this machine's TPM key holder: make this boot's transport key,
    /// keep it in memory only, and carry the node's signing requests to the
    /// providers with the operator passkey's grant. Run it as its own
    /// service, so a node restart keeps the key and the grant; only a reboot
    /// needs a new grant.
    #[command(name = "key-holder")]
    KeyHolder {
        /// The socket to listen on.
        #[arg(long, value_name = "SOCKET")]
        socket: PathBuf,
        /// The providers: `<endpoint id>@<ip:port>[,<ip:port>...]`, several
        /// separated by `;` (the first is the primary).
        #[arg(long, value_name = "ID@ADDR")]
        provider: String,
        /// A further user id that may use the socket (the node's, when it
        /// runs as another user). This process's own user always may.
        #[arg(long, value_name = "UID")]
        allow_uid: Vec<u32>,
        /// How long one request to a provider may take, counting its wait
        /// for a turn at the provider's TPM.
        #[arg(long, default_value_t = 150)]
        request_timeout_secs: u64,
        /// Retries of a request the provider refused because its TPM line
        /// is full.
        #[arg(long, default_value_t = 5)]
        busy_retries: u32,
    },
    /// Print what the operator passkey signs to grant the key holder a key
    /// label: the holder's transport endpoint, the grant's end and the
    /// WebAuthn challenge (base64url).
    #[command(name = "grant-request")]
    GrantRequest {
        #[arg(long, value_name = "SOCKET")]
        socket: PathBuf,
        /// The key label enrolled for this machine at the provider.
        #[arg(long)]
        label: String,
        /// How long the grant lasts.
        #[arg(long, default_value_t = 24 * 30)]
        valid_hours: u64,
    },
    /// Give the key holder the grant: the passkey assertion over the
    /// challenge `grant-request` printed, each field base64url.
    #[command(name = "grant-install")]
    GrantInstall {
        #[arg(long, value_name = "SOCKET")]
        socket: PathBuf,
        #[arg(long)]
        label: String,
        /// The grant's end, as `grant-request` printed it.
        #[arg(long)]
        not_after_ms: u64,
        #[arg(long)]
        credential_id: String,
        #[arg(long)]
        authenticator_data: String,
        #[arg(long)]
        client_data_json: String,
        #[arg(long)]
        signature: String,
    },
    /// Open this machine's identity key at its provider through the key
    /// holder and sign a test message with it.
    #[command(name = "remote-check")]
    RemoteCheck {
        #[arg(long, value_name = "SOCKET")]
        key_holder: PathBuf,
        #[arg(long)]
        label: String,
    },
}

/// Runs the key holder until the process ends.
#[cfg(unix)]
async fn run_key_holder(
    socket: PathBuf,
    provider: &str,
    allow_uid: Vec<u32>,
    busy_retries: u32,
    request_timeout: std::time::Duration,
) -> Result<()> {
    let providers = tenzro_node::remote_tpm::parse_providers(provider)
        .map_err(|e| error::NodeError::Config(format!("--provider: {e}")))?;
    #[cfg(target_os = "linux")]
    // SAFETY: prctl(PR_SET_DUMPABLE, 0) has no memory preconditions; it keeps
    // the transport key out of core dumps and away from same-user ptrace.
    unsafe {
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
    }
    let mut holder = tenzro_node::tpm_key_holder::Holder::new(std::sync::Arc::new(
        tenzro_node::tpm_key_holder::IrohUpstream::new(providers).with_timeout(request_timeout),
    ))
    .map_err(error::NodeError::Config)?;
    holder = holder.with_busy_retries(busy_retries);
    let holder = std::sync::Arc::new(holder);
    println!(
        "tpm key holder: transport endpoint {} on {}",
        hex::encode(holder.endpoint_id()),
        socket.display()
    );
    tenzro_node::tpm_key_holder::serve(holder, &socket, allow_uid)
        .await
        .map_err(|e| error::NodeError::Other(format!("key holder: {e}")))
}

#[cfg(not(unix))]
async fn run_key_holder(
    _socket: PathBuf,
    _provider: &str,
    _allow_uid: Vec<u32>,
    _busy_retries: u32,
    _request_timeout: std::time::Duration,
) -> Result<()> {
    Err(error::NodeError::Config(
        "the TPM key holder needs a Unix socket, which this platform does not have".into(),
    ))
}

/// Prints what the operator passkey signs to grant the key holder `label`.
#[cfg(unix)]
fn run_grant_request(socket: PathBuf, label: &str, valid_hours: u64) -> Result<()> {
    use base64::Engine as _;
    let (endpoint, _) =
        tenzro_node::tpm_key_holder::holder_id(&socket).map_err(error::NodeError::Config)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| error::NodeError::Other(e.to_string()))?
        .as_millis() as u64;
    let not_after_ms = now + valid_hours.saturating_mul(3_600_000);
    let challenge = tenzro_node::remote_tpm::grant_challenge(&endpoint, label, not_after_ms);
    println!("endpoint_id {}", hex::encode(endpoint));
    println!("label {label}");
    println!("not_after_ms {not_after_ms}");
    println!(
        "webauthn_challenge {}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(challenge)
    );
    Ok(())
}

#[cfg(not(unix))]
fn run_grant_request(_socket: PathBuf, _label: &str, _valid_hours: u64) -> Result<()> {
    Err(error::NodeError::Config(
        "the TPM key holder needs a Unix socket, which this platform does not have".into(),
    ))
}

/// Gives the key holder the operator passkey's grant.
#[cfg(unix)]
fn run_grant_install(
    socket: PathBuf,
    label: String,
    not_after_ms: u64,
    credential_id: String,
    authenticator_data: String,
    client_data_json: String,
    signature: String,
) -> Result<()> {
    let (endpoint, _) =
        tenzro_node::tpm_key_holder::holder_id(&socket).map_err(error::NodeError::Config)?;
    let grant = tenzro_node::remote_tpm::TransportGrant {
        endpoint_id: hex::encode(endpoint),
        label,
        not_after_ms,
        credential_id,
        authenticator_data,
        client_data_json,
        signature,
    };
    let bytes = serde_json::to_vec(&grant).map_err(|e| error::NodeError::Other(e.to_string()))?;
    tenzro_node::tpm_key_holder::request(&socket, tenzro_node::tpm_key_holder::OP_GRANT, &bytes)
        .map_err(error::NodeError::Config)?;
    println!("grant installed until {not_after_ms}");
    Ok(())
}

#[cfg(not(unix))]
fn run_grant_install(
    _socket: PathBuf,
    _label: String,
    _not_after_ms: u64,
    _credential_id: String,
    _authenticator_data: String,
    _client_data_json: String,
    _signature: String,
) -> Result<()> {
    Err(error::NodeError::Config(
        "the TPM key holder needs a Unix socket, which this platform does not have".into(),
    ))
}

/// Opens the identity key at a provider and signs a test message with it.
async fn run_remote_check(key_holder: PathBuf, label: String) -> Result<()> {
    let config = tenzro_node::remote_tpm::RemoteConfig { label, key_holder };
    let outcome = tokio::task::spawn_blocking(move || -> std::result::Result<String, String> {
        // The node's own paths: the machine identity key through the signer
        // factory, and a derived node key through the derivation root.
        tenzro_node::identity_bootstrap::use_remote_tpm(config).map_err(|e| e.to_string())?;
        let signer = tenzro_device_key::signer::open_or_create(
            tenzro_types::did_derivation::MACHINE_KEY_LABEL,
        )
        .map_err(|e| e.to_string())?;
        let public = signer.public_key_sec1().map_err(|e| e.to_string())?;
        let message = b"tenzro/remote-check/v1";
        let sig = signer.sign(message).map_err(|e| e.to_string())?;
        let verified = tenzro_device_key::signer::verify_p256(&public, message, &sig);
        let root = tenzro_device_key::derive::DerivationRoot::open_or_create()
            .map_err(|e| e.to_string())?;
        let ed_public = root
            .ed25519_public("tenzro/remote-check/ed25519")
            .map_err(|e| e.to_string())?;
        let ed_sig = root
            .ed25519_sign("tenzro/remote-check/ed25519", message)
            .map_err(|e| e.to_string())?;
        Ok(format!(
            "backend {}\nidentity key {}\nidentity signature verifies {verified}\nderived root {}\nderived ed25519 key {}\nderived signature {}",
            signer.backend().as_str(),
            hex::encode(public),
            root.backend().as_str(),
            hex::encode(ed_public),
            hex::encode(ed_sig)
        ))
    })
    .await
    .map_err(|e| error::NodeError::Other(e.to_string()))?
    .map_err(error::NodeError::Config)?;
    println!("{outcome}");
    Ok(())
}

fn main() -> Result<()> {
    // A runtime host is started by re-running this executable as its
    // confinement launcher, which must confine itself while it is still
    // single-threaded: before the async runtime starts any thread.
    praecise_host::sandbox::enter_if_requested();
    // A model file's header is parsed by this executable re-run as a
    // locked-down child, which must lock itself down before any thread.
    #[cfg(feature = "inference")]
    tenzro_model::parse_jail::enter_if_requested();
    let cli = Cli::parse();
    let tuning = runtime_tuning(&cli)?;
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(cli.worker_threads.unwrap_or(tuning.worker_threads).max(1))
        .max_blocking_threads(tuning.max_blocking_threads)
        .enable_all()
        .build()?
        .block_on(run(cli))
}

/// The tier's defaults for the async runtime, fixed before it starts: the
/// tier and roles from the flags, or else the configuration file.
fn runtime_tuning(cli: &Cli) -> Result<tenzro_node::tier::Tuning> {
    let mut config = load_config(cli)?;
    if let Some(roles) = &cli.roles {
        config.roles = parse_roles(roles)?;
    }
    if let Some(tier) = &cli.tier {
        config.tier = tier.parse().map_err(error::NodeError::Config)?;
    }
    Ok(config
        .resolved_tier()
        .tuning(tenzro_node::tier::machine_cores()))
}

async fn run(mut cli: Cli) -> Result<()> {
    // Initialize logging
    init_logging(&cli.log_level, &cli.log_format)?;

    // Administrative subcommands run as one-shot RPC clients against a
    // *running* node and exit — they do not boot a node themselves. Any
    // hardware key one opens is the configured node's, under its namespace,
    // never the machine's default-labelled keys.
    if let Some(cmd) = cli.command.take() {
        let config = load_config(&cli)?;
        if let Some(namespace) = &config.hardware_key_namespace {
            tenzro_device_key::set_label_namespace(namespace)
                .map_err(|e| error::NodeError::Config(format!("hardware_key_namespace: {e}")))?;
        }
        configure_tpm(&config)?;
        return run_subcommand(cmd, &config).await;
    }

    // Install aws-lc-rs as the process-wide rustls CryptoProvider before any
    // TLS-using subsystem (reqwest, axum-rustls, iroh QUIC, hyper-rustls)
    // touches rustls. aws-lc-rs is the only mainstream rustls provider that
    // offers X25519MLKEM768 hybrid post-quantum key exchange (per the FIPS 203
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

    // The light build refuses the roles that run models before anything else,
    // naming them. The roles come from `--roles` or, without it, the file; a
    // `[connector]` section in the file serves the `ai` role from the
    // operator's own endpoint.
    let file_config = load_config(&cli)?;
    let requested_roles = match &cli.roles {
        Some(roles) => parse_roles(roles)?,
        None => file_config.roles.clone(),
    };
    if let Err(reason) =
        tenzro_node::engine_roles::check(&requested_roles, file_config.connector.is_some())
    {
        eprintln!("\n{reason}\n");
        return Err(error::NodeError::Config(reason));
    }

    // A machine with no TPM of its own may hold its identity key in another
    // machine's TPM, through a provider the operator enrolled it with.
    if let Some(socket) = &cli.tpm_key_holder {
        let label = cli
            .tpm_label
            .clone()
            .ok_or_else(|| error::NodeError::Config("--tpm-key-holder needs --tpm-label".into()))?;
        tenzro_node::identity_bootstrap::use_remote_tpm(tenzro_node::remote_tpm::RemoteConfig {
            label,
            key_holder: socket.clone(),
        })
        .map_err(error::NodeError::Config)?;
        tenzro_network::service::declare_identity_root(
            tenzro_network::service::IdentityRoot::TpmDelegated,
        );
    }

    // A machine with no TPM 2.0 or Secure Enclave refuses before anything
    // else: a node never runs without its identity key in hardware.
    if let Err(reason) = tenzro_node::identity_bootstrap::require_hardware_key_store() {
        eprintln!("\n{reason}\n");
        return Err(error::NodeError::Config(reason));
    }

    // A GPU build with no usable GPU or driver refuses before anything else,
    // naming the CPU build, rather than serving every layer on the CPU. It
    // depends on the machine only, not on the configuration or the genesis.
    #[cfg(feature = "inference")]
    tokio::task::spawn_blocking(tenzro_model::hardware_policy::verify_this_machine)
        .await
        .map_err(|e| error::NodeError::Config(format!("hardware check: {e}")))?
        .map_err(error::NodeError::Config)?;

    let config = node_config(&cli).await?;

    // Refuse to start on a TPM whose persistent keys were never provisioned:
    // the node only reads them, it never creates them.
    #[cfg(any(target_os = "linux", windows))]
    if !tenzro_node::identity_bootstrap::remote_tpm_configured() {
        tokio::task::spawn_blocking(tenzro_device_key::tpm_provision::check)
            .await
            .map_err(|e| error::NodeError::Other(format!("TPM check task failed: {e}")))?
            .map_err(|e| error::NodeError::Config(e.to_string()))?;
    }

    // No TPM 2.0 or Secure Enclave, or an identity key that does not open:
    // the node refuses to start. There is no keyless mode to fall back to.
    if let Err(reason) =
        tokio::task::spawn_blocking(tenzro_node::identity_bootstrap::require_hardware_identity)
            .await
            .map_err(|e| error::NodeError::Other(format!("hardware identity check failed: {e}")))?
    {
        // Printed as well as logged: the operator has to read and act on it.
        eprintln!("\n{reason}\n");
        return Err(error::NodeError::Config(reason));
    }

    // The calendar clock the node's own time rules read, from the genesis.
    if let Some(genesis) = &config.genesis {
        tenzro_node::calendar::install(
            (genesis.timestamp as i64).saturating_mul(1000),
            genesis.time.calendar_scale,
        );
    }

    // ONNX session limits, fixed before any model can load. Then refuse to
    // start on an NVIDIA machine this binary's ONNX Runtime cannot use.
    // Detection shells out to the GPU vendor tools, so it runs off the
    // async workers.
    #[cfg(feature = "inference")]
    {
        tenzro_model::onnx_session::install(tenzro_model::onnx_session::OnnxSettings::resolve(
            &config.onnx,
            std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(1),
        ));
        tokio::task::spawn_blocking(tenzro_model::onnx_session::verify_accelerators)
            .await
            .map_err(|e| error::NodeError::Config(format!("ONNX accelerator check: {e}")))??;
    }

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
            "Node configuration loaded"
        );
    }

    // One node per data directory, refused here rather than discovered later.
    //
    // Held for the whole process lifetime: the lock lives on the descriptor, so
    // binding it to a variable that outlives startup is what keeps it. The
    // kernel releases it however this process exits, including a SIGKILL, so a
    // crash never leaves a stale claim that blocks the next start.
    //
    // Taken *before* `TenzroNode::new`, which opens RocksDB. Two nodes over one
    // data directory would open the same database, keystore and snapshot tree;
    // RocksDB's own lock does catch that, but only deep inside storage
    // initialisation and with an error that names a path rather than a process.
    let _instance_lock = match tenzro_node::single_instance::acquire(&config.data_dir) {
        Ok(lock) => {
            info!(
                data_dir = %lock.data_dir().display(),
                "Single-instance lock acquired"
            );
            lock
        }
        Err(e) => {
            // Printed as well as logged: this is the one failure an operator
            // has to read and act on, and a structured log line buries the
            // instructions.
            eprintln!("\n{e}\n");
            return Err(error::NodeError::Other(
                "refusing to start a second node over the same data directory".to_string(),
            ));
        }
    };

    // The operator's own origin credential, when they set one. Only whether
    // it is set and where it came from is logged.
    match tenzro_node::credentials::install_operator_credential(
        &config.data_dir,
        config.huggingface_credential.as_ref(),
    ) {
        Ok(Some(source)) => info!(?source, "Operator Hugging Face credential set"),
        Ok(None) => {}
        Err(e) => {
            return Err(error::NodeError::Config(format!(
                "operator credential: {e}"
            )));
        }
    }

    // Every address this node intends to bind, checked together so an operator
    // moving listeners is told about all of them at once instead of restarting
    // to discover the next conflict.
    if let Err(e) = tenzro_node::single_instance::check_ports(&[
        ("json-rpc", &config.rpc_addr),
        ("web api", &config.web_addr),
        ("mcp", &config.mcp_addr),
        ("a2a", &config.a2a_addr),
    ]) {
        eprintln!("\n{e}\n");
        return Err(error::NodeError::Other(
            "one or more listen addresses are already in use".to_string(),
        ));
    }

    // Create shutdown broadcast channel — all subsystems subscribe to this
    let (shutdown_tx, _) = broadcast::channel::<()>(1);

    // Create and start the node
    let mut node = TenzroNode::new(config.clone()).await?;

    // Weak-subjectivity checkpoint and state sync. The checkpoint comes from
    // the command line, or else from the genesis `[weak_subjectivity]` block;
    // either way it is a finalized block, by hash, trusted out of band.
    //
    // State-sync peers come from `--state-sync-from`. Endpoint keys are per
    // boot, so no file can name them in advance; what a peer serves is checked
    // against the checkpoint's state root, not trusted for who it is.
    let checkpoint: Option<(u64, [u8; 32])> = match (&cli.checkpoint_hash, cli.checkpoint_height) {
        (Some(hash_hex), Some(height)) => {
            Some((height, parse_hash32(hash_hex, "--checkpoint-hash")?))
        }
        _ => match config
            .genesis
            .as_ref()
            .and_then(|g| g.weak_subjectivity.as_ref())
        {
            Some(ws) => Some((
                ws.height,
                parse_hash32(
                    &ws.block_hash_hex,
                    "genesis weak_subjectivity.block_hash_hex",
                )?,
            )),
            None => None,
        },
    };
    if let Some((height, hash)) = checkpoint {
        node.set_weak_subjectivity_anchor(height, hash);
        info!(
            height,
            block_hash = %format!("0x{}", hex::encode(hash)),
            "Weak-subjectivity checkpoint installed"
        );
    }

    let peers = parse_state_sync_peers(config.state_sync_from.iter().chain(&cli.state_sync_from))?;
    if !peers.is_empty() {
        if checkpoint.is_none() {
            return Err(error::NodeError::Other(
                "state sync needs a weak-subjectivity checkpoint: pass --checkpoint-height and \
                 --checkpoint-hash, or use a genesis with a [weak_subjectivity] block"
                    .to_string(),
            ));
        }
        info!(peers = peers.len(), "State sync configured");
        node.set_state_sync_peers(peers);
    }
    if let (Some(path), Some(digest)) = (&cli.recovery_manifest, &cli.recovery_digest) {
        node.set_recovery(tenzro_node::recovery::RecoveryRequest::load(
            path,
            digest,
            cli.recovery_confirm.as_deref(),
            checkpoint,
            cli.recovery_check,
        )?);
    }
    match node.start().await {
        Err(error::NodeError::RecoveryChecked(_)) => return Ok(()),
        other => other?,
    }

    // Start RPC server
    let node_arc = Arc::new(node);
    node_arc.bind_self();

    // Every model runtime asks this before running a model, so a gated model
    // refuses a caller without its key on every protocol, including one that
    // never asks for itself. Installed before any listener starts.
    tenzro_model::access::install(Arc::new(
        tenzro_node::inference_admission::RuntimeAccess::for_node(&node_arc),
    ));

    // A validator checks audit commitments and bridge reserves each epoch.
    tenzro_node::agent_audit::spawn_watchers(&node_arc);
    tenzro_node::agent_audit::spawn_committer(&node_arc);

    // Standby replicas: weights staged in host memory, activated on a
    // failover or a surge.
    #[cfg(feature = "inference")]
    tenzro_node::standby::start(&node_arc).await;

    // Continuity sessions: KV deltas to each session's successor, and the
    // chains this node holds as one.
    #[cfg(feature = "inference")]
    tenzro_node::kv_continuity::start(&node_arc);
    tenzro_node::relay_health::start(&node_arc);

    // Embedding, forecast, vision and the other ONNX models a previous process
    // served. Their loaders need the shared node, so this is the first point
    // they can run; in the background, because a 2 GB bundle load must not hold
    // up the RPC server coming up.
    #[cfg(feature = "inference")]
    tokio::spawn(tenzro_node::rpc::restore_multimodal_models(Arc::clone(
        &node_arc,
    )));

    // Territorial licence enforcement. Configured before any request is served,
    // because the default is to enforce and a restricted model must never be
    // servable in the window before this runs.
    {
        use tenzro_node::territory::{
            CountryDb, EnforcementMode, LocalCallerPolicy, TerritoryEnforcer,
        };
        let mode = match cli.territory_mode.trim().to_ascii_lowercase().as_str() {
            "enforce" => EnforcementMode::Enforce,
            "refuse-restricted" | "refuse_restricted" => EnforcementMode::RefuseRestricted,
            other => {
                // Refuse to start rather than silently fall back: guessing here
                // could mean serving a restricted model the operator meant to
                // withhold, or withholding one they meant to serve.
                return Err(error::NodeError::Other(format!(
                    "--territory-mode must be enforce or refuse-restricted (got '{other}')"
                )));
            }
        };

        let db = match (&cli.territory_db, mode) {
            (Some(path), _) => {
                let label = cli
                    .territory_db_label
                    .clone()
                    .unwrap_or_else(|| path.display().to_string());
                match CountryDb::open(path, label) {
                    Ok(db) => Some(db),
                    // A database that was named but cannot be opened is an
                    // operator error, not a reason to serve unchecked.
                    Err(e) => {
                        return Err(error::NodeError::Other(format!("--territory-db: {e}")));
                    }
                }
            }
            (None, EnforcementMode::Enforce) => {
                tracing::warn!(
                    "no --territory-db: territorially-restricted models will be refused. \
                     Other models are unaffected."
                );
                None
            }
            (None, _) => None,
        };

        let (local_policy, declared_local_country) = match &cli.local_territory {
            Some(cc) => (LocalCallerPolicy::DeclareInside, Some(cc.to_uppercase())),
            None => (LocalCallerPolicy::Refuse, None),
        };

        *node_arc.territory.write() = TerritoryEnforcer {
            mode,
            db,
            trusted_proxies: cli.trusted_proxy.clone(),
            local_policy,
            declared_local_country,
        };
    }

    #[cfg(feature = "inference")]
    {
        let restore_node = node_arc.clone();
        tokio::spawn(async move {
            // Warm the chat tier. Its weights are restored as an
            // *intention* to serve and loaded on first use, which means the
            // first caller after every restart pays the whole load — 70s for a
            // 22 GB GGUF — and callers arriving during it are told to come
            // back rather than served. On a provider node that is backwards:
            // the node is idle at boot, which is exactly when the load is
            // cheapest, and busy later when it is most disruptive.
            //
            // Sequential on purpose. Warming several large models at once
            // competes for the same memory bandwidth and makes all of them
            // late, and a failure here is not fatal — the lazy path still
            // works, so a model that cannot be warmed is left for first use.
            let served: Vec<String> = restore_node
                .served_models
                .iter()
                .map(|e| e.key().clone())
                .collect();
            for model_id in served {
                match restore_node.ensure_local_model_loaded(&model_id).await {
                    Ok(true) => info!(%model_id, "Pre-warmed served model"),
                    Ok(false) => {}
                    Err(e) => warn!(%model_id, error = %e, "Could not pre-warm served model"),
                }
            }
        });
    }

    // GPU-wedge watchdog (validator-safe): every 60s, flag any model whose
    // in-flight work has been continuous for >10 min — the signature of a wedged
    // decode that #46/#55 could not catch. Log-only: it never force-kills a
    // kernel or touches consensus; the loud WARN is the operator signal and the
    // router already steers away from an unhealthy provider.
    #[cfg(feature = "inference")]
    {
        let wd_node = node_arc.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(60));
            let deadline = std::time::Duration::from_secs(600);
            loop {
                tick.tick().await;
                if let Some(rt) = wd_node.model_runtime_arc() {
                    for (model_id, age) in rt.stalled_inflight(deadline) {
                        warn!(
                            %model_id,
                            age_s = age.as_secs(),
                            "GPU-wedge watchdog: model in-flight with no completion past deadline — suspected stall (routing steers away; no force-kill)"
                        );
                    }
                }
            }
        });
    }

    let mut rpc_server = RpcServer::new(node_arc.clone(), config.rpc_addr.clone());

    // Every payment entry point settles through the gateway, which holds a
    // delegated payer to its consensus Terms.
    tenzro_node::terms_gate::install(&node_arc);

    // Serving models is what the network pays providers for, so a node in the
    // `ai` role gates its inference routes by default, settling to its own
    // validator address unless the operator named a different recipient or
    // opted out. The amount defaults to whatever the config carries (0 on a
    // freshly launched node), so the gate can be wired and proven before a
    // real price is set.
    let default_recipient = node_arc.local_validator_address().map(|a| a.to_string());
    let payments = config
        .payments
        .effective(&config.roles, default_recipient.as_deref());

    // Access control first, and unconditionally: a model's visibility is
    // enforced because the operator published it that way, not because they
    // also configured a way to charge for it.
    rpc_server = rpc_server.with_inference_admission(Arc::new(
        tenzro_node::inference_admission::NodeInferenceAdmission::for_node(&node_arc),
    ));

    if payments.gate_on
        && let Some(gateway) = node_arc.payment_gateway()
    {
        let mut rpc_gate = tenzro_payments::middleware::PaymentGateMiddleware::new(
            gateway.clone(),
            tenzro_payments::middleware::PaymentGateConfig {
                default_amount: payments.amount,
                default_asset: payments.asset.clone(),
                recipient: payments.recipient.clone(),
                default_protocol: payments.protocol.clone(),
            },
            gateway.challenge_store(),
        );
        rpc_gate = tenzro_node::payment_gate::with_metering(
            &node_arc,
            rpc_gate,
            payments.metered_settlement,
        );
        // Same access-aware authorizer as the Web API: a caller the access
        // policy names is served without x402 on the RPC inference routes
        // (/v1/chat/completions), and gated models refuse an unnamed caller
        // rather than issuing a pay-per-call challenge.
        let rpc_admission =
            Arc::new(tenzro_node::inference_admission::NodeInferenceAdmission::for_node(&node_arc));
        rpc_gate = rpc_gate.with_inference_admission(rpc_admission);
        info!(
            recipient = %payments.recipient,
            amount = %payments.amount,
            asset = %payments.asset,
            "HTTP 402 payment gate enabled for RPC /v1/chat/completions",
        );
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
    // so the `tenzro_network_*` metrics (gossip, dial rate limits,
    // peer counts, connection totals) are served from the same `/metrics`
    // endpoint as the node-level counters.
    if let Some(network) = node_arc.network() {
        web_state = web_state.with_network_metrics_registry(network.metrics_registry());
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
    let mut web_server =
        web::WebServer::new(config.web_addr.clone()).with_state_arc(web_state.clone());

    if payments.gate_on {
        if let Some(gateway) = node_arc.payment_gateway() {
            let mut middleware = tenzro_payments::middleware::PaymentGateMiddleware::new(
                gateway.clone(),
                tenzro_payments::middleware::PaymentGateConfig {
                    default_amount: payments.amount,
                    default_asset: payments.asset.clone(),
                    recipient: payments.recipient.clone(),
                    default_protocol: payments.protocol.clone(),
                },
                gateway.challenge_store(),
            );
            middleware = tenzro_node::payment_gate::with_metering(
                &node_arc,
                middleware,
                payments.metered_settlement,
            );
            let admission = Arc::new(
                tenzro_node::inference_admission::NodeInferenceAdmission::for_node(&node_arc),
            );
            middleware = middleware.with_inference_admission(admission);
            let setup = web::server::PaymentGateSetup::new(
                middleware,
                tenzro_node::access::web_pricing(node_arc.clone()),
            );
            info!(
                protocol = %payments.protocol,
                amount = %payments.amount,
                asset = %payments.asset,
                recipient = %payments.recipient,
                "HTTP 402 payment gate enabled for Web API",
            );
            web_server = web_server.with_payment_gate(setup);
        } else {
            tracing::warn!(
                "payment gate active but TenzroPaymentGateway not initialised; \
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
    // iroh-transport surface operate against the **same**
    // `TaskManager` — tasks created over either transport land in the same
    // table.
    let a2a_addr = config.a2a_addr.clone();
    let a2a_state = a2a::server::build_a2a_state(node_arc.clone(), web_state);

    // Install the iroh-side A2A dispatcher. The iroh
    // router registered the `tenzro/a2a` ALPN at bind time backed by a
    // deferred dispatcher (see `init_ai_infrastructure`); now that we
    // have the shared `Arc<A2aState>`, swap the real one in. Peers that
    // connected before this point received `-32603` "dispatcher not yet
    // bound" envelopes — after this swap they get the full A2A surface.
    if let Some(deferred) = node_arc.iroh_a2a_dispatcher.as_ref() {
        let dispatcher: Arc<dyn tenzro_iroh::JsonRpcDispatcher> = Arc::new(
            a2a::iroh_transport::IrohA2aDispatcher::new(a2a_state.clone()),
        );
        deferred.set(dispatcher);
        info!("A2A dispatcher installed on iroh transport (ALPN tenzro/a2a)");
    }

    // Install the iroh-side MCP handler. The iroh
    // router registered the `tenzro/mcp` ALPN at bind time backed by a
    // deferred handler (see `init_ai_infrastructure`); now that we have
    // `Arc<TenzroNode>` we swap the real one in. Each
    // inbound bi-stream becomes a full rmcp session (`AsyncRwTransport`
    // line-delimited JSON-RPC — same wire format as stdio MCP).
    if let Some(deferred) = node_arc.iroh_mcp_handler.as_ref() {
        let handler: Arc<dyn tenzro_iroh::McpStreamHandler> =
            Arc::new(mcp::iroh_transport::IrohMcpHandler::new(node_arc.clone()));
        deferred.set(handler);
        info!("MCP handler installed on iroh transport (ALPN tenzro/mcp)");
    }

    // Install the iroh-side inference dispatcher. The iroh router registered
    // the `tenzro/infer` ALPN at bind time backed by a deferred dispatcher
    // (see `init_ai_infrastructure`); now that we have `Arc<TenzroNode>` we
    // swap the real one in. Consumers dial a provider's `EndpointId` on this
    // ALPN and send a `tenzro_chat` frame or an OpenAI chat completion.
    if let Some(deferred) = node_arc.iroh_infer_dispatcher.as_ref() {
        let dispatcher: Arc<dyn tenzro_iroh::RequestHandler> =
            Arc::new(infer::IrohInferDispatcher::new(node_arc.clone()));
        deferred.set(dispatcher);
        info!("Inference dispatcher installed on iroh transport (ALPN tenzro/infer)");
    }

    // Start the autotune sampler. Needs `Arc<TenzroNode>` to read the three
    // bounds, so it starts here rather than in `init_ai_infrastructure`.
    //
    // It runs whether or not it is enabled: when disabled it observes and
    // records what it *would* have done, which is how an operator builds
    // confidence before letting a node change its own configuration. The light
    // build has no model to tune.
    #[cfg(feature = "inference")]
    {
        let sampler = tenzro_node::autotune_sampler::AutotuneSampler::spawn(
            node_arc.clone(),
            config.autotune.clone(),
        );
        *node_arc.autotune.write() = Some(sampler);
    }

    // MoE replication repair. Each pass raises replication on the experts
    // this node was rendezvous-selected to hold; nodes serving no experts
    // return immediately, so this is spawned unconditionally.
    #[cfg(feature = "inference")]
    moe::spawn_moe_repair_loop(node_arc.clone());
    tenzro_node::compute_index_reporter::spawn_fee_rate_reporter(node_arc.clone());
    tenzro_node::sla_attest::spawn_probe_scheduler(node_arc.clone());
    tenzro_node::sla_attest::spawn_attestation_submitter(node_arc.clone());
    tenzro_node::sla_attest::spawn_burst_challenge_scheduler(node_arc.clone());
    tenzro_node::optimistic::spawn_reviewer(node_arc.clone());
    tenzro_node::da_retention::spawn(node_arc.clone());
    tenzro_node::beacon::spawn_contributor(node_arc.clone());
    tenzro_node::hardware_possession::spawn(node_arc.clone());
    tenzro_node::identity_bootstrap::keep_chain_policies(node_arc.clone());

    let a2a_shutdown_rx = shutdown_tx.subscribe();
    let a2a_addr_https = a2a_addr.clone();
    let mut a2a_handle = tokio::spawn(async move {
        if let Err(e) =
            a2a::server::start_a2a_server_with_shutdown(a2a_addr_https, a2a_state, a2a_shutdown_rx)
                .await
        {
            error!("A2A server error: {}", e);
        }
    });

    // Wait for shutdown signal (Ctrl+C or SIGTERM)
    info!("Node is running. Press Ctrl+C to stop.");
    let shutdown_signal = async {
        let ctrl_c = tokio::signal::ctrl_c();

        #[cfg(unix)]
        {
            let mut sigterm =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    .expect("Failed to install SIGTERM handler");
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
async fn run_subcommand(cmd: Command, config: &NodeConfig) -> Result<()> {
    match cmd {
        Command::Init {
            data_dir,
            stake,
            format,
        } => run_init(data_dir, stake, format),
        Command::GracefulExit {
            rpc_url,
            max_wait_secs,
            force,
        } => run_graceful_exit(rpc_url, max_wait_secs, force).await,
        Command::ValidatorEntry {
            data_dir,
            stake,
            relay_url,
        } => run_validator_entry(data_dir, stake, relay_url),
        Command::Access {
            data_dir,
            preset,
            admins,
            remove_admins,
            token_ttl_secs,
            show,
            page,
            rpc_url,
        } => run_access(AccessArgs {
            data_dir,
            preset,
            admins,
            remove_admins,
            token_ttl_secs,
            show,
            page,
            rpc_url,
        }),
        Command::Backup {
            data_dir,
            dest,
            rate_mb,
        } => run_backup(data_dir, dest, rate_mb),
        Command::Credentials { action } => run_credentials(action, config),
        Command::Tpm {
            action: TpmAction::Provision,
        } => run_tpm_provision(),
        Command::Tpm {
            action: TpmAction::Serve { config },
        } => tenzro_node::remote_tpm::serve(&config).await,
        Command::Tpm {
            action:
                TpmAction::KeyHolder {
                    socket,
                    provider,
                    allow_uid,
                    request_timeout_secs,
                    busy_retries,
                },
        } => {
            run_key_holder(
                socket,
                &provider,
                allow_uid,
                busy_retries,
                std::time::Duration::from_secs(request_timeout_secs),
            )
            .await
        }
        Command::Tpm {
            action:
                TpmAction::GrantRequest {
                    socket,
                    label,
                    valid_hours,
                },
        } => run_grant_request(socket, &label, valid_hours),
        Command::Tpm {
            action:
                TpmAction::GrantInstall {
                    socket,
                    label,
                    not_after_ms,
                    credential_id,
                    authenticator_data,
                    client_data_json,
                    signature,
                },
        } => run_grant_install(
            socket,
            label,
            not_after_ms,
            credential_id,
            authenticator_data,
            client_data_json,
            signature,
        ),
        Command::Tpm {
            action: TpmAction::RemoteCheck { key_holder, label },
        } => run_remote_check(key_holder, label).await,
        Command::Hardware => run_hardware(config),
        Command::Doctor {
            json,
            allow_inbound,
        } => {
            let binary = tenzro_node::doctor::current_binary();
            if allow_inbound {
                let port = config.iroh.bind_addr.port();
                match tenzro_node::host_firewall::allow(&binary, port) {
                    Ok(done) => println!("{done}\n"),
                    Err(e) => return Err(error::NodeError::Config(e)),
                }
            }
            let report = tenzro_node::doctor::report(config, &binary).await;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&report).unwrap_or_default()
                );
            } else {
                print!("{}", tenzro_node::doctor::render(&report));
            }
            Ok(())
        }
        Command::Restore {
            data_dir,
            snapshot,
            chain_id,
            genesis_hash,
            genesis_committee_root,
            proof_from,
            proof,
            handover_program,
        } => {
            let handover_program = handover_program
                .map(|h| hex32(&h, "--handover-program"))
                .transpose()?;
            let anchor = tenzro_consensus::light_client::GenesisAnchor {
                chain_id,
                genesis_hash: hex32(&genesis_hash, "--genesis-hash")?,
                committee_root: hex32(&genesis_committee_root, "--genesis-committee-root")?,
            };
            run_restore(
                data_dir,
                snapshot,
                anchor,
                proof_from,
                proof,
                handover_program,
            )
            .await
        }
        Command::ProverInputs { rpc_url, out } => {
            let segment = tenzro_node::storage_maintenance::fetch_segment(&rpc_url, None).await?;
            let epochs = tenzro_node::proof_log::write_prover_inputs(&segment, &out)?;
            match (epochs.first(), epochs.last()) {
                (Some(first), Some(last)) => println!(
                    "wrote the inputs of epochs {first}..={last} to {}",
                    out.display()
                ),
                _ => println!(
                    "the chain proof reaches epoch {}; no handover since",
                    segment.first_epoch()
                ),
            }
            Ok(())
        }
    }
}

/// `tenzro-node hardware`: the build flavour, the GPUs it can drive, the
/// ONNX Runtime execution providers it will use, and the startup verdict.
/// One `key: value` line each, so install scripts can read them.
#[cfg(not(feature = "inference"))]
fn run_hardware(_config: &NodeConfig) -> Result<()> {
    // The light build drives no GPU and links no ONNX Runtime, so there is no
    // accelerator to check.
    println!("build: light");
    println!("gpus: 0");
    println!("onnx: none");
    println!("startup: ok");
    Ok(())
}

/// `tenzro-node hardware` for a build with the model engines.
#[cfg(feature = "inference")]
fn run_hardware(config: &NodeConfig) -> Result<()> {
    use tenzro_model::hardware_policy::{BuildFlavour, usable_accelerators};
    use tenzro_model::onnx_session;
    let flavour = BuildFlavour::current();
    let gpus = usable_accelerators();
    println!("build: {}", flavour.label());
    println!("gpus: {gpus}");
    onnx_session::install(onnx_session::OnnxSettings::resolve(
        &config.onnx,
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1),
    ));
    let onnx = onnx_session::accelerators()
        .map(|plan| plan.iter().map(|a| a.name()).collect::<Vec<_>>())
        .map_err(|e| error::NodeError::Config(format!("ONNX accelerator check: {e}")));
    // A build that loads ONNX Runtime at run time (Intel macOS) and does not
    // find it starts without ONNX models; the report says so.
    let runtime_unavailable = onnx_session::runtime_unavailable();
    match (&onnx, &runtime_unavailable) {
        (_, Some(cause)) => println!("onnx: unavailable ({cause})"),
        (Ok(names), None) if names.is_empty() => println!("onnx: CPU"),
        (Ok(names), None) => println!("onnx: {}", names.join(",")),
        (Err(e), None) => println!("onnx: refused ({e})"),
    }
    let onnx = if runtime_unavailable.is_some() { Ok(Vec::new()) } else { onnx };
    // A build whose GPU backend has no ONNX Runtime provider (Vulkan) starts
    // and refuses ONNX models one by one; for every other build an ONNX
    // runtime that cannot use this machine's accelerator stops it.
    let onnx = if flavour.accelerates_onnx() {
        onnx.map(|_| ())
    } else {
        Ok(())
    };
    let verdict = tenzro_model::hardware_policy::check_startup(flavour, gpus)
        .map_err(error::NodeError::Config)
        .and(onnx);
    match &verdict {
        Ok(()) => println!("startup: ok"),
        Err(e) => println!("startup: refused ({e})"),
    }
    verdict
}

struct AccessArgs {
    data_dir: Option<PathBuf>,
    preset: Option<String>,
    admins: Vec<String>,
    remove_admins: Vec<String>,
    token_ttl_secs: Option<u64>,
    show: bool,
    page: bool,
    rpc_url: String,
}

/// Read one answer from the terminal; empty keeps `default`.
fn ask(question: &str, default: &str) -> Result<String> {
    use std::io::Write;
    print!("{question} [{default}]: ");
    std::io::stdout().flush()?;
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    let line = line.trim();
    Ok(if line.is_empty() {
        default.to_string()
    } else {
        line.to_string()
    })
}

/// `tenzro-node access`: the access wizard.
fn run_access(args: AccessArgs) -> Result<()> {
    use tenzro_node::access::{AccessPolicyStore, issue_page_ticket, render_policy};
    use tenzro_types::node_access::Rule;
    let data_dir = args
        .data_dir
        .map(tenzro_types::paths::expand_tilde)
        .unwrap_or_else(tenzro_types::paths::default_data_dir);
    std::fs::create_dir_all(&data_dir)?;
    let config_err = |e: String| error::NodeError::Config(e);
    let store = AccessPolicyStore::open(&data_dir).map_err(config_err)?;
    if args.page {
        let ticket = issue_page_ticket(&data_dir).map_err(config_err)?;
        println!("{}/access#{ticket}", args.rpc_url.trim_end_matches('/'));
        println!("Open it on this machine within 15 minutes.");
        return Ok(());
    }
    let mut policy = (*store.policy()).clone();
    if args.show {
        print!("{}", render_policy(&policy).map_err(config_err)?);
        return Ok(());
    }
    let interactive = args.preset.is_none()
        && args.admins.is_empty()
        && args.remove_admins.is_empty()
        && args.token_ttl_secs.is_none();
    let preset = if interactive {
        println!("Who may use this node's services (RPC, MCP, A2A, OpenAI, files, web, iroh)?");
        println!("  open              anyone");
        println!("  signed_in         anyone signed in with a passkey or hardware key");
        println!("  agents_with_terms agents acting under consensus Terms");
        println!("  closed            nobody but administrators");
        Some(ask("Preset", "open")?)
    } else {
        args.preset
    };
    if let Some(name) = preset {
        policy.default_rule = Rule::preset(&name).ok_or_else(|| {
            config_err(format!(
                "unknown preset '{name}': open, closed, signed_in or agents_with_terms"
            ))
        })?;
    }
    let mut admins = args.admins;
    if interactive {
        let line = ask(
            "Administrator DIDs besides the operator, comma separated",
            &policy.admins.join(","),
        )?;
        policy.admins.clear();
        admins = line
            .split(',')
            .map(str::trim)
            .filter(|d| !d.is_empty())
            .map(str::to_string)
            .collect();
    }
    for did in admins {
        if !policy.admins.contains(&did) {
            policy.admins.push(did);
        }
    }
    policy.admins.retain(|d| !args.remove_admins.contains(d));
    if let Some(ttl) = args.token_ttl_secs {
        policy.token_ttl_secs = ttl;
    }
    let version = store
        .set(policy, "tenzro-node access")
        .map_err(config_err)?;
    println!(
        "Access policy version {version} written to {}.",
        data_dir.join(tenzro_node::access::POLICY_FILE).display()
    );
    Ok(())
}

/// `tenzro-node backup`: incremental copy of the newest epoch snapshot.
/// Apply the `[tpm]` limits to every TPM command this process sends. On a
/// platform without a TPM backend there is nothing to limit.
fn configure_tpm(config: &NodeConfig) -> Result<()> {
    #[cfg(any(target_os = "linux", windows))]
    tenzro_device_key::tpm_exec::configure(tenzro_device_key::tpm_exec::Limits {
        call_timeout: std::time::Duration::from_secs(config.tpm.call_timeout_secs),
        signs_per_second: config.tpm.signs_per_second,
        quotes_per_second: config.tpm.quotes_per_second,
    })
    .map_err(|e| error::NodeError::Config(format!("[tpm]: {e}")))?;
    #[cfg(target_os = "linux")]
    tenzro_device_key::derive_tpm::set_authorization_handle(config.tpm.root_authorization_handle)
        .map_err(|e| error::NodeError::Config(format!("[tpm] root_authorization_handle: {e}")))?;
    #[cfg(not(any(target_os = "linux", windows)))]
    let _ = config;
    Ok(())
}

#[cfg(any(target_os = "linux", windows))]
fn run_tpm_provision() -> Result<()> {
    use tenzro_device_key::tpm_provision::Slot;
    let report = tenzro_device_key::tpm_provision::provision()
        .map_err(|e| error::NodeError::Other(e.to_string()))?;
    for (what, (handle, slot)) in [
        ("storage root", report.storage_root),
        ("attestation key", report.attestation),
        ("node identity key", report.identity),
    ] {
        let state = match slot {
            Slot::Present => "already present",
            Slot::Created => "created",
        };
        println!("{what:<18} 0x{handle:08x}  {state}");
    }
    match report.endorsement_key {
        Some(ek) => println!(
            "endorsement key    0x{:08x}  {}, manufacturer-certified {}",
            ek.handle,
            match ek.slot {
                Slot::Present => "already present",
                Slot::Created => "made persistent",
            },
            ek.kind
        ),
        None if report.uncertified_endorsement_key => println!(
            "endorsement key    0x{:08x}  present, but the TPM holds no manufacturer certificate for an EK",
            tenzro_device_key::tpm_wire::EK_ECC_PERSISTENT_HANDLE
        ),
        None => println!(
            "endorsement key    missing: this TPM holds no manufacturer-certified EK and none at 0x{:08x}",
            tenzro_device_key::tpm_wire::EK_ECC_PERSISTENT_HANDLE
        ),
    }
    // The identity the node signs in as and the account it earns into: what
    // `operator_did` and `payments.recipient` name when this machine operates
    // the node itself.
    let did = tenzro_node::identity_bootstrap::machine_did()
        .ok_or_else(|| error::NodeError::Other("the node identity key does not open".into()))?;
    println!("{:<18} {did}", "machine DID");
    let wallet = tenzro_device_key::HardwareHybridSigner::open_or_create(
        tenzro_node::machine_admission::MACHINE_WALLET_KEY_LABEL,
    )
    .map_err(|e| error::NodeError::Other(format!("the node account key: {e}")))?;
    let account = tenzro_crypto::composite::HybridSigner::public_key(&wallet).account_slot();
    println!("{:<18} 0x{}", "node account", hex::encode(account));
    Ok(())
}

#[cfg(not(any(target_os = "linux", windows)))]
fn run_tpm_provision() -> Result<()> {
    Err(error::NodeError::Config(
        "TPM provisioning needs a TPM 2.0 (Linux /dev/tpmrm0 or Windows TPM Base Services)".into(),
    ))
}

fn run_backup(data_dir: Option<PathBuf>, dest: PathBuf, rate_mb: u64) -> Result<()> {
    let data_dir = data_dir
        .map(tenzro_types::paths::expand_tilde)
        .unwrap_or_else(tenzro_types::paths::default_data_dir);
    lower_own_priority();
    let r = tenzro_node::storage_maintenance::backup_latest(&data_dir, &dest, rate_mb << 20)?;
    if r.already_present {
        println!("{} is already backed up", r.dest.display());
    } else {
        println!(
            "backed up to {}: {} files copied ({} MiB), {} unchanged SST files linked",
            r.dest.display(),
            r.copied_files,
            r.copied_bytes >> 20,
            r.linked_files
        );
    }
    Ok(())
}

fn hex32(s: &str, what: &str) -> Result<[u8; 32]> {
    hex::decode(s.trim_start_matches("0x"))
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| error::NodeError::Config(format!("{what} must be 32 bytes of hex")))
}

/// `tenzro-node restore`: rebuild the store from a verified snapshot.
async fn run_restore(
    data_dir: Option<PathBuf>,
    snapshot: PathBuf,
    anchor: tenzro_consensus::light_client::GenesisAnchor,
    proof_from: Option<String>,
    proof: Option<PathBuf>,
    handover_program: Option<[u8; 32]>,
) -> Result<()> {
    use tenzro_node::storage_maintenance as sm;
    let data_dir = data_dir
        .map(tenzro_types::paths::expand_tilde)
        .unwrap_or_else(tenzro_types::paths::default_data_dir);
    let proof = match (proof_from, proof) {
        (Some(peer), _) => {
            // The snapshot names the checkpoint to ask for; the answer is
            // verified like any other proof.
            let named = sm::snapshot_proof(&snapshot)?.checkpoint().clone();
            Some(sm::fetch_certification(&peer, named.epoch, named.index).await?)
        }
        (None, Some(file)) => {
            let bytes = std::fs::read(&file)
                .map_err(|e| error::NodeError::Config(format!("read {}: {e}", file.display())))?;
            Some(sm::decode_proof(&bytes).map_err(|e| {
                error::NodeError::Config(format!(
                    "{} is not a checkpoint proof: {e}",
                    file.display()
                ))
            })?)
        }
        (None, None) => None,
    };
    let cp = sm::restore(&snapshot, &data_dir, &anchor, proof, handover_program)?;
    println!(
        "restored {} from checkpoint {} (epoch {}); state at height {} verified against its certified root",
        data_dir.join("db").display(),
        cp.index,
        cp.epoch,
        cp.state_height
    );
    Ok(())
}

/// Idle CPU and I/O priority for a bulk copy running beside the node.
fn lower_own_priority() {
    // SAFETY: plain calls on this process with constant arguments.
    #[cfg(unix)]
    unsafe {
        libc::setpriority(libc::PRIO_PROCESS, 0, 19);
        #[cfg(target_os = "linux")]
        libc::syscall(libc::SYS_ioprio_set, 1, 0, 3 << 13);
    }
    // Background mode lowers both the CPU and the I/O priority.
    #[cfg(windows)]
    unsafe {
        use windows_sys::Win32::System::Threading::{
            GetCurrentProcess, PROCESS_MODE_BACKGROUND_BEGIN, SetPriorityClass,
        };
        SetPriorityClass(GetCurrentProcess(), PROCESS_MODE_BACKGROUND_BEGIN);
    }
}

/// `tenzro-node validator-entry` — this machine's `[[validators]]` genesis
/// entry: the node account, the public halves of the hardware consensus
/// key, the node key, both keys' proofs of possession, and the relay the
/// validator is reachable through. Refuses on a machine without a TPM 2.0 or
/// Secure Enclave.
fn run_validator_entry(
    data_dir: Option<PathBuf>,
    stake: u64,
    relay_url: Option<url::Url>,
) -> Result<()> {
    let data_dir = data_dir
        .map(tenzro_types::paths::expand_tilde)
        .unwrap_or_else(tenzro_types::paths::default_data_dir);
    let mut entry = tenzro_node::config::GenesisValidator::from_local_hardware(&data_dir, stake)?;
    entry.relay = relay_url.map(|u| u.to_string());
    print!("{}", entry.to_toml());
    Ok(())
}

/// `tenzro-node init` — print this machine's `[[validators]]` genesis entry,
/// as TOML or JSON. Nothing is generated or written: every key is derived
/// from or held by this machine's hardware.
fn run_credentials(action: CredentialsAction, config: &NodeConfig) -> Result<()> {
    use tenzro_node::credentials;
    let fail = |e: String| error::NodeError::Config(e);
    let dir = |d: Option<PathBuf>| d.unwrap_or_else(|| config.data_dir.clone());
    match action {
        CredentialsAction::Set { origin, data_dir } => {
            let data_dir = dir(data_dir);
            let mut line = zeroize::Zeroizing::new(String::new());
            std::io::stdin()
                .read_line(&mut line)
                .map_err(|e| fail(format!("reading the credential from stdin: {e}")))?;
            if let CredentialOrigin::Huggingface = origin {
                tenzro_model::origin_credential::OriginCredential::new(&line).map_err(fail)?;
            }
            let keys = tenzro_keygen::NodeKeys::open(&data_dir)
                .map_err(|e| fail(format!("node keys: {e}")))?;
            let path = credentials::seal(&data_dir, &keys, origin.secret(), &line).map_err(fail)?;
            println!(
                "{} sealed to this machine at {}; restart the node to use it.",
                origin.name(),
                path.display()
            );
        }
        CredentialsAction::Clear { origin, data_dir } => {
            if credentials::clear(&dir(data_dir), origin.secret()).map_err(fail)? {
                println!("{} removed; restart the node.", origin.name());
            } else {
                println!("No {} was stored.", origin.name());
            }
        }
        CredentialsAction::Status { data_dir } => {
            let data_dir = dir(data_dir);
            // The same configuration the node runs with (`--config`), so the
            // file's credentials are reported as the node resolves them.
            for (secret, configured, unset) in [
                (
                    credentials::Secret::Huggingface,
                    config.huggingface_credential.as_ref(),
                    "not set (open models and network peers only)",
                ),
                (
                    credentials::Secret::Upstream,
                    config.connector.as_ref().and_then(|c| c.api_key.as_ref()),
                    "not set (the connector's endpoint is called without a key)",
                ),
            ] {
                println!(
                    "{}",
                    credentials::status(&data_dir, secret, configured, unset)
                );
            }
        }
    }
    Ok(())
}

fn run_init(data_dir: Option<PathBuf>, stake: u64, format: String) -> Result<()> {
    let data_dir = data_dir
        .map(tenzro_types::paths::expand_tilde)
        .unwrap_or_else(tenzro_types::paths::default_data_dir);
    let entry = tenzro_node::config::GenesisValidator::from_local_hardware(&data_dir, stake)?;
    match format.to_lowercase().as_str() {
        "json" => println!(
            "{}",
            serde_json::to_string_pretty(&entry).unwrap_or_default()
        ),
        _ => print!("{}", entry.to_toml()),
    }
    Ok(())
}

/// `tenzro-node graceful-exit` — call `tenzro_gracefulExit` on the
/// running node's JSON-RPC. The RPC handler waits until this replica
/// leads none of the rounds its schedule looks ahead over, then triggers
/// the in-process `NodeEvent::Shutdown`. We print the JSON response and
/// exit 0 if the call succeeded — actual process termination on the
/// server is asynchronous (5s drain in `main()`).
async fn run_graceful_exit(rpc_url: String, max_wait_secs: u64, force: bool) -> Result<()> {
    let req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tenzro_gracefulExit",
        "params": {
            "max_wait_secs": max_wait_secs,
            "force": force,
        },
    });

    info!(
        rpc_url = %rpc_url,
        max_wait_secs,
        force,
        "Sending graceful-exit request"
    );

    // The RPC handler blocks for up to `max_wait_secs` waiting for
    // leader rotation, so the HTTP timeout must comfortably exceed it.
    let resp = tenzro_node::http_client::shared()
        .post(&rpc_url)
        .timeout(std::time::Duration::from_secs(
            max_wait_secs.saturating_add(30),
        ))
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

    let result = body
        .get("result")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    println!(
        "{}",
        serde_json::to_string_pretty(&result).unwrap_or_default()
    );
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

    // --log-level governs, and nothing here may raise a crate back above it.
    // Three per-crate directives used to be pinned to trace/debug at this
    // point, so the flag set a floor and they immediately overrode it for the
    // three noisiest crates in the process: a node started with
    // `--log-level info` still emitted TRACE from tenzro_node and DEBUG from
    // tenzro_network and tenzro_consensus. That was ~2.9 GB/day into syslog on
    // a validator, and it read as a configuration mistake rather than a
    // hardcoded override. RUST_LOG still wins, through from_default_env.
    let filter = EnvFilter::from_default_env().add_directive(level.into());

    match log_format.to_lowercase().as_str() {
        "json" => {
            // Structured JSON logging — ideal for log aggregation (Loki, ELK, Datadog)
            tracing_subscriber::fmt()
                .with_writer(std::io::stderr)
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
                .with_writer(std::io::stderr)
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

/// The node's configuration: the file, the hardware key scope it names and
/// the TPM limits, then the command-line overrides.
async fn node_config(cli: &Cli) -> Result<NodeConfig> {
    let mut config = load_config(cli)?;

    // Every hardware key this node opens lives under its namespace, when it
    // names one; set before any key is opened, the overrides' included:
    // `--dev` and `--solo` write this machine's genesis entry from its keys.
    if let Some(namespace) = &config.hardware_key_namespace {
        tenzro_device_key::set_label_namespace(namespace)
            .map_err(|e| error::NodeError::Config(format!("hardware_key_namespace: {e}")))?;
    }

    // TPM limits, before any key is opened.
    configure_tpm(&config)?;

    // Apply CLI overrides (async because the bootstrap-DNS resolver
    // path makes live DNS queries before the swarm starts).
    apply_cli_overrides(&mut config, cli).await?;

    // Validate configuration
    config.validate()?;
    Ok(config)
}

/// Apply CLI argument overrides to configuration
async fn apply_cli_overrides(config: &mut NodeConfig, cli: &Cli) -> Result<()> {
    if let Some(data_dir) = &cli.data_dir {
        // Expanded rather than taken literally: a tilde survives quoting and
        // systemd unit files, and unexpanded it creates a directory named `~`
        // beside whatever the working directory happened to be.
        config.data_dir = tenzro_types::paths::expand_tilde(data_dir);
    }

    if let Some(gb) = cli.reserve_gb {
        config.memory.reserve_gb = gb;
    }
    if cli.resident_ceiling_gb.is_some() {
        config.memory.resident_ceiling_gb = cli.resident_ceiling_gb;
    }
    if cli.on_demand_ceiling_gb.is_some() {
        config.memory.on_demand_ceiling_gb = cli.on_demand_ceiling_gb;
    }

    // Model-license acceptance. CLI flags are additive on top of any policy
    // set in the config file: `--accept-non-commercial` turns the flag on,
    // and each `--accept-license <id>` appends to the accepted set. Neither
    // flag can *revoke* a config-file acceptance — the operator drops those
    // by editing the config, not by omitting a flag.
    if cli.accept_non_commercial {
        config.model_licensing.accept_non_commercial = true;
    }
    for did in cli.catalog_publisher.iter().filter(|d| !d.is_empty()) {
        if !config.catalog_publishers.contains(did) {
            config.catalog_publishers.push(did.clone());
        }
    }
    for did in cli.release_publisher.iter().filter(|d| !d.is_empty()) {
        if !config.release_publishers.contains(did) {
            config.release_publishers.push(did.clone());
        }
    }
    for id in cli.kyc_asset.iter().filter(|d| !d.is_empty()) {
        if !config.kyc_assets.contains(id) {
            config.kyc_assets.push(id.clone());
        }
    }
    for id in &cli.accept_license {
        let id = id.trim();
        if !id.is_empty()
            && !config
                .model_licensing
                .accepted_license_ids
                .iter()
                .any(|a| a == id)
        {
            config
                .model_licensing
                .accepted_license_ids
                .push(id.to_string());
        }
    }

    if let Some(tier) = &cli.tier {
        config.tier = tier.parse().map_err(error::NodeError::Config)?;
    }

    if let Some(roles_str) = &cli.roles {
        config.roles = parse_roles(roles_str)?;
        // Auto-create consensus config for validators if not already set
        if config.roles.is_validator() && config.consensus.is_none() {
            config.consensus = Some(tenzro_consensus::ConsensusConfig::default());
        }
        // NOTE: genesis is deliberately NOT auto-filled here. A missing genesis
        // must never silently become `default_testnet()` (empty validator set),
        // which would make the node self-quorum onto a private chain that only
        // cosmetically resembles the real network. Genesis is resolved below,
        // AFTER boot nodes are known, so "join the network" and "run solo" are
        // distinguishable.
    }

    if let Some(stake_str) = &cli.validator_self_stake {
        let wei = stake_str.parse::<u128>().map_err(|e| {
            error::NodeError::Other(format!(
                "invalid --validator-self-stake '{}': {}",
                stake_str, e
            ))
        })?;
        config.validator_self_stake = Some(wei);
    }

    if let Some(name) = &cli.consensus_key_scheme {
        config.consensus_key_scheme =
            tenzro_consensus::validator_key::SignatureScheme::from_name(name).ok_or_else(|| {
                error::NodeError::Other(format!(
                    "invalid --consensus-key-scheme {name:?}: the schemes are \
                     COMPSIG-MLDSA65-ECDSA-P256 and COMPSIG-MLDSA87-ECDSA-P384"
                ))
            })?;
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
        }
        if config.roles.serves_tee() {
            config.tee_enabled = NodeConfig::default_tee_provider().tee_enabled;
        }
    }

    // Boot identities. Parsed strictly: an entry that is not a machine
    // identity (a transport path, a socket address) refuses the whole list rather
    // than being skipped, so an operator never boots on half a list.
    if let Some(boot_nodes) = &cli.boot_nodes {
        let entries = tenzro_iroh::parse_boot_list(boot_nodes)
            .map_err(|e| error::NodeError::Config(format!("--boot-nodes: {e}")))?;
        if !entries.is_empty() {
            config.iroh.boot = entries;
            info!("Boot identities override: {}", config.iroh.boot.len());
        }
    }

    // Env-supplied boot identities (TENZRO_BOOT_NODES) are the natural config
    // surface for container / systemd deploys. Appended to whatever
    // --boot-nodes set so env and CLI compose rather than clobber.
    if let Ok(raw) = std::env::var("TENZRO_BOOT_NODES") {
        let entries = tenzro_iroh::parse_boot_list(&raw)
            .map_err(|e| error::NodeError::Config(format!("TENZRO_BOOT_NODES: {e}")))?;
        for entry in entries {
            if !config.iroh.boot.contains(&entry) {
                config.iroh.boot.push(entry);
            }
        }
    }

    if let (Some(bind_addr), Some(public_url)) = (cli.relay_listen, cli.relay_url.clone()) {
        info!(listen = %bind_addr, url = %public_url, "Relay role enabled");
        config.iroh.relay = Some(tenzro_iroh::RelayRoleConfig {
            bind_addr,
            public_url,
        });
    }
    if let Some(port) = cli.relay_udp_port {
        config.iroh.relay_udp_port = port;
    }

    // An explicitly empty `--boot-nodes ""` means "no peers" — isolated mode.
    // That is deliberately distinct from *omitting* the flag, which means
    // "join the public network through its genesis validators". Without the
    // distinction a node started with no flags on new hardware would dial
    // the live network when its operator meant to bring it up alone.
    let isolated = cli
        .boot_nodes
        .as_deref()
        .is_some_and(|s| s.trim().is_empty());

    if isolated {
        info!(
            "Isolated mode: --boot-nodes was given empty, so this node will not dial the network"
        );
    }

    // Genesis resolution — runs AFTER boot nodes are known so "join the
    // network" and "run a solo chain" are never confused. An explicit
    // `--genesis <file>` (loaded further below) always wins; this only fills a
    // still-absent genesis. Two cases:
    //
    //   1. Solo (explicit `--solo`, or isolated `--boot-nodes ""`): a
    //      single-validator genesis whose one validator is this machine's
    //      hardware consensus key. Opt-in; refused without that hardware.
    //   2. Joining the real network (not solo): use the built-in
    //      public-network genesis, whose validators' machine identities are
    //      the boot identities, so the node verifies against the real
    //      validator set instead of inventing its own.
    if cli.dev {
        if !config.iroh.boot.is_empty() {
            return Err(error::NodeError::Config(
                "--dev runs a local chain that dials no one; it takes no boot identities".into(),
            ));
        }
        if tenzro_device_key::signer::platform_backend().is_none() {
            return Err(error::NodeError::Config(
                tenzro_node::config::DEV_NEEDS_HARDWARE.into(),
            ));
        }
        info!("Developer chain: a local single-validator chain keyed by this machine's hardware");
        config.genesis = Some(tenzro_node::config::GenesisConfig::developer(
            tenzro_node::config::GenesisValidator::from_local_hardware(
                &config.data_dir,
                1_000_000,
            )?,
            &cli.fund,
        )?);
    }

    if cli.genesis.is_none() && config.genesis.is_none() {
        let solo = cli.solo || isolated;
        if solo {
            info!(
                "Solo mode: a single-validator genesis with this machine's hardware key as \
                 the only validator. This chain is private and does not join the public network."
            );
            let mut g = GenesisConfig::default_testnet();
            g.validators = vec![tenzro_node::config::GenesisValidator::from_local_hardware(
                &config.data_dir,
                1_000_000,
            )?];
            config.genesis = Some(g);
        } else {
            info!(
                "No genesis provided; using the built-in public-network genesis \
                 (chain_id {}) so this node verifies against the real validator set",
                tenzro_node::config::PUBLIC_NETWORK_CHAIN_ID
            );
            config.genesis = Some(tenzro_node::config::public_network_genesis()?);
        }
    }

    if let Some(genesis_path) = &cli.genesis {
        let contents = std::fs::read_to_string(genesis_path)
            .map_err(|e| error::NodeError::Config(format!("Failed to read genesis file: {}", e)))?;
        let genesis: GenesisConfig = toml::from_str(&contents).map_err(|e| {
            error::NodeError::Config(format!("Failed to parse genesis config: {}", e))
        })?;
        config.genesis = Some(genesis);
    }

    config.log_level = cli.log_level.clone();
    apply_listen_overrides(config, cli);

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

/// Listen addresses: a flag replaces the config file's value; without the
/// flag the config file's value (or its default) stands.
fn apply_listen_overrides(config: &mut NodeConfig, cli: &Cli) {
    for (flag, addr) in [
        (&cli.rpc_addr, &mut config.rpc_addr),
        (&cli.web_addr, &mut config.web_addr),
        (&cli.mcp_addr, &mut config.mcp_addr),
        (&cli.a2a_addr, &mut config.a2a_addr),
    ] {
        if let Some(a) = flag {
            *addr = a.clone();
        }
    }
}

/// Parse a comma-separated roles string into a `RoleSet`.
/// Parses the state-sync peers (`<EndpointId>` or `<EndpointId>@<ip:port>`),
/// joining entries that name one endpoint.
fn parse_state_sync_peers<'a>(
    entries: impl IntoIterator<Item = &'a String>,
) -> Result<Vec<tenzro_iroh::EndpointAddr>> {
    let mut peers = Vec::new();
    for entry in entries {
        peers.push(tenzro_iroh::parse_peer(entry).map_err(|e| {
            error::NodeError::Other(format!("--state-sync-from {entry}: {e}"))
        })?);
    }
    Ok(tenzro_iroh::merge_peers(peers))
}

#[cfg(test)]
mod state_sync_peer_tests {
    use super::*;

    #[test]
    fn config_and_flag_entries_merge_and_bad_ones_are_refused() {
        let id = tenzro_iroh::EndpointId::from_bytes(&ed25519_public([9; 32])).unwrap();
        let from_config = vec![format!("{id}@127.0.0.1:1")];
        let from_flag = vec![format!("{id}@127.0.0.1:2"), id.to_string()];
        let peers = parse_state_sync_peers(from_config.iter().chain(&from_flag)).unwrap();
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].ip_addrs().count(), 2);
        assert!(parse_state_sync_peers(&vec!["x@y".to_string()]).is_err());
    }

    fn ed25519_public(seed: [u8; 32]) -> [u8; 32] {
        ed25519_dalek::SigningKey::from_bytes(&seed)
            .verifying_key()
            .to_bytes()
    }
}

/// Parses a 32-byte hash given as hex, with or without `0x`.
fn parse_hash32(hex_str: &str, what: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(hex_str.trim_start_matches("0x"))
        .map_err(|e| error::NodeError::Other(format!("{what} is not valid hex: {e}")))?;
    <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| {
        error::NodeError::Other(format!(
            "{what} must be exactly 32 bytes (got {})",
            bytes.len()
        ))
    })
}

fn parse_roles(roles: &str) -> Result<tenzro_types::RoleSet> {
    use std::str::FromStr;

    let set = tenzro_types::RoleSet::from_str(roles)
        .map_err(|e| error::NodeError::Config(format!("Invalid roles '{}': {}", roles, e)))?;
    Ok(set)
}

/// Print startup banner
fn print_banner() {
    const INNER: usize = 60;
    let version = format!("Version {}", env!("CARGO_PKG_VERSION"));
    let pad_l = (INNER - version.chars().count()) / 2;
    let pad_r = INNER - version.chars().count() - pad_l;
    print!(
        r#"
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
"#
    );
    println!("║{}{}{}║", " ".repeat(pad_l), version, " ".repeat(pad_r));
    println!("║                                                            ║");
    println!("╚════════════════════════════════════════════════════════════╝");
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

#[cfg(test)]
mod listen_override_tests {
    use super::*;
    use clap::Parser;

    fn config_with_own_listeners() -> NodeConfig {
        NodeConfig {
            rpc_addr: "127.0.0.1:27400".into(),
            web_addr: "127.0.0.1:27401".into(),
            mcp_addr: "127.0.0.1:27402".into(),
            a2a_addr: "127.0.0.1:27403".into(),
            ..NodeConfig::default()
        }
    }

    #[test]
    fn the_config_files_listen_addresses_stand_without_flags() {
        let cli = Cli::try_parse_from(["tenzro-node"]).unwrap();
        let mut config = config_with_own_listeners();
        apply_listen_overrides(&mut config, &cli);
        assert_eq!(
            [
                &config.rpc_addr,
                &config.web_addr,
                &config.mcp_addr,
                &config.a2a_addr
            ],
            [
                "127.0.0.1:27400",
                "127.0.0.1:27401",
                "127.0.0.1:27402",
                "127.0.0.1:27403"
            ]
        );
    }

    #[test]
    fn a_listen_flag_replaces_only_its_own_address() {
        let cli = Cli::try_parse_from(["tenzro-node", "--mcp-addr", "127.0.0.1:4001"]).unwrap();
        let mut config = config_with_own_listeners();
        apply_listen_overrides(&mut config, &cli);
        assert_eq!(config.mcp_addr, "127.0.0.1:4001");
        assert_eq!(config.a2a_addr, "127.0.0.1:27403");
        assert_eq!(config.rpc_addr, "127.0.0.1:27400");
    }

    #[test]
    fn without_a_config_file_or_flags_the_defaults_are_loopback() {
        let cli = Cli::try_parse_from(["tenzro-node"]).unwrap();
        let mut config = NodeConfig::default();
        apply_listen_overrides(&mut config, &cli);
        assert_eq!(config.rpc_addr, "127.0.0.1:8545");
        assert_eq!(config.mcp_addr, "127.0.0.1:3001");
    }
}

#[cfg(all(test, target_os = "linux"))]
mod dev_genesis_namespace_tests {
    use super::*;
    use clap::Parser;

    /// A `--dev` chain's one validator is this node's machine account under
    /// the key namespace its configuration names, so the node holds the
    /// validator bond it starts with. Needs a TPM whose keys for that
    /// namespace are provisioned: `TENZRO_TEST_DEV_NAMESPACE=<namespace>`.
    #[tokio::test]
    #[ignore = "needs a TPM with a provisioned key namespace"]
    async fn a_dev_chain_bonds_the_namespaced_machine_account() {
        let namespace = std::env::var("TENZRO_TEST_DEV_NAMESPACE")
            .expect("TENZRO_TEST_DEV_NAMESPACE names a provisioned key namespace");
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("node.toml");
        std::fs::write(
            &config_path,
            format!("hardware_key_namespace = \"{namespace}\"\n"),
        )
        .unwrap();
        let data_dir = dir.path().join("data");
        let cli = Cli::try_parse_from([
            "tenzro-node".as_ref(),
            "-c".as_ref(),
            config_path.as_os_str(),
            "--dev".as_ref(),
            "--roles".as_ref(),
            "validator".as_ref(),
            "--boot-nodes".as_ref(),
            "".as_ref(),
            "--data-dir".as_ref(),
            data_dir.as_os_str(),
        ] as [&std::ffi::OsStr; 10])
        .unwrap();

        let config = node_config(&cli).await.unwrap();

        let genesis = config.genesis.expect("--dev writes a genesis");
        assert_eq!(genesis.validators.len(), 1);
        let identity = tenzro_device_key::HardwareHybridSigner::open_or_create(
            tenzro_node::machine_admission::MACHINE_WALLET_KEY_LABEL,
        )
        .unwrap();
        let account = tenzro_crypto::composite::HybridSigner::public_key(&identity).account_slot();
        assert_eq!(
            genesis.validators[0].address,
            hex::encode(account),
            "the dev genesis bonds another account than this node's machine account under namespace {namespace}"
        );
    }
}
