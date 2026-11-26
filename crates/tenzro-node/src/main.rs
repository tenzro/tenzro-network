//! Tenzro Network Node - Full node binary

// The light build (no `inference` feature) leaves out the engine start-up;
// what only that uses is allowed to go unused there, as in the library.
#![cfg_attr(
    not(feature = "inference"),
    allow(dead_code, unused_imports, unused_variables, unused_mut)
)]

use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
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

    /// How long a node started before its key holder waits for one to answer
    /// at `--tpm-key-holder` before it refuses to start. A holder that
    /// answers without a grant is waited on until the grant is installed.
    #[arg(
        long,
        value_name = "SECS",
        env = "TENZRO_TPM_KEY_HOLDER_WAIT",
        default_value_t = 120
    )]
    tpm_key_holder_wait: u64,

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

    /// Async runtime worker threads. Omit for the tier's: the core count,
    /// 2 to 8 on a validator or provider, 1 to 2 on an edge device.
    #[arg(long, value_name = "N", env = "TENZRO_WORKER_THREADS")]
    worker_threads: Option<usize>,

    /// Node roles, comma-separated (e.g. "validator,storage,ai"). A node may
    /// serve any combination of roles; each role is bonded separately from the
    /// same account. Aliases accepted:
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
    /// validators' identities. A genesis validator does not omit it: it
    /// names every other genesis validator's machine identity with its relay
    /// URL, or a fresh network does not bootstrap.
    ///
    /// Pass an explicitly empty value — `--boot-nodes ""` — to stay **isolated**:
    /// no dialling out. That is what a local or solo node wants, and it is
    /// distinct from omitting the flag. A validator in the `enforce`
    /// onboarding mode dials only these identities, the validators' machines
    /// and the peers named with `--state-sync-from`, and keeps gossip
    /// neighbours only among these identities and the validators; inbound
    /// connections that pass the identity gate are still admitted, so other
    /// nodes can sync from it. Every validator's list names the relay and RPC
    /// entry points.
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

    /// UDP port this node's iroh endpoint binds (default 9001, or the
    /// port of `bind_addr` in the config file's iroh section). One process
    /// per host can hold a port, so a second node on a machine names its own.
    #[arg(long, value_name = "PORT")]
    iroh_bind_port: Option<u16>,

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
    /// `--checkpoint-hash` block commits or, with no checkpoint pinned, the
    /// block of the snapshot anchor a peer certifies, verified from the
    /// genesis committee. The recovery after a corrupt store
    /// (`scripts/repair-validator-store.sh`, then restart with this flag)
    /// works on a fixed `bind_addr` too: the state-sync endpoint is released
    /// before the node's own endpoint binds. Each peer is asked in turn; if
    /// none holds the snapshot the checkpoint commits, the node refuses to
    /// start. A node whose store already holds chain state continues from its
    /// tip and ignores this flag.
    ///
    /// Requires `--checkpoint-height` and `--checkpoint-hash`: take them from
    /// a snapshot the peer lists (`tenzro node snapshots`, fields
    /// `checkpoint_height` and `checkpoint_hash`).
    #[arg(long = "state-sync-from", value_name = "ENDPOINT_ID[@IP:PORT]")]
    state_sync_from: Vec<String>,

    /// Join by snapshot over a store that already holds chain state: the
    /// store is moved aside to `db.replaced-<unix seconds>` in the data
    /// directory (nothing is deleted; move it back to undo) and the node
    /// starts fresh, restoring from the peers named with `--state-sync-from`
    /// or the boot peers. Without this flag a node whose store holds chain
    /// state continues from its tip and says why it ignores the peers.
    #[arg(long = "replace-store")]
    replace_store: bool,

    /// Replay the chain from the local tip even on a role that would join by
    /// snapshot. A node without the validator role restores the committed
    /// state from a boot peer's snapshot by default, verified against the
    /// weak-subjectivity checkpoint when one is pinned
    /// (`--checkpoint-height`/`--checkpoint-hash` or genesis
    /// `[weak_subjectivity]`) and otherwise against the anchor the peer
    /// certifies, checked from the genesis committee; a validator always
    /// replays. A planned snapshot join that no peer can serve stops the
    /// start, except an unpinned join from boot peers, which replays.
    /// Also settable as `state_sync = "off"` in the config file.
    #[arg(long = "no-state-sync")]
    no_state_sync: bool,

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

    /// Print the identity key change that records this machine's identity
    /// key at VERSION, committing to the key at the version after it.
    ///
    /// Each version is its own key, derived on demand from this machine's
    /// TPM or Secure Enclave; nothing is written. The machine's root approves
    /// the change with `tenzro identity keys --did <machine DID> --change
    /// <file>`. Once the chain records it and root signatures are live, the
    /// node signs its jurisdiction receipts with this key.
    #[command(name = "identity-key")]
    IdentityKey {
        /// The node's data directory. Also settable via
        /// `$TENZRO_DATA_DIR`.
        #[arg(long, value_name = "DIR", env = "TENZRO_DATA_DIR")]
        data_dir: Option<PathBuf>,

        /// The key version: 1 for the first, one above the version the
        /// chain records for a rotation.
        #[arg(long, default_value_t = 1)]
        version: u64,
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
    /// The method is the operator's: the command first signs in as this
    /// machine with its hardware identity key, the operator of a node whose
    /// config names no other `operator_did`, so it runs on the node's machine
    /// as the user whose keys the node uses. When `operator_did` names
    /// someone else it refuses: that operator signs in with
    /// `tenzro access sign-in` and calls the method, or the service is
    /// stopped, which sends SIGTERM.
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

    /// List, or discard, the validator registry's undo records.
    ///
    /// A node that stops between a registry change and its commit puts the
    /// registry back from these records at its next start. If a record
    /// cannot be read the start fails and keeps them. This command, with the
    /// node stopped, shows the chain tip and the records. `--discard`
    /// removes the unreadable ones, the readable ones too only with
    /// `--force`, after stating what follows and asking for a word to be
    /// typed (`--yes` goes on without asking, for scripts). Nothing is put back: the registry stays as the last run left
    /// it. When a discarded record covers a block or epoch boundary that
    /// never committed, the node then starts only if the registry equals what
    /// the chain holds: the rows committed at the epoch's first block, with
    /// the validator logs since replayed from the node's event log; where the
    /// event log does not reach back that far it must be restored from a
    /// snapshot.
    #[command(name = "registry-undo")]
    RegistryUndo {
        /// The node's data directory.
        #[arg(long, value_name = "DIR", env = "TENZRO_DATA_DIR")]
        data_dir: Option<PathBuf>,

        /// Remove the unreadable records.
        #[arg(long, default_value_t = false)]
        discard: bool,

        /// With --discard, remove the readable records as well.
        #[arg(long, default_value_t = false)]
        force: bool,

        /// With --discard, go on without asking for the word to be typed, for
        /// scripts; what follows is still printed.
        #[arg(long, default_value_t = false)]
        yes: bool,
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

        /// Genesis file of the chain: the first committee is read from its
        /// validators.
        #[arg(long, value_name = "FILE")]
        genesis: PathBuf,

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

    /// A volume this machine offers for storage.
    #[command(name = "volume")]
    Volume {
        #[command(subcommand)]
        action: VolumeAction,
    },

    /// Report what this binary was built for and whether it can use this
    /// machine's accelerators, then exit: the same check the node runs at
    /// startup, without starting a node. Exits non-zero when the node would
    /// refuse to start here. An ONNX Runtime that cannot use this machine's
    /// GPU stops only a node that serves models: with `--roles` (or a config
    /// file) it counts as for those roles; without them it counts against a
    /// GPU build and not against the CPU build.
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
        /// firewall: on Windows one inbound rule for the UDP port the node
        /// binds, keyed to the port so an update needs no new rule, on the
        /// private profile only (and removal of block rules a dismissed
        /// prompt left for the install's binaries); on macOS an
        /// entry in the application firewall for this binary. Optional: the
        /// node works without it, through relays and hole punching. Needs an
        /// administrator PowerShell on Windows and sudo on macOS. On Linux it
        /// prints the command for your firewall.
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
enum ClientsAction {
    /// The clients enrolled, with what each field means.
    #[command(name = "list")]
    List {
        /// The provider file `serve` runs with.
        #[arg(long, value_name = "FILE")]
        config: PathBuf,
    },
    /// Enrol operator passkeys for a key label, from the registrations the
    /// passkeys gave when they were created. A label enrolled for the first
    /// time takes two, from two of the operator's devices, so losing one
    /// device does not lock the machine out.
    #[command(name = "add")]
    Add {
        /// The provider file `serve` runs with.
        #[arg(long, value_name = "FILE")]
        config: PathBuf,
        /// The key label a grant from this passkey opens: the key the client
        /// machine signs with.
        #[arg(long)]
        label: String,
        /// The passkey's relying party id (the site it was created on).
        #[arg(long)]
        rp_id: String,
        /// A file holding a passkey's registration: the JSON of the
        /// `PublicKeyCredential` the browser returned when the passkey was
        /// created (`toJSON()`). Give it once per device.
        #[arg(long = "registration", value_name = "FILE", required = true)]
        registrations: Vec<PathBuf>,
        /// Accept a single passkey for a new label: losing that device locks
        /// the machine out until the operator enrols again.
        #[arg(long)]
        one_device: bool,
        /// Also let the client use keys derived from this machine's root
        /// (validator, VRF, sealing and access-token keys). Only for a
        /// client that validates; a running provider started without any
        /// such client needs a restart to take one.
        #[arg(long)]
        derived: bool,
    },
    /// Remove the passkeys of a key label, or one of them.
    #[command(name = "remove")]
    Remove {
        /// The provider file `serve` runs with.
        #[arg(long, value_name = "FILE")]
        config: PathBuf,
        /// The key label.
        #[arg(long)]
        label: String,
        /// Only this passkey (hex x || y); without it, every passkey of the label.
        #[arg(long)]
        passkey_public_key: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
enum VolumeAction {
    /// Measure the volume holding a directory (random and sequential reads,
    /// free space) and propose the storage classes it qualifies for: per
    /// class, how many objects it can answer a possession probe for inside
    /// the class's governed deadline, read from the running node. The
    /// measurement only proposes; the network believes what its probes
    /// measure. Prints JSON.
    #[command(name = "measure")]
    Measure {
        /// A directory on the volume to measure; a scratch file is written
        /// there and removed.
        #[arg(long, value_name = "DIR")]
        dir: std::path::PathBuf,
        /// Size of the scratch file, MiB.
        #[arg(long, default_value_t = 256)]
        sample_mib: u64,
        /// Random chunk reads to time.
        #[arg(long, default_value_t = 512)]
        reads: usize,
        /// This machine's uplink, megabits per second: proofs travel over it.
        #[arg(long)]
        uplink_mbps: u64,
        /// JSON-RPC endpoint of the running node, for the class deadlines.
        #[arg(long, value_name = "URL", default_value = "http://127.0.0.1:8545")]
        rpc_url: String,
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
    /// List the persistent TPM handles this node made: the storage root, the
    /// attestation key and each namespace's identity key, marking the one
    /// this process runs under. Reads only.
    #[command(name = "handles")]
    Handles,
    /// Delete one stale identity key this node made, a namespace's that no
    /// longer runs here. Asks you to type the handle to confirm; the storage
    /// root, the attestation key, this process's identity key and anything
    /// the node did not make are refused. Run with the node stopped.
    #[command(name = "delete-handle")]
    DeleteHandle {
        /// The handle to delete, as listed by `tpm handles` (hex, `0x81018105`).
        handle: String,
    },
    /// Check whether this machine can be admitted as an autonomous identity:
    /// attest its TPM as admission does (credential activation and a quote
    /// over the admission challenge, verified here), grade its endorsement
    /// against the given manufacturer roots and list its identifier sources.
    /// One line per requirement of docs/standards/machine-identity-onboarding.md;
    /// exits non-zero when a required one is not met. Run after `provision`.
    #[command(name = "check")]
    Check {
        /// A PEM file of TPM manufacturer roots to grade the endorsement
        /// against; repeat for several.
        #[arg(long = "roots", value_name = "PEM")]
        roots: Vec<PathBuf>,
        /// Write the evidence and the report as JSON to this file.
        #[arg(long, value_name = "FILE")]
        out: Option<PathBuf>,
    },
    /// Sign, with this machine's TPM, for the machines listed in the file:
    /// machines with no TPM of their own, enrolled by the operator.
    #[command(name = "serve")]
    Serve {
        #[arg(long, value_name = "FILE")]
        config: PathBuf,
    },
    /// Enrol one more machine's operator passkey with the provider file, and
    /// tell the running provider to take it, with no restart.
    #[command(name = "enrol-client")]
    EnrolClient {
        #[arg(long, value_name = "FILE")]
        config: PathBuf,
        /// The passkey's P-256 public key, hex `x || y`.
        #[arg(long, value_name = "HEX")]
        passkey_public_key: String,
        /// The passkey's WebAuthn relying party id.
        #[arg(long, value_name = "ID")]
        rp_id: String,
        /// The key label a grant from this passkey opens.
        #[arg(long)]
        label: String,
        /// Also allow the keys derived from the provider's root.
        #[arg(long)]
        derived: bool,
    },
    /// The machines `serve` signs for: list, add or remove an operator
    /// passkey and the key label its grants open. The command writes the
    /// provider file (every other line and comment stays); a running
    /// provider reads the change within seconds.
    #[command(name = "clients")]
    Clients {
        #[command(subcommand)]
        action: ClientsAction,
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
        /// Print the request as one JSON object for the grant page
        /// (`tools/grant-page/grant.html`) instead of lines.
        #[arg(long, requires = "credential_id")]
        json: bool,
        /// The enrolled operator passkey's credential id, base64url: the
        /// page asks the browser for that passkey and no other.
        #[arg(long, requires = "json", value_name = "ID")]
        credential_id: Option<String>,
        /// The WebAuthn relying party the passkey belongs to.
        #[arg(long, requires = "json", default_value = "localhost")]
        rp_id: String,
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
    /// Take this machine onto its provider in one step: print what the
    /// operator's passkey signs, take the assertion the browser returns,
    /// install the grant in the key holder, sign a test message with the
    /// machine's key at the provider, and print the flags the node starts
    /// with. Run it with the key holder running, after the operator enrolled
    /// their passkeys at the provider (`tpm clients add`).
    #[command(name = "enrol")]
    Enrol {
        /// The key holder's socket.
        #[arg(long, value_name = "SOCKET")]
        socket: PathBuf,
        /// The key label enrolled for this machine at the provider.
        #[arg(long)]
        label: String,
        /// The relying party the operator's passkey belongs to, whose page
        /// the operator signs on.
        #[arg(long)]
        rp_id: String,
        /// How long the grant lasts.
        #[arg(long, default_value_t = 24 * 30)]
        valid_hours: u64,
        /// A file holding the assertion; without it the command waits for
        /// the assertion pasted on its input.
        #[arg(long, value_name = "FILE")]
        assertion: Option<PathBuf>,
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
    /// Write every key blob of this machine's device-key directory into one
    /// backup file, then read the file back and compare it with the
    /// directory. The blobs open only inside this machine's TPM or Secure
    /// Enclave, so the file is ciphertext anywhere else: it guards against
    /// losing the disk, not the hardware. Make a new one after any key or
    /// grant is created.
    #[command(name = "keys-backup")]
    KeysBackup {
        /// The backup file to write; it must not exist.
        file: PathBuf,
        /// The device-key directory (defaults to this machine's).
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    /// Compare a backup file with the device-key directory and list what is
    /// missing, changed or new since it was made. Exits non-zero when they
    /// differ.
    #[command(name = "keys-verify")]
    KeysVerify {
        file: PathBuf,
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    /// Put back the key blobs of a backup file that the device-key directory
    /// lacks. A blob already there with other content stops the restore
    /// before anything is written. Run with the node and the key holder
    /// stopped.
    #[command(name = "keys-restore")]
    KeysRestore {
        file: PathBuf,
        #[arg(long)]
        dir: Option<PathBuf>,
    },
}

/// The device-key directory a `tpm keys-*` command works on.
fn device_key_dir(dir: Option<PathBuf>) -> Result<PathBuf> {
    dir.or_else(tenzro_device_key::device_key_dir)
        .ok_or_else(|| {
            error::NodeError::Config(
                "this machine has no device-key directory; name one with --dir".to_string(),
            )
        })
}

fn read_keys_backup(file: &std::path::Path) -> Result<tenzro_device_key::dir_backup::Backup> {
    let bytes = std::fs::read(file)
        .map_err(|e| error::NodeError::Config(format!("reading {}: {e}", file.display())))?;
    tenzro_device_key::dir_backup::Backup::from_bytes(&bytes)
        .map_err(|e| error::NodeError::Config(format!("{}: {e}", file.display())))
}

fn run_keys_backup(file: PathBuf, dir: Option<PathBuf>) -> Result<()> {
    use std::io::Write as _;
    use tenzro_device_key::dir_backup::Backup;
    let dir = device_key_dir(dir)?;
    let failed = |e: &dyn std::fmt::Display| error::NodeError::Config(e.to_string());
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64);
    let backup = Backup::of_dir(&dir, now_ms).map_err(|e| failed(&e))?;
    if backup.is_empty() {
        return Err(error::NodeError::Config(format!(
            "{} holds no key file; there is nothing to back up",
            dir.display()
        )));
    }
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut out = options
        .open(&file)
        .map_err(|e| failed(&format!("creating {}: {e}", file.display())))?;
    out.write_all(&backup.to_bytes())
        .and_then(|()| out.sync_all())
        .map_err(|e| failed(&format!("writing {}: {e}", file.display())))?;
    // The file as it is on disk, against the directory as it is now.
    let differences = read_keys_backup(&file)?
        .differences(&dir)
        .map_err(|e| failed(&e))?;
    if !differences.none() {
        return Err(error::NodeError::Config(format!(
            "the directory changed while it was backed up; delete {} and run the backup again",
            file.display()
        )));
    }
    println!(
        "Backed up {} key files from {} to {}\nDigest: {}\nThe file opens only with this machine's own TPM or Secure Enclave. Keep a copy off this disk.",
        backup.len(),
        dir.display(),
        file.display(),
        hex::encode(backup.digest())
    );
    Ok(())
}

fn run_keys_verify(file: PathBuf, dir: Option<PathBuf>) -> Result<()> {
    let dir = device_key_dir(dir)?;
    let backup = read_keys_backup(&file)?;
    let d = backup
        .differences(&dir)
        .map_err(|e| error::NodeError::Config(e.to_string()))?;
    println!("Backup digest: {}", hex::encode(backup.digest()));
    if d.none() {
        println!(
            "{} holds exactly the {} key files of the backup",
            dir.display(),
            backup.len()
        );
        return Ok(());
    }
    for (what, paths) in [
        ("missing from the directory", &d.missing),
        ("changed since the backup", &d.changed),
        ("not in the backup", &d.extra),
    ] {
        for path in paths {
            println!("{what}: {path}");
        }
    }
    Err(error::NodeError::Config(format!(
        "{} differs from the backup",
        dir.display()
    )))
}

fn run_keys_restore(file: PathBuf, dir: Option<PathBuf>) -> Result<()> {
    let dir = device_key_dir(dir)?;
    let backup = read_keys_backup(&file)?;
    let written = backup
        .restore_into(&dir)
        .map_err(|e| error::NodeError::Config(e.to_string()))?;
    println!(
        "Restored {written} of {} key files into {}; the rest were already there",
        backup.len(),
        dir.display()
    );
    Ok(())
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

/// Prints what the operator passkey signs to grant the key holder `label`:
/// lines, or with `credential_id` one JSON object the grant page reads.
#[cfg(unix)]
fn run_grant_request(
    socket: PathBuf,
    label: &str,
    valid_hours: u64,
    credential_id: Option<String>,
    rp_id: &str,
) -> Result<()> {
    use base64::Engine as _;
    use sha2::Digest as _;
    let (endpoint, _) =
        tenzro_node::tpm_key_holder::holder_id(&socket).map_err(error::NodeError::Config)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| error::NodeError::Other(e.to_string()))?
        .as_millis() as u64;
    let not_after_ms = now + valid_hours.saturating_mul(3_600_000);
    let challenge = tenzro_node::remote_tpm::grant_challenge(&endpoint, label, not_after_ms);
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(challenge);
    let Some(credential_id) = credential_id else {
        println!("endpoint_id {}", hex::encode(endpoint));
        println!("label {label}");
        println!("not_after_ms {not_after_ms}");
        println!("webauthn_challenge {challenge}");
        return Ok(());
    };
    let id = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(credential_id.trim_end_matches('='))
        .map_err(|_| error::NodeError::Config("--credential-id is not base64url".into()))?;
    let fingerprint = hex::encode(&sha2::Sha256::digest(&id)[..8]);
    println!(
        "{}",
        serde_json::json!({
            "socket": socket,
            "endpoint_id": hex::encode(endpoint),
            "label": label,
            "not_after_ms": not_after_ms,
            "webauthn_challenge": challenge,
            "credential_id": credential_id,
            "rp_id": rp_id,
            "fingerprint": fingerprint,
        })
    );
    Ok(())
}

#[cfg(not(unix))]
fn run_grant_request(
    _socket: PathBuf,
    _label: &str,
    _valid_hours: u64,
    _credential_id: Option<String>,
    _rp_id: &str,
) -> Result<()> {
    Err(error::NodeError::Config(
        "the TPM key holder needs a Unix socket, which this platform does not have".into(),
    ))
}

/// `tenzro-node tpm enrol`: the grant request, the operator's assertion,
/// the grant installed, the key checked at the provider, in one step.
#[cfg(unix)]
async fn run_enrol(
    socket: PathBuf,
    label: String,
    rp_id: String,
    valid_hours: u64,
    assertion: Option<PathBuf>,
) -> Result<()> {
    let (endpoint, _) =
        tenzro_node::tpm_key_holder::holder_id(&socket).map_err(error::NodeError::Config)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| error::NodeError::Other(e.to_string()))?
        .as_millis() as u64;
    let not_after_ms = now + valid_hours.saturating_mul(3_600_000);
    let challenge = tenzro_node::remote_tpm::grant_challenge(&endpoint, &label, not_after_ms);
    println!(
        "1. On a device whose passkey is enrolled for {label:?} at the provider, open \
         https://{rp_id} and run in its browser console:\n\n   {}\n",
        tenzro_node::remote_tpm::assertion_snippet(&challenge, &rp_id)
    );
    let text = match &assertion {
        Some(path) => std::fs::read_to_string(path)
            .map_err(|e| error::NodeError::Config(format!("{}: {e}", path.display())))?,
        None => {
            println!("2. Paste the line it prints here, then Enter:");
            let mut line = String::new();
            std::io::stdin()
                .read_line(&mut line)
                .map_err(|e| error::NodeError::Other(format!("reading the assertion: {e}")))?;
            line
        }
    };
    let grant =
        tenzro_node::remote_tpm::grant_from_assertion(text.trim(), &endpoint, &label, not_after_ms)
            .map_err(error::NodeError::Config)?;
    let bytes = serde_json::to_vec(&grant).map_err(|e| error::NodeError::Other(e.to_string()))?;
    tenzro_node::tpm_key_holder::request(&socket, tenzro_node::tpm_key_holder::OP_GRANT, &bytes)
        .map_err(error::NodeError::Config)?;
    println!("grant installed until {not_after_ms} (unix ms)");
    run_remote_check(socket.clone(), label.clone()).await?;
    println!(
        "\nThis machine's key answers through the provider. Start the node with:\n  \
         --tpm-key-holder {} --tpm-label {label}",
        socket.display()
    );
    Ok(())
}

#[cfg(not(unix))]
async fn run_enrol(
    _socket: PathBuf,
    _label: String,
    _rp_id: String,
    _valid_hours: u64,
    _assertion: Option<PathBuf>,
) -> Result<()> {
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

fn main() -> Result<ExitCode> {
    // First, so a panic anywhere in start-up is reported: before logging is
    // set up it goes to stderr. It starts no thread.
    log_panics();
    // A runtime host is started by re-running this executable as its
    // confinement launcher, which must confine itself while it is still
    // single-threaded: before the async runtime starts any thread.
    // Before any thread exists: the arena cap applies to arenas opened later.
    tenzro_node::malloc_tuning::limit_arenas(tenzro_node::malloc_tuning::MAX_ARENAS);
    praecise_host::sandbox::enter_if_requested();
    // A model file's header is parsed by this executable re-run as a
    // locked-down child, which must lock itself down before any thread.
    #[cfg(feature = "inference")]
    tenzro_model::parse_jail::enter_if_requested();
    // Every TLS client and server in this process uses aws-lc-rs, the provider
    // with the X25519MLKEM768 hybrid key exchange, never one another dependency
    // compiled in. Subcommands connect too, so this comes before any of them.
    if rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .is_err()
    {
        return Err(error::NodeError::Internal(
            "a TLS provider was installed before main".into(),
        ));
    }
    let cli = Cli::parse();
    // Every path the node uses hangs off the Tenzro root; a process that cannot
    // name it refuses here, with the variable to set, rather than at the first
    // path it asks for.
    tenzro_types::paths::try_tenzro_home().map_err(|e| error::NodeError::Config(e.to_string()))?;
    let config = startup_config(&cli)?;
    set_engine_budgets(&config);
    tenzro_node::malloc_tuning::spawn_trimmer();
    run_on_runtime(cli, &config)
}

/// The node inside an Android app's process (the light build): `args` are
/// the command line after the program name. It runs the node only, never a
/// subcommand, and returns when [`tenzro_node::embedded::request_stop`] has
/// stopped it. The process is the app's, so nothing here re-runs this
/// executable or sets the environment.
#[cfg(all(target_os = "android", not(feature = "inference")))]
pub(crate) fn run_embedded(args: Vec<String>) -> Result<()> {
    let cli = embedded_cli(args)?;
    let config = startup_config(&cli)?;
    run_on_runtime(cli, &config).map(|_| ())
}

/// The command line of an embedded node: the node itself, with a data
/// directory of the app's own.
#[cfg(any(all(target_os = "android", not(feature = "inference")), test))]
fn embedded_cli(args: Vec<String>) -> Result<Cli> {
    let cli = Cli::try_parse_from(std::iter::once("tenzro-node".to_string()).chain(args))
        .map_err(|e| error::NodeError::Config(e.to_string()))?;
    if cli.command.is_some() {
        return Err(error::NodeError::Config(
            "an embedded node runs the node, not a subcommand".into(),
        ));
    }
    if cli.data_dir.is_none() {
        return Err(error::NodeError::Config(
            "an embedded node needs --data-dir: the app's own files directory".into(),
        ));
    }
    Ok(cli)
}

/// The async runtime sized for this node's tier, running the node to its end.
fn run_on_runtime(cli: Cli, config: &NodeConfig) -> Result<ExitCode> {
    let tuning = config
        .resolved_tier()
        .tuning(tenzro_node::tier::machine_cores());
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(cli.worker_threads.unwrap_or(tuning.worker_threads).max(1))
        .max_blocking_threads(tuning.max_blocking_threads)
        .enable_all()
        .build()?;
    run_to_end(runtime, run(cli), RUNTIME_END_GRACE)
}

/// How long the process waits, after the node has drained and said it is
/// done, for work still running on the blocking pool (a model's generation or
/// load cannot be cancelled) before it ends regardless.
const RUNTIME_END_GRACE: std::time::Duration = std::time::Duration::from_secs(10);

/// Runs `fut` to its end on `runtime`, then drops the runtime without waiting
/// longer than `grace` for blocking tasks. Dropping a runtime waits for every
/// blocking task, so a node stopped while a model was generating stayed alive
/// until the generation finished, minutes after it logged that it was done.
fn run_to_end<T>(
    runtime: tokio::runtime::Runtime,
    fut: impl std::future::Future<Output = T>,
    grace: std::time::Duration,
) -> T {
    let out = runtime.block_on(fut);
    runtime.shutdown_timeout(grace);
    out
}

/// What has to be known before the async runtime starts: the tier, roles
/// and memory reserve from the flags, or else the configuration file.
fn startup_config(cli: &Cli) -> Result<NodeConfig> {
    let mut config = load_config(cli)?;
    if let Some(roles) = &cli.roles {
        config.roles = parse_roles(roles)?;
    }
    if let Some(tier) = &cli.tier {
        config.tier = tier.parse().map_err(error::NodeError::Config)?;
    }
    if let Some(gb) = cli.reserve_gb {
        config.memory.reserve_gb = gb;
    }
    Ok(config)
}

/// The batching engine reads its KV and checkpoint budgets from the
/// environment when a model loads, and without them takes half of whatever
/// memory is free for KV and most of the rest for checkpoints. Sets them out
/// of this node's resident tier, so a serve stays inside the memory budget
/// and the reserve; a budget the operator set in the environment is kept.
fn set_engine_budgets(config: &NodeConfig) {
    let ceiling = config
        .memory
        .to_budget_config(config.roles.is_validator())
        .resident_ceiling();
    let (kv, checkpoints) = tenzro_model::serve_memory::node_engine_budgets(ceiling);
    for (name, bytes) in [
        ("BATCH_KV_MEMORY", kv),
        ("BATCH_CHECKPOINT_MEMORY", checkpoints),
    ] {
        if std::env::var_os(name).is_none() {
            // SAFETY: called from `main` before any other thread is started,
            // so nothing reads the environment concurrently.
            unsafe { std::env::set_var(name, bytes.to_string()) };
        }
    }
}

/// How often a node waiting for its key holder's grant looks again.
#[cfg(unix)]
const KEY_GRANT_LOOK_EVERY: std::time::Duration = std::time::Duration::from_secs(5);

/// How often a node waiting for the grant says so again.
#[cfg(unix)]
const KEY_GRANT_REMIND_EVERY: std::time::Duration = std::time::Duration::from_secs(600);

/// Routes this process's hardware keys through the key holder named by
/// `--tpm-key-holder` / `--tpm-label`, when given. True when it did.
fn use_key_holder(cli: &Cli) -> Result<bool> {
    let Some(socket) = &cli.tpm_key_holder else {
        return Ok(false);
    };
    let label = cli
        .tpm_label
        .clone()
        .ok_or_else(|| error::NodeError::Config("--tpm-key-holder needs --tpm-label".into()))?;
    #[cfg(unix)]
    {
        tenzro_node::identity_bootstrap::use_remote_tpm(tenzro_node::remote_tpm::RemoteConfig {
            label,
            key_holder: socket.clone(),
        })
        .map_err(error::NodeError::Config)?;
        Ok(true)
    }
    // Refused here, naming the socket, rather than at the first key use.
    #[cfg(not(unix))]
    Err(error::NodeError::Config(format!(
        "--tpm-key-holder {} for '{label}': the TPM key holder needs a Unix socket, which this \
         platform does not have",
        socket.display()
    )))
}

/// A subcommand that opens the machine's keys (validator-entry, doctor,
/// ...) opens them through the key holder the node uses. The `tpm`
/// subcommands run or address a key holder themselves. True when the key
/// holder was installed.
fn subcommand_key_holder(cli: &Cli, cmd: &Command) -> Result<bool> {
    if matches!(cmd, Command::Tpm { .. } | Command::Volume { .. }) {
        return Ok(false);
    }
    use_key_holder(cli)
}

async fn run(mut cli: Cli) -> Result<ExitCode> {
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
        let delegated = subcommand_key_holder(&cli, &cmd)?;
        let key_holder = cli.tpm_key_holder.clone().filter(|_| delegated);
        // Roles the operator named, on the command line or in a config file;
        // without either the subcommand has only the defaults to go by.
        let roles_named = cli.roles.is_some() || cli.config.is_some();
        return run_subcommand(cmd, &config, key_holder.as_deref(), roles_named)
            .await
            .map(|()| ExitCode::SUCCESS);
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
    if use_key_holder(&cli)? {
        tenzro_network::service::declare_identity_root(
            tenzro_network::service::IdentityRoot::TpmDelegated,
        );
        // The keys open only under the operator's grant: without one the
        // node waits for it instead of ending, and for a key holder that
        // starts after it up to `--tpm-key-holder-wait`.
        #[cfg(unix)]
        if let Some(socket) = &cli.tpm_key_holder {
            let wait = tenzro_node::tpm_key_holder::GrantWait {
                step: KEY_GRANT_LOOK_EVERY,
                remind: KEY_GRANT_REMIND_EVERY,
                holder: std::time::Duration::from_secs(cli.tpm_key_holder_wait),
            };
            if let Err(reason) = tenzro_node::tpm_key_holder::await_grant(socket, wait).await {
                eprintln!("\n{reason}\n");
                return Err(error::NodeError::Config(reason));
            }
            // A grant that runs out later leaves the node running and
            // waiting for a new one, which its status names.
            tenzro_node::tpm_key_holder::watch_running_grant(socket.clone(), wait);
        }
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
    // start on an NVIDIA machine this binary's ONNX Runtime cannot use, when
    // the node serves models; a node that serves none starts, and every ONNX
    // session it is asked to build is refused with the same cause.
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
        let checked = tokio::task::spawn_blocking(tenzro_model::onnx_session::verify_accelerators)
            .await
            .map_err(|e| error::NodeError::Config(format!("ONNX accelerator check: {e}")))?;
        if let Err(e) = checked {
            if onnx_refusal_stops_start(&config.roles) {
                return Err(e.into());
            }
            warn!(
                roles = %config.roles,
                "ONNX models are refused on this machine ({e}); this node serves no models, so it starts"
            );
        }
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
    if cli.replace_store {
        if config.state_sync_from.is_empty() && cli.state_sync_from.is_empty() {
            return Err(error::NodeError::Config(
                "--replace-store restores the store from a snapshot: name the peer that holds it \
                 with --state-sync-from (and the checkpoint with --checkpoint-height and \
                 --checkpoint-hash), or the store would be moved aside with nothing to restore it"
                    .to_string(),
            ));
        }
        if let Some((db, aside)) = move_store_aside(&config.data_dir)? {
            info!(
                from = %db.display(),
                to = %aside.display(),
                "--replace-store: the old store is moved aside; move it back to undo"
            );
        }
    }
    let mut node = TenzroNode::new(config.clone()).await?;

    // Weak-subjectivity checkpoint and state sync. The checkpoint comes from
    // the command line, or else from the genesis `[weak_subjectivity]` block;
    // either way it is a finalized block, by hash, trusted out of band.
    //
    // State-sync peers come from `--state-sync-from`. Endpoint keys are per
    // boot, so no file can name them in advance; what a peer serves is checked
    // against the checkpoint's state root, not trusted for who it is.
    let checkpoint = weak_subjectivity_checkpoint(
        cli.checkpoint_hash.as_deref(),
        cli.checkpoint_height,
        config
            .genesis
            .as_ref()
            .and_then(|g| g.weak_subjectivity.as_ref()),
    )?;
    if let Some((height, hash, source)) = checkpoint {
        node.set_weak_subjectivity_anchor(height, hash);
        info!(
            height,
            block_hash = %format!("0x{}", hex::encode(hash)),
            source,
            "Weak-subjectivity checkpoint installed"
        );
    }

    let peers = parse_state_sync_peers(config.state_sync_from.iter().chain(&cli.state_sync_from))?;
    if !peers.is_empty() {
        info!(peers = peers.len(), "State sync configured");
        node.set_state_sync_peers(peers);
    }
    if let (Some(path), Some(digest)) = (&cli.recovery_manifest, &cli.recovery_digest) {
        node.set_recovery(tenzro_node::recovery::RecoveryRequest::load(
            path,
            digest,
            cli.recovery_confirm.as_deref(),
            checkpoint.map(|(height, hash, _)| (height, hash)),
            cli.recovery_check,
        )?);
    }
    match node.start().await {
        Err(error::NodeError::RecoveryChecked(_)) => return Ok(ExitCode::SUCCESS),
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
    // decode that the other guards do not catch. Log-only: it never force-kills a
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

    // The listener paired devices reach the node on; it binds nothing until a
    // pairing starts or a device is paired.
    #[cfg(feature = "paired-devices")]
    tokio::spawn(tenzro_node::paired_listener::run(
        node_arc.clone(),
        shutdown_tx.subscribe(),
    ));

    // Start Web Verification API
    let mut web_state = web::handlers::WebState::new()
        .with_node(node_arc.clone())
        .with_metrics((**node_arc.metrics()).clone());

    // If the P2P layer is initialised, wire its shared Prometheus registry
    // so the `tenzro_network_*` metrics (gossip, dial rate limits,
    // peer counts, connection totals) are served from the same `/metrics`
    // endpoint as the node-level counters.
    if let Some(network) = node_arc.network() {
        if let Some(resolver) = node_arc.iroh_resolver() {
            let resolver = resolver.clone();
            network.report_paths(move || resolver.path_report());
        }
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
            if !config.payments.trusted_agent_keys.is_empty() {
                // Checked when the configuration was loaded.
                let tap = tenzro_payments::rfc9421::tap::TapVerifier::from_jwks(
                    &config.payments.trusted_agent_keys,
                )
                .map_err(|e| {
                    error::NodeError::Config(format!("payments.trusted_agent_keys: {e}"))
                })?;
                middleware = middleware.with_trusted_agents(Arc::new(tap));
            }
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
            None,
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
    let a2a_state = a2a::server::build_a2a_state(
        node_arc.clone(),
        web_state,
        tenzro_node::identity_bootstrap::machine_did(),
    );

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
    tenzro_node::storage_placement::spawn_storage_repair_loop(node_arc.clone());
    tenzro_node::compute_index_reporter::spawn_fee_rate_reporter(node_arc.clone());
    tenzro_node::challenge_notice::spawn(node_arc.clone());
    tenzro_node::sla_attest::spawn_probe_scheduler(node_arc.clone());
    tenzro_node::sla_attest::spawn_attestation_submitter(node_arc.clone());
    tenzro_node::sla_attest::spawn_burst_challenge_scheduler(node_arc.clone());
    tenzro_node::optimistic::spawn_reviewer(node_arc.clone());
    tenzro_node::da_retention::spawn(node_arc.clone());
    tenzro_node::beacon::spawn_contributor(node_arc.clone());
    tenzro_node::role_bonds::spawn_watch(node_arc.clone());
    tenzro_node::hardware_possession::spawn(node_arc.clone());
    tenzro_node::operator_alert::spawn(node_arc.clone());
    tenzro_node::identity_bootstrap::keep_chain_policies(node_arc.clone());

    let a2a_shutdown_rx = shutdown_tx.subscribe();
    let a2a_addr_https = a2a_addr.clone();
    let mut a2a_handle = tokio::spawn(async move {
        if let Err(e) = a2a::server::start_a2a_server_with_shutdown(
            a2a_addr_https,
            a2a_state,
            a2a_shutdown_rx,
            None,
        )
        .await
        {
            error!("A2A server error: {}", e);
        }
    });

    // Wait for shutdown signal (Ctrl+C or SIGTERM, or the app that runs the
    // node in its own process asking it to stop)
    info!("Node is running. Press Ctrl+C to stop.");
    let app_stop = async {
        #[cfg(all(target_os = "android", not(feature = "inference")))]
        tenzro_node::embedded::stop_requested().await;
        #[cfg(not(all(target_os = "android", not(feature = "inference"))))]
        std::future::pending::<()>().await;
    };
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

        // Ctrl+Break, a closing console and a logoff or shutdown end the
        // node the way SIGTERM does on Unix: the node drains instead of
        // being cut off.
        #[cfg(windows)]
        {
            use tokio::signal::windows;
            let mut brk = windows::ctrl_break().expect("Failed to install Ctrl+Break handler");
            let mut close = windows::ctrl_close().expect("Failed to install console close handler");
            let mut shutdown =
                windows::ctrl_shutdown().expect("Failed to install shutdown handler");
            tokio::select! {
                _ = ctrl_c => info!("Received Ctrl+C"),
                _ = brk.recv() => info!("Received Ctrl+Break"),
                _ = close.recv() => info!("Received console close"),
                _ = shutdown.recv() => info!("Received system shutdown"),
            }
        }

        #[cfg(not(any(unix, windows)))]
        {
            ctrl_c.await.ok();
            info!("Received shutdown signal");
        }
    };

    // Only a requested stop ends the process with success: a failed event
    // loop or a server that stopped on its own ends it with an error, so a
    // service manager restarts it.
    let mut restart = false;
    let failure: Option<String> = tokio::select! {
        _ = shutdown_signal => None,
        _ = node_arc.restart.notified() => {
            info!("Restart requested: ending for the service to start the node again");
            restart = true;
            None
        },
        _ = app_stop => {
            info!("Stop requested by the app the node runs in");
            None
        }
        end = node_arc.event_loop_stopped() => match end {
            tenzro_node::node::EventLoopEnd::Shutdown => {
                info!("Event loop stopped");
                None
            }
            tenzro_node::node::EventLoopEnd::Failed(why) => {
                error!(reason = %why, "Event loop failed");
                Some(format!("the event loop failed: {why}"))
            }
        },
        result = &mut rpc_handle => {
            if let Err(e) = result { error!(error = %e, "RPC server task panicked"); }
            else { error!("RPC server terminated unexpectedly"); }
            Some("the RPC server stopped".to_string())
        },
        result = &mut web_handle => {
            if let Err(e) = result { error!(error = %e, "Web server task panicked"); }
            else { error!("Web server terminated unexpectedly"); }
            Some("the web server stopped".to_string())
        },
        result = &mut mcp_handle => {
            if let Err(e) = result { error!(error = %e, "MCP server task panicked"); }
            else { error!("MCP server terminated unexpectedly"); }
            Some("the MCP server stopped".to_string())
        },
        result = &mut a2a_handle => {
            if let Err(e) = result { error!(error = %e, "A2A server task panicked"); }
            else { error!("A2A server terminated unexpectedly"); }
            Some("the A2A server stopped".to_string())
        },
    };

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

    match failure {
        Some(why) => Err(error::NodeError::Other(why)),
        None if restart => Ok(ExitCode::from(tenzro_node::restart::STATUS)),
        None => Ok(ExitCode::SUCCESS),
    }
}

/// Dispatch an administrative subcommand. Each variant is a one-shot
/// JSON-RPC call against a running node; the function returns the exit
/// status for the process.
async fn run_subcommand(
    cmd: Command,
    config: &NodeConfig,
    key_holder: Option<&std::path::Path>,
    roles_named: bool,
) -> Result<()> {
    let delegated = key_holder.is_some();
    match cmd {
        Command::Init {
            data_dir,
            stake,
            format,
        } => run_init(data_dir, stake, format),
        Command::IdentityKey { data_dir, version } => run_identity_key(data_dir, version),
        Command::GracefulExit {
            rpc_url,
            max_wait_secs,
            force,
        } => run_graceful_exit(rpc_url, max_wait_secs, force, config, delegated).await,
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
        Command::RegistryUndo {
            data_dir,
            discard,
            force,
            yes,
        } => run_registry_undo(data_dir, discard, force, yes).await,
        Command::Credentials { action } => run_credentials(action, config),
        Command::Volume {
            action:
                VolumeAction::Measure {
                    dir,
                    sample_mib,
                    reads,
                    uplink_mbps,
                    rpc_url,
                },
        } => run_volume_measure(dir, sample_mib, reads, uplink_mbps, rpc_url).await,
        Command::Tpm {
            action: TpmAction::Provision,
        } => run_tpm_provision(),
        Command::Tpm {
            action: TpmAction::Handles,
        } => run_tpm_handles(),
        Command::Tpm {
            action: TpmAction::DeleteHandle { handle },
        } => run_tpm_delete_handle(&handle),
        Command::Tpm {
            action: TpmAction::Check { roots, out },
        } => run_tpm_check(&roots, out.as_deref()),
        Command::Tpm {
            action: TpmAction::Serve { config },
        } => tenzro_node::remote_tpm::serve(&config).await,
        Command::Tpm {
            action: TpmAction::Clients { action },
        } => run_tpm_clients(action),
        Command::Tpm {
            action:
                TpmAction::EnrolClient {
                    config,
                    passkey_public_key,
                    rp_id,
                    label,
                    derived,
                },
        } => run_enrol_client(&config, &passkey_public_key, &rp_id, &label, derived),
        Command::Tpm {
            action:
                TpmAction::Enrol {
                    socket,
                    label,
                    rp_id,
                    valid_hours,
                    assertion,
                },
        } => run_enrol(socket, label, rp_id, valid_hours, assertion).await,
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
                    json,
                    credential_id,
                    rp_id,
                },
        } => run_grant_request(
            socket,
            &label,
            valid_hours,
            credential_id.filter(|_| json),
            &rp_id,
        ),
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
        Command::Hardware => run_hardware(config, roles_named),
        Command::Tpm {
            action: TpmAction::KeysBackup { file, dir },
        } => run_keys_backup(file, dir),
        Command::Tpm {
            action: TpmAction::KeysVerify { file, dir },
        } => run_keys_verify(file, dir),
        Command::Tpm {
            action: TpmAction::KeysRestore { file, dir },
        } => run_keys_restore(file, dir),
        Command::Doctor {
            json,
            allow_inbound,
        } => {
            let binary = tenzro_node::doctor::current_binary();
            if allow_inbound {
                match tenzro_node::host_firewall::node_udp_port(&config.iroh) {
                    Some(port) => match tenzro_node::host_firewall::allow(&binary, port) {
                        Ok(done) => println!("{done}\n"),
                        Err(e) => return Err(error::NodeError::Config(e)),
                    },
                    None => println!(
                        "this node binds no fixed UDP port (a private node, or a port the system picks), so no \
                         inbound rule applies\n"
                    ),
                }
            }
            let report = tenzro_node::doctor::report(config, &binary, key_holder).await;
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
            genesis,
            proof_from,
            proof,
            handover_program,
        } => {
            let handover_program = handover_program
                .map(|h| hex32(&h, "--handover-program"))
                .transpose()?;
            let anchor = tenzro_light::TrustAnchor {
                epoch: 0,
                chain_id,
                genesis_hash: hex32(&genesis_hash, "--genesis-hash")?,
                committee_root: read_genesis(&genesis)?.committee_root()?,
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

/// `tenzro-node tpm clients`: reads, and for add and remove rewrites, the
/// provider file.
fn run_tpm_clients(action: ClientsAction) -> Result<()> {
    use tenzro_node::tpm_clients;
    let read = |path: &std::path::Path| {
        std::fs::read_to_string(path)
            .map_err(|e| error::NodeError::Config(format!("{}: {e}", path.display())))
    };
    match action {
        ClientsAction::List { config } => {
            let clients = tpm_clients::list(&read(&config)?)?;
            if clients.is_empty() {
                println!("no clients enrolled in {}", config.display());
            }
            for c in &clients {
                let key = c.passkey_public_key.trim_start_matches("0x");
                println!(
                    "label {}  rp_id {}  passkey {}…  derived {}",
                    c.label,
                    c.rp_id,
                    &key[..16.min(key.len())],
                    if c.derived { "yes" } else { "no" }
                );
            }
            println!("\n{}", tpm_clients::FIELD_NOTES);
            Ok(())
        }
        ClientsAction::Add {
            config,
            label,
            rp_id,
            registrations,
            one_device,
            derived,
        } => {
            let clients = registrations
                .iter()
                .map(|path| {
                    Ok(tenzro_node::remote_tpm::ClientEntry {
                        passkey_public_key: tpm_clients::passkey_from_registration(
                            &read(path)?,
                            &rp_id,
                        )
                        .map_err(|e| {
                            error::NodeError::Config(format!("{}: {e}", path.display()))
                        })?,
                        rp_id: rp_id.clone(),
                        label: label.clone(),
                        derived,
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            tpm_clients::write(
                &config,
                &tpm_clients::add(&read(&config)?, &clients, one_device)?,
            )?;
            println!(
                "enrolled {} passkey(s) for {label:?} in {}; a running provider takes them within \
                 seconds",
                clients.len(),
                config.display()
            );
            Ok(())
        }
        ClientsAction::Remove {
            config,
            label,
            passkey_public_key,
        } => {
            let out = tpm_clients::remove(&read(&config)?, &label, passkey_public_key.as_deref())?;
            tpm_clients::write(&config, &out)?;
            println!(
                "removed from {}; a running provider refuses the removed passkey within seconds",
                config.display()
            );
            Ok(())
        }
    }
}

/// Whether an ONNX Runtime that cannot use this machine's accelerator stops
/// a node with `roles` from starting: only when it serves models. Any other
/// node starts and refuses each ONNX model with the cause, so nothing runs
/// on the CPU in place of the GPU it found.
fn onnx_refusal_stops_start(roles: &tenzro_types::RoleSet) -> bool {
    roles.has(tenzro_types::NetworkRole::ModelProvider)
}

/// Whether `tenzro-node hardware` counts an ONNX refusal against starting.
/// With the operator's roles (`--roles` or a config file) it decides as the
/// node does at startup. Without them it cannot know the roles, and decides
/// by the build: a GPU build whose ONNX Runtime cannot use the GPU is broken
/// for the purpose it was taken for, while the CPU build on a GPU machine is
/// the one taken for roles that serve no models (and installs and updates
/// run this check without roles).
#[cfg(feature = "inference")]
fn onnx_refusal_counts(
    flavour: tenzro_model::hardware_policy::BuildFlavour,
    named_roles: Option<&tenzro_types::RoleSet>,
) -> bool {
    match named_roles {
        Some(roles) => onnx_refusal_stops_start(roles),
        None => flavour != tenzro_model::hardware_policy::BuildFlavour::Cpu,
    }
}

/// `tenzro-node hardware`: the build flavour, the GPUs it can drive, the
/// ONNX Runtime execution providers it will use, and the startup verdict.
/// One `key: value` line each, so install scripts can read them. An ONNX
/// refusal decides the verdict as [`onnx_refusal_counts`] says.
#[cfg(not(feature = "inference"))]
fn run_hardware(_config: &NodeConfig, _roles_named: bool) -> Result<()> {
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
fn run_hardware(config: &NodeConfig, roles_named: bool) -> Result<()> {
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
    let onnx = if runtime_unavailable.is_some() {
        Ok(Vec::new())
    } else {
        onnx
    };
    // A build whose GPU backend has no ONNX Runtime provider (Vulkan) starts
    // and refuses ONNX models one by one; for every other build an ONNX
    // runtime that cannot use this machine's accelerator stops it.
    let onnx = if flavour.accelerates_onnx() {
        onnx.map(|_| ())
    } else {
        Ok(())
    };
    let onnx = match onnx {
        Err(_) if !onnx_refusal_counts(flavour, roles_named.then_some(&config.roles)) => {
            println!(
                "onnx refusal: stops only a node that serves models; ONNX models are refused on this machine"
            );
            Ok(())
        }
        onnx => onnx,
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
    tenzro_node::single_instance::create_data_dir(&data_dir)?;
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
        consensus_timeout: std::time::Duration::from_secs(config.tpm.consensus_timeout_secs),
        breaker_trip_after: config.tpm.breaker_trip_after,
        breaker_base: std::time::Duration::from_secs(1),
        breaker_cap: std::time::Duration::from_secs(config.tpm.breaker_cap_secs.max(1)),
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

fn run_enrol_client(
    config: &std::path::Path,
    passkey_public_key: &str,
    rp_id: &str,
    label: &str,
    derived: bool,
) -> Result<()> {
    use tenzro_node::remote_tpm::{NewClient, Reload, enrol_client, reload_running};
    let clients = enrol_client(
        config,
        &NewClient {
            passkey_public_key,
            rp_id,
            label,
            derived,
        },
    )?;
    println!(
        "Enrolled {label} in {} ({clients} client(s)).",
        config.display()
    );
    match reload_running(config)? {
        Reload::Signalled(pid) => println!(
            "The provider running from this file (process {pid}) was told to take the new \
             client; it needs no restart."
        ),
        Reload::NotRunning => println!(
            "No provider is running from this file; the client is used when `tenzro-node tpm \
             serve --config {}` starts.",
            config.display()
        ),
    }
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

#[cfg(any(target_os = "linux", windows))]
fn run_tpm_handles() -> Result<()> {
    use tenzro_device_key::tpm_provision::HandleOwner;
    let handles = tenzro_device_key::tpm_provision::list_node_handles()
        .map_err(|e| error::NodeError::Other(e.to_string()))?;
    for h in &handles {
        let owner = match h.owner {
            HandleOwner::StorageRoot => "storage root",
            HandleOwner::Attestation => "attestation key",
            HandleOwner::ThisIdentity => "identity key of this process",
            HandleOwner::OtherIdentity => "identity key of another namespace (deletable)",
        };
        println!("0x{:08x}  {owner}", h.handle);
    }
    if handles.is_empty() {
        println!("no persistent handle made by this node");
    }
    Ok(())
}

#[cfg(any(target_os = "linux", windows))]
fn run_tpm_delete_handle(handle: &str) -> Result<()> {
    use std::io::{BufRead, IsTerminal};
    let value = u32::from_str_radix(handle.trim_start_matches("0x"), 16)
        .map_err(|_| error::NodeError::Config(format!("`{handle}` is not a hex TPM handle")))?;
    if !std::io::stdin().is_terminal() {
        return Err(error::NodeError::Config(
            "deleting a TPM handle needs an operator at a terminal to confirm".into(),
        ));
    }
    println!("This permanently deletes the key at 0x{value:08x} from the TPM.");
    println!("Type the handle to confirm:");
    let mut line = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut line)
        .map_err(|e| error::NodeError::Other(e.to_string()))?;
    let typed = line.trim().trim_start_matches("0x");
    if u32::from_str_radix(typed, 16) != Ok(value) {
        return Err(error::NodeError::Config(
            "not confirmed; nothing deleted".into(),
        ));
    }
    tenzro_device_key::tpm_provision::delete_node_handle(value)
        .map_err(|e| error::NodeError::Other(e.to_string()))?;
    println!("deleted 0x{value:08x}");
    Ok(())
}

#[cfg(not(any(target_os = "linux", windows)))]
fn run_tpm_handles() -> Result<()> {
    run_tpm_provision()
}

#[cfg(not(any(target_os = "linux", windows)))]
fn run_tpm_delete_handle(_handle: &str) -> Result<()> {
    run_tpm_provision()
}

fn run_tpm_check(roots: &[PathBuf], out: Option<&std::path::Path>) -> Result<()> {
    use tenzro_node::machine_conformance::{admissible, requirements};
    let other = |e: String| error::NodeError::Other(e);
    let pem = roots
        .iter()
        .map(|p| std::fs::read_to_string(p).map_err(|e| other(format!("{}: {e}", p.display()))))
        .collect::<Result<Vec<String>>>()?;
    let roots = tenzro_tee::tpm_attest::parse_roots(&pem).map_err(|e| other(e.to_string()))?;
    let (did, attestation) =
        tenzro_tee::tpm_attest::attest_local_machine(&[]).map_err(|e| other(e.to_string()))?;
    let identity = tenzro_tee::hardware_identity::HardwareIdentity::collect();
    let now = chrono::Utc::now().timestamp().max(0) as u64;
    let grade = tenzro_tee::tpm_attest::endorsement_grade(&attestation, &roots, now);
    let report = requirements(&did, &attestation, identity.sources(), &grade);
    println!("{:<18} {did}", "machine DID");
    for r in &report {
        let state = match (r.met, r.required) {
            (true, _) => "met",
            (false, true) => "NOT MET",
            (false, false) => "not met (reputation only)",
        };
        println!("{:<26} {state:<26} {}", r.id, r.detail);
    }
    if let Some(path) = out {
        let json = serde_json::json!({
            "did": did,
            "evidence": attestation.evidence,
            "nonce": hex::encode(&attestation.nonce),
            "identifier_sources": identity.sources(),
            "endorsement": grade.as_str(),
            "requirements": report,
        });
        std::fs::write(
            path,
            serde_json::to_vec_pretty(&json).map_err(|e| other(e.to_string()))?,
        )
        .map_err(|e| other(format!("{}: {e}", path.display())))?;
    }
    if admissible(&report) {
        Ok(())
    } else {
        Err(other(
            "this machine does not meet every required requirement".into(),
        ))
    }
}

#[cfg(not(any(target_os = "linux", windows)))]
fn run_tpm_check(_roots: &[PathBuf], _out: Option<&std::path::Path>) -> Result<()> {
    Err(error::NodeError::Config(
        "the TPM check needs a TPM 2.0 (Linux /dev/tpmrm0 or Windows TPM Base Services)".into(),
    ))
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

/// `tenzro-node registry-undo`: show, or discard, the registry's undo records.
async fn run_registry_undo(
    data_dir: Option<PathBuf>,
    discard: bool,
    force: bool,
    yes: bool,
) -> Result<()> {
    use tenzro_storage::traits::BlockStore as _;
    let data_dir = data_dir
        .map(tenzro_types::paths::expand_tilde)
        .unwrap_or_else(tenzro_types::paths::default_data_dir);
    // Only a store that is there: a wrong path is an error, not a new empty store.
    let store = std::sync::Arc::new(
        tenzro_storage::RocksDbStore::open_existing(&tenzro_storage::StorageConfig::new(
            data_dir.join("db"),
        ))
        .map_err(|e| {
            error::NodeError::Other(format!(
                "no node store could be opened at {} (wrong --data-dir, or the node is running?): {e}",
                data_dir.display()
            ))
        })?,
    );
    let blocks = tenzro_storage::BlockStoreImpl::new(store.clone())
        .map_err(|e| error::NodeError::Other(e.to_string()))?;
    let tip = blocks
        .latest_height()
        .await
        .map_err(|e| error::NodeError::Other(e.to_string()))?;
    let tip_epoch = match tip {
        Some(h) => blocks
            .get_block_by_height(h)
            .await
            .ok()
            .flatten()
            .map(|b| b.header.epoch),
        None => None,
    };
    println!(
        "chain tip: height {}, epoch {}",
        tip.map_or("none".to_string(), |h| h.0.to_string()),
        tip_epoch.map_or("none".to_string(), |e| e.to_string())
    );
    let registry = tenzro_token::validator_registry::ValidatorRegistry::with_storage(store);
    let records = registry.undo_summaries();
    if records.is_empty() {
        println!("no undo records");
        return Ok(());
    }
    for (tag, seq) in &records {
        match seq {
            Some(seq) => println!("{tag}  written #{seq}"),
            None => println!("{tag}  UNREADABLE"),
        }
    }
    if !discard {
        return Ok(());
    }
    let tags: Vec<String> = if force {
        records.iter().map(|(t, _)| t.clone()).collect()
    } else {
        registry.unreadable_undo_tags()
    };
    let uncommitted = tags
        .iter()
        .filter(|t| {
            event_loop::EventLoop::registry_tag_uncommitted(
                t,
                tip.map_or(0, |h| h.0),
                None,
                tip_epoch.unwrap_or(0),
            )
        })
        .count();
    eprintln!("{}", discard_consequence(tags.len(), uncommitted));
    if !yes {
        eprintln!("Type `{DISCARD_WORD}` to go on, or pass --yes:");
        confirm_typed(DISCARD_WORD, &mut std::io::stdin().lock())?;
    }
    // The mark goes in first: a stop between the two steps leaves a node that
    // refuses to start, never one that runs on an unmarked registry.
    if uncommitted > 0 {
        registry
            .mark_unverified()
            .map_err(error::NodeError::Other)?;
    }
    let n = registry
        .discard_undo_tags(&tags)
        .map_err(error::NodeError::Other)?;
    println!("discarded {n} undo records");
    Ok(())
}

/// The word `registry-undo --discard` asks for.
const DISCARD_WORD: &str = "discard";

/// What discarding `count` undo records, `uncommitted` of them of a change
/// that never committed, leads to.
fn discard_consequence(count: usize, uncommitted: usize) -> String {
    let mut text = format!(
        "Discarding {count} undo record(s) puts nothing back: the validator registry stays as the \
         last run left it."
    );
    if uncommitted > 0 {
        text.push_str(&format!(
            " {uncommitted} of them cover a block or epoch boundary that never committed, so the \
             registry may keep that change. The node will then refuse to start unless the registry \
             equals what the chain holds, replayed from its event log since the epoch's first block; \
             where the event log does not reach back that far it must be restored from a snapshot \
             (`tenzro-node restore`). A node that ran on such a \
             registry would stop following the chain, or as a validator sign for another committee \
             than the quorum, at the next epoch boundary."
        ));
    }
    text
}

/// Reads one line from `input` and refuses unless it is `word`.
fn confirm_typed(word: &str, input: &mut impl std::io::BufRead) -> Result<()> {
    let mut line = String::new();
    input.read_line(&mut line)?;
    if line.trim() == word {
        Ok(())
    } else {
        Err(error::NodeError::Config(format!(
            "`{word}` was not typed: nothing was discarded"
        )))
    }
}

#[cfg(test)]
mod registry_undo_tests {
    use super::{confirm_typed, discard_consequence};

    #[test]
    fn a_discard_goes_on_only_when_the_word_is_typed() {
        confirm_typed("discard", &mut "discard\n".as_bytes()).unwrap();
        assert!(confirm_typed("discard", &mut "yes\n".as_bytes()).is_err());
        assert!(confirm_typed("discard", &mut "".as_bytes()).is_err());
    }

    #[test]
    fn the_consequence_names_the_refusal_only_for_an_uncommitted_change() {
        let harmless = discard_consequence(2, 0);
        assert!(!harmless.contains("refuse to start"), "{harmless}");
        let risky = discard_consequence(2, 1);
        assert!(risky.contains("refuse to start"), "{risky}");
        assert!(risky.contains("tenzro-node restore"), "{risky}");
    }
}

fn read_genesis(path: &std::path::Path) -> Result<GenesisConfig> {
    let contents = std::fs::read_to_string(path)
        .map_err(|e| error::NodeError::Config(format!("Failed to read genesis file: {}", e)))?;
    toml::from_str(&contents)
        .map_err(|e| error::NodeError::Config(format!("Failed to parse genesis config: {}", e)))
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
    anchor: tenzro_light::TrustAnchor,
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

fn run_identity_key(data_dir: Option<PathBuf>, version: u64) -> Result<()> {
    if version == 0 {
        return Err(error::NodeError::Other(
            "key versions start at 1".to_string(),
        ));
    }
    let data_dir = data_dir
        .map(tenzro_types::paths::expand_tilde)
        .unwrap_or_else(tenzro_types::paths::default_data_dir);
    let keys = tenzro_keygen::NodeKeys::open(&data_dir)?;
    let change = tenzro_node::root_signatures::identity_key_update(&keys, version)?;
    println!("{}", serde_json::to_string_pretty(&change)?);
    Ok(())
}

/// `tenzro-node graceful-exit` — call `tenzro_gracefulExit` on the
/// running node's JSON-RPC. The RPC handler waits until this replica
/// leads none of the rounds its schedule looks ahead over, then triggers
/// the in-process `NodeEvent::Shutdown`. We print the JSON response and
/// exit 0 if the call succeeded — actual process termination on the
/// server is asynchronous (5s drain in `main()`).
///
/// The method is for the node's operator, so the command first signs in as
/// this machine with its hardware identity key, the operator of a node whose
/// config names no other, and presents the DPoP-bound token it is issued.
/// A node whose `operator_did` names someone else is stopped by them: they
/// sign in with `tenzro access sign-in` and call the method, or stop the
/// service, which sends SIGTERM.
async fn run_graceful_exit(
    rpc_url: String,
    max_wait_secs: u64,
    force: bool,
    config: &NodeConfig,
    delegated: bool,
) -> Result<()> {
    use tenzro_auth::client::{DPOP_KEY_LABEL, DpopKey, KeyHolderDpopKey};
    let other = |e: String| error::NodeError::Other(e);
    // Opened, never created: a machine without its identity key is not the
    // machine the node runs as, and a new key would sign in as nobody.
    let identity = tenzro_device_key::signer::open(tenzro_types::did_derivation::MACHINE_KEY_LABEL)
        .map_err(|e| other(format!("this machine's identity key: {e}")))?;
    let did = tenzro_types::did_derivation::machine_did(
        &identity
            .public_key_sec1()
            .map_err(|e| other(format!("this machine's identity key: {e}")))?,
    );
    if let Some(operator) = config
        .operator_did
        .as_deref()
        .map(str::trim)
        .filter(|o| !o.is_empty() && *o != did)
    {
        return Err(error::NodeError::Config(format!(
            "this node's operator is {operator}, not this machine ({did}); graceful-exit signs in \
             as the machine. The operator signs in with `tenzro access sign-in` and calls \
             tenzro_gracefulExit, or the service is stopped, which sends SIGTERM"
        )));
    }
    // A machine whose keys are in another machine's TPM proves with the key
    // its key holder derives for DPoP: the holder signs with a TPM-resident
    // key only messages in a Tenzro domain, which a DPoP proof never is.
    let dpop_signer: Box<dyn tenzro_device_key::HardwareSigner> = if delegated {
        Box::new(KeyHolderDpopKey::open().map_err(|e| other(e.to_string()))?)
    } else {
        tenzro_device_key::signer::open_or_create(DPOP_KEY_LABEL)
            .map_err(|e| other(format!("no hardware key for DPoP: {e}")))?
    };
    let dpop = DpopKey::new(dpop_signer);
    let http = tenzro_node::http_client::shared();
    let signed = tenzro_auth::client::sign_in(
        |method, params| {
            let url = rpc_url.clone();
            async move { json_rpc(http, &url, method, params).await }
        },
        identity.as_ref(),
        &dpop,
    )
    .await
    .map_err(|e| other(format!("signing in to {rpc_url} as {did}: {e}")))?;
    let headers = tenzro_auth::client::authorization(&signed.access_token, &dpop, &rpc_url)
        .map_err(|e| other(e.to_string()))?;

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
    let mut request = http
        .post(&rpc_url)
        .timeout(std::time::Duration::from_secs(
            max_wait_secs.saturating_add(30),
        ))
        .json(&req);
    for (name, value) in headers {
        request = request.header(name, value);
    }
    let resp = request
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

/// `tenzro-node volume measure`: measures the volume and prints, as JSON,
/// the measurement and the classes it qualifies for under the deadlines the
/// node's chain governs.
async fn run_volume_measure(
    dir: std::path::PathBuf,
    sample_mib: u64,
    reads: usize,
    uplink_mbps: u64,
    rpc_url: String,
) -> Result<()> {
    use tenzro_storage_provider::volume_probe;
    let other = |e: String| error::NodeError::Other(e);
    let http = reqwest::Client::new();
    let mut classes = Vec::new();
    for class in ["hot", "warm", "cold"] {
        let key = format!("feature.storage_classes.{class}_deadline_ms");
        let param = json_rpc(
            &http,
            &rpc_url,
            "tenzro_getNetworkParams",
            serde_json::json!({ "key": key }),
        )
        .await
        .map_err(other)?;
        let deadline = param["value"]
            .as_str()
            .and_then(|v| v.parse::<u64>().ok())
            .ok_or_else(|| other(format!("{key}: the node answered no value")))?;
        classes.push((class.to_string(), deadline));
    }
    let measured =
        tokio::task::spawn_blocking(move || volume_probe::measure(&dir, sample_mib << 20, reads))
            .await
            .map_err(|e| other(e.to_string()))?
            .map_err(|e| other(e.to_string()))?;
    let uplink_bytes_per_s = uplink_mbps.saturating_mul(1_000_000) / 8;
    let samples_param = json_rpc(
        &http,
        &rpc_url,
        "tenzro_getNetworkParams",
        serde_json::json!({ "key": tenzro_vm::native::compute_claim::POSSESSION_PROBE_SAMPLES_PARAM }),
    )
    .await
    .map_err(other)?;
    let samples = samples_param["value"]
        .as_str()
        .and_then(|v| v.parse::<u32>().ok())
        .ok_or_else(|| other("the node answered no possession sample count".to_string()))?;
    let fits = volume_probe::propose(&measured, uplink_bytes_per_s, samples, &classes);
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "volume": measured,
            "uplink_bytes_per_s": uplink_bytes_per_s,
            "probe_samples_per_object": samples,
            "margin": volume_probe::PROPOSAL_MARGIN,
            "classes": fits,
        }))
        .unwrap_or_default()
    );
    Ok(())
}

/// One JSON-RPC call to `url`: its result, or the error the node answered.
async fn json_rpc(
    http: &reqwest::Client,
    url: &str,
    method: &str,
    params: serde_json::Value,
) -> std::result::Result<serde_json::Value, String> {
    let body: serde_json::Value = http
        .post(url)
        .json(&serde_json::json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params }))
        .send()
        .await
        .map_err(|e| format!("{method}: {e}"))?
        .json()
        .await
        .map_err(|e| format!("{method}: {e}"))?;
    match body.get("error") {
        Some(error) => Err(format!("{method}: {error}")),
        None => Ok(body.get("result").cloned().unwrap_or_default()),
    }
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

/// Sends every panic to the log, at error, with what it said, where it was
/// raised and the stack it was raised on. The stack is captured whether or
/// not `RUST_BACKTRACE` is set, so a crash in a service started without it
/// still names the functions it went through.
fn log_panics() {
    let last_stack = std::sync::atomic::AtomicI64::new(i64::MIN);
    std::panic::set_hook(Box::new(move |info| {
        let location = info
            .location()
            .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()))
            .unwrap_or_else(|| "an unknown location".to_string());
        let thread = std::thread::current();
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_millis() as i64);
        report_panic(
            thread.name().unwrap_or("unnamed"),
            &location,
            panic_message(info.payload()),
            &last_stack,
            now_ms,
        );
    }));
}

/// Reports one panic: to the log at error once a log subscriber is in
/// effect, to stderr before. The stack goes with it when [`stack_due`] says.
fn report_panic(
    thread: &str,
    location: &str,
    message: &str,
    last_stack: &std::sync::atomic::AtomicI64,
    now_ms: i64,
) {
    let stack = stack_due(last_stack, now_ms).then(std::backtrace::Backtrace::force_capture);
    if !logging_is_set() {
        eprintln!("panic in thread {thread} at {location}: {message}");
        match &stack {
            Some(stack) => eprintln!("{stack}"),
            None => eprintln!(
                "(stack omitted: one is captured at most every {}s)",
                PANIC_STACK_SPACING_MS / 1000
            ),
        }
        return;
    }
    match &stack {
        Some(stack) => tracing::error!(
            thread,
            %location,
            backtrace = %stack,
            "panic: {message}"
        ),
        None => tracing::error!(
            thread,
            %location,
            "panic: {message} (stack omitted: one is captured at most every {}s)",
            PANIC_STACK_SPACING_MS / 1000
        ),
    }
}

/// Whether a log subscriber is in effect on this thread, the process-wide one
/// or a scoped one: until there is, a log event goes nowhere.
fn logging_is_set() -> bool {
    tracing::dispatcher::get_default(|d| !d.is::<tracing::subscriber::NoSubscriber>())
}

/// Least time between two panics logged with their stack, ms. Some panics
/// are raised on input from peers and caught, so a peer could otherwise make
/// the node walk and log its stack once per message.
const PANIC_STACK_SPACING_MS: i64 = 60_000;

/// Whether a panic at `now_ms` is logged with its stack: the first one is,
/// and then one per [`PANIC_STACK_SPACING_MS`]. `last` holds when the last
/// stack was taken and is moved on by the panic that takes the next.
fn stack_due(last: &std::sync::atomic::AtomicI64, now_ms: i64) -> bool {
    use std::sync::atomic::Ordering;
    let prev = last.load(Ordering::Relaxed);
    if prev != i64::MIN && now_ms.saturating_sub(prev) < PANIC_STACK_SPACING_MS {
        return false;
    }
    last.compare_exchange(prev, now_ms, Ordering::Relaxed, Ordering::Relaxed)
        .is_ok()
}

/// What a panic said: the text of a `panic!`, or a note that its payload is
/// not text.
fn panic_message(payload: &(dyn std::any::Any + Send)) -> &str {
    payload
        .downcast_ref::<&str>()
        .copied()
        .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
        .unwrap_or("a payload that is not text")
}

#[cfg(test)]
mod panic_log_tests {
    use super::{PANIC_STACK_SPACING_MS, panic_message, report_panic, stack_due};
    use std::sync::atomic::AtomicI64;
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Default)]
    struct Buffer(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for Buffer {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// A panic goes to the log with its message, and one within the spacing
    /// of the last stack without its stack. The subscriber is scoped to this
    /// thread and no hook is installed, so no other test sees either.
    #[test]
    fn a_panic_is_logged_and_stacks_are_rationed() {
        let buffer = Buffer::default();
        let writer = buffer.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(move || writer.clone())
            .with_ansi(false)
            .finish();
        let last = AtomicI64::new(i64::MIN);
        tracing::subscriber::with_default(subscriber, || {
            report_panic("t", "here.rs:1:1", "first", &last, 1_000);
            report_panic("t", "here.rs:2:1", "second", &last, 2_000);
        });
        let out = String::from_utf8(buffer.0.lock().unwrap().clone()).unwrap();
        assert!(out.contains("panic: first"), "{out}");
        assert!(out.contains("backtrace="), "{out}");
        assert!(out.contains("panic: second"), "{out}");
        assert!(out.contains("stack omitted"), "{out}");
    }

    /// Without a log subscriber in effect a panic is written to stderr; with
    /// one, to the log. Both are scoped to this thread, so whatever another
    /// test sets process-wide does not change the answer.
    #[test]
    fn a_panic_before_logging_is_set_goes_to_stderr() {
        tracing::subscriber::with_default(tracing::subscriber::NoSubscriber::default(), || {
            assert!(!super::logging_is_set())
        });
        let subscriber = tracing_subscriber::fmt()
            .with_writer(std::io::sink)
            .finish();
        tracing::subscriber::with_default(subscriber, || assert!(super::logging_is_set()));
    }

    #[test]
    fn a_stack_is_taken_at_most_once_per_spacing() {
        let last = AtomicI64::new(i64::MIN);
        assert!(stack_due(&last, 1_000));
        assert!(!stack_due(&last, 1_000 + PANIC_STACK_SPACING_MS - 1));
        assert!(stack_due(&last, 1_000 + PANIC_STACK_SPACING_MS));
        assert!(!stack_due(&last, 1_001 + PANIC_STACK_SPACING_MS));
    }

    #[test]
    fn a_panic_message_is_read_from_both_text_payloads() {
        let literal = std::panic::catch_unwind(|| panic!("literal")).unwrap_err();
        assert_eq!(panic_message(literal.as_ref()), "literal");
        let n = 7;
        let formatted = std::panic::catch_unwind(|| panic!("formatted {n}")).unwrap_err();
        assert_eq!(panic_message(formatted.as_ref()), "formatted 7");
        let other = std::panic::catch_unwind(|| std::panic::panic_any(7u8)).unwrap_err();
        assert_eq!(panic_message(other.as_ref()), "a payload that is not text");
    }
}

/// The node config file as a raw TOML table, when one is given and parses.
fn config_table(cli: &Cli) -> Option<toml::Table> {
    cli.config
        .as_ref()
        .and_then(|path| std::fs::read_to_string(path).ok())
        .and_then(|text| text.parse::<toml::Table>().ok())
}

/// Whether the node config file names `[onboarding] mode` itself.
fn config_sets_onboarding_mode(cli: &Cli) -> bool {
    config_table(cli)
        .and_then(|table| table.get("onboarding")?.get("mode").cloned())
        .is_some()
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
        config.genesis = Some(read_genesis(genesis_path)?);
    }

    // A node given no `--boot-nodes` joins through the network profile the
    // release ships (`share/network/<chain_id>.toml`): the relay, its
    // operator's identity and the genesis validators. Not for a local chain
    // (--dev, --solo) or an isolated node, which dial no one.
    if !cli.dev && !cli.solo && !isolated {
        let exe = std::env::current_exe()
            .ok()
            .and_then(|p| p.canonicalize().ok());
        let from_env = std::env::var(tenzro_node::network_profile::PROFILE_ENV).ok();
        let chain_id = config.chain_id();
        tenzro_node::network_profile::apply(
            &mut config.iroh.boot,
            cli.boot_nodes.is_some(),
            chain_id,
            exe.as_deref(),
            from_env.as_deref(),
        )?;
    }

    // The identity gate mode the network profile ships, unless this node's
    // config file sets one: a release that ships the profile enforces the
    // rule without any setting by the operator.
    if !cli.dev && !cli.solo && !isolated && !config_sets_onboarding_mode(cli) {
        let exe = std::env::current_exe()
            .ok()
            .and_then(|p| p.canonicalize().ok());
        let from_env = std::env::var(tenzro_node::network_profile::PROFILE_ENV).ok();
        if let Some(mode) = tenzro_node::network_profile::onboarding_mode(
            config.chain_id(),
            exe.as_deref(),
            from_env.as_deref(),
        )? {
            info!(?mode, "identity gate mode taken from the network profile");
            config.onboarding.policy.mode = mode;
        }
    }

    // Snapshot join defaults the network profile ships: the snapshot peers
    // (`[state_sync] from`) and the snapshot producer settings (`[snapshot]`).
    // Whatever the node config file sets itself wins.
    if !cli.dev && !cli.solo && !isolated {
        let exe = std::env::current_exe()
            .ok()
            .and_then(|p| p.canonicalize().ok());
        let from_env = std::env::var(tenzro_node::network_profile::PROFILE_ENV).ok();
        if let Some(profile) = tenzro_node::network_profile::shipped(
            config.chain_id(),
            exe.as_deref(),
            from_env.as_deref(),
        )? {
            let table = config_table(cli);
            if let Some(sync) = &profile.state_sync {
                let node_sets = table
                    .as_ref()
                    .is_some_and(|t| t.contains_key("state_sync_from"));
                if !node_sets && config.state_sync_from.is_empty() && !sync.from.is_empty() {
                    info!(
                        peers = sync.from.len(),
                        "state sync peers taken from the network profile"
                    );
                    config.state_sync_from = sync.from.clone();
                }
            }
            if let Some(snapshot) = &profile.snapshot {
                let node_sets = |key: &str| {
                    table
                        .as_ref()
                        .and_then(|t| t.get("snapshot")?.as_table()?.get(key))
                        .is_some()
                };
                snapshot.apply_to(&mut config.snapshot, &node_sets);
            }
        }
    }

    config.log_level = cli.log_level.clone();
    apply_listen_overrides(config, cli);

    if cli.no_state_sync {
        config.state_sync = tenzro_node::state_sync_policy::StateSyncMode::Off;
    }

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
    if let Some(port) = cli.iroh_bind_port {
        config.iroh.bind_addr.set_port(port);
    }
}

/// Moves the data directory's chain store to `db.replaced-<unix seconds>`
/// beside it, so a snapshot join starts on an empty store and the old one can
/// be moved back. Returns where it went, or `None` when there was no store.
fn move_store_aside(data_dir: &Path) -> Result<Option<(PathBuf, PathBuf)>> {
    let db = data_dir.join("db");
    if !db.exists() {
        return Ok(None);
    }
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let aside = data_dir.join(format!("db.replaced-{stamp}"));
    std::fs::rename(&db, &aside).map_err(|e| {
        error::NodeError::Other(format!(
            "--replace-store: moving {} to {}: {e}",
            db.display(),
            aside.display()
        ))
    })?;
    Ok(Some((db, aside)))
}

/// Parse a comma-separated roles string into a `RoleSet`.
/// Parses the state-sync peers (`<EndpointId>` or `<EndpointId>@<ip:port>`),
/// joining entries that name one endpoint.
fn parse_state_sync_peers<'a>(
    entries: impl IntoIterator<Item = &'a String>,
) -> Result<Vec<tenzro_iroh::EndpointAddr>> {
    let mut peers = Vec::new();
    for entry in entries {
        peers.push(
            tenzro_iroh::parse_peer(entry)
                .map_err(|e| error::NodeError::Other(format!("--state-sync-from {entry}: {e}")))?,
        );
    }
    Ok(tenzro_iroh::merge_peers(peers))
}

#[cfg(test)]
mod state_sync_peer_tests {
    #[test]
    fn replace_store_moves_the_store_aside_and_keeps_it() {
        let dir = tempfile::tempdir().unwrap();
        assert!(
            move_store_aside(dir.path()).unwrap().is_none(),
            "no store, nothing moved"
        );
        std::fs::create_dir(dir.path().join("db")).unwrap();
        std::fs::write(dir.path().join("db").join("CURRENT"), b"chain").unwrap();
        let (db, aside) = move_store_aside(dir.path()).unwrap().expect("store moved");
        assert!(
            !db.exists(),
            "the live store path is free for the fresh store"
        );
        assert_eq!(std::fs::read(aside.join("CURRENT")).unwrap(), b"chain");
        assert!(
            aside
                .file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("db.replaced-")
        );
    }

    use super::*;

    #[test]
    fn config_and_flag_entries_merge_and_bad_ones_are_refused() {
        let id = tenzro_iroh::EndpointId::from_bytes(&ed25519_public([9; 32])).unwrap();
        let from_config = [format!("{id}@127.0.0.1:1")];
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

/// The weak-subjectivity checkpoint this node starts from, as height, block
/// hash and where the pair was read: the command line when it gives both, or
/// else the genesis `[weak_subjectivity]` block. The source is named in the
/// start log, so an operator sees which of the two the node trusts. Half a
/// pair is refused: falling back to the genesis checkpoint would trust one
/// the operator did not name.
fn weak_subjectivity_checkpoint(
    cli_hash: Option<&str>,
    cli_height: Option<u64>,
    genesis: Option<&tenzro_node::config::WeakSubjectivityAnchor>,
) -> Result<Option<(u64, [u8; 32], &'static str)>> {
    match (cli_hash, cli_height, genesis) {
        (Some(hash_hex), Some(height), _) => Ok(Some((
            height,
            parse_hash32(hash_hex, "--checkpoint-hash")?,
            "--checkpoint-height and --checkpoint-hash",
        ))),
        (Some(_), None, _) => Err(error::NodeError::Config(
            "--checkpoint-hash needs --checkpoint-height".to_string(),
        )),
        (None, Some(_), _) => Err(error::NodeError::Config(
            "--checkpoint-height needs --checkpoint-hash".to_string(),
        )),
        (None, None, Some(ws)) => Ok(Some((
            ws.height,
            parse_hash32(
                &ws.block_hash_hex,
                "genesis weak_subjectivity.block_hash_hex",
            )?,
            "genesis [weak_subjectivity]",
        ))),
        _ => Ok(None),
    }
}

#[cfg(test)]
mod weak_subjectivity_checkpoint_tests {
    use super::*;

    /// The command line's pair stands over the genesis block's, and each is
    /// reported with where it was read.
    #[test]
    fn the_checkpoint_names_its_source() {
        let genesis = tenzro_node::config::WeakSubjectivityAnchor {
            height: 7,
            block_hash_hex: hex::encode([7u8; 32]),
        };
        let cli_hash = format!("0x{}", hex::encode([9u8; 32]));
        assert_eq!(
            weak_subjectivity_checkpoint(Some(&cli_hash), Some(9), Some(&genesis)).unwrap(),
            Some((9, [9; 32], "--checkpoint-height and --checkpoint-hash"))
        );
        assert_eq!(
            weak_subjectivity_checkpoint(None, None, Some(&genesis)).unwrap(),
            Some((7, [7; 32], "genesis [weak_subjectivity]"))
        );
        // Half a pair is refused, never filled in from the genesis.
        let refused = |r: Result<Option<(u64, [u8; 32], &str)>>| {
            r.expect_err("half a checkpoint was accepted").to_string()
        };
        assert!(
            refused(weak_subjectivity_checkpoint(
                Some(&cli_hash),
                None,
                Some(&genesis)
            ))
            .contains("--checkpoint-hash needs --checkpoint-height")
        );
        assert!(
            refused(weak_subjectivity_checkpoint(None, Some(9), Some(&genesis)))
                .contains("--checkpoint-height needs --checkpoint-hash")
        );
        assert!(weak_subjectivity_checkpoint(None, Some(9), None).is_err());
        assert_eq!(
            weak_subjectivity_checkpoint(None, None, None).unwrap(),
            None
        );
        assert!(weak_subjectivity_checkpoint(Some("zz"), Some(1), None).is_err());
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
║          Compute of every kind, settled in TNZO           ║
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

    /// `--iroh-bind-port` names the port the iroh endpoint binds and leaves
    /// the rest of its address alone; without it the configured one stays.
    #[test]
    fn the_iroh_bind_port_flag_sets_only_the_port() {
        let mut config = config_with_own_listeners();
        let ip = config.iroh.bind_addr.ip();
        let before = config.iroh.bind_addr.port();
        let cli = Cli::try_parse_from(["tenzro-node"]).unwrap();
        apply_listen_overrides(&mut config, &cli);
        assert_eq!(config.iroh.bind_addr.port(), before);
        let cli = Cli::try_parse_from(["tenzro-node", "--iroh-bind-port", "9101"]).unwrap();
        apply_listen_overrides(&mut config, &cli);
        assert_eq!(
            (config.iroh.bind_addr.ip(), config.iroh.bind_addr.port()),
            (ip, 9101)
        );
    }

    /// A blocking task still running when the node is done does not hold the
    /// process: the runtime ends within the grace, not when the task does.
    #[test]
    fn a_blocking_task_does_not_hold_the_process_past_the_grace() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        let started = std::time::Instant::now();
        let out = run_to_end(
            runtime,
            async {
                tokio::task::spawn_blocking(|| {
                    std::thread::sleep(std::time::Duration::from_secs(30))
                });
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                7
            },
            std::time::Duration::from_millis(300),
        );
        assert_eq!(out, 7);
        assert!(
            started.elapsed() < std::time::Duration::from_secs(10),
            "ended after {:?}",
            started.elapsed()
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

#[cfg(all(test, unix))]
mod key_holder_tests {
    //! The key holder listens on a Unix socket, so these run on Unix only.
    use super::*;
    use clap::Parser;

    fn parse(args: &[&str]) -> (Cli, Command) {
        let mut cli = Cli::try_parse_from(args).unwrap();
        let cmd = cli.command.take().expect("a subcommand");
        (cli, cmd)
    }

    /// A one-off subcommand on a machine whose key is held elsewhere opens
    /// its keys through the key holder, before it runs.
    #[test]
    fn a_one_off_subcommand_opens_its_keys_through_the_key_holder() {
        let (cli, cmd) = parse(&[
            "tenzro-node",
            "--tpm-key-holder",
            "/nonexistent/holder.sock",
            "--tpm-label",
            "edge",
            "validator-entry",
            "--stake",
            "1",
        ]);
        assert!(subcommand_key_holder(&cli, &cmd).unwrap());
        assert!(tenzro_node::identity_bootstrap::remote_tpm_configured());
    }

    /// A key holder named without its label is refused, not ignored.
    #[test]
    fn a_key_holder_without_a_label_is_refused() {
        let (cli, cmd) = parse(&[
            "tenzro-node",
            "--tpm-key-holder",
            "/nonexistent/holder.sock",
            "validator-entry",
            "--stake",
            "1",
        ]);
        assert!(subcommand_key_holder(&cli, &cmd).is_err());
    }

    /// The `tpm` subcommands address a key holder themselves; the global
    /// flags do not install one under them.
    #[test]
    fn tpm_subcommands_leave_the_key_holder_to_themselves() {
        let (cli, cmd) = parse(&[
            "tenzro-node",
            "--tpm-key-holder",
            "/nonexistent/holder.sock",
            "--tpm-label",
            "edge",
            "tpm",
            "remote-check",
            "--key-holder",
            "/nonexistent/holder.sock",
            "--label",
            "edge",
        ]);
        assert!(!subcommand_key_holder(&cli, &cmd).unwrap());
    }
}

#[cfg(test)]
mod onnx_refusal_tests {
    use super::*;
    use tenzro_types::{NetworkRole, RoleSet};

    #[test]
    fn only_a_node_that_serves_models_is_stopped_by_an_onnx_runtime_that_cannot_use_the_gpu() {
        for r in NetworkRole::ALL {
            let alone = RoleSet::from_roles([r]);
            assert_eq!(
                onnx_refusal_stops_start(&alone),
                r == NetworkRole::ModelProvider,
                "{r:?}"
            );
            let with_models = RoleSet::from_roles([r, NetworkRole::ModelProvider]);
            assert!(
                onnx_refusal_stops_start(&with_models),
                "{r:?} with ModelProvider"
            );
        }
        // A CPU build on an NVIDIA machine runs the validator, rpc and light roles.
        let roles = RoleSet::from_roles([
            NetworkRole::Validator,
            NetworkRole::Rpc,
            NetworkRole::LightClient,
        ]);
        assert!(!onnx_refusal_stops_start(&roles));
    }

    #[cfg(feature = "inference")]
    #[test]
    fn the_hardware_check_without_roles_holds_a_gpu_build_to_its_gpu_and_not_the_cpu_build() {
        use tenzro_model::hardware_policy::BuildFlavour;
        assert!(!onnx_refusal_counts(BuildFlavour::Cpu, None));
        assert!(onnx_refusal_counts(BuildFlavour::Cuda, None));
        let models = RoleSet::from_roles([NetworkRole::ModelProvider]);
        let validator = RoleSet::from_roles([NetworkRole::Validator]);
        for flavour in [BuildFlavour::Cpu, BuildFlavour::Cuda] {
            assert!(onnx_refusal_counts(flavour, Some(&models)), "{flavour:?}");
            assert!(
                !onnx_refusal_counts(flavour, Some(&validator)),
                "{flavour:?}"
            );
        }
    }
}

#[cfg(test)]
mod embedded_cli_tests {
    use super::*;

    fn args(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn an_embedded_node_runs_the_node_in_the_apps_own_directory() {
        let cli = embedded_cli(args(&[
            "--data-dir",
            "/data/user/0/app/files/node",
            "--roles",
            "light",
        ]))
        .unwrap();
        assert_eq!(
            cli.data_dir.as_deref(),
            Some(std::path::Path::new("/data/user/0/app/files/node"))
        );
        // A subcommand, a missing data directory or an unknown flag is refused.
        assert!(embedded_cli(args(&["--data-dir", "/d", "hardware"])).is_err());
        assert!(embedded_cli(args(&["--roles", "light"])).is_err());
        assert!(embedded_cli(args(&["--data-dir", "/d", "--no-such-flag"])).is_err());
    }
}
