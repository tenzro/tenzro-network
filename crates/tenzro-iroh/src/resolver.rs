//! `IrohResolver` trait — the dispatch surface that crates depend on
//! without pulling in the iroh runtime, and `IrohBackedResolver` — the
//! concrete iroh-blobs-backed implementation added here
//! alongside the `DaBackend` impl in `tenzro-storage::da`.

use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::ops::Deref;
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use dashmap::DashMap;
use iroh::{Endpoint, EndpointId, protocol::Router};
use iroh_blobs::{
    ALPN, BlobFormat, BlobsProtocol, Hash,
    api::{
        Store as BlobStore,
        blobs::{AddPathOptions, ImportMode},
        downloader::Downloader,
    },
    store::{fs::FsStore, mem::MemStore},
};
use tokio::sync::Mutex;

use crate::config::TenzroIrohConfig;
use crate::discovery::{ALPN_DISCOVERY, DiscoveryProtocol, DiscoveryStore};
use crate::error::{IrohError, IrohResult};
use crate::connection_limits::{ConnectionGate, GatedRouter};
use crate::identity_transport::{IdentityTransport, base_builder, base_builder_with, with_relays};
use crate::jsonrpc::{
    ALPN_A2A_PQ, ALPN_MCP_PQ, ALPN_MOE_PQ, JsonRpcDispatcher,
    JsonRpcProtocol, McpProtocol, McpStreamHandler,
};
use crate::request::{
    ALPN_DA_COMMITTEE, ALPN_INFER, DeferredRequestHandler, MAX_INFER_BYTES, MAX_STORE_REQUEST,
    RequestHandler, RequestProtocol,
};
use tenzro_types::tenzro_uri::TenzroUri;

/// Resolution dispatch surface.
///
/// Implementations decode `TenzroUri` variants into their concrete fetch
/// paths (iroh-blobs for content, iroh::Endpoint dial for node references,
/// etc.). Callers that only need to fetch a payload (RPC handlers, the
/// CLI, MCP tool handlers) depend on this trait and stay decoupled from
/// the iroh runtime.
#[async_trait]
pub trait IrohResolver: Send + Sync {
    /// Fetch the raw bytes referenced by a content-addressed URI variant:
    /// `Blob`, `Model`, `Receipt`.
    ///
    /// For non-content variants (`Node`, `Did`), implementations
    /// return `IrohError::UnsupportedVariant(...)` — callers should match
    /// on the URI variant before deciding which resolver method to call.
    async fn fetch_bytes(&self, uri: &TenzroUri) -> IrohResult<Bytes>;

    /// Publish raw bytes to the iroh-blobs store under a content-addressed
    /// URI. Returns the canonical `TenzroUri::Blob` (or variant-specific
    /// equivalent) under which the bytes are now reachable.
    ///
    /// The returned URI's BLAKE3 hash is derived from the canonical payload
    /// — implementations are responsible for computing it (typically via
    /// `iroh_blobs::Hash::from_bytes`) rather than trusting the caller.
    async fn publish_bytes(&self, bytes: Bytes) -> IrohResult<TenzroUri>;

    /// Publish a file already on disk, referencing it in place rather than
    /// copying its bytes into the store.
    ///
    /// Model weights are multi-gigabyte, so the `publish_bytes` path costs a
    /// full read into memory plus a second copy on disk. `ImportMode::TryReference`
    /// avoids both when the file and the store share a filesystem. The caller
    /// keeps ownership of the file and must not modify it afterwards — iroh
    /// assumes referenced content is immutable.
    async fn publish_path(&self, path: &Path) -> IrohResult<TenzroUri>;
}

/// Blob store backing for the resolver. Both variants deref to
/// [`iroh_blobs::api::Store`], so every read/write path is identical —
/// the enum only pins which owner keeps the store actor alive.
///
/// - `Fs` — redb-backed persistent store rooted under the node data dir
///   (`{data_dir}/iroh/blobs`). Used by every config-driven bind so
///   published blobs survive process restart.
/// - `Mem` — in-memory store for tests and ad-hoc clients bound via
///   [`IrohBackedResolver::bind_in_memory`].
enum ResolverStore {
    Fs(FsStore),
    Mem(MemStore),
}

impl Deref for ResolverStore {
    type Target = BlobStore;

    fn deref(&self) -> &BlobStore {
        match self {
            Self::Fs(s) => s,
            Self::Mem(s) => s,
        }
    }
}

/// iroh-blobs-backed implementation of [`IrohResolver`].
///
/// Owns an [`Endpoint`], a [`BlobStore`] (filesystem-backed under the node
/// data dir for config-driven binds; in-memory for tests), and a [`Router`]
/// that registers the iroh-blobs ALPN so peers can fetch by hash. Drop /
/// `shutdown` to release the endpoint cleanly.
///
/// # Variant support
///
/// - `tenzro://blob/<hash>` — fetch + publish via the local store, with
///   transparent BLAKE3 verification on fetch.
/// - `tenzro://model/<id>@<hash>` and `tenzro://receipt/<kind>/<hash>` —
///   dispatch to the same blob path keyed on the URI's embedded hash. The
///   non-hash fields are metadata for the caller; the resolver treats them
///   as content-addressed against `hash`.
/// - `tenzro://node/<id>` and `tenzro://did/<did>` — return
///   `IrohError::UnsupportedVariant`. Node / DID dialing lives on a separate
///   surface.
pub struct IrohBackedResolver {
    endpoint: Endpoint,
    store: ResolverStore,
    /// Router is kept alive (not used directly after spawn) so the
    /// iroh-blobs ALPN handler stays registered until shutdown.
    router: Mutex<Option<Router>>,
    /// Cross-node blob downloader. Constructed once over `endpoint` + `store`
    /// at bind time, reused on every `fetch_bytes` miss. Performs the actual
    /// QUIC dial + BAO-stream pull against a provider `EndpointId` when the
    /// blob is not yet in the local store.
    downloader: Downloader,
    /// The records of the machines this node knows, its own included. A
    /// licence-bound blob is served only to a machine whose record accepts
    /// the licence, and this node's own record is shown to a provider before
    /// it asks for one.
    discovery: Option<Arc<DiscoveryStore>>,
    /// The ML-DSA leg of endpoint authentication for the versioned RPC
    /// ALPNs, when the node runs an identity transport.
    pq: Option<crate::pq_endpoint::PqChannel>,
    /// Blob-availability hint cache: BLAKE3 hex → endpoints known to hold
    /// the blob. Populated by the node layer from `tenzro/blobs` gossip
    /// announcements (see `record_blob_provider`), consulted by
    /// `fetch_bytes` when the URI carries no explicit provider hint.
    /// Bounded per-hash at [`MAX_PROVIDERS_PER_BLOB`]; entries rotate
    /// oldest-out so freshly announced providers win.
    hint_cache: DashMap<String, Vec<EndpointId>>,
    /// Snapshot manifests this node serves over [`crate::state_sync::ALPN_STATE_SYNC`].
    /// Empty until the node installs its snapshot store.
    snapshot_directory: crate::state_sync::DeferredSnapshotDirectory,
    /// Consensus streams peers open over [`crate::consensus::ALPN_CONSENSUS`].
    consensus_handler: crate::consensus::DeferredConsensusHandler,
    /// Block-sync requests peers send over [`crate::block_sync::ALPN_BLOCK_SYNC`].
    block_sync_server: crate::block_sync::DeferredBlockSyncServer,
    /// Topic broadcast served over [`crate::gossip::ALPN_GOSSIP`].
    gossip: crate::gossip::GossipTransport,
    /// Committee DA requests peers send over [`ALPN_DA_COMMITTEE`].
    da_committee_handler: DeferredRequestHandler,
    /// Agent-key requests peers send over [`crate::request::ALPN_AGENT_KEY`].
    agent_key_handler: DeferredRequestHandler,
    /// Agent tokens peers deliver over [`crate::request::ALPN_AGENT_TOKEN`].
    agent_token_handler: DeferredRequestHandler,
    /// Session successor assignments and sealed KV-cache deltas peers send
    /// over [`crate::request::ALPN_KV_CHECKPOINT`].
    kv_checkpoint_handler: DeferredRequestHandler,
    /// The path transport bound to `endpoint`, released on shutdown.
    paths: Option<crate::paths::Paths>,
}

/// Upper bound on cached provider endpoints per blob hash. Announcements
/// beyond the cap evict the oldest cached endpoint (front of the list),
/// keeping the cache biased toward providers that announced recently.
const MAX_PROVIDERS_PER_BLOB: usize = 8;

impl IrohBackedResolver {
    /// Bind a new endpoint on a random port, with no relay and no address
    /// lookup, and stand up an in-memory blob store with the iroh-blobs
    /// protocol handler registered. For tests and local tools; nodes use
    /// [`Self::bind_with_jsonrpc`].
    ///
    /// The blob store is in-memory and does not survive the process —
    /// config-driven binds use the persistent filesystem store instead.
    pub async fn bind_in_memory() -> IrohResult<Arc<Self>> {
        let gate = crate::gossip::GossipGate::default();
        let endpoint = base_builder()
            .hooks(gate.clone())
            .bind()
            .await
            .map_err(|e| IrohError::Backend(format!("endpoint bind: {e}")))?;
        Self::with_endpoint(
            endpoint,
            gate,
            ResolverStore::Mem(MemStore::new()),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            crate::limits::AdmissionLimits::default(),
            crate::connection_limits::ConnectionLimits::default(),
        )
    }

    /// An in-memory resolver whose endpoint is found through `lookup` and
    /// whose discovery store is `discovery`.
    #[cfg(test)]
    pub(crate) async fn bind_for_test(
        lookup: &iroh::address_lookup::memory::MemoryLookup,
        discovery: Arc<DiscoveryStore>,
    ) -> IrohResult<Arc<Self>> {
        let gate = crate::gossip::GossipGate::default();
        let endpoint = Endpoint::builder(iroh::endpoint::presets::Minimal)
            .hooks(gate.clone())
            .bind()
            .await
            .map_err(|e| IrohError::Backend(format!("endpoint bind: {e}")))?;
        endpoint
            .address_lookup()
            .map_err(|e| IrohError::Backend(format!("address lookup: {e}")))?
            .add(lookup.clone());
        lookup.add_endpoint_info(endpoint.addr());
        Self::with_endpoint(
            endpoint,
            gate,
            ResolverStore::Mem(MemStore::new()),
            Some(discovery),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            crate::limits::AdmissionLimits::default(),
            crate::connection_limits::ConnectionLimits::default(),
        )
    }

    /// Load the persistent redb-backed blob store rooted under the
    /// configured data dir (`{data_dir}/blobs`, i.e. `{node_data_dir}/iroh/blobs`
    /// once `tenzro-node` rebases the iroh dir). `FsStore::load` creates the
    /// directory tree on first boot and replays the redb manifest on
    /// subsequent boots, so blobs published before a restart stay fetchable.
    async fn load_fs_store(cfg: &TenzroIrohConfig) -> IrohResult<ResolverStore> {
        let root = cfg.data_dir.join("blobs");
        let store = FsStore::load(&root).await.map_err(|e| {
            IrohError::Backend(format!("blob store load at {}: {e}", root.display()))
        })?;
        Ok(ResolverStore::Fs(store))
    }

    /// Bind a new endpoint using a [`TenzroIrohConfig`].
    ///
    /// The endpoint key is fresh at every bind and held only in memory; a
    /// node's hardware key vouches for its `EndpointId` in the signed
    /// endpoint record it publishes (see [`crate::identity_record`]).
    ///
    /// With `identity`, the endpoint relays through the relays it admitted,
    /// finds endpoints through its discovery store and serves that store on
    /// the `tenzro/discovery` ALPN; without, it has none of these. Nothing
    /// outside the Tenzro network is contacted. The gossip gate screens
    /// every gossip connection.
    pub async fn bind_with_config(
        cfg: &TenzroIrohConfig,
        identity: Option<&IdentityTransport>,
    ) -> IrohResult<Arc<Self>> {
        let gate = crate::gossip::GossipGate::default();
        let endpoint = Self::build_endpoint(cfg, identity, &gate).await?;
        let store = Self::load_fs_store(cfg).await?;
        let discovery = identity.map(|t| t.store().clone());
        let peer_relay = identity.and_then(IdentityTransport::peer_relay_service);
        let punch = identity.map(|t| t.paths().clone());
        Self::with_endpoint(
            endpoint,
            gate,
            store,
            discovery,
            identity.map(|t| t.pq_channel().clone()),
            None,
            None,
            None,
            None,
            peer_relay,
            punch,
            cfg.admission,
            cfg.connection,
        )
    }

    /// Build an iroh `Endpoint` from a [`TenzroIrohConfig`] and the node's
    /// identity transport. Shared by `bind_with_config` and
    /// `bind_with_jsonrpc` so the relay, gossip gate and bind wiring stays
    /// in one place.
    async fn build_endpoint(
        cfg: &TenzroIrohConfig,
        identity: Option<&IdentityTransport>,
        gate: &crate::gossip::GossipGate,
    ) -> IrohResult<Endpoint> {
        let (relays, discovery) = match identity {
            Some(t) => (t.relays(), Some(t.store().clone())),
            None => (&[][..], None),
        };
        let mut builder = with_relays(base_builder_with(&cfg.connection), relays, discovery)
            .hooks(gate.clone())
            .clear_ip_transports();
        if let Some(secret) = &cfg.endpoint_secret.0 {
            builder = builder.secret_key(iroh::SecretKey::from_bytes(secret));
        }
        if let Some(t) = identity {
            builder = t.paths().install(builder);
        }
        if !cfg.port_mapping {
            builder = builder.portmapper_config(iroh::endpoint::PortmapperConfig::Disabled);
        }
        // Relays are reached over HTTPS, through the operator's proxy when
        // the network allows outbound web traffic only through one.
        builder = match &cfg.proxy {
            Some(url) => builder.proxy_url(url.clone()),
            None => builder.proxy_from_env(),
        };
        if cfg.relay_only {
            // No IP socket at all: every packet goes through a relay.
            let endpoint = builder
                .bind()
                .await
                .map_err(|e| IrohError::Backend(format!("endpoint bind: {e}")))?;
            if let Some(t) = identity {
                t.paths().attach(&endpoint);
            }
            return Ok(endpoint);
        }

        // Pin the QUIC port to the configured bind address so the magicsock
        // doesn't bind a random ephemeral UDP port (which cannot be opened
        // in firewalls ahead of time). `clear_ip_transports` strips the
        // builder's default `0.0.0.0:0` + `[::]:0` pre-binds before we
        // install our pinned IPv4 + IPv6 addresses.
        // A node serving the relay role is a peer relay too: it binds its
        // relay UDP port (443 by default, the port networks that pass only
        // web traffic leave open).
        let mut bind = cfg.bind_addr;
        if identity.is_some_and(|t| t.peer_relay_service().is_some()) {
            bind.set_port(cfg.relay_udp_port);
        }
        builder = builder
            .bind_addr(bind)
            .map_err(|e| IrohError::Backend(format!("bind_addr {bind} invalid: {e}")))?;
        // IPv6 wildcard at the same port — `bind_addr_with_opts` would allow
        // tuning the prefix length, but the default (`/0`) matches the
        // builder's pre-configured `[::]:0` semantics. Failure to bind the
        // v6 socket is allowed by iroh (matches the default-builder
        // contract for the unspecified `[::]` address).
        builder = builder
            .bind_addr(SocketAddr::new(
                IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                bind.port(),
            ))
            .map_err(|e| {
                IrohError::Backend(format!("bind_addr [::]:{} invalid: {e}", bind.port()))
            })?;

        let endpoint = builder
            .bind()
            .await
            .map_err(|e| IrohError::Backend(format!("endpoint bind: {e}")))?;
        if let Some(t) = identity {
            t.paths().attach(&endpoint);
        }
        Ok(endpoint)
    }

    /// Bind a new endpoint and additionally register A2A + MCP JSON-RPC
    /// dispatchers on the same iroh router.
    ///
    /// When `a2a` / `mcp` are `Some(...)`, peers can reach those services
    /// over the iroh transport (under ALPNs `tenzro/a2a` / `tenzro/mcp`)
    /// in addition to the existing HTTPS surfaces. The same iroh endpoint
    /// (and therefore the same identity-certified EndpointId, relayed
    /// through `relays`) is used for blobs and JSON-RPC alike — one QUIC
    /// stack, several ALPNs.
    ///
    /// `None` for any dispatcher skips that ALPN registration. Nodes
    /// that do not run an A2A or MCP server — or do not host MoE
    /// experts — pass `None` for the corresponding slot.
    pub async fn bind_with_jsonrpc(
        cfg: &TenzroIrohConfig,
        identity: Option<&IdentityTransport>,
        a2a: Option<Arc<dyn JsonRpcDispatcher>>,
        mcp: Option<Arc<dyn McpStreamHandler>>,
        moe: Option<Arc<dyn JsonRpcDispatcher>>,
        infer: Option<Arc<dyn RequestHandler>>,
    ) -> IrohResult<Arc<Self>> {
        let gate = crate::gossip::GossipGate::default();
        let endpoint = Self::build_endpoint(cfg, identity, &gate).await?;
        let store = Self::load_fs_store(cfg).await?;
        let discovery = identity.map(|t| t.store().clone());
        let peer_relay = identity.and_then(IdentityTransport::peer_relay_service);
        let punch = identity.map(|t| t.paths().clone());
        let pq = identity.map(|t| t.pq_channel().clone());
        Self::with_endpoint(
            endpoint,
            gate,
            store,
            discovery,
            pq,
            a2a,
            mcp,
            moe,
            infer,
            peer_relay,
            punch,
            cfg.admission,
            cfg.connection,
        )
    }

    /// Stand up the blob store + iroh-blobs ALPN router on top of an
    /// already-bound endpoint, optionally registering an A2A JSON-RPC
    /// dispatcher, an MCP session handler, a MoE expert-host dispatcher and
    /// an inference dispatcher on the same router.
    fn with_endpoint(
        endpoint: Endpoint,
        gate: crate::gossip::GossipGate,
        store: ResolverStore,
        discovery: Option<Arc<DiscoveryStore>>,
        pq: Option<crate::pq_endpoint::PqChannel>,
        a2a: Option<Arc<dyn JsonRpcDispatcher>>,
        mcp: Option<Arc<dyn McpStreamHandler>>,
        moe: Option<Arc<dyn JsonRpcDispatcher>>,
        infer: Option<Arc<dyn RequestHandler>>,
        peer_relay: Option<crate::paths::PeerRelayService>,
        punch: Option<crate::paths::Paths>,
        limits: crate::limits::AdmissionLimits,
        connection: crate::connection_limits::ConnectionLimits,
    ) -> IrohResult<Arc<Self>> {
        let blobs = BlobsProtocol::new(
            &store,
            Some(crate::licence_gate::events(
                BlobStore::clone(&store),
                discovery.clone(),
            )),
        );
        let snapshot_directory = crate::state_sync::DeferredSnapshotDirectory::new();
        let consensus_handler = crate::consensus::DeferredConsensusHandler::new();
        let block_sync_server = crate::block_sync::DeferredBlockSyncServer::new();
        let gossip = crate::gossip::GossipTransport::spawn(&endpoint, gate);
        let da_committee_handler = DeferredRequestHandler::new("committee DA");
        let agent_key_handler = DeferredRequestHandler::new("agent serving");
        let agent_token_handler = DeferredRequestHandler::new("agent serving");
        let kv_checkpoint_handler = DeferredRequestHandler::new("session continuity");
        let mut builder = GatedRouter::new(
            Router::builder(endpoint.clone()),
            ConnectionGate::new(connection),
        )
        .accept(ALPN, blobs)
            .accept(
                ALPN_DA_COMMITTEE,
                RequestProtocol::new(
                    "da-committee",
                    Arc::new(da_committee_handler.clone()),
                    MAX_STORE_REQUEST,
                    limits,
                ),
            )
            .accept(
                crate::request::ALPN_AGENT_KEY,
                RequestProtocol::new(
                    "agent-key",
                    Arc::new(agent_key_handler.clone()),
                    crate::request::MAX_AGENT_KEY_REQUEST,
                    limits,
                ),
            )
            .accept(
                crate::request::ALPN_AGENT_TOKEN,
                RequestProtocol::new(
                    "agent-token",
                    Arc::new(agent_token_handler.clone()),
                    crate::request::MAX_AGENT_KEY_REQUEST * 4,
                    limits,
                ),
            )
            .accept(
                crate::request::ALPN_KV_CHECKPOINT,
                RequestProtocol::new(
                    "kv-checkpoint",
                    Arc::new(kv_checkpoint_handler.clone()),
                    crate::request::MAX_KV_CHECKPOINT_REQUEST,
                    limits,
                ),
            )
            .accept(
                crate::state_sync::ALPN_STATE_SYNC,
                crate::state_sync::StateSyncProtocol::new(Arc::new(snapshot_directory.clone())),
            )
            .accept(
                crate::consensus::ALPN_CONSENSUS,
                crate::consensus::ConsensusProtocol::new(Arc::new(consensus_handler.clone())),
            )
            .accept(
                crate::block_sync::ALPN_BLOCK_SYNC,
                crate::block_sync::BlockSyncProtocol::new(block_sync_server.clone(), limits),
            )
            .accept(crate::gossip::ALPN_GOSSIP, gossip.protocol());
        if let Some(discovery) = discovery.clone() {
            builder = builder.accept(ALPN_DISCOVERY, DiscoveryProtocol::new(discovery));
        }
        if let Some(service) = peer_relay {
            builder = builder.accept(crate::paths::ALPN_PEER_RELAY, service);
        }
        let paths_handle = punch.clone();
        if let Some(paths) = punch {
            builder = builder.accept(
                crate::paths::ALPN_PUNCH,
                crate::paths::PunchService::new(paths),
            );
        }
        // Each RPC protocol is served only on its versioned ALPN, which
        // carries the ML-DSA leg of endpoint authentication: with no identity
        // transport there is no way to authenticate a peer, and none is
        // served on the first ALPN.
        if let Some(dispatcher) = a2a
            && let Some(pq) = pq.clone()
        {
            let proto = JsonRpcProtocol::a2a(dispatcher, limits);
            builder = builder.accept(ALPN_A2A_PQ, proto.with_pq_channel(pq));
        }
        if let Some(handler) = mcp
            && let Some(pq) = pq.clone()
        {
            let proto = McpProtocol::new(handler, limits);
            builder = builder.accept(ALPN_MCP_PQ, proto.with_pq_channel(pq));
        }
        if let Some(dispatcher) = moe
            && let Some(pq) = pq.clone()
        {
            let proto = JsonRpcProtocol::moe(dispatcher, limits);
            builder = builder.accept(ALPN_MOE_PQ, proto.with_pq_channel(pq));
        }
        if let Some(handler) = infer {
            builder = builder.accept(
                ALPN_INFER,
                RequestProtocol::new("infer", handler, MAX_INFER_BYTES, limits),
            );
        }
        let router = builder.spawn();
        let downloader = Downloader::new(&store, &endpoint);
        Ok(Arc::new(Self {
            endpoint,
            store,
            router: Mutex::new(Some(router)),
            downloader,
            discovery,
            pq,
            hint_cache: DashMap::new(),
            snapshot_directory,
            consensus_handler,
            block_sync_server,
            gossip,
            da_committee_handler,
            agent_key_handler,
            agent_token_handler,
            kv_checkpoint_handler,
            paths: paths_handle,
        }))
    }

    /// The gossip protocol on this endpoint. The node attaches its topic
    /// layer to it once the endpoint is bound.
    pub fn gossip(&self) -> &crate::gossip::GossipTransport {
        &self.gossip
    }

    /// The handler of committee DA requests peers send over
    /// [`ALPN_DA_COMMITTEE`]. A validator installs its sliver server here.
    pub fn da_committee_handler(&self) -> &DeferredRequestHandler {
        &self.da_committee_handler
    }

    /// The handler of agent-key requests peers send over
    /// [`crate::request::ALPN_AGENT_KEY`]. A node that serves delegated
    /// agents installs its key server here.
    pub fn agent_key_handler(&self) -> &DeferredRequestHandler {
        &self.agent_key_handler
    }

    /// The handler of agent tokens peers deliver over
    /// [`crate::request::ALPN_AGENT_TOKEN`].
    pub fn agent_token_handler(&self) -> &DeferredRequestHandler {
        &self.agent_token_handler
    }

    /// The handler of session successor assignments and sealed KV-cache
    /// deltas peers send over [`crate::request::ALPN_KV_CHECKPOINT`].
    pub fn kv_checkpoint_handler(&self) -> &DeferredRequestHandler {
        &self.kv_checkpoint_handler
    }

    /// The server of block-sync requests peers send over
    /// [`crate::block_sync::ALPN_BLOCK_SYNC`]. The node installs its block
    /// store here once it exists.
    pub fn block_sync_server(&self) -> &crate::block_sync::DeferredBlockSyncServer {
        &self.block_sync_server
    }

    /// The snapshot directory served over the state-sync ALPN. The node
    /// installs its snapshot store here once it exists.
    pub fn snapshot_directory(&self) -> &crate::state_sync::DeferredSnapshotDirectory {
        &self.snapshot_directory
    }

    /// The handler of consensus streams peers open over
    /// [`crate::consensus::ALPN_CONSENSUS`]. The node's consensus installs
    /// itself here once it runs.
    pub fn consensus_handler(&self) -> &crate::consensus::DeferredConsensusHandler {
        &self.consensus_handler
    }

    /// Asks `peer` for the manifest blob of its snapshot at `height`, over
    /// a connection authenticated to `peer`'s key.
    pub async fn request_snapshot_manifest(
        &self,
        peer: EndpointId,
        height: u64,
    ) -> IrohResult<Option<[u8; 32]>> {
        crate::state_sync::request_manifest(&self.endpoint, peer, height).await
    }

    /// Teaches this endpoint where to reach a peer, so a dial by `EndpointId`
    /// finds it on a network with no discovery.
    pub fn remember_addr(&self, addr: iroh::EndpointAddr) -> IrohResult<()> {
        let lookup = iroh::address_lookup::MemoryLookup::new();
        lookup.add_endpoint_info(addr);
        self.endpoint
            .address_lookup()
            .map_err(|e| IrohError::Backend(format!("address lookup: {e}")))?
            .add(lookup);
        Ok(())
    }

    /// This endpoint's iroh `EndpointId` — the identity peers dial when a
    /// blob announcement names this node as a provider.
    pub fn endpoint_id(&self) -> EndpointId {
        self.endpoint.id()
    }

    /// Record that `provider` holds the blob addressed by `blake3_hex`.
    ///
    /// Called by the node layer when a signed `tenzro/blobs` gossip
    /// announcement arrives. Idempotent per (hash, provider); when the
    /// per-hash list exceeds [`MAX_PROVIDERS_PER_BLOB`] the oldest entry
    /// is evicted so recently announced providers win. Announcements for
    /// this node's own endpoint are ignored — the local store already
    /// covers the fast path.
    pub fn record_blob_provider(&self, blake3_hex: &str, provider: EndpointId) {
        if provider == self.endpoint.id() {
            return;
        }
        let mut entry = self.hint_cache.entry(blake3_hex.to_string()).or_default();
        if let Some(pos) = entry.iter().position(|p| *p == provider) {
            // Re-announcement: move to the back (freshest position).
            entry.remove(pos);
        } else if entry.len() >= MAX_PROVIDERS_PER_BLOB {
            entry.remove(0);
        }
        entry.push(provider);
    }

    /// Providers currently cached for `blake3_hex`, freshest last. Empty
    /// when no announcement has been observed for the hash.
    pub fn known_blob_providers(&self, blake3_hex: &str) -> Vec<EndpointId> {
        self.hint_cache
            .get(blake3_hex)
            .map(|v| v.clone())
            .unwrap_or_default()
    }

    /// Enumerate the BLAKE3 hex hashes of every blob in the local store.
    ///
    /// Used by the node layer to build `tenzro/blobs` availability
    /// announcements — on startup (re-announcing blobs that survived a
    /// restart in the persistent store) and on the periodic heartbeat.
    pub async fn local_blob_hashes(&self) -> IrohResult<Vec<String>> {
        let hashes = self
            .store
            .blobs()
            .list()
            .hashes()
            .await
            .map_err(|e| IrohError::Backend(format!("blob list: {e}")))?;
        Ok(hashes.into_iter().map(|h| h.to_string()).collect())
    }

    /// The ML-DSA leg of endpoint authentication, when the node runs an
    /// identity transport.
    pub fn pq_channel(&self) -> Option<&crate::pq_endpoint::PqChannel> {
        self.pq.as_ref()
    }

    /// A JSON-RPC call to `remote` on the versioned ALPN of `alpn`, with the
    /// ML-DSA leg of endpoint authentication. Refused when this node holds no
    /// record of `remote` that binds an ML-DSA key, or has no channel keys of
    /// its own: a peer is never called with classical-only authentication.
    pub async fn call_jsonrpc(
        &self,
        remote: EndpointId,
        alpn: &[u8],
        request: Bytes,
    ) -> IrohResult<Bytes> {
        let (Some(pq), Some(versioned)) = (&self.pq, crate::jsonrpc::pq_alpn(alpn)) else {
            return Err(IrohError::Backend(
                "no ML-DSA endpoint authentication for this protocol: the call is refused".into(),
            ));
        };
        let peer = pq.bound_record(remote).ok_or_else(|| {
            IrohError::Backend(
                "the peer's record binds no ML-DSA key: classical-only authentication is refused"
                    .into(),
            )
        })?;
        crate::jsonrpc::call_pq(&self.endpoint, remote, versioned, request, pq, &peer).await
    }

    /// Access the underlying iroh endpoint — needed by higher-level
    /// transport wiring (e.g. the `Downloader` constructor).
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// Access the underlying blob store as `iroh_blobs::api::Store`.
    /// Higher-level callers operate against this directly.
    pub fn store(&self) -> &BlobStore {
        &self.store
    }

    /// Binds the blob `hash` (BLAKE3 hex) to the model licence `licence`:
    /// from now on this node serves it only to machines whose current record
    /// states their operator accepted the licence. Bind before the bytes
    /// enter the store, by publish or by fetch, so they are never served
    /// unbound. The binding is kept in the store and persists with it.
    pub async fn bind_licence(&self, hash: &str, licence: &str) -> IrohResult<()> {
        let hash = Hash::from_str(hash)
            .map_err(|e| IrohError::Backend(format!("bad blake3 hex {hash}: {e}")))?;
        crate::licence_gate::bind(&self.store, hash, licence).await
    }

    /// Shows this node's current record to each of `providers`, so a
    /// provider of a licence-bound blob can see which licences this node's
    /// operator accepted before it is asked for the blob.
    async fn show_own_record(&self, providers: &[EndpointId]) {
        let Some(own) = self.discovery.as_ref().and_then(|d| {
            let key = crate::identity_transport::iroh_endpoint_key(self.endpoint.id());
            d.records().into_iter().find(|r| r.endpoint == key)
        }) else {
            tracing::warn!(
                "this node has no current record to show providers of a licence-bound blob"
            );
            return;
        };
        let request = crate::discovery::DiscoveryRequest::Publish(own);
        for provider in providers {
            if let Err(e) =
                crate::discovery::ask(&self.endpoint, (*provider).into(), &request).await
            {
                tracing::debug!(%provider, error = %e, "own record not shown to a provider");
            }
        }
    }

    /// Cleanly shut down the router (which closes the endpoint).
    /// Idempotent.
    pub async fn shutdown(&self) -> IrohResult<()> {
        let router = self.router.lock().await.take();
        let result = match router {
            Some(r) => r
                .shutdown()
                .await
                .map_err(|e| IrohError::Backend(format!("router shutdown: {e}"))),
            None => Ok(()),
        };
        // The path transport is shared with the node's identity transport and
        // outlives this endpoint; while it holds a clone the sockets stay
        // bound and the next endpoint on this address cannot bind.
        if let Some(paths) = &self.paths {
            paths.detach();
        }
        result
    }

    /// Extract the BLAKE3 hash hex string addressed by `uri`. Returns
    /// `UnsupportedVariant` for non-content variants.
    fn content_hash(uri: &TenzroUri) -> IrohResult<&str> {
        match uri {
            TenzroUri::Blob { hash, .. }
            | TenzroUri::Model { hash, .. }
            | TenzroUri::Receipt { hash, .. } => Ok(hash),
            TenzroUri::Node { .. } => Err(IrohError::UnsupportedVariant("Node")),
            TenzroUri::Did { .. } => Err(IrohError::UnsupportedVariant("Did")),
            // Memory record-uuids aren't BLAKE3 hashes — they're an indirection
            // (agent_did, record_uuid) → DA pointer that requires a
            // MemoryManager lookup. We deliberately do NOT inject the
            // MemoryManager into the iroh resolver (would invert the dep
            // graph: iroh → agent). Memory URIs are instead dispatched
            // upstream at the RPC layer (see `handle_iroh_fetch_blob` in
            // `tenzro-node/src/rpc.rs`) which holds both the MemoryManager
            // and a resolver reference, runs the uuid→record lookup, then
            // fans out to `MemoryManager::fetch_archived` (which itself
            // resolves the DaPointer via the iroh blob path for archived
            // records). Callers hitting the resolver directly with a Memory
            // URI have likely skipped the RPC layer by accident.
        }
    }

    /// Extract the optional provider hint (peer iroh `EndpointId`) from `uri`,
    /// where the URI variant supports one. Only `Blob` carries a hint in its
    /// canonical form today (`?n=<endpoint-id>`); other content variants may
    /// grow one in a follow-up.
    ///
    /// The hint string is accepted in either lowercase hex (the form emitted
    /// by iroh's `Display` impl, and the form documented for `TenzroUri::Blob`)
    /// or z-base-32 — iroh's `EndpointId::from_str` accepts both. Invalid
    /// strings are returned as `Backend` errors so the caller can surface the
    /// parse failure rather than silently swallowing the hint.
    fn provider_hint(uri: &TenzroUri) -> IrohResult<Option<EndpointId>> {
        let hint_str = match uri {
            TenzroUri::Blob { provider_hint, .. } => provider_hint.as_deref(),
            _ => None,
        };
        match hint_str {
            None => Ok(None),
            Some(s) => EndpointId::from_str(s)
                .map(Some)
                .map_err(|e| IrohError::Backend(format!("bad provider hint `{s}`: {e}"))),
        }
    }
}

#[async_trait]
impl IrohResolver for IrohBackedResolver {
    async fn fetch_bytes(&self, uri: &TenzroUri) -> IrohResult<Bytes> {
        let hex = Self::content_hash(uri)?;
        let hash = Hash::from_str(hex)
            .map_err(|e| IrohError::Backend(format!("bad blake3 hex {hex}: {e}")))?;

        // Fast path: blob already in the local store. iroh-blobs verifies the
        // BLAKE3 root on read, so a successful `get_bytes` is the same trust
        // surface as a successful remote pull.
        if let Ok(bytes) = self.store.blobs().get_bytes(hash).await {
            return Ok(bytes);
        }

        // Cross-node path. Candidate providers, in priority order:
        //   (a) the explicit provider hint on the URI, when present — the
        //       caller named a peer, so it dials first;
        //   (b) providers cached from signed `tenzro/blobs` gossip
        //       announcements (freshest announcements first).
        // Only when both sets are empty is the fetch a `NotFound`.
        let mut candidates: Vec<EndpointId> = Vec::new();
        if let Some(provider) = Self::provider_hint(uri)? {
            candidates.push(provider);
        }
        for provider in self.known_blob_providers(hex).into_iter().rev() {
            if !candidates.contains(&provider) {
                candidates.push(provider);
            }
        }
        if candidates.is_empty() {
            return Err(IrohError::NotFound(format!(
                "blob {hex} not local, no provider hint on URI, and no announced providers"
            )));
        }

        // A provider serves a licence-bound blob only to a machine whose
        // record it holds and that accepts the licence.
        if !crate::licence_gate::licences_of(&self.store, hash)
            .await?
            .is_empty()
        {
            self.show_own_record(&candidates).await;
        }

        // `Downloader::download(hash, providers)` tries the given providers
        // and writes the blob into the store we constructed it with. Block on
        // completion via the `IntoFuture` impl on `DownloadProgress`.
        self.downloader
            .download(hash, candidates.clone())
            .await
            .map_err(|e| {
                IrohError::NotFound(format!(
                    "blob {hex} not local; cross-node fetch from {} candidate provider(s) failed: {e}",
                    candidates.len()
                ))
            })?;

        // The download wrote into the same store we read from. iroh-blobs
        // verifies the BLAKE3 root on `get_bytes`, so a hash mismatch fails
        // here rather than silently returning corrupt data.
        let bytes = self.store.blobs().get_bytes(hash).await.map_err(|e| {
            IrohError::Backend(format!("blob {hex} downloaded but get_bytes failed: {e}"))
        })?;
        Ok(bytes)
    }

    async fn publish_bytes(&self, bytes: Bytes) -> IrohResult<TenzroUri> {
        let tag = self
            .store
            .blobs()
            .add_bytes(bytes)
            .await
            .map_err(|e| IrohError::Backend(format!("add_bytes: {e}")))?;
        Ok(TenzroUri::Blob {
            hash: tag.hash.to_string(),
            provider_hint: None,
        })
    }

    async fn publish_path(&self, path: &Path) -> IrohResult<TenzroUri> {
        let tag = self
            .store
            .blobs()
            .add_path_with_opts(AddPathOptions {
                path: path.to_path_buf(),
                format: BlobFormat::Raw,
                mode: ImportMode::TryReference,
            })
            .await
            .map_err(|e| IrohError::Backend(format!("add_path {}: {e}", path.display())))?;
        Ok(TenzroUri::Blob {
            hash: tag.hash.to_string(),
            provider_hint: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn free_udp_port() -> u16 {
        std::net::UdpSocket::bind("127.0.0.1:0")
            .expect("probe port")
            .local_addr()
            .expect("probe addr")
            .port()
    }

    /// State sync binds a dial-only endpoint before the node's own; it must
    /// not take the configured port, which the node's endpoint binds next.
    #[tokio::test]
    async fn a_dial_only_endpoint_leaves_the_configured_port_free() {
        let dir = std::env::temp_dir().join(format!("tz-rebind-{}", free_udp_port()));
        let mut cfg = TenzroIrohConfig::with_data_dir(dir.clone());
        let port = free_udp_port();
        cfg.bind_addr = SocketAddr::from(([127, 0, 0, 1], port));
        cfg.port_mapping = false;
        let sync = IrohBackedResolver::bind_with_config(&cfg.dial_only(), None)
            .await
            .expect("dial-only bind");
        let node = IrohBackedResolver::bind_with_config(&cfg, None)
            .await
            .expect("bind on the configured port while the first is open");
        let bound = node.endpoint().bound_sockets();
        assert!(bound.iter().any(|a| a.port() == port), "bound {bound:?}");
        assert!(sync.endpoint().bound_sockets().iter().all(|a| a.port() != port));
        let _ = node.shutdown().await;
        let _ = sync.shutdown().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The path transport is shared and outlives the endpoint; once detached
    /// it no longer pins the closed endpoint's sockets.
    #[tokio::test]
    async fn a_detached_path_transport_releases_the_endpoint_sockets() {
        let addr = SocketAddr::from(([127, 0, 0, 1], free_udp_port()));
        let paths = crate::paths::Paths::new();
        let bind = |paths: &crate::paths::Paths| {
            let builder = paths
                .install(crate::identity_transport::base_builder().clear_ip_transports())
                .bind_addr(addr)
                .expect("bind_addr");
            async move { builder.bind().await }
        };
        let first = bind(&paths).await.expect("first bind");
        paths.attach(&first);
        first.close().await;
        paths.detach();
        drop(first);
        let second = bind(&paths).await;
        assert!(second.is_ok(), "second bind: {:?}", second.err());
    }

    /// Tag the cargo runner with the `iroh-net` cfg so the iroh n0 preset
    /// can pick up its rustls provider when invoked from this test module.
    fn test_bytes() -> Bytes {
        Bytes::from_static(b"tenzro-iroh round-trip payload")
    }

    #[tokio::test]
    async fn publish_then_fetch_round_trips() {
        let resolver = IrohBackedResolver::bind_in_memory()
            .await
            .expect("bind in-memory resolver");
        let payload = test_bytes();

        let uri = resolver
            .publish_bytes(payload.clone())
            .await
            .expect("publish blob");

        // Returned URI is a Blob with a 64-char lowercase hex hash.
        match &uri {
            TenzroUri::Blob {
                hash,
                provider_hint,
            } => {
                assert_eq!(hash.len(), 64, "blake3 hex should be 64 chars");
                assert!(
                    hash.chars()
                        .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase())
                );
                assert!(provider_hint.is_none());
            }
            other => panic!("publish_bytes returned non-Blob URI: {other:?}"),
        }

        let fetched = resolver.fetch_bytes(&uri).await.expect("fetch blob");
        assert_eq!(fetched, payload);

        resolver.shutdown().await.expect("shutdown clean");
    }

    #[tokio::test]
    async fn fetch_unknown_blob_is_not_found() {
        let resolver = IrohBackedResolver::bind_in_memory()
            .await
            .expect("bind in-memory resolver");
        let uri = TenzroUri::Blob {
            hash: "0".repeat(64),
            provider_hint: None,
        };
        let err = resolver
            .fetch_bytes(&uri)
            .await
            .expect_err("zero-hash blob should miss");
        assert!(matches!(err, IrohError::NotFound(_)));
        resolver.shutdown().await.ok();
    }

    #[tokio::test]
    async fn unsupported_variants_rejected() {
        let resolver = IrohBackedResolver::bind_in_memory()
            .await
            .expect("bind in-memory resolver");

        for uri in [
            TenzroUri::Node {
                node_id: "abcd".into(),
            },
            TenzroUri::Did {
                did: "did:tenzro:human:alice".into(),
            },
        ] {
            let err = resolver
                .fetch_bytes(&uri)
                .await
                .expect_err("non-content variant must error");
            assert!(matches!(err, IrohError::UnsupportedVariant(_)));
        }
        resolver.shutdown().await.ok();
    }

    #[tokio::test]
    async fn hint_cache_records_and_rotates_providers() {
        let resolver = IrohBackedResolver::bind_in_memory()
            .await
            .expect("bind in-memory resolver");
        let hash = "a".repeat(64);

        // Self-announcements are ignored.
        resolver.record_blob_provider(&hash, resolver.endpoint_id());
        assert!(resolver.known_blob_providers(&hash).is_empty());

        // Distinct providers accumulate, freshest last.
        let mk = |i: u8| {
            let mut bytes = [0u8; 32];
            bytes[0] = i;
            // Not all byte strings are valid Ed25519 points; derive from a
            // secret key instead so every id is well-formed.
            iroh::SecretKey::from_bytes(&bytes).public()
        };
        for i in 1..=MAX_PROVIDERS_PER_BLOB as u8 {
            resolver.record_blob_provider(&hash, mk(i));
        }
        let providers = resolver.known_blob_providers(&hash);
        assert_eq!(providers.len(), MAX_PROVIDERS_PER_BLOB);
        assert_eq!(*providers.last().unwrap(), mk(MAX_PROVIDERS_PER_BLOB as u8));

        // Re-announcing an existing provider moves it to the back without
        // growing the list.
        resolver.record_blob_provider(&hash, mk(1));
        let providers = resolver.known_blob_providers(&hash);
        assert_eq!(providers.len(), MAX_PROVIDERS_PER_BLOB);
        assert_eq!(*providers.last().unwrap(), mk(1));

        // One more distinct provider evicts the oldest.
        let extra = mk(MAX_PROVIDERS_PER_BLOB as u8 + 1);
        resolver.record_blob_provider(&hash, extra);
        let providers = resolver.known_blob_providers(&hash);
        assert_eq!(providers.len(), MAX_PROVIDERS_PER_BLOB);
        assert_eq!(*providers.last().unwrap(), extra);
        assert!(
            !providers.contains(&mk(2)),
            "oldest entry should be evicted"
        );

        resolver.shutdown().await.ok();
    }

    #[tokio::test]
    async fn published_blobs_are_enumerable() {
        let resolver = IrohBackedResolver::bind_in_memory()
            .await
            .expect("bind in-memory resolver");
        let uri = resolver
            .publish_bytes(test_bytes())
            .await
            .expect("publish blob");
        let TenzroUri::Blob { hash, .. } = &uri else {
            panic!("publish_bytes returned non-Blob URI");
        };
        let hashes = resolver.local_blob_hashes().await.expect("list blobs");
        assert!(hashes.contains(hash));
        resolver.shutdown().await.ok();
    }
}
