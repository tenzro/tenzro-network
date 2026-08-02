//! `IrohResolver` trait — the dispatch surface that crates depend on
//! without pulling in the iroh runtime, and `IrohBackedResolver` — the
//! concrete iroh-blobs-backed implementation added in Phase A2 (#214)
//! alongside the `DaBackend` impl in `tenzro-storage::da`.

use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::ops::Deref;
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use dashmap::DashMap;
use iroh::{
    Endpoint, EndpointId,
    address_lookup::{AddrFilter, DnsAddressLookup, PkarrPublisher, PkarrResolver},
    endpoint::presets,
    protocol::Router,
};
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
use crate::error::{IrohError, IrohResult};
use crate::jsonrpc::{
    ALPN_A2A, ALPN_HTTP, ALPN_INFER, ALPN_MCP, ALPN_MOE, HttpForwardHandler, HttpForwardProtocol,
    JsonRpcDispatcher, JsonRpcProtocol, McpProtocol, McpStreamHandler,
};
use crate::shell::{ALPN_SHELL, ShellHandler, ShellProtocol};
use crate::tdip::derive_iroh_secret_key_from_ed25519;
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
    /// `Blob`, `Model`, `Gradient`, `Shard`, `Memory`, `Receipt`.
    ///
    /// For non-content variants (`Node`, `Did`, `Manifest`), implementations
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
/// # Variant support (Phase A2)
///
/// - `tenzro://blob/<hash>` — fetch + publish via the local store, with
///   transparent BLAKE3 verification on fetch.
/// - `tenzro://model/<id>@<hash>`, `tenzro://gradient/<run>/<round>/<hash>`,
///   `tenzro://shard/<m>/<e>`, `tenzro://memory/<did>/<uuid>`,
///   `tenzro://receipt/<kind>/<hash>` — all dispatch to the same blob
///   path keyed on the URI's embedded hash. The non-hash fields are
///   metadata for the caller; the resolver treats them as content-
///   addressed against `hash` (or `envelope_hash` for `Shard`).
/// - `tenzro://node/<id>`, `tenzro://did/<did>`, `tenzro://manifest/<h>`
///   — return `IrohError::UnsupportedVariant`. Node / DID dialing lives
///   on a separate surface; manifest sync arrives with Phase B2.
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
    /// Blob-availability hint cache: BLAKE3 hex → endpoints known to hold
    /// the blob. Populated by the node layer from `tenzro/blobs` gossip
    /// announcements (see `record_blob_provider`), consulted by
    /// `fetch_bytes` when the URI carries no explicit provider hint.
    /// Bounded per-hash at [`MAX_PROVIDERS_PER_BLOB`]; entries rotate
    /// oldest-out so freshly announced providers win.
    hint_cache: DashMap<String, Vec<EndpointId>>,
}

/// Upper bound on cached provider endpoints per blob hash. Announcements
/// beyond the cap evict the oldest cached endpoint (front of the list),
/// keeping the cache biased toward providers that announced recently.
const MAX_PROVIDERS_PER_BLOB: usize = 8;

impl IrohBackedResolver {
    /// Bind a new endpoint with default (n0) discovery and stand up an
    /// in-memory blob store with the iroh-blobs protocol handler registered.
    ///
    /// Equivalent to `bind_with_config(&TenzroIrohConfig::with_data_dir(...))`
    /// where neither `pkarr_relay_url` nor `secret_key_seed` are set —
    /// suitable for tests and local development. Protocol nodes should use
    /// [`Self::bind_with_config`] so the iroh `EndpointId` is anchored to
    /// their TDIP identity and discovery records flow through the
    /// Tenzro-operated Pkarr relay.
    ///
    /// The blob store is in-memory and does not survive the process —
    /// config-driven binds use the persistent filesystem store instead.
    pub async fn bind_in_memory() -> IrohResult<Arc<Self>> {
        let endpoint = Endpoint::bind(presets::N0)
            .await
            .map_err(|e| IrohError::Backend(format!("endpoint bind: {e}")))?;
        Self::with_endpoint(
            endpoint,
            ResolverStore::Mem(MemStore::new()),
            None,
            None,
            None,
            None,
            None,
            None,
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

    /// Bind a new endpoint using a [`TenzroIrohConfig`] — Phase C2 (#220).
    ///
    /// When `cfg.secret_key_seed` is set, the iroh `EndpointId` is derived
    /// deterministically from the seed (typically the node's TDIP Ed25519
    /// seed), so the endpoint key is provably bound to the node DID.
    ///
    /// When `cfg.pkarr_relay_url` is set, the endpoint publishes its
    /// addressing record to the Tenzro-operated Pkarr relay and resolves
    /// peers via the same relay. When `cfg.publish_to_n0_default_discovery`
    /// is also true, the n0-dns publisher + DNS resolver are layered in
    /// alongside for cross-network discoverability.
    ///
    /// `cfg.bind_addr` pins the QUIC UDP port — the magicsock would
    /// otherwise bind two random ephemeral ports per boot, which cannot
    /// be opened in firewalls ahead of time. Defaults to `0.0.0.0:9001`
    /// (one above the libp2p QUIC port at 9000). Test / local-dev callers
    /// that pass `bind_addr.port() == 0` AND set neither `pkarr_relay_url`
    /// nor `secret_key_seed` get a random ephemeral binding via the n0
    /// preset — but still a persistent blob store under `cfg.data_dir`.
    pub async fn bind_with_config(cfg: &TenzroIrohConfig) -> IrohResult<Arc<Self>> {
        let endpoint = Self::bind_endpoint_for_config(cfg).await?;
        let store = Self::load_fs_store(cfg).await?;
        Self::with_endpoint(endpoint, store, None, None, None, None, None, None)
    }

    /// Endpoint bind decision shared by `bind_with_config` and
    /// `bind_with_jsonrpc`: the n0 preset as-is (random ephemeral port)
    /// when no Tenzro-specific overrides are configured AND the bind port
    /// is 0 (test / local-dev), otherwise the full builder path via
    /// `build_endpoint`.
    async fn bind_endpoint_for_config(cfg: &TenzroIrohConfig) -> IrohResult<Endpoint> {
        if cfg.pkarr_relay_url.is_none()
            && cfg.secret_key_seed.is_none()
            && cfg.bind_addr.port() == 0
        {
            Endpoint::bind(presets::N0)
                .await
                .map_err(|e| IrohError::Backend(format!("endpoint bind: {e}")))
        } else {
            Self::build_endpoint(cfg).await
        }
    }

    /// Build an iroh `Endpoint` from a [`TenzroIrohConfig`]. Shared by
    /// `bind_with_config` and `bind_with_jsonrpc` so the discovery + bind
    /// wiring stays in one place.
    async fn build_endpoint(cfg: &TenzroIrohConfig) -> IrohResult<Endpoint> {
        let mut builder = Endpoint::builder(presets::Minimal);

        // Pin the QUIC port to the configured bind address so the magicsock
        // doesn't bind a random ephemeral UDP port (which cannot be opened
        // in firewalls ahead of time). `clear_ip_transports` strips the
        // builder's default `0.0.0.0:0` + `[::]:0` pre-binds before we
        // install our pinned IPv4 + IPv6 addresses.
        builder = builder
            .clear_ip_transports()
            .bind_addr(cfg.bind_addr)
            .map_err(|e| IrohError::Backend(format!("bind_addr {} invalid: {e}", cfg.bind_addr)))?;
        // IPv6 wildcard at the same port — `bind_addr_with_opts` would allow
        // tuning the prefix length, but the default (`/0`) matches the
        // builder's pre-configured `[::]:0` semantics. Failure to bind the
        // v6 socket is allowed by iroh (matches the default-builder
        // contract for the unspecified `[::]` address).
        builder = builder
            .bind_addr(SocketAddr::new(
                IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                cfg.bind_addr.port(),
            ))
            .map_err(|e| {
                IrohError::Backend(format!(
                    "bind_addr [::]:{} invalid: {e}",
                    cfg.bind_addr.port()
                ))
            })?;

        // Anchor the iroh EndpointId to the node's TDIP Ed25519 seed when
        // provided — otherwise iroh generates a fresh ephemeral key.
        if let Some(seed) = cfg.secret_key_seed {
            builder = builder.secret_key(derive_iroh_secret_key_from_ed25519(&seed));
        }

        // Inject operator-supplied external addresses. Without these, an
        // endpoint built on `presets::Minimal` (relay-disabled, no STUN
        // `net_report`) has no way to autodiscover its public reachable
        // address — magicsock only sees its bind socket's local address
        // (e.g. `10.0.0.37:9001` on GCE, which isn't reachable from outside
        // the VPC). The Pkarr publisher would then emit a signed-but-empty
        // DNS body, and cross-node fetches by `EndpointId` would fail to
        // resolve any dialable sockaddr. Operators on cloud platforms with
        // public IPs plumb the VM's external IP through here; home/mobile
        // nodes leave this empty and rely on the (forthcoming) relay path.
        for addr in &cfg.external_addrs {
            builder = builder.external_addr(*addr);
        }

        // The Pkarr publisher's default `AddrFilter::relay_only()` drops
        // direct addresses from the published DNS body. That's the safe
        // default for NAT'd nodes that route through an iroh relay (it
        // avoids leaking local IPs), but it breaks the public-IP-no-relay
        // model the fleet runs in. When external addrs are configured,
        // switch the filter to `unfiltered()` so the published packet
        // actually carries the dialable addrs we just injected.
        let pkarr_filter = if cfg.external_addrs.is_empty() {
            AddrFilter::relay_only()
        } else {
            AddrFilter::unfiltered()
        };

        // Tenzro-operated Pkarr relay: publish and resolve through it.
        if let Some(url) = &cfg.pkarr_relay_url {
            builder = builder.address_lookup(
                PkarrPublisher::builder(url.clone()).addr_filter(pkarr_filter.clone()),
            );
            builder = builder.address_lookup(PkarrResolver::builder(url.clone()));
        }

        // Layer in n0 defaults alongside (cross-network discoverability) when
        // requested. We don't target `wasm_browser`, so always pair the n0
        // pkarr publisher with the DNS resolver (the n0 preset's native-only
        // branch). The same `pkarr_filter` decision applies — if we have a
        // routable public addr we want the n0 mirror to advertise it too.
        if cfg.publish_to_n0_default_discovery {
            builder = builder.address_lookup(PkarrPublisher::n0_dns().addr_filter(pkarr_filter));
            builder = builder.address_lookup(DnsAddressLookup::n0_dns());
        }

        builder
            .bind()
            .await
            .map_err(|e| IrohError::Backend(format!("endpoint bind: {e}")))
    }

    /// Bind a new endpoint and additionally register A2A + MCP JSON-RPC
    /// dispatchers on the same iroh router — Phase D2 (#223).
    ///
    /// When `a2a` / `mcp` are `Some(...)`, peers can reach those services
    /// over the iroh transport (under ALPNs `tenzro/a2a` / `tenzro/mcp`)
    /// in addition to the existing HTTPS surfaces. The same iroh endpoint
    /// (and therefore the same TDIP-anchored EndpointId + Pkarr-discovered
    /// addressing record) is used for blobs and JSON-RPC alike — one
    /// QUIC stack, three ALPNs.
    ///
    /// `None` for any dispatcher skips that ALPN registration. Nodes
    /// that do not run an A2A or MCP server — or do not host MoE
    /// experts — pass `None` for the corresponding slot.
    pub async fn bind_with_jsonrpc(
        cfg: &TenzroIrohConfig,
        a2a: Option<Arc<dyn JsonRpcDispatcher>>,
        mcp: Option<Arc<dyn McpStreamHandler>>,
        moe: Option<Arc<dyn JsonRpcDispatcher>>,
        infer: Option<Arc<dyn JsonRpcDispatcher>>,
        http: Option<Arc<dyn HttpForwardHandler>>,
        shell: Option<Arc<dyn ShellHandler>>,
    ) -> IrohResult<Arc<Self>> {
        let endpoint = Self::bind_endpoint_for_config(cfg).await?;
        let store = Self::load_fs_store(cfg).await?;
        Self::with_endpoint(endpoint, store, a2a, mcp, moe, infer, http, shell)
    }

    /// Stand up the blob store + iroh-blobs ALPN router on top of an
    /// already-bound endpoint, optionally registering an A2A JSON-RPC
    /// dispatcher, an MCP session handler, a MoE expert-host dispatcher,
    /// an inference dispatcher, and an HTTP-forward handler (the
    /// app-hosting ingress data plane) on the same router.
    fn with_endpoint(
        endpoint: Endpoint,
        store: ResolverStore,
        a2a: Option<Arc<dyn JsonRpcDispatcher>>,
        mcp: Option<Arc<dyn McpStreamHandler>>,
        moe: Option<Arc<dyn JsonRpcDispatcher>>,
        infer: Option<Arc<dyn JsonRpcDispatcher>>,
        http: Option<Arc<dyn HttpForwardHandler>>,
        shell: Option<Arc<dyn ShellHandler>>,
    ) -> IrohResult<Arc<Self>> {
        let blobs = BlobsProtocol::new(&store, None);
        let mut builder = Router::builder(endpoint.clone()).accept(ALPN, blobs);
        if let Some(dispatcher) = a2a {
            builder = builder.accept(ALPN_A2A, JsonRpcProtocol::a2a(dispatcher));
        }
        if let Some(handler) = mcp {
            builder = builder.accept(ALPN_MCP, McpProtocol::new(handler));
        }
        if let Some(dispatcher) = moe {
            builder = builder.accept(ALPN_MOE, JsonRpcProtocol::moe(dispatcher));
        }
        if let Some(dispatcher) = infer {
            builder = builder.accept(ALPN_INFER, JsonRpcProtocol::infer(dispatcher));
        }
        if let Some(handler) = http {
            builder = builder.accept(ALPN_HTTP, HttpForwardProtocol::new(handler));
        }
        if let Some(handler) = shell {
            builder = builder.accept(ALPN_SHELL, ShellProtocol::new(handler));
        }
        let router = builder.spawn();
        let downloader = Downloader::new(&store, &endpoint);
        Ok(Arc::new(Self {
            endpoint,
            store,
            router: Mutex::new(Some(router)),
            downloader,
            hint_cache: DashMap::new(),
        }))
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

    /// Access the underlying iroh endpoint — needed by higher-level
    /// transport wiring (e.g. the `Downloader` constructor in Phase B1).
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// Access the underlying blob store as `iroh_blobs::api::Store`.
    /// Higher-level callers (e.g. agent-memory archival, training
    /// outer-gradient distribution) operate against this directly.
    pub fn store(&self) -> &BlobStore {
        &self.store
    }

    /// Cleanly shut down the router (which closes the endpoint).
    /// Idempotent.
    pub async fn shutdown(&self) -> IrohResult<()> {
        let router = self.router.lock().await.take();
        if let Some(r) = router {
            r.shutdown()
                .await
                .map_err(|e| IrohError::Backend(format!("router shutdown: {e}")))?;
        }
        Ok(())
    }

    /// Extract the BLAKE3 hash hex string addressed by `uri`. Returns
    /// `UnsupportedVariant` for non-content variants.
    fn content_hash(uri: &TenzroUri) -> IrohResult<&str> {
        match uri {
            TenzroUri::Blob { hash, .. }
            | TenzroUri::Model { hash, .. }
            | TenzroUri::Gradient { hash, .. }
            | TenzroUri::Receipt { hash, .. } => Ok(hash),
            TenzroUri::Shard { envelope_hash, .. } => Ok(envelope_hash),
            TenzroUri::Node { .. } => Err(IrohError::UnsupportedVariant("Node")),
            TenzroUri::Did { .. } => Err(IrohError::UnsupportedVariant("Did")),
            TenzroUri::Manifest { .. } => Err(IrohError::UnsupportedVariant("Manifest")),
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
            TenzroUri::Memory { .. } => Err(IrohError::UnsupportedVariant("Memory")),
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

    /// Tag the cargo runner with the `iroh-net` cfg so the iroh n0 preset
    /// can pick up its rustls provider when invoked from this test module.
    fn test_bytes() -> Bytes {
        Bytes::from_static(b"tenzro-iroh phase A2 round-trip payload")
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
            TenzroUri::Manifest {
                manifest_hash: "0".repeat(64),
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
