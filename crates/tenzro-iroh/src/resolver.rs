//! `IrohResolver` trait — the dispatch surface that crates depend on
//! without pulling in the iroh runtime, and `IrohBackedResolver` — the
//! concrete iroh-blobs-backed implementation that lands as part of
//! Phase A2 (#214) alongside the `DaBackend` impl in `tenzro-storage::da`.

use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use iroh::{
    address_lookup::{AddrFilter, DnsAddressLookup, PkarrPublisher, PkarrResolver},
    endpoint::presets,
    protocol::Router,
    Endpoint, EndpointId,
};
use iroh_blobs::{
    api::{downloader::Downloader, Store as BlobStore},
    store::mem::MemStore,
    BlobsProtocol, Hash, ALPN,
};
use tokio::sync::Mutex;

use crate::config::TenzroIrohConfig;
use crate::error::{IrohError, IrohResult};
use crate::jsonrpc::{
    JsonRpcDispatcher, JsonRpcProtocol, McpProtocol, McpStreamHandler, ALPN_A2A, ALPN_MCP,
};
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
}

/// iroh-blobs-backed implementation of [`IrohResolver`].
///
/// Owns an [`Endpoint`], a [`BlobStore`] (currently in-memory via
/// [`MemStore`] — the filesystem-backed variant will be wired in when the
/// node config grows a persistence flag), and a [`Router`] that registers
/// the iroh-blobs ALPN so peers can fetch by hash. Drop / `shutdown` to
/// release the endpoint cleanly.
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
    store: MemStore,
    /// Router is kept alive (not used directly after spawn) so the
    /// iroh-blobs ALPN handler stays registered until shutdown.
    router: Mutex<Option<Router>>,
    /// Cross-node blob downloader. Constructed once over `endpoint` + `store`
    /// at bind time, reused on every `fetch_bytes` miss. Performs the actual
    /// QUIC dial + BAO-stream pull against a provider `EndpointId` when the
    /// blob is not yet in the local store.
    downloader: Downloader,
}

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
    /// The persistent filesystem-backed variant (`FsStore::load(path)`)
    /// will be added when the node config grows a persistence flag —
    /// the in-memory store is exercisable in tests and on validators that
    /// re-derive their receipt cache from on-chain commitments.
    pub async fn bind_in_memory() -> IrohResult<Arc<Self>> {
        let endpoint = Endpoint::bind(presets::N0)
            .await
            .map_err(|e| IrohError::Backend(format!("endpoint bind: {e}")))?;
        Self::with_endpoint(endpoint, None, None)
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
    /// nor `secret_key_seed` fall through to [`Self::bind_in_memory`] for
    /// a random ephemeral binding via the n0 preset.
    pub async fn bind_with_config(cfg: &TenzroIrohConfig) -> IrohResult<Arc<Self>> {
        // Fast path: no Tenzro-specific overrides AND port-0 bind — use the
        // n0 preset as-is (random ephemeral port). This is the test /
        // local-dev path; any operator who needs a deterministic port and
        // production discovery wiring falls through to the builder path
        // via `build_endpoint`.
        if cfg.pkarr_relay_url.is_none()
            && cfg.secret_key_seed.is_none()
            && cfg.bind_addr.port() == 0
        {
            return Self::bind_in_memory().await;
        }

        let endpoint = Self::build_endpoint(cfg).await?;
        Self::with_endpoint(endpoint, None, None)
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
            .map_err(|e| {
                IrohError::Backend(format!("bind_addr {} invalid: {e}", cfg.bind_addr))
            })?;
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
            builder =
                builder.address_lookup(PkarrPublisher::n0_dns().addr_filter(pkarr_filter));
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
    /// `None` for either dispatcher skips that ALPN registration. Nodes
    /// that do not run an A2A or MCP server pass `None` for the
    /// corresponding slot.
    pub async fn bind_with_jsonrpc(
        cfg: &TenzroIrohConfig,
        a2a: Option<Arc<dyn JsonRpcDispatcher>>,
        mcp: Option<Arc<dyn McpStreamHandler>>,
    ) -> IrohResult<Arc<Self>> {
        // Same bind decision as `bind_with_config` — see comments there.
        let endpoint = if cfg.pkarr_relay_url.is_none()
            && cfg.secret_key_seed.is_none()
            && cfg.bind_addr.port() == 0
        {
            Endpoint::bind(presets::N0)
                .await
                .map_err(|e| IrohError::Backend(format!("endpoint bind: {e}")))?
        } else {
            Self::build_endpoint(cfg).await?
        };
        Self::with_endpoint(endpoint, a2a, mcp)
    }

    /// Stand up an in-memory blob store + iroh-blobs ALPN router on top of
    /// an already-bound endpoint, optionally registering an A2A JSON-RPC
    /// dispatcher and an MCP session handler on the same router.
    fn with_endpoint(
        endpoint: Endpoint,
        a2a: Option<Arc<dyn JsonRpcDispatcher>>,
        mcp: Option<Arc<dyn McpStreamHandler>>,
    ) -> IrohResult<Arc<Self>> {
        let store = MemStore::new();
        let blobs = BlobsProtocol::new(&store, None);
        let mut builder = Router::builder(endpoint.clone()).accept(ALPN, blobs);
        if let Some(dispatcher) = a2a {
            builder = builder.accept(ALPN_A2A, JsonRpcProtocol::a2a(dispatcher));
        }
        if let Some(handler) = mcp {
            builder = builder.accept(ALPN_MCP, McpProtocol::new(handler));
        }
        let router = builder.spawn();
        let downloader = Downloader::new(&*store, &endpoint);
        Ok(Arc::new(Self {
            endpoint,
            store,
            router: Mutex::new(Some(router)),
            downloader,
        }))
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

        // Cross-node path. Two cases:
        //   (a) the URI carries an explicit provider hint — dial that peer
        //       directly via the shared `Downloader` and pull the blob into
        //       the local store, then re-read.
        //   (b) no hint — return `NotFound` with a message that names the
        //       follow-up (Pkarr-based content discovery). We intentionally
        //       do NOT broadcast a discovery query here: a hint-less fetch is
        //       a caller-side bug today, and silently succeeding via discovery
        //       would mask wiring gaps in upstream callers (publish-side
        //       provider announcements are the right place to fix that).
        let Some(provider) = Self::provider_hint(uri)? else {
            return Err(IrohError::NotFound(format!(
                "blob {hex} not local and no provider hint on URI"
            )));
        };

        // `Downloader::download(hash, providers)` writes the blob into the
        // store we constructed it with. Block on completion via the
        // `IntoFuture` impl on `DownloadProgress` (returns `Result<()>`).
        self.downloader
            .download(hash, vec![provider])
            .await
            .map_err(|e| {
                IrohError::NotFound(format!(
                    "blob {hex} not local; cross-node fetch from {provider} failed: {e}"
                ))
            })?;

        // The download wrote into the same `MemStore` we read from. iroh-blobs
        // verifies the BLAKE3 root on `get_bytes`, so a hashed mismatch fails
        // here rather than silently returning corrupt data.
        let bytes = self.store.blobs().get_bytes(hash).await.map_err(|e| {
            IrohError::Backend(format!(
                "blob {hex} downloaded from {provider} but get_bytes failed: {e}"
            ))
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
                assert!(hash.chars().all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()));
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
}
