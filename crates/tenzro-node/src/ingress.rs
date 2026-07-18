//! Dynamic ingress: routing an incoming public HTTP request to whichever node
//! actually holds a deployed app, over the `tenzro/http` iroh ALPN.
//!
//! # Two sides of one exchange
//!
//! - **Edge side** ([`forward_request`]). A node that terminates TLS for a
//!   hostname (the operator's edge) resolves the Host header to a site, looks
//!   up the site's placement in the [`IngressTable`], and — when the serving
//!   node is remote — opens a `tenzro/http` bi-stream to that node's
//!   `EndpointId`, writes the raw HTTP/1.1 request, and relays the raw
//!   HTTP/1.1 response back to the public client. When the placement is local
//!   (or absent), the edge serves the site itself via the ordinary
//!   `/sites/<id>` path and never forwards.
//!
//! - **Serving side** ([`IrohIngressHandler`]). The node that holds the site's
//!   blobs implements [`tenzro_iroh::HttpForwardHandler`]: it reads the raw
//!   HTTP/1.1 request off the stream, resolves the target site (by the
//!   forwarded `Host` header or an explicit `/sites/<id>` path), runs the
//!   manifest route resolution + blob fetch (the same resolution the local
//!   `web/sites.rs` serve path uses), and writes the raw HTTP/1.1 response
//!   back.
//!
//! # Placement is node-agnostic content, plus an addressing table
//!
//! A [`crate::sites::SiteManifest`] maps routes to content-addressed blobs;
//! any node holding those blobs can serve it. The [`IngressTable`] is the thin
//! addressing layer on top: `site_id → [serving EndpointId]`. It is
//! write-through to `CF_METADATA` under `site_placement:` and hydrates on boot,
//! matching every other registry. An empty placement (no record, or a record
//! that lists only this node) means "serve locally".

use std::sync::Arc;

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use tenzro_iroh::{
    open_http_stream, EndpointId, HttpForwardHandler, IrohResolver as _, RecvStream, SendStream,
};
use tenzro_storage::{CF_METADATA, KvStore};
use tenzro_types::tenzro_uri::TenzroUri;
use thiserror::Error;
use tracing::{debug, warn};

use crate::node::TenzroNode;
use crate::sites::{is_asset_path, normalize_hostname, SiteManifest};
use crate::web::sites::parse_credential;

/// Key prefix for site-placement records within `CF_METADATA`.
const PLACEMENT_PREFIX: &str = "site_placement:";

/// Cap on the raw HTTP/1.1 request head (request line + headers) we buffer
/// before dispatch. Bodies stream separately; only the head is parsed. Matches
/// common server head limits (nginx `large_client_header_buffers` territory).
const MAX_HEAD_BYTES: usize = 64 * 1024;

/// Cap on a served response body assembled from a single blob. Static assets
/// are content-addressed blobs already bounded by the publish path; this guards
/// the ingress buffer against a pathological manifest.
const MAX_RESPONSE_BODY_BYTES: usize = 128 * 1024 * 1024;

/// Cap on a request body the edge will buffer before forwarding over
/// `tenzro/http`. Static-site requests are small; a larger body indicates a
/// runtime target (a later layer), which will stream rather than buffer.
pub const MAX_FORWARD_BODY_BYTES: usize = 16 * 1024 * 1024;

fn placement_key(site_id: &str) -> Vec<u8> {
    format!("{PLACEMENT_PREFIX}{site_id}").into_bytes()
}

#[derive(Debug, Error)]
pub enum IngressError {
    #[error("storage error: {0}")]
    Storage(String),
    #[error("serialization error: {0}")]
    Serialization(String),
    #[error("malformed http request: {0}")]
    BadRequest(String),
    #[error("stream io error: {0}")]
    Io(String),
    #[error("invalid serving endpoint id: {0}")]
    BadEndpointId(String),
}

/// Where a site is served from: the set of nodes that hold its blobs and answer
/// `tenzro/http` forwards for it. The first reachable entry is dialed; the rest
/// are failover candidates. An empty list is equivalent to no record — the edge
/// serves locally.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlacementRecord {
    pub site_id: String,
    /// Serving nodes, as iroh `EndpointId` strings (the identity peers dial).
    /// Ordered by preference; index 0 is primary, the rest are failover.
    pub serving_nodes: Vec<String>,
    pub updated_at: u64,
}

/// `site_id → serving-node placement`, write-through to `CF_METADATA` and
/// hydrated on boot.
pub struct IngressTable {
    placements: DashMap<String, PlacementRecord>,
    storage: Option<Arc<dyn KvStore>>,
}

impl std::fmt::Debug for IngressTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IngressTable")
            .field("placements", &self.placements.len())
            .finish()
    }
}

impl IngressTable {
    pub fn new() -> Self {
        Self {
            placements: DashMap::new(),
            storage: None,
        }
    }

    /// Storage-backed table: hydrates existing placement records from
    /// `CF_METADATA` under the `site_placement:` prefix.
    pub fn with_storage(storage: Arc<dyn KvStore>) -> Result<Self, IngressError> {
        let table = Self {
            placements: DashMap::new(),
            storage: Some(storage.clone()),
        };
        let keys = storage
            .get_keys_with_prefix(CF_METADATA, PLACEMENT_PREFIX.as_bytes())
            .map_err(|e| IngressError::Storage(format!("placement scan: {e}")))?;
        let mut restored = 0usize;
        for key in keys {
            match storage.get(CF_METADATA, &key) {
                Ok(Some(bytes)) => match serde_json::from_slice::<PlacementRecord>(&bytes) {
                    Ok(record) => {
                        table.placements.insert(record.site_id.clone(), record);
                        restored += 1;
                    }
                    Err(e) => warn!("skipping undecodable site placement: {e}"),
                },
                Ok(None) => {}
                Err(e) => return Err(IngressError::Storage(format!("placement get: {e}"))),
            }
        }
        if restored > 0 {
            debug!("hydrated {restored} site placement record(s)");
        }
        Ok(table)
    }

    fn persist(&self, record: &PlacementRecord) -> Result<(), IngressError> {
        if let Some(storage) = &self.storage {
            let bytes = serde_json::to_vec(record)
                .map_err(|e| IngressError::Serialization(e.to_string()))?;
            storage
                .put(CF_METADATA, &placement_key(&record.site_id), &bytes)
                .map_err(|e| IngressError::Storage(e.to_string()))?;
        }
        Ok(())
    }

    /// Record the serving nodes for a site. An empty `serving_nodes` removes the
    /// placement (equivalent to "serve locally").
    pub fn set_placement(
        &self,
        site_id: &str,
        serving_nodes: Vec<String>,
        now_ms: u64,
    ) -> Result<(), IngressError> {
        if serving_nodes.is_empty() {
            return self.remove_placement(site_id);
        }
        for node in &serving_nodes {
            node.parse::<EndpointId>()
                .map_err(|e| IngressError::BadEndpointId(format!("{node}: {e}")))?;
        }
        let record = PlacementRecord {
            site_id: site_id.to_string(),
            serving_nodes,
            updated_at: now_ms,
        };
        self.persist(&record)?;
        self.placements.insert(site_id.to_string(), record);
        Ok(())
    }

    pub fn get_placement(&self, site_id: &str) -> Option<PlacementRecord> {
        self.placements.get(site_id).map(|r| r.clone())
    }

    pub fn remove_placement(&self, site_id: &str) -> Result<(), IngressError> {
        self.placements.remove(site_id);
        if let Some(storage) = &self.storage {
            storage
                .delete(CF_METADATA, &placement_key(site_id))
                .map_err(|e| IngressError::Storage(e.to_string()))?;
        }
        Ok(())
    }

    pub fn list_placements(&self) -> Vec<PlacementRecord> {
        self.placements.iter().map(|e| e.value().clone()).collect()
    }

    /// The serving nodes for a site that are *not* this local node, in
    /// preference order. Returns an empty vec when the site should be served
    /// locally (no record, or the record lists only this node).
    pub fn remote_serving_nodes(&self, site_id: &str, local: &EndpointId) -> Vec<EndpointId> {
        let local_str = local.to_string();
        self.get_placement(site_id)
            .map(|r| {
                r.serving_nodes
                    .into_iter()
                    .filter(|n| n != &local_str)
                    .filter_map(|n| n.parse::<EndpointId>().ok())
                    .collect()
            })
            .unwrap_or_default()
    }
}

impl Default for IngressTable {
    fn default() -> Self {
        Self::new()
    }
}

/// Parsed head of a raw HTTP/1.1 request: the request line plus headers, with
/// the leftover bytes that belong to the body (already read past the head).
struct RequestHead {
    method: String,
    target: String,
    /// Lowercased header name → value (last wins), enough for Host + routing.
    headers: Vec<(String, String)>,
    /// Bytes read after the `\r\n\r\n` head terminator — the start of the body.
    body_prefix: Vec<u8>,
}

impl RequestHead {
    fn header(&self, name: &str) -> Option<&str> {
        let want = name.to_ascii_lowercase();
        self.headers
            .iter()
            .rev()
            .find(|(k, _)| *k == want)
            .map(|(_, v)| v.as_str())
    }

    fn host(&self) -> Option<String> {
        self.header("host").and_then(normalize_hostname)
    }

    /// The request path (target with any query stripped).
    fn path(&self) -> &str {
        self.target.split('?').next().unwrap_or(&self.target)
    }
}

/// Read the HTTP/1.1 request head off a stream up to `\r\n\r\n`, capping at
/// [`MAX_HEAD_BYTES`]. Returns the parsed head plus any body bytes already read.
async fn read_request_head(recv: &mut RecvStream) -> Result<RequestHead, IngressError> {
    let mut buf: Vec<u8> = Vec::with_capacity(2048);
    let mut chunk = [0u8; 4096];
    let head_end;
    loop {
        // Look for the CRLFCRLF head terminator in what we have so far.
        if let Some(pos) = find_head_end(&buf) {
            head_end = pos;
            break;
        }
        if buf.len() > MAX_HEAD_BYTES {
            return Err(IngressError::BadRequest("request head too large".into()));
        }
        let n = recv
            .read(&mut chunk)
            .await
            .map_err(|e| IngressError::Io(format!("read head: {e}")))?
            .unwrap_or(0);
        if n == 0 {
            // Stream ended before a complete head arrived.
            if let Some(pos) = find_head_end(&buf) {
                head_end = pos;
                break;
            }
            return Err(IngressError::BadRequest(
                "connection closed before complete request head".into(),
            ));
        }
        buf.extend_from_slice(&chunk[..n]);
    }

    let body_prefix = buf[head_end + 4..].to_vec();
    let head = &buf[..head_end];
    let text = std::str::from_utf8(head)
        .map_err(|_| IngressError::BadRequest("non-utf8 request head".into()))?;
    let mut lines = text.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| IngressError::BadRequest("empty request".into()))?;
    let mut parts = request_line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| IngressError::BadRequest("missing method".into()))?
        .to_string();
    let target = parts
        .next()
        .ok_or_else(|| IngressError::BadRequest("missing target".into()))?
        .to_string();

    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if let Some((k, v)) = line.split_once(':') {
            headers.push((k.trim().to_ascii_lowercase(), v.trim().to_string()));
        }
    }

    Ok(RequestHead {
        method,
        target,
        headers,
        body_prefix,
    })
}

/// Index of the `\r\n\r\n` that terminates the request head, if present.
fn find_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

/// Serving-node side of `tenzro/http`. Holds an `Arc<TenzroNode>` so it can
/// reach the site registry, the iroh blob resolver, and the payment gateway —
/// the same handles the local `web/sites.rs` serve path uses.
#[derive(Clone)]
pub struct IrohIngressHandler {
    node: Arc<TenzroNode>,
}

impl std::fmt::Debug for IrohIngressHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IrohIngressHandler").finish()
    }
}

impl IrohIngressHandler {
    pub fn new(node: Arc<TenzroNode>) -> Self {
        Self { node }
    }

    /// Resolve the target site id for a forwarded request. Precedence mirrors
    /// the edge: an explicit `/sites/<id>` path (the edge rewrote it), then the
    /// forwarded `Host` header against the alias then verified-domain tables.
    fn resolve_site_id(&self, head: &RequestHead) -> Option<(String, String)> {
        let path = head.path();
        if let Some(rest) = path.strip_prefix("/sites/") {
            let mut split = rest.splitn(2, '/');
            let site_id = split.next().unwrap_or("").to_string();
            if !site_id.is_empty() {
                let suffix = match split.next() {
                    Some(s) if !s.is_empty() => format!("/{s}"),
                    _ => String::new(),
                };
                return Some((site_id, suffix));
            }
        }
        let host = head.host()?;
        let registry = self.node.site_registry();
        let site_id = registry
            .resolve_alias(&host)
            .or_else(|| registry.resolve_domain(&host))?;
        Some((site_id, path.to_string()))
    }

    /// Resolve a request against a manifest and produce the response bytes.
    /// Returns the raw HTTP/1.1 response ready to write to the stream.
    async fn render(
        &self,
        manifest: &SiteManifest,
        request_suffix: &str,
        head: &RequestHead,
    ) -> Vec<u8> {
        // Static routes are read-only: anything but GET/HEAD is a method error,
        // not a 404.
        if head.method != "GET" && head.method != "HEAD" {
            return http_response(
                405,
                "text/plain; charset=utf-8",
                b"method not allowed for static site",
            );
        }
        let request_path = if request_suffix.is_empty() || request_suffix == "/" {
            manifest.index_path.clone()
        } else {
            request_suffix.to_string()
        };

        let (route_path, status_line) = if manifest.routes.contains_key(&request_path) {
            (request_path.clone(), "200 OK")
        } else if manifest.spa
            && !is_asset_path(&request_path)
            && manifest.routes.contains_key(&manifest.index_path)
        {
            (manifest.index_path.clone(), "200 OK")
        } else if let Some(nf) = manifest
            .not_found_path
            .as_ref()
            .filter(|nf| manifest.routes.contains_key(*nf))
        {
            (nf.clone(), "404 Not Found")
        } else {
            return http_response(404, "text/plain; charset=utf-8", b"no route for path");
        };

        // x402 gate: when the manifest carries a price, a forwarded request
        // must already carry a settled credential. The forwarding edge relays
        // the caller's `Payment-Credential` / `Authorization` header, so the
        // serving node verifies it here — the same two-path challenge/settle
        // the local serve uses, minus challenge minting (the edge owns the
        // public-facing 402 body; a bare forward with no credential returns
        // 402 and the edge relays it).
        if let Some(price) = manifest.price_per_request
            && let Err(resp) = self.enforce_payment(manifest, &request_path, price, head).await
        {
            return resp;
        }

        let route = manifest
            .routes
            .get(&route_path)
            .expect("route_path checked above")
            .clone();

        let etag = format!("\"{}\"", route.blob_hash);
        if head
            .header("if-none-match")
            .is_some_and(|inm| inm.split(',').any(|c| c.trim() == etag))
        {
            return http_response_with_headers(
                304,
                &[("etag", &etag)],
                b"",
            );
        }

        let registry = self.node.site_registry();
        let cache = registry.blob_cache();
        let body = if let Some(bytes) = cache.get(&route.blob_hash) {
            bytes
        } else {
            let Some(resolver) = self.node.iroh_resolver() else {
                return http_response(
                    503,
                    "text/plain; charset=utf-8",
                    b"blob resolver unavailable",
                );
            };
            let uri = TenzroUri::Blob {
                hash: route.blob_hash.clone(),
                provider_hint: None,
            };
            match resolver.fetch_bytes(&uri).await {
                Ok(bytes) => {
                    cache.insert(&route.blob_hash, bytes.clone());
                    bytes
                }
                Err(e) => {
                    warn!(
                        "ingress: site {} blob fetch failed for {route_path}: {e}",
                        manifest.site_id
                    );
                    return http_response(502, "text/plain; charset=utf-8", b"blob fetch failed");
                }
            }
        };

        if body.len() > MAX_RESPONSE_BODY_BYTES {
            return http_response(502, "text/plain; charset=utf-8", b"blob too large");
        }

        let status_code: u16 = if status_line.starts_with("404") { 404 } else { 200 };
        http_response_with_headers(
            status_code,
            &[
                ("content-type", &route.content_type),
                ("cache-control", "public,max-age=60"),
                ("etag", &etag),
            ],
            &body,
        )
    }

    /// Verify a relayed payment credential for a priced site. `Ok(())` = proceed;
    /// `Err` carries the raw HTTP/1.1 response (402 when absent, 4xx on failure)
    /// the edge relays to the public client.
    async fn enforce_payment(
        &self,
        manifest: &SiteManifest,
        resource: &str,
        _price: u128,
        head: &RequestHead,
    ) -> Result<(), Vec<u8>> {
        use tenzro_payments::traits::PaymentGateway as _;

        let Some(gateway) = self.node.payment_gateway() else {
            return Err(http_response(
                503,
                "text/plain; charset=utf-8",
                b"payment gateway unavailable",
            ));
        };

        let credential_header = head
            .header("payment-credential")
            .or_else(|| head.header("authorization"));

        let Some(header_value) = credential_header else {
            // No credential on a forwarded priced request: signal 402 back to
            // the edge, which mints/relays the public-facing challenge.
            return Err(http_response(
                402,
                "text/plain; charset=utf-8",
                b"payment required",
            ));
        };

        let credential = match parse_credential(header_value) {
            Ok(c) => c,
            Err(e) => {
                return Err(http_response(
                    400,
                    "text/plain; charset=utf-8",
                    format!("invalid credential: {e}").as_bytes(),
                ));
            }
        };
        debug!(
            "ingress: site {} verifying credential {} for {}",
            manifest.site_id, credential.credential_id, resource
        );
        gateway.verify_and_settle(&credential).await.map_err(|e| {
            http_response(
                402,
                "text/plain; charset=utf-8",
                format!("payment verification failed: {e}").as_bytes(),
            )
        })?;
        Ok(())
    }

    /// Verify a relayed payment credential for a priced function. Same
    /// two-path challenge/settle as [`enforce_payment`], keyed on a function
    /// deployment rather than a site manifest.
    #[cfg(feature = "wasi-skills")]
    async fn enforce_function_payment(
        &self,
        deployment: &crate::functions::FunctionDeployment,
        head: &RequestHead,
    ) -> Result<(), Vec<u8>> {
        use tenzro_payments::traits::PaymentGateway as _;

        let Some(gateway) = self.node.payment_gateway() else {
            return Err(http_response(
                503,
                "text/plain; charset=utf-8",
                b"payment gateway unavailable",
            ));
        };
        let credential_header = head
            .header("payment-credential")
            .or_else(|| head.header("authorization"));
        let Some(header_value) = credential_header else {
            return Err(http_response(
                402,
                "text/plain; charset=utf-8",
                b"payment required",
            ));
        };
        let credential = match parse_credential(header_value) {
            Ok(c) => c,
            Err(e) => {
                return Err(http_response(
                    400,
                    "text/plain; charset=utf-8",
                    format!("invalid credential: {e}").as_bytes(),
                ));
            }
        };
        debug!(
            "ingress: function {} verifying credential {}",
            deployment.id, credential.credential_id
        );
        gateway.verify_and_settle(&credential).await.map_err(|e| {
            http_response(
                402,
                "text/plain; charset=utf-8",
                format!("payment verification failed: {e}").as_bytes(),
            )
        })?;
        Ok(())
    }

    /// Verify a relayed payment credential for a priced machine app. Same
    /// two-path challenge/settle as [`enforce_payment`], keyed on a machine
    /// deployment.
    #[cfg(feature = "firecracker")]
    async fn enforce_machine_payment(
        &self,
        deployment: &crate::machines::MachineDeployment,
        head: &RequestHead,
    ) -> Result<(), Vec<u8>> {
        use tenzro_payments::traits::PaymentGateway as _;

        let Some(gateway) = self.node.payment_gateway() else {
            return Err(http_response(
                503,
                "text/plain; charset=utf-8",
                b"payment gateway unavailable",
            ));
        };
        let credential_header = head
            .header("payment-credential")
            .or_else(|| head.header("authorization"));
        let Some(header_value) = credential_header else {
            return Err(http_response(
                402,
                "text/plain; charset=utf-8",
                b"payment required",
            ));
        };
        let credential = match parse_credential(header_value) {
            Ok(c) => c,
            Err(e) => {
                return Err(http_response(
                    400,
                    "text/plain; charset=utf-8",
                    format!("invalid credential: {e}").as_bytes(),
                ));
            }
        };
        debug!(
            "ingress: machine {} verifying credential {}",
            deployment.id, credential.credential_id
        );
        gateway.verify_and_settle(&credential).await.map_err(|e| {
            http_response(
                402,
                "text/plain; charset=utf-8",
                format!("payment verification failed: {e}").as_bytes(),
            )
        })?;
        Ok(())
    }

    /// Serve a request through a deployed `wasi:http` function component.
    ///
    /// Fetches the component blob from the iroh store (content-addressed, so
    /// the fetched bytes are self-verifying against `wasm_blob_hash`),
    /// compiles-or-reuses it via the node's [`crate::functions::FunctionComponentCache`],
    /// and runs one request-scoped invocation. `request_suffix` is the resolved
    /// path (the target the guest sees); the request body is forwarded verbatim.
    ///
    /// A node built without the `wasi-skills` feature holds the deployment
    /// metadata but cannot serve it — returns 501.
    #[cfg(feature = "wasi-skills")]
    async fn serve_function(
        &self,
        deployment: &crate::functions::FunctionDeployment,
        request_suffix: &str,
        head: &RequestHead,
        body: Vec<u8>,
    ) -> Vec<u8> {
        // x402 gate: a priced function requires a settled credential on the
        // forwarded request, exactly as a priced site does.
        if deployment.price_per_request.is_some()
            && let Err(resp) = self.enforce_function_payment(deployment, head).await
        {
            return resp;
        }

        let Some(resolver) = self.node.iroh_resolver() else {
            return http_response(503, "text/plain; charset=utf-8", b"blob resolver unavailable");
        };
        let uri = TenzroUri::Blob {
            hash: deployment.wasm_blob_hash.clone(),
            provider_hint: None,
        };
        let wasm_bytes = match resolver.fetch_bytes(&uri).await {
            Ok(bytes) => bytes,
            Err(e) => {
                warn!(
                    "ingress: function {} blob fetch failed: {e}",
                    deployment.id
                );
                return http_response(502, "text/plain; charset=utf-8", b"component fetch failed");
            }
        };

        let component = match self
            .node
            .function_components()
            .get_or_compile(deployment, &wasm_bytes)
        {
            Ok(c) => c,
            Err(e) => {
                warn!("ingress: function {} compile failed: {e}", deployment.id);
                return http_response(502, "text/plain; charset=utf-8", b"component compile failed");
            }
        };

        // The guest sees the resolved path as its request target. Reuse the
        // original method and headers; the body is forwarded verbatim.
        let target = if request_suffix.is_empty() { "/" } else { request_suffix };
        match component
            .serve_buffered(
                true, // edge terminates TLS: guest sees https
                &head.method,
                target,
                &head.headers,
                bytes::Bytes::from(body),
                MAX_RESPONSE_BODY_BYTES,
            )
            .await
        {
            Ok(resp) => {
                let header_refs: Vec<(&str, &str)> = resp
                    .headers
                    .iter()
                    .map(|(k, v)| (k.as_str(), v.as_str()))
                    .collect();
                http_response_with_headers(resp.status, &header_refs, &resp.body)
            }
            Err(e) => {
                warn!("ingress: function {} invocation failed: {e}", deployment.id);
                http_response(502, "text/plain; charset=utf-8", b"function invocation failed")
            }
        }
    }

    /// Fallback when the node is built without wasm support: the deployment
    /// exists in the registry but this node cannot execute it.
    #[cfg(not(feature = "wasi-skills"))]
    async fn serve_function(
        &self,
        _deployment: &crate::functions::FunctionDeployment,
        _request_suffix: &str,
        _head: &RequestHead,
        _body: Vec<u8>,
    ) -> Vec<u8> {
        http_response(
            501,
            "text/plain; charset=utf-8",
            b"function runtime not available on this node",
        )
    }

    /// Machine path: bridge the forwarded HTTP request to the assigned app's
    /// microVM. The supervisor boots (or confirms already-running) the
    /// Firecracker instance for this deployment and returns the host-routable
    /// address of the guest's declared `internal_port`; we open a plain TCP
    /// connection to it, replay the raw HTTP/1.1 request the edge forwarded,
    /// and stream the guest's raw HTTP/1.1 response back unchanged.
    ///
    /// A node built without the `firecracker` feature (or without the KVM /
    /// root prerequisites to construct a supervisor) holds the deployment
    /// metadata but cannot run it — returns 501, matching the function path.
    #[cfg(feature = "firecracker")]
    async fn serve_machine(
        &self,
        deployment: &crate::machines::MachineDeployment,
        head: &RequestHead,
        body: Vec<u8>,
    ) -> Vec<u8> {
        // x402 gate: a priced machine app requires a settled credential on the
        // forwarded request, exactly as a priced function or site does.
        if deployment.price_per_request.is_some()
            && let Err(resp) = self.enforce_machine_payment(deployment, head).await
        {
            return resp;
        }

        let Some(supervisor) = self.node.machine_supervisor() else {
            return http_response(
                501,
                "text/plain; charset=utf-8",
                b"machine runtime unavailable on this node",
            );
        };

        let guest_addr = match supervisor.ensure_running(deployment).await {
            Ok(addr) => addr,
            Err(e) => {
                warn!("ingress: machine {} launch failed: {e}", deployment.id);
                return http_response(502, "text/plain; charset=utf-8", b"machine launch failed");
            }
        };

        match bridge_to_guest(guest_addr, head, &body).await {
            Ok(resp) => resp,
            Err(e) => {
                warn!("ingress: machine {} bridge failed: {e}", deployment.id);
                http_response(502, "text/plain; charset=utf-8", b"machine bridge failed")
            }
        }
    }

    /// Fallback when the node is built without the `firecracker` feature: the
    /// deployment exists in the registry but this node cannot run a microVM.
    #[cfg(not(feature = "firecracker"))]
    async fn serve_machine(
        &self,
        _deployment: &crate::machines::MachineDeployment,
        _head: &RequestHead,
        _body: Vec<u8>,
    ) -> Vec<u8> {
        http_response(
            501,
            "text/plain; charset=utf-8",
            b"machine runtime not available on this node",
        )
    }
}

#[async_trait::async_trait]
impl HttpForwardHandler for IrohIngressHandler {
    async fn serve_request(
        self: Arc<Self>,
        mut send: SendStream,
        mut recv: RecvStream,
    ) -> tenzro_iroh::IrohResult<()> {
        let head = match read_request_head(&mut recv).await {
            Ok(h) => h,
            Err(e) => {
                warn!("ingress: bad forwarded request: {e}");
                let resp = http_response(400, "text/plain; charset=utf-8", b"bad request");
                let _ = send.write_all(&resp).await;
                let _ = send.finish();
                return Ok(());
            }
        };

        // Resolve the host/path to a shared-namespace id once. A given id is a
        // function deployment, a machine deployment, or a static site — never
        // more than one; check function, then machine, then static. When none
        // matches, 404.
        let resp = match self.resolve_site_id(&head) {
            Some((id, suffix)) => {
                if let Some(deployment) = self.node.function_registry().get(&id) {
                    // Function path: the body is part of the request, so read it
                    // to end-of-stream and forward it to the component.
                    let body = read_full_body(&head, &mut recv).await;
                    self.serve_function(&deployment, &suffix, &head, body).await
                } else if let Some(deployment) = self.node.machine_registry().get(&id) {
                    // Machine path: bridge the full request to the microVM's
                    // guest loopback and stream the response back.
                    let body = read_full_body(&head, &mut recv).await;
                    self.serve_machine(&deployment, &head, body).await
                } else {
                    // Static path: no body of interest; drain it for a clean
                    // exchange, then serve from the site manifest.
                    drain_body(&head, &mut recv).await;
                    match self.node.site_registry().get_site(&id) {
                        Some(manifest) => self.render(&manifest, &suffix, &head).await,
                        None => http_response(404, "text/plain; charset=utf-8", b"site not found"),
                    }
                }
            }
            None => {
                drain_body(&head, &mut recv).await;
                http_response(404, "text/plain; charset=utf-8", b"no site for host")
            }
        };

        if let Err(e) = send.write_all(&resp).await {
            debug!("ingress: response write failed: {e}");
            return Ok(());
        }
        let _ = send.finish();
        Ok(())
    }
}

/// Read and discard the request body per Content-Length. Requests to a static
/// site carry no body of interest; consuming it keeps the exchange clean.
async fn drain_body(head: &RequestHead, recv: &mut RecvStream) {
    let declared: usize = head
        .header("content-length")
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(0);
    if declared == 0 {
        return;
    }
    let mut remaining = declared.saturating_sub(head.body_prefix.len());
    let mut chunk = [0u8; 8192];
    while remaining > 0 {
        match recv.read(&mut chunk).await {
            Ok(Some(n)) if n > 0 => remaining = remaining.saturating_sub(n),
            _ => break,
        }
    }
}

/// Read the full request body, retaining the bytes. Mirrors [`drain_body`]'s
/// content-length logic but accumulates into a buffer seeded with the prefix
/// already read off the stream head.
async fn read_full_body(head: &RequestHead, recv: &mut RecvStream) -> Vec<u8> {
    let declared: usize = head
        .header("content-length")
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(0);
    let mut body = head.body_prefix.clone();
    if declared <= body.len() {
        body.truncate(declared);
        return body;
    }
    let mut remaining = declared - body.len();
    let mut chunk = [0u8; 8192];
    while remaining > 0 {
        match recv.read(&mut chunk).await {
            Ok(Some(n)) if n > 0 => {
                let take = n.min(remaining);
                body.extend_from_slice(&chunk[..take]);
                remaining -= take;
            }
            _ => break,
        }
    }
    body
}

/// Bridge one forwarded HTTP request to a machine app's guest port over a
/// plain TCP connection, returning the guest's raw HTTP/1.1 response bytes.
///
/// The edge already terminated TLS and framed the request; we reconstruct the
/// exact request line + headers from the parsed [`RequestHead`] and append the
/// buffered body, then read the response to end-of-stream. Framing stays raw:
/// the guest speaks ordinary HTTP/1.1 on loopback, and the response bytes flow
/// back to the edge unchanged. `Connection: close` is forced so the guest
/// signals end-of-response by closing, which bounds the read without parsing
/// content-length / chunked encoding on the response.
#[cfg(feature = "firecracker")]
async fn bridge_to_guest(
    guest_addr: std::net::SocketAddr,
    head: &RequestHead,
    body: &[u8],
) -> std::io::Result<Vec<u8>> {
    use tokio::net::TcpStream;

    let mut req = Vec::with_capacity(256 + head.headers.len() * 32 + body.len());
    req.extend_from_slice(head.method.as_bytes());
    req.push(b' ');
    req.extend_from_slice(head.target.as_bytes());
    req.extend_from_slice(b" HTTP/1.1\r\n");
    for (k, v) in &head.headers {
        // Drop hop-by-hop framing headers the edge set for the tenzro/http
        // stream; the guest connection manages its own.
        if k == "connection" || k == "keep-alive" || k == "transfer-encoding" {
            continue;
        }
        req.extend_from_slice(k.as_bytes());
        req.extend_from_slice(b": ");
        req.extend_from_slice(v.as_bytes());
        req.extend_from_slice(b"\r\n");
    }
    req.extend_from_slice(b"connection: close\r\n\r\n");
    req.extend_from_slice(body);

    let mut stream = TcpStream::connect(guest_addr).await?;
    stream.write_all(&req).await?;
    stream.flush().await?;

    let mut resp = Vec::with_capacity(8192);
    let mut chunk = [0u8; 8192];
    loop {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        resp.extend_from_slice(&chunk[..n]);
        if resp.len() > MAX_RESPONSE_BODY_BYTES {
            break;
        }
    }
    Ok(resp)
}

/// Build a raw HTTP/1.1 response with a single content type.
fn http_response(status: u16, content_type: &str, body: &[u8]) -> Vec<u8> {
    http_response_with_headers(status, &[("content-type", content_type)], body)
}

/// Build a raw HTTP/1.1 response with arbitrary headers. `content-length` and
/// `connection: close` are always appended; the caller supplies the rest.
fn http_response_with_headers(status: u16, headers: &[(&str, &str)], body: &[u8]) -> Vec<u8> {
    let reason = reason_phrase(status);
    let mut out = format!("HTTP/1.1 {status} {reason}\r\n").into_bytes();
    for (k, v) in headers {
        out.extend_from_slice(format!("{k}: {v}\r\n").as_bytes());
    }
    out.extend_from_slice(format!("content-length: {}\r\n", body.len()).as_bytes());
    out.extend_from_slice(b"connection: close\r\n\r\n");
    out.extend_from_slice(body);
    out
}

fn reason_phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
        304 => "Not Modified",
        400 => "Bad Request",
        402 => "Payment Required",
        404 => "Not Found",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        _ => "OK",
    }
}

/// Edge side of `tenzro/http`. Open a bi-stream to `serving_node`, write the
/// raw HTTP/1.1 request (`request_head` + `body`), and return the raw HTTP/1.1
/// response bytes. The edge relays those verbatim to the public client.
///
/// `request_head` is the already-assembled request line + headers ending in
/// `\r\n\r\n`; `body` is the (possibly empty) request body. The connection is
/// held for the duration of the exchange and dropped on return.
pub async fn forward_request(
    node: &TenzroNode,
    serving_node: EndpointId,
    request_head: &[u8],
    body: &[u8],
) -> Result<Vec<u8>, IngressError> {
    let Some(resolver) = node.iroh_resolver() else {
        return Err(IngressError::Io("iroh endpoint not bound".into()));
    };
    let endpoint = resolver.endpoint();
    let (conn, mut send, mut recv) = open_http_stream(endpoint, serving_node)
        .await
        .map_err(|e| IngressError::Io(format!("open http stream: {e}")))?;

    send.write_all(request_head)
        .await
        .map_err(|e| IngressError::Io(format!("write head: {e}")))?;
    if !body.is_empty() {
        send.write_all(body)
            .await
            .map_err(|e| IngressError::Io(format!("write body: {e}")))?;
    }
    send.finish()
        .map_err(|e| IngressError::Io(format!("finish: {e}")))?;

    let mut resp = Vec::with_capacity(4096);
    let mut chunk = [0u8; 8192];
    loop {
        match recv.read(&mut chunk).await {
            Ok(Some(n)) if n > 0 => {
                resp.extend_from_slice(&chunk[..n]);
                if resp.len() > MAX_RESPONSE_BODY_BYTES {
                    return Err(IngressError::Io("forwarded response too large".into()));
                }
            }
            _ => break,
        }
    }
    conn.close(0u32.into(), b"done");
    Ok(resp)
}

/// Parse a raw HTTP/1.1 response (as returned by [`forward_request`]) into an
/// axum response the edge relays to the public client. Preserves status and
/// every response header except the hop-by-hop `connection` and the
/// `content-length` axum recomputes. Returns `None` if the buffer has no valid
/// status line / head terminator.
pub fn raw_http_to_response(raw: &[u8]) -> Option<axum::response::Response> {
    use axum::http::{HeaderName, HeaderValue, StatusCode};

    let head_end = find_head_end(raw)?;
    let head = std::str::from_utf8(&raw[..head_end]).ok()?;
    let body = raw[head_end + 4..].to_vec();

    let mut lines = head.split("\r\n");
    let status_line = lines.next()?;
    let mut sp = status_line.splitn(3, ' ');
    let _version = sp.next()?;
    let code: u16 = sp.next()?.parse().ok()?;
    let status = StatusCode::from_u16(code).ok()?;

    let mut builder = axum::response::Response::builder().status(status);
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let Some((k, v)) = line.split_once(':') else {
            continue;
        };
        let key = k.trim().to_ascii_lowercase();
        // Drop hop-by-hop and length headers; axum sets content-length from the
        // body, and `connection: close` is an ingress-internal artifact.
        if key == "connection" || key == "content-length" || key == "transfer-encoding" {
            continue;
        }
        if let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(key.as_bytes()),
            HeaderValue::from_str(v.trim()),
        ) {
            builder = builder.header(name, value);
        }
    }

    builder.body(axum::body::Body::from(body)).ok()
}
