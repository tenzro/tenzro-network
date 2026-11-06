//! Outbound HTTP to destinations a caller names.
//!
//! Some node features fetch a URL that someone other than the operator chose:
//! a skill or knowledge tool's `endpoint`, a webhook target, a `did:web`
//! document host, a hosted function's outgoing request, a provider endpoint
//! another node advertised over gossip, a URL handed to the `url_fetch`
//! tool. Pointed at
//! `http://169.254.169.254/` or `http://127.0.0.1:8545/`, any of those turns
//! the node into a proxy into its own network: cloud credentials, the loopback
//! admin RPC, a database on the LAN. Every such fetch goes through
//! [`EgressGuard`] instead of a plain client.
//!
//! # What the guard enforces
//!
//! - **Scheme.** `http` and `https` only; callers that deliver secrets can
//!   require `https` ([`Scheme::HttpsOnly`]).
//! - **Destination address, after resolution.** The host is resolved and every
//!   resolved address is checked against [`forbidden_reason`]: loopback,
//!   private (RFC 1918), carrier-grade NAT, link-local (which holds the cloud
//!   metadata endpoints), IPv6 unique-local and link-local, multicast,
//!   documentation and reserved ranges, and IPv4 embedded in IPv6 through the
//!   mapped, compatible, NAT64 and 6to4 forms. A name with *any* forbidden
//!   address is refused outright rather than filtered, so a round-robin record
//!   mixing a public and a private address cannot be used to win a race.
//! - **Rebinding.** The resolver above is installed as the client's own DNS
//!   resolver, so the connection is made to exactly the address that was
//!   checked. There is no second lookup for a short-TTL record to answer
//!   differently.
//! - **IP literals.** A URL naming an address directly never reaches the
//!   resolver, so literals are checked on the URL itself.
//! - **Redirects.** Not followed. A `3xx` comes back to the caller as a
//!   response; a redirect is the easiest way to move a checked URL onto an
//!   unchecked one.
//! - **Proxies.** Ignored. A `HTTP_PROXY` in the process environment would
//!   otherwise receive the request and do its own resolution.
//! - **Response size.** Bodies are read through [`GuardedResponse`], which
//!   stops at a byte cap instead of buffering whatever the far end sends.
//!
//! # Owner grants
//!
//! The only way past the refused ranges is a machine-access grant the
//! machine's owner signed ([`crate::machine_access`]): an unexpired, unrevoked
//! grant to the jobs on this node, or to the agent a request is made for
//! ([`EgressGuard::for_grantee`]), that names the destination's range, and its
//! port when it names one. The port is checked for host names as well as IP
//! literals: a port a grant names gets its own client whose resolver checks
//! that port. Bytes read through a grant with a byte allowance are counted
//! against it. Every connection through a grant, and every refusal, is logged
//! under the `machine_access` target. There is no configuration setting that
//! opens a range.
//!
//! # Brokered credentials
//!
//! An agent's terms may carry credentials its controller sealed to each
//! serving node's hardware sealing key
//! ([`tenzro_types::agent_terms::BrokeredCredential`]). When a request made
//! for the agent goes over HTTPS to exactly a credential's host,
//! [`EgressGuard::send`] opens the envelope with this machine's sealing key,
//! derived for that one opening, and attaches the secret as the credential's
//! header. The agent never holds the secret, cannot set that header itself,
//! and every attachment is recorded in its audit trail.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::machine_access::MachineAccessGrants;

/// Default cap on a response body read through the guard.
pub const DEFAULT_MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Operator configuration for outbound fetches to caller-named destinations.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EgressConfig {
    /// Largest response body, in bytes, read from a guarded fetch.
    #[serde(default = "default_max_response_bytes")]
    pub max_response_bytes: usize,
}

fn default_max_response_bytes() -> usize {
    DEFAULT_MAX_RESPONSE_BYTES
}

impl Default for EgressConfig {
    fn default() -> Self {
        Self {
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
        }
    }
}

/// Why an outbound fetch was refused or failed.
#[derive(Debug, Error)]
pub enum EgressError {
    #[error("invalid URL: {0}")]
    InvalidUrl(String),
    #[error("scheme {0:?} is not permitted for this fetch")]
    Scheme(String),
    #[error("destination {host} resolves to {ip}, which is {reason}")]
    Forbidden {
        host: String,
        ip: IpAddr,
        reason: &'static str,
    },
    #[error("could not resolve {host}: {detail}")]
    Resolve { host: String, detail: String },
    #[error("response body exceeds {limit} bytes")]
    TooLarge { limit: usize },
    #[error("request failed: {0}")]
    Http(String),
    #[error("invalid egress configuration: {0}")]
    Config(String),
    #[error("machine-access grant {grant_id} has moved all the bytes it allows")]
    AllowanceSpent { grant_id: String },
    #[error("agent {0} is quarantined")]
    Quarantined(String),
    #[error("brokered credential refused: {0}")]
    Credential(String),
}

/// Which URL schemes a particular fetch accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    /// `http` or `https`.
    HttpOrHttps,
    /// `https` only; for fetches that carry a secret or a signature.
    HttpsOnly,
}

/// A CIDR range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Cidr {
    network: IpAddr,
    prefix: u8,
}

impl Cidr {
    /// `a.b.c.d/n`, `x::y/n`, or a bare address (a single-host range).
    pub(crate) fn parse(s: &str) -> Result<Self, EgressError> {
        let (addr, prefix) = match s.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (s, None),
        };
        let network: IpAddr = addr
            .trim()
            .parse()
            .map_err(|_| EgressError::Config(format!("{s:?} is not an address or CIDR")))?;
        let max = if network.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix {
            Some(p) => p
                .trim()
                .parse::<u8>()
                .ok()
                .filter(|p| *p <= max)
                .ok_or_else(|| EgressError::Config(format!("{s:?} has an invalid prefix")))?,
            None => max,
        };
        Ok(Self { network, prefix })
    }

    pub(crate) fn contains(&self, ip: IpAddr) -> bool {
        match (self.network, ip) {
            (IpAddr::V4(n), IpAddr::V4(a)) => prefix_match(&n.octets(), &a.octets(), self.prefix),
            (IpAddr::V6(n), IpAddr::V6(a)) => prefix_match(&n.octets(), &a.octets(), self.prefix),
            _ => false,
        }
    }
}

fn prefix_match(net: &[u8], addr: &[u8], prefix: u8) -> bool {
    let full = (prefix / 8) as usize;
    if net[..full] != addr[..full] {
        return false;
    }
    let rem = prefix % 8;
    if rem == 0 {
        return true;
    }
    let mask = 0xffu8 << (8 - rem);
    (net[full] & mask) == (addr[full] & mask)
}

fn v4_in(ip: Ipv4Addr, net: [u8; 4], prefix: u8) -> bool {
    prefix_match(&net, &ip.octets(), prefix)
}

/// Why `ip` may not be the destination of a caller-named fetch, or `None` if
/// it is a publicly routable unicast address.
pub fn forbidden_reason(ip: IpAddr) -> Option<&'static str> {
    match ip {
        IpAddr::V4(v4) => forbidden_v4(v4),
        IpAddr::V6(v6) => forbidden_v6(v6),
    }
}

fn forbidden_v4(ip: Ipv4Addr) -> Option<&'static str> {
    const RANGES: &[([u8; 4], u8, &str)] = &[
        ([0, 0, 0, 0], 8, "the unspecified/this-network range"),
        ([10, 0, 0, 0], 8, "a private (RFC 1918) address"),
        ([100, 64, 0, 0], 10, "a carrier-grade NAT / overlay address"),
        ([127, 0, 0, 0], 8, "a loopback address"),
        (
            [169, 254, 0, 0],
            16,
            "a link-local address (cloud metadata lives here)",
        ),
        ([172, 16, 0, 0], 12, "a private (RFC 1918) address"),
        ([192, 0, 0, 0], 24, "an IETF protocol-assignment address"),
        ([192, 0, 2, 0], 24, "a documentation address"),
        ([192, 88, 99, 0], 24, "a 6to4 relay address"),
        ([192, 168, 0, 0], 16, "a private (RFC 1918) address"),
        ([198, 18, 0, 0], 15, "a benchmarking address"),
        ([198, 51, 100, 0], 24, "a documentation address"),
        ([203, 0, 113, 0], 24, "a documentation address"),
        ([224, 0, 0, 0], 4, "a multicast address"),
        ([240, 0, 0, 0], 4, "a reserved address"),
    ];
    RANGES
        .iter()
        .find(|(net, prefix, _)| v4_in(ip, *net, *prefix))
        .map(|(_, _, reason)| *reason)
}

fn forbidden_v6(ip: Ipv6Addr) -> Option<&'static str> {
    let seg = ip.segments();
    if ip.is_unspecified() {
        return Some("the unspecified address");
    }
    if ip.is_loopback() {
        return Some("a loopback address");
    }
    // IPv4-mapped (::ffff:a.b.c.d) and the deprecated IPv4-compatible
    // (::a.b.c.d) forms both reach the embedded IPv4 destination.
    if seg[0..5] == [0, 0, 0, 0, 0] && (seg[5] == 0xffff || seg[5] == 0) {
        let v4 = Ipv4Addr::new(
            (seg[6] >> 8) as u8,
            seg[6] as u8,
            (seg[7] >> 8) as u8,
            seg[7] as u8,
        );
        return forbidden_v4(v4).or(if seg[5] == 0 {
            Some("an IPv4-compatible address")
        } else {
            None
        });
    }
    // NAT64 well-known prefix 64:ff9b::/96 translates to the embedded IPv4.
    if seg[0..6] == [0x64, 0xff9b, 0, 0, 0, 0] {
        let v4 = Ipv4Addr::new(
            (seg[6] >> 8) as u8,
            seg[6] as u8,
            (seg[7] >> 8) as u8,
            seg[7] as u8,
        );
        return forbidden_v4(v4);
    }
    // 64:ff9b:1::/48, the local-use NAT64 prefix.
    if seg[0] == 0x64 && seg[1] == 0xff9b && seg[2] == 1 {
        return Some("a local-use NAT64 address");
    }
    // 6to4 (2002::/16) carries the relay-side IPv4 in bits 16..48.
    if seg[0] == 0x2002 {
        let v4 = Ipv4Addr::new(
            (seg[1] >> 8) as u8,
            seg[1] as u8,
            (seg[2] >> 8) as u8,
            seg[2] as u8,
        );
        return forbidden_v4(v4);
    }
    // Teredo (2001::/32) tunnels to an obfuscated IPv4; refuse outright.
    if seg[0] == 0x2001 && seg[1] == 0 {
        return Some("a Teredo tunnel address");
    }
    if seg[0] == 0x2001 && seg[1] == 0x0db8 {
        return Some("a documentation address");
    }
    if seg[0] == 0x0100 && seg[1..4] == [0, 0, 0] {
        return Some("a discard-only address");
    }
    if (seg[0] & 0xfe00) == 0xfc00 {
        return Some("a unique-local (ULA) address, which includes cloud metadata endpoints");
    }
    if (seg[0] & 0xffc0) == 0xfe80 {
        return Some("a link-local address");
    }
    if (seg[0] & 0xffc0) == 0xfec0 {
        return Some("a site-local address");
    }
    if (seg[0] & 0xff00) == 0xff00 {
        return Some("a multicast address");
    }
    None
}

/// The address policy: the fixed refusal ranges, opened only where the
/// machine owner signed a grant. Shared by the HTTP client's resolver and by
/// callers that make their own connections (the function host's outgoing
/// requests).
#[derive(Debug, Clone)]
pub struct AddressPolicy {
    grants: Arc<MachineAccessGrants>,
    /// The agent or tool the checked connections are made for, when the
    /// caller knows it; its own grants apply alongside the node's.
    grantee: Option<String>,
}

impl AddressPolicy {
    /// The owner-signed grants this policy consults.
    pub fn grants(&self) -> &Arc<MachineAccessGrants> {
        &self.grants
    }

    /// `Err` with the reason when `ip` may not be connected to. `port` is the
    /// destination port, or 0 when the caller does not know it.
    pub fn check(&self, host: &str, ip: IpAddr, port: u16) -> Result<(), EgressError> {
        let Some(reason) = forbidden_reason(ip) else {
            return Ok(());
        };
        if self
            .grants
            .authorize_network(host, ip, port, self.grantee.as_deref())
            .is_some()
        {
            return Ok(());
        }
        tracing::warn!(
            target: "machine_access",
            host,
            %ip,
            port,
            grantee = ?self.grantee,
            reason,
            "egress refused: no machine-access grant opens this destination"
        );
        Err(EgressError::Forbidden {
            host: host.to_string(),
            ip,
            reason,
        })
    }

    /// Resolve `host` and return its addresses on `port`, refusing the name
    /// if any address it resolves to is forbidden. An IP literal is checked
    /// without a lookup. A `port` of 0 means the caller does not know it.
    pub async fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, EgressError> {
        let bare = host.trim_start_matches('[').trim_end_matches(']');
        if let Ok(ip) = bare.parse::<IpAddr>() {
            self.check(host, ip, port)?;
            return Ok(vec![SocketAddr::new(ip, port)]);
        }
        let addrs: Vec<SocketAddr> = tokio::net::lookup_host((bare, port))
            .await
            .map_err(|e| EgressError::Resolve {
                host: host.to_string(),
                detail: e.to_string(),
            })?
            .collect();
        if addrs.is_empty() {
            return Err(EgressError::Resolve {
                host: host.to_string(),
                detail: "no addresses".to_string(),
            });
        }
        for addr in &addrs {
            self.check(host, addr.ip(), port)?;
        }
        Ok(addrs)
    }
}

/// DNS resolver installed into a guarded client, so the address reqwest
/// connects to is the address that was checked. A client is built for one
/// destination port (0 when it serves every port no grant names), so the
/// check sees the port as well as the address.
struct CheckedResolver {
    policy: Arc<AddressPolicy>,
    port: u16,
}

impl reqwest::dns::Resolve for CheckedResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let policy = self.policy.clone();
        let port = self.port;
        let host = name.as_str().to_string();
        Box::pin(async move {
            let addrs = policy
                .resolve(&host, port)
                .await
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })?;
            let iter: reqwest::dns::Addrs = Box::new(addrs.into_iter());
            Ok(iter)
        })
    }
}

/// The two clients for one grantee and destination port.
#[derive(Clone)]
struct Clients {
    client: reqwest::Client,
    /// Same checks, no total-request timeout, for a response consumed as a
    /// stream (a completion that runs as long as the model generates).
    streaming: reqwest::Client,
}

impl Clients {
    fn build(policy: Arc<AddressPolicy>, port: u16) -> Result<Self, EgressError> {
        let build = |total: Option<Duration>| {
            let mut builder = reqwest::Client::builder()
                .dns_resolver(Arc::new(CheckedResolver {
                    policy: policy.clone(),
                    port,
                }))
                .redirect(reqwest::redirect::Policy::none())
                .no_proxy()
                .connect_timeout(CONNECT_TIMEOUT);
            if let Some(total) = total {
                builder = builder.timeout(total);
            }
            builder
                .build()
                .map_err(|e| EgressError::Config(format!("client construction: {e}")))
        };
        Ok(Self {
            client: build(Some(REQUEST_TIMEOUT))?,
            streaming: build(None)?,
        })
    }
}

/// Clients keyed by grantee and destination port. Only grantees that hold a
/// network grant and ports a grant names get their own; everything else
/// shares the node's port-agnostic pair, so the map is bounded by the grants.
type ClientCache = parking_lot::Mutex<std::collections::HashMap<(Option<String>, u16), Clients>>;

/// A client for outbound fetches to caller-named destinations.
#[derive(Clone)]
pub struct EgressGuard {
    policy: Arc<AddressPolicy>,
    clients: Arc<ClientCache>,
    max_response_bytes: usize,
    /// The agent requests are made for, when [`for_grantee`](Self::for_grantee)
    /// named one: a quarantined agent reaches nothing.
    actor: Option<String>,
    quarantines: Option<Arc<crate::agent_audit::AgentAudit>>,
    /// The node's data directory, from which its hardware sealing key is
    /// derived to open brokered credentials.
    credential_keys: Option<std::path::PathBuf>,
}

impl std::fmt::Debug for EgressGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EgressGuard")
            .field("grants", &self.policy.grants)
            .field("grantee", &self.policy.grantee)
            .field("max_response_bytes", &self.max_response_bytes)
            .finish()
    }
}

impl EgressGuard {
    /// Build a guard from operator configuration and the machine owner's
    /// grants.
    pub fn from_config(
        config: &EgressConfig,
        grants: Arc<MachineAccessGrants>,
    ) -> Result<Self, EgressError> {
        let policy = Arc::new(AddressPolicy {
            grants,
            grantee: None,
        });
        let mut clients = std::collections::HashMap::new();
        clients.insert((None, 0), Clients::build(policy.clone(), 0)?);
        Ok(Self {
            policy,
            clients: Arc::new(parking_lot::Mutex::new(clients)),
            max_response_bytes: config.max_response_bytes.max(1),
            actor: None,
            quarantines: None,
            credential_keys: None,
        })
    }

    /// Open agents' brokered credentials with the sealing key derived from
    /// the hardware keys under `data_dir`.
    pub fn with_credentials(mut self, data_dir: std::path::PathBuf) -> Self {
        self.credential_keys = Some(data_dir);
        self
    }

    /// Attach the brokered credential the agent's terms hold for `request`'s
    /// host, if any.
    async fn attach_credential(
        &self,
        agent: &str,
        request: &mut reqwest::Request,
    ) -> Result<(), EgressError> {
        let (Some(data_dir), Some(quarantines)) = (&self.credential_keys, &self.quarantines) else {
            return Ok(());
        };
        let Some(chain) = quarantines.chain() else {
            return Ok(());
        };
        let Some(stored) = tenzro_vm::native::read_agent_terms(&chain, agent) else {
            return Ok(());
        };
        let machine = crate::identity_bootstrap::machine_did().unwrap_or_default();
        let Some((credential, sealed)) =
            select_credential(&stored.terms, request.url(), request.headers(), &machine)?
        else {
            return Ok(());
        };
        let data_dir = data_dir.clone();
        let sealed = sealed.clone();
        let secret = tokio::task::spawn_blocking(move || {
            let recipient = crate::keygen::NodeKeys::open(&data_dir)
                .and_then(|k| k.machine_sealing())
                .map_err(|e| EgressError::Credential(e.to_string()))?;
            open_credential(&recipient, &sealed)
        })
        .await
        .map_err(|e| EgressError::Credential(e.to_string()))??;
        let _host = request
            .url()
            .host_str()
            .unwrap_or_default()
            .to_ascii_lowercase();
        let name = reqwest::header::HeaderName::from_bytes(credential.header.as_bytes())
            .map_err(|e| EgressError::Credential(e.to_string()))?;
        request.headers_mut().insert(name, secret);
        Ok(())
    }

    /// Refuse every request made for an agent chain state quarantines.
    pub fn with_quarantines(mut self, quarantines: Arc<crate::agent_audit::AgentAudit>) -> Self {
        self.quarantines = Some(quarantines);
        self
    }

    /// Check `raw` for a request, refusing every destination to an agent
    /// chain state quarantines.
    fn checked(&self, raw: &str, scheme: Scheme) -> Result<url::Url, EgressError> {
        match (&self.actor, &self.quarantines) {
            (Some(actor), Some(q)) if q.is_quarantined(actor) => {
                Err(EgressError::Quarantined(actor.clone()))
            }
            _ => self.check_url(raw, scheme),
        }
    }

    /// This guard as it applies to requests made for `did`: the grants the
    /// machine owner made out to that agent or tool apply alongside the
    /// node's. Without a DID, or for a DID holding no network grant, it is
    /// the node's guard.
    pub fn for_grantee(&self, did: Option<&str>) -> EgressGuard {
        let mut guard = match did {
            Some(did) if self.policy.grants.has_network_grant_for(did) => EgressGuard {
                policy: Arc::new(AddressPolicy {
                    grants: self.policy.grants.clone(),
                    grantee: Some(did.to_string()),
                }),
                clients: self.clients.clone(),
                max_response_bytes: self.max_response_bytes,
                actor: None,
                quarantines: self.quarantines.clone(),
                credential_keys: self.credential_keys.clone(),
            },
            _ => self.clone(),
        };
        guard.actor = did.map(str::to_string);
        guard
    }

    /// The clients that connect to `url`: built for its port when a grant
    /// covering this guard's grantee names that port, otherwise the
    /// port-agnostic pair, whose checks never match a port-limited grant.
    fn clients_for(&self, url: &url::Url) -> Result<Clients, EgressError> {
        let grantee = self.policy.grantee.clone();
        let port = url
            .port_or_known_default()
            .filter(|p| self.policy.grants.names_port(*p, grantee.as_deref()))
            .unwrap_or(0);
        let mut clients = self.clients.lock();
        if let Some(found) = clients.get(&(grantee.clone(), port)) {
            return Ok(found.clone());
        }
        let built = Clients::build(self.policy.clone(), port)?;
        clients.insert((grantee, port), built.clone());
        Ok(built)
    }

    /// `POST` to a checked URL whose response the caller reads itself, as a
    /// stream or with its own size handling. The destination is checked
    /// exactly as for [`post`](Self::post); only the byte cap and the total
    /// timeout are left to the caller (set one per request with
    /// [`reqwest::RequestBuilder::timeout`] when the response is buffered).
    pub fn post_streaming(&self, raw: &str) -> Result<reqwest::RequestBuilder, EgressError> {
        let url = self.checked(raw, Scheme::HttpOrHttps)?;
        Ok(self.clients_for(&url)?.streaming.post(url))
    }

    /// The address policy, for callers that open their own connections.
    pub fn address_policy(&self) -> &Arc<AddressPolicy> {
        &self.policy
    }

    /// The configured response-body cap.
    pub fn max_response_bytes(&self) -> usize {
        self.max_response_bytes
    }

    /// Parse and pre-check `raw`: scheme, presence of a host, and an IP-literal
    /// host against the address policy. A hostname is checked when the request
    /// resolves it.
    pub fn check_url(&self, raw: &str, scheme: Scheme) -> Result<url::Url, EgressError> {
        let url = url::Url::parse(raw).map_err(|e| EgressError::InvalidUrl(e.to_string()))?;
        match (url.scheme(), scheme) {
            ("https", _) | ("http", Scheme::HttpOrHttps) => {}
            (other, _) => return Err(EgressError::Scheme(other.to_string())),
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(EgressError::InvalidUrl(
                "credentials in the URL are not accepted".to_string(),
            ));
        }
        let port = url.port_or_known_default().unwrap_or(0);
        match url.host() {
            Some(url::Host::Ipv4(ip)) => self.policy.check(raw, IpAddr::V4(ip), port)?,
            Some(url::Host::Ipv6(ip)) => self.policy.check(raw, IpAddr::V6(ip), port)?,
            Some(url::Host::Domain(d)) if !d.is_empty() => {}
            _ => return Err(EgressError::InvalidUrl("URL has no host".to_string())),
        }
        Ok(url)
    }

    /// Check `raw` completely, including resolving a hostname, without sending
    /// anything. Used where a URL is accepted now and fetched later (a
    /// webhook registration), so a bad destination is refused at the door.
    /// The fetch itself is checked again when it happens.
    pub async fn check_destination(
        &self,
        raw: &str,
        scheme: Scheme,
    ) -> Result<url::Url, EgressError> {
        let url = self.check_url(raw, scheme)?;
        if let Some(url::Host::Domain(d)) = url.host() {
            let port = url.port_or_known_default().unwrap_or(443);
            self.policy.resolve(d, port).await?;
        }
        Ok(url)
    }

    /// The guarded client for a protocol client that builds its own requests
    /// under the base URL `raw`, which is checked here. The client's resolver
    /// checks every address it connects to, on the base URL's port, and it
    /// follows no redirects.
    pub fn client_for(&self, raw: &str, scheme: Scheme) -> Result<reqwest::Client, EgressError> {
        let url = self.checked(raw, scheme)?;
        Ok(self.clients_for(&url)?.client)
    }

    /// A request builder for `method` on a checked `raw` URL.
    pub fn request(
        &self,
        method: reqwest::Method,
        raw: &str,
        scheme: Scheme,
    ) -> Result<reqwest::RequestBuilder, EgressError> {
        let url = self.checked(raw, scheme)?;
        Ok(self.clients_for(&url)?.client.request(method, url))
    }

    /// `POST` to a checked URL.
    pub fn post(&self, raw: &str, scheme: Scheme) -> Result<reqwest::RequestBuilder, EgressError> {
        self.request(reqwest::Method::POST, raw, scheme)
    }

    /// `GET` from a checked URL.
    pub fn get(&self, raw: &str, scheme: Scheme) -> Result<reqwest::RequestBuilder, EgressError> {
        self.request(reqwest::Method::GET, raw, scheme)
    }

    /// `POST` a JSON body to a caller-named endpoint and parse the JSON reply,
    /// within the byte cap. A non-2xx status is an error carrying the status.
    pub async fn post_json(
        &self,
        raw: &str,
        body: &serde_json::Value,
    ) -> Result<serde_json::Value, EgressError> {
        let response = self
            .send(self.post(raw, Scheme::HttpOrHttps)?.json(body))
            .await?;
        if !response.status().is_success() {
            return Err(EgressError::Http(format!("HTTP {}", response.status())));
        }
        response.json().await
    }

    /// Send a request built by [`request`](Self::request) (or its
    /// shorthands). The final URL is checked again, so a builder cannot be
    /// re-pointed between construction and send.
    pub async fn send(
        &self,
        builder: reqwest::RequestBuilder,
    ) -> Result<GuardedResponse, EgressError> {
        let mut request = builder
            .build()
            .map_err(|e| EgressError::InvalidUrl(e.to_string()))?;
        self.check_url(request.url().as_str(), Scheme::HttpOrHttps)?;
        if let Some(agent) = &self.actor {
            self.attach_credential(agent, &mut request).await?;
        }
        let request = match &self.actor {
            Some(agent) => {
                let chain = self.quarantines.as_ref().and_then(|a| a.chain());
                crate::agent_http_signature::sign_for_agent(chain, agent, request)
                    .await
                    .map_err(|e| {
                        EgressError::Http(format!("could not sign the agent's request: {e}"))
                    })?
            }
            None => request,
        };
        let clients = self.clients_for(request.url())?;
        let sent = request
            .body()
            .and_then(reqwest::Body::as_bytes)
            .map_or(0, |b| b.len() as u64);
        let response = clients
            .client
            .execute(request)
            .await
            .map_err(|e| EgressError::Http(describe_reqwest_error(&e)))?;
        let meter = self.meter_for(&response);
        if let Some(meter) = &meter {
            meter.charge(sent)?;
        }
        Ok(GuardedResponse {
            inner: response,
            limit: self.max_response_bytes,
            meter,
        })
    }

    /// The grant a response's connection went through, when it reached a
    /// refused range: the bytes read from it are counted against that grant.
    fn meter_for(&self, response: &reqwest::Response) -> Option<GrantMeter> {
        let addr = response.remote_addr()?;
        forbidden_reason(addr.ip())?;
        let grant_id =
            self.policy
                .grants
                .grant_for(addr.ip(), addr.port(), self.policy.grantee.as_deref())?;
        Some(GrantMeter {
            grants: self.policy.grants.clone(),
            grant_id,
        })
    }
}

/// The credential `terms` hold for a request to `url`, and its envelope for
/// `machine`: `None` when no credential names the host. A request that sets
/// the credential's header itself, goes over plain HTTP, or reaches a node
/// the credential is not sealed to is refused.
fn select_credential<'a>(
    terms: &'a tenzro_types::agent_terms::AgentTerms,
    url: &url::Url,
    headers: &reqwest::header::HeaderMap,
    machine: &str,
) -> Result<
    Option<(
        &'a tenzro_types::agent_terms::BrokeredCredential,
        &'a tenzro_types::agent_terms::SealedForNode,
    )>,
    EgressError,
> {
    let refuse = EgressError::Credential;
    let host = url.host_str().unwrap_or_default().to_ascii_lowercase();
    let Some(credential) = terms.credentials.iter().find(|c| c.host == host) else {
        return Ok(None);
    };
    if headers.contains_key(credential.header.as_str()) {
        return Err(refuse(format!(
            "the agent may not set {}, the header credential {} is attached as",
            credential.header, credential.name
        )));
    }
    if url.scheme() != "https" {
        return Err(refuse(format!(
            "credential {} is attached only over https",
            credential.name
        )));
    }
    let sealed = credential
        .sealed
        .iter()
        .find(|s| s.machine_did == machine)
        .ok_or_else(|| {
            refuse(format!(
                "credential {} is not sealed to this node",
                credential.name
            ))
        })?;
    Ok(Some((credential, sealed)))
}

/// Open a sealed credential with `recipient` into a header value marked
/// sensitive, so it is never logged.
fn open_credential(
    recipient: &dyn tenzro_crypto::hybrid_seal::HybridRecipient,
    sealed: &tenzro_types::agent_terms::SealedForNode,
) -> Result<reqwest::header::HeaderValue, EgressError> {
    let refuse = EgressError::Credential;
    let envelope: tenzro_crypto::encryption::EncryptedEnvelope =
        serde_json::from_str(&sealed.envelope).map_err(|e| refuse(format!("the envelope: {e}")))?;
    let secret = zeroize::Zeroizing::new(
        tenzro_crypto::encryption::envelope_decrypt(recipient, &envelope)
            .map_err(|e| refuse(format!("the credential does not open on this node: {e}")))?,
    );
    let mut value = reqwest::header::HeaderValue::from_bytes(&secret)
        .map_err(|_| refuse("not a header value".into()))?;
    value.set_sensitive(true);
    Ok(value)
}

/// Counts the bytes of one response against the grant that opened its
/// destination.
#[derive(Debug)]
struct GrantMeter {
    grants: Arc<MachineAccessGrants>,
    grant_id: String,
}

impl GrantMeter {
    fn charge(&self, bytes: u64) -> Result<(), EgressError> {
        if self.grants.charge_bytes(&self.grant_id, bytes) {
            Ok(())
        } else {
            Err(EgressError::AllowanceSpent {
                grant_id: self.grant_id.clone(),
            })
        }
    }
}

/// reqwest wraps the resolver's error; surface the guard's refusal text
/// rather than a generic "error sending request".
fn describe_reqwest_error(e: &reqwest::Error) -> String {
    let mut out = e.to_string();
    let mut source = std::error::Error::source(e);
    while let Some(s) = source {
        out.push_str(": ");
        out.push_str(&s.to_string());
        source = s.source();
    }
    out
}

/// A response whose body can only be read up to the guard's byte cap.
#[derive(Debug)]
pub struct GuardedResponse {
    inner: reqwest::Response,
    limit: usize,
    meter: Option<GrantMeter>,
}

impl GuardedResponse {
    pub fn status(&self) -> reqwest::StatusCode {
        self.inner.status()
    }

    pub fn headers(&self) -> &reqwest::header::HeaderMap {
        self.inner.headers()
    }

    /// Lower the byte cap for this response.
    pub fn with_limit(mut self, limit: usize) -> Self {
        self.limit = self.limit.min(limit);
        self
    }

    /// The body, refused once it passes the cap. A declared
    /// `Content-Length` over the cap is refused before reading anything.
    pub async fn bytes(self) -> Result<Bytes, EgressError> {
        let limit = self.limit;
        if let Some(len) = self.inner.content_length()
            && len > limit as u64
        {
            return Err(EgressError::TooLarge { limit });
        }
        let meter = self.meter;
        let mut stream = self.inner.bytes_stream();
        let mut buf = BytesMut::new();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|e| EgressError::Http(describe_reqwest_error(&e)))?;
            if buf.len() + chunk.len() > limit {
                return Err(EgressError::TooLarge { limit });
            }
            if let Some(meter) = &meter {
                meter.charge(chunk.len() as u64)?;
            }
            buf.extend_from_slice(&chunk);
        }
        Ok(buf.freeze())
    }

    /// At most the first `limit` bytes of the body (never more than the cap),
    /// and whether anything was left unread. Reading stops at the limit, so
    /// an endless body costs no more than `limit` bytes.
    pub async fn prefix(self) -> Result<(Bytes, bool), EgressError> {
        let limit = self.limit;
        let meter = self.meter;
        let mut stream = self.inner.bytes_stream();
        let mut buf = BytesMut::new();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|e| EgressError::Http(describe_reqwest_error(&e)))?;
            let room = limit - buf.len();
            let taken = chunk.len().min(room);
            if let Some(meter) = &meter {
                meter.charge(taken as u64)?;
            }
            if chunk.len() > room {
                buf.extend_from_slice(&chunk[..room]);
                return Ok((buf.freeze(), true));
            }
            buf.extend_from_slice(&chunk);
        }
        Ok((buf.freeze(), false))
    }

    /// The body parsed as JSON, within the cap.
    pub async fn json<T: serde::de::DeserializeOwned>(self) -> Result<T, EgressError> {
        let body = self.bytes().await?;
        serde_json::from_slice(&body).map_err(|e| EgressError::Http(format!("invalid JSON: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_identity::MachineResource;

    /// Terms holding one credential for `api.example.org`, sealed to the
    /// serving node `machine` under `key`.
    fn credential_terms(
        key: &tenzro_crypto::hybrid_seal::HybridSecretKey,
        machine: &str,
    ) -> tenzro_types::agent_terms::AgentTerms {
        use tenzro_types::agent_terms::{
            AgentTerms, BrokeredCredential, SealedForNode, ServingNode,
        };
        let envelope =
            tenzro_crypto::encryption::envelope_encrypt(key.public(), b"Bearer sk-live-secret")
                .unwrap();
        AgentTerms {
            controller_did: "did:tenzro:human:c".into(),
            agent_name: "a".into(),
            delegation_scope: Default::default(),
            capabilities: Vec::new(),
            serving_nodes: vec![ServingNode {
                machine_did: machine.into(),
                sealing_public_key: hex::encode(key.public().encode()),
                ..Default::default()
            }],
            min_distinct_operators: 1,
            expires_at_ms: None,
            trifecta_exception: false,
            auto_approve: None,
            credentials: vec![BrokeredCredential {
                name: "search".into(),
                host: "api.example.org".into(),
                header: "authorization".into(),
                sealed: vec![SealedForNode {
                    machine_did: machine.into(),
                    envelope: serde_json::to_string(&envelope).unwrap(),
                }],
            }],
        }
    }

    #[test]
    fn a_brokered_credential_is_attached_only_where_its_terms_say() {
        let key = tenzro_crypto::hybrid_seal::HybridSecretKey::generate();
        let terms = credential_terms(&key, "did:tenzro:machine:m");
        let none = reqwest::header::HeaderMap::new();
        let url = |u: &str| url::Url::parse(u).unwrap();
        let (cred, sealed) = select_credential(
            &terms,
            &url("https://api.example.org/v1/q"),
            &none,
            "did:tenzro:machine:m",
        )
        .unwrap()
        .unwrap();
        assert_eq!(cred.name, "search");
        let value = open_credential(&key, sealed).unwrap();
        assert_eq!(value.as_bytes(), b"Bearer sk-live-secret");
        assert!(value.is_sensitive(), "the secret is never logged");
        // Another host carries nothing.
        assert!(
            select_credential(
                &terms,
                &url("https://other.example.org/"),
                &none,
                "did:tenzro:machine:m"
            )
            .unwrap()
            .is_none()
        );
        // Plain HTTP, a header the agent set itself, and a node it is not sealed to are refused.
        assert!(
            select_credential(
                &terms,
                &url("http://api.example.org/"),
                &none,
                "did:tenzro:machine:m"
            )
            .is_err()
        );
        let mut set = reqwest::header::HeaderMap::new();
        set.insert("authorization", "Bearer mine".parse().unwrap());
        assert!(
            select_credential(
                &terms,
                &url("https://api.example.org/"),
                &set,
                "did:tenzro:machine:m"
            )
            .is_err()
        );
        assert!(
            select_credential(
                &terms,
                &url("https://api.example.org/"),
                &none,
                "did:tenzro:machine:x"
            )
            .is_err()
        );
        // Another node's key does not open it.
        let other = tenzro_crypto::hybrid_seal::HybridSecretKey::generate();
        assert!(open_credential(&other, sealed).is_err());
    }

    #[test]
    fn terms_with_a_credential_validate_against_their_serving_nodes() {
        let key = tenzro_crypto::hybrid_seal::HybridSecretKey::generate();
        let terms = credential_terms(&key, "did:tenzro:machine:m");
        terms.credentials[0].validate(&terms.serving_nodes).unwrap();
        let mut stray = terms.clone();
        stray.credentials[0].sealed[0].machine_did = "did:tenzro:machine:elsewhere".into();
        assert!(
            stray.credentials[0].validate(&stray.serving_nodes).is_err(),
            "sealed to a node that does not serve"
        );
        let mut host = terms.clone();
        host.credentials[0].header = "host".into();
        assert!(
            host.credentials[0].validate(&host.serving_nodes).is_err(),
            "a reserved header"
        );
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn refuses_every_internal_ipv4_range() {
        for a in [
            "127.0.0.1",
            "127.255.255.254",
            "10.1.2.3",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "169.254.169.254",
            "100.100.100.200",
            "100.64.0.1",
            "0.0.0.0",
            "224.0.0.1",
            "255.255.255.255",
            "198.18.0.1",
        ] {
            assert!(forbidden_reason(ip(a)).is_some(), "{a} must be refused");
        }
    }

    #[test]
    fn refuses_every_internal_ipv6_range_and_embedded_ipv4() {
        for a in [
            "::1",
            "::",
            "fe80::1",
            "fd00:ec2::254",
            "fc00::1",
            "ff02::1",
            "::ffff:127.0.0.1",
            "::ffff:169.254.169.254",
            "::ffff:10.0.0.1",
            "::127.0.0.1",
            "64:ff9b::a9fe:a9fe",
            "2002:7f00:0001::1",
            "2001:0:4136:e378:8000:63bf:3fff:fdd2",
            "2001:db8::1",
            "fec0::1",
        ] {
            assert!(forbidden_reason(ip(a)).is_some(), "{a} must be refused");
        }
    }

    #[test]
    fn public_addresses_pass() {
        for a in [
            "1.1.1.1",
            "8.8.8.8",
            "172.32.0.1",
            "100.128.0.1",
            "2606:4700:4700::1111",
            "::ffff:8.8.8.8",
            "64:ff9b::808:808",
        ] {
            assert!(forbidden_reason(ip(a)).is_none(), "{a} must be allowed");
        }
    }

    /// A guard with no grants: every refused range stays refused.
    fn ungranted() -> EgressGuard {
        EgressGuard::from_config(
            &EgressConfig::default(),
            Arc::new(MachineAccessGrants::new(None)),
        )
        .unwrap()
    }

    /// A guard whose node holds one owner grant for `resources`.
    fn granted(resources: Vec<MachineResource>, max: usize) -> (EgressGuard, String) {
        let (grants, id) = MachineAccessGrants::with_node_grant_for_test(
            resources,
            &[crate::machine_access::OP_CONNECT],
            chrono::Duration::hours(1),
            None,
        );
        let guard = EgressGuard::from_config(
            &EgressConfig {
                max_response_bytes: max,
            },
            grants,
        )
        .unwrap();
        (guard, id)
    }

    #[test]
    fn an_owner_grant_admits_only_its_range_and_port() {
        let (guard, _) = granted(
            vec![MachineResource::Network {
                cidr: "10.20.0.0/16".into(),
                port: Some(443),
            }],
            1024,
        );
        let policy = guard.address_policy();
        assert!(policy.check("h", ip("10.20.5.5"), 443).is_ok());
        assert!(policy.check("h", ip("10.20.5.5"), 80).is_err());
        assert!(policy.check("h", ip("10.21.0.1"), 443).is_err());
        assert!(policy.check("h", ip("127.0.0.1"), 443).is_err());
        assert!(
            guard
                .check_url("https://10.20.5.5/", Scheme::HttpsOnly)
                .is_ok()
        );
        assert!(
            guard
                .check_url("http://10.20.5.5/", Scheme::HttpOrHttps)
                .is_err()
        );
        assert!(
            guard
                .check_url("https://10.20.5.5:8443/", Scheme::HttpsOnly)
                .is_err()
        );
        // Public destinations need no grant.
        assert!(policy.check("h", ip("8.8.8.8"), 0).is_ok());
    }

    #[test]
    fn a_revoked_grant_closes_the_range_on_the_next_check() {
        let (guard, id) = granted(
            vec![MachineResource::Network {
                cidr: "127.0.0.1/32".into(),
                port: None,
            }],
            1024,
        );
        assert!(
            guard
                .check_url("http://127.0.0.1:9/", Scheme::HttpOrHttps)
                .is_ok()
        );
        guard.address_policy().grants().revoke(&id);
        assert!(
            guard
                .check_url("http://127.0.0.1:9/", Scheme::HttpOrHttps)
                .is_err()
        );
    }

    /// A guard for node [`crate::machine_access::TEST_NODE_DID`] holding one
    /// grant to `grantee` with the given limits.
    fn guard_with(
        grantee: &str,
        resources: Vec<MachineResource>,
        max_bytes: Option<u64>,
    ) -> EgressGuard {
        let grants = Arc::new(MachineAccessGrants::new(Some(
            crate::machine_access::TEST_NODE_DID.to_string(),
        )));
        grants.grant_with_limits_for_test(
            grantee,
            resources,
            &[crate::machine_access::OP_CONNECT],
            chrono::Duration::hours(1),
            None,
            max_bytes,
        );
        EgressGuard::from_config(&EgressConfig::default(), grants).unwrap()
    }

    fn loopback_on(port: Option<u16>) -> Vec<MachineResource> {
        ["127.0.0.1/32", "::1/128"]
            .into_iter()
            .map(|cidr| MachineResource::Network {
                cidr: cidr.into(),
                port,
            })
            .collect()
    }

    #[tokio::test]
    async fn a_port_limited_grant_applies_to_a_host_name_on_that_port_only() {
        let port = serve_once("200 OK", "", b"ok".to_vec()).await;
        let other = serve_once("200 OK", "", b"no".to_vec()).await;
        let guard = guard_with(
            crate::machine_access::TEST_NODE_DID,
            loopback_on(Some(port)),
            None,
        );
        let resp = guard
            .send(
                guard
                    .get(&format!("http://localhost:{port}/"), Scheme::HttpOrHttps)
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.bytes().await.unwrap().as_ref(), b"ok");
        let err = guard
            .send(
                guard
                    .get(&format!("http://localhost:{other}/"), Scheme::HttpOrHttps)
                    .unwrap(),
            )
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("loopback"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn an_agents_grant_opens_only_that_agents_requests() {
        let agent = "did:tenzro:machine:agent";
        let guard = guard_with(agent, loopback_on(None), None);
        let url = "http://127.0.0.1:9/";
        assert!(guard.check_url(url, Scheme::HttpOrHttps).is_err());
        assert!(
            guard
                .for_grantee(None)
                .check_url(url, Scheme::HttpOrHttps)
                .is_err()
        );
        assert!(
            guard
                .for_grantee(Some("did:tenzro:machine:other"))
                .check_url(url, Scheme::HttpOrHttps)
                .is_err()
        );
        assert!(
            guard
                .for_grantee(Some(agent))
                .check_url(url, Scheme::HttpOrHttps)
                .is_ok()
        );
    }

    #[tokio::test]
    async fn a_byte_allowance_stops_the_read_and_closes_the_grant() {
        let port = serve_once("200 OK", "", vec![b'x'; 4096]).await;
        let guard = guard_with(
            crate::machine_access::TEST_NODE_DID,
            loopback_on(None),
            Some(1000),
        );
        let url = format!("http://127.0.0.1:{port}/");
        let resp = guard
            .send(guard.get(&url, Scheme::HttpOrHttps).unwrap())
            .await
            .unwrap();
        let err = resp.bytes().await.unwrap_err();
        assert!(
            matches!(err, EgressError::AllowanceSpent { .. }),
            "unexpected error: {err}"
        );
        assert!(guard.check_url(&url, Scheme::HttpOrHttps).is_err());
    }

    #[test]
    fn url_literals_and_schemes_are_checked_before_any_request() {
        let guard = ungranted();
        for bad in [
            "http://127.0.0.1:8545/",
            "http://[::1]/",
            "http://169.254.169.254/latest/meta-data/",
            "http://[::ffff:a9fe:a9fe]/",
            "http://0x7f.1/",
            "http://2130706433/",
            "file:///etc/passwd",
            "gopher://example.com/",
            "http://user:pw@example.com/",
        ] {
            assert!(
                guard.check_url(bad, Scheme::HttpOrHttps).is_err(),
                "{bad} must be refused"
            );
        }
        assert!(
            guard
                .check_url("http://example.com/", Scheme::HttpsOnly)
                .is_err()
        );
        assert!(
            guard
                .check_url("https://example.com/x", Scheme::HttpsOnly)
                .is_ok()
        );
    }

    #[tokio::test]
    async fn a_name_resolving_to_loopback_is_refused_at_connect() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let guard = ungranted();
        // `localhost` is a name, not a literal, so this exercises the
        // resolver path rather than the URL check.
        let url = format!("http://localhost:{port}/");
        let err = guard
            .send(guard.get(&url, Scheme::HttpOrHttps).unwrap())
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("loopback"),
            "unexpected error: {err}"
        );
    }

    async fn serve_once(status: &'static str, extra: &'static str, body: Vec<u8>) -> u16 {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                let mut buf = [0u8; 4096];
                let _ = sock.read(&mut buf).await;
                let head = format!(
                    "HTTP/1.1 {status}\r\n{extra}Content-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = sock.write_all(head.as_bytes()).await;
                let _ = sock.write_all(&body).await;
            }
        });
        port
    }

    fn loopback_allowed(max: usize) -> EgressGuard {
        granted(
            vec![MachineResource::Network {
                cidr: "127.0.0.1/32".into(),
                port: None,
            }],
            max,
        )
        .0
    }

    #[tokio::test]
    async fn redirects_are_returned_not_followed() {
        let port = serve_once(
            "302 Found",
            "Location: http://169.254.169.254/latest/meta-data/\r\n",
            Vec::new(),
        )
        .await;
        let guard = loopback_allowed(1024);
        let resp = guard
            .send(
                guard
                    .get(&format!("http://127.0.0.1:{port}/"), Scheme::HttpOrHttps)
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 302);
    }

    #[tokio::test]
    async fn an_oversized_body_is_refused() {
        let port = serve_once("200 OK", "", vec![b'x'; 4096]).await;
        let guard = loopback_allowed(1024);
        let resp = guard
            .send(
                guard
                    .get(&format!("http://127.0.0.1:{port}/"), Scheme::HttpOrHttps)
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(matches!(
            resp.bytes().await,
            Err(EgressError::TooLarge { limit: 1024 })
        ));
    }

    #[tokio::test]
    async fn a_body_within_the_cap_is_returned() {
        let port = serve_once("200 OK", "", b"{\"ok\":true}".to_vec()).await;
        let guard = loopback_allowed(1024);
        let resp = guard
            .send(
                guard
                    .get(&format!("http://127.0.0.1:{port}/"), Scheme::HttpOrHttps)
                    .unwrap(),
            )
            .await
            .unwrap();
        let v: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(v["ok"], true);
    }

    #[tokio::test]
    async fn a_streaming_post_is_checked_like_any_other() {
        let guard = ungranted();
        for raw in [
            "http://127.0.0.1:8545/",
            "http://169.254.169.254/latest/meta-data/",
            "http://[::1]/",
            "file:///etc/passwd",
        ] {
            assert!(guard.post_streaming(raw).is_err(), "{raw}");
        }
        let port = serve_once("200 OK", "", b"ok".to_vec()).await;
        let request = guard
            .post_streaming(&format!("http://localhost:{port}/"))
            .unwrap();
        assert!(request.send().await.is_err());

        let allowed = loopback_allowed(1024);
        let request = allowed
            .post_streaming(&format!("http://127.0.0.1:{port}/"))
            .unwrap();
        let resp = request.send().await.unwrap();
        assert_eq!(resp.status().as_u16(), 200);
    }

    #[tokio::test]
    async fn a_prefix_read_stops_at_the_limit() {
        let port = serve_once("200 OK", "", vec![b'x'; 4096]).await;
        let guard = loopback_allowed(1_000_000);
        let resp = guard
            .send(
                guard
                    .get(&format!("http://127.0.0.1:{port}/"), Scheme::HttpOrHttps)
                    .unwrap(),
            )
            .await
            .unwrap()
            .with_limit(100);
        let (body, truncated) = resp.prefix().await.unwrap();
        assert_eq!(body.len(), 100);
        assert!(truncated);

        let port = serve_once("200 OK", "", b"short".to_vec()).await;
        let resp = guard
            .send(
                guard
                    .get(&format!("http://127.0.0.1:{port}/"), Scheme::HttpOrHttps)
                    .unwrap(),
            )
            .await
            .unwrap()
            .with_limit(100);
        let (body, truncated) = resp.prefix().await.unwrap();
        assert_eq!(&body[..], b"short");
        assert!(!truncated);
    }
}
