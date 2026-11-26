//! Reaching nodes by machine identity over iroh.
//!
//! [`IdentityTransport`] holds what a node needs to be found and to find
//! others by identity: its [`DiscoveryStore`], the relays it admitted by
//! their operators' records, the relay it serves itself when it runs the
//! role, and the boot identities it joins through. Once the node's endpoint
//! is bound, [`IdentityTransport::run`] keeps the node's own
//! [`EndpointRecord`] signed and published to the peers it knows, and pulls
//! their records in return, so knowing one Tenzro node is enough to come to
//! know the rest.
//!
//! No relay, discovery service or peer is built in, and nothing outside the
//! Tenzro network is consulted: relays come from the boot list and the
//! operator's own relay role, each admitted only after its operator's record
//! verifies, and records travel only between Tenzro nodes.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use iroh::endpoint::{Builder, presets};
use iroh::{Endpoint, EndpointAddr, EndpointId, RelayConfig, RelayMap, RelayMode, RelayUrl};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use tenzro_device_key::HardwareSigner;
use url::Url;

use crate::connection_limits::ConnectionLimits;
use crate::discovery::{DiscoveryRequest, DiscoveryResponse, DiscoveryStore, ask};
use crate::error::{IrohError, IrohResult};
use crate::identity_gate::IdentityGate;
use crate::identity_record::{BootIdentity, EndpointKey, EndpointRecord, RecordScope, RelayRef};
use crate::reachability::{self, Connectivity, Observations};
use crate::relay::{RelayCheck, RelayServer, check_relay, fetch_relay_record, now_ms};

/// How long a boot relay that has not signed or served its record yet is
/// waited for: nodes of a network start in no particular order, and one that
/// starts first must still admit the relays that come up just after it.
const RELAY_ADMISSION_WAIT: Duration = Duration::from_secs(60);

/// How far ahead of the clock a saved record sequence may lie and still be
/// followed: about a century.
const SEQUENCE_CEILING_AHEAD_MS: u64 = 100 * 365 * 24 * 3_600 * 1_000;

/// Flushes the directory that holds `path`, so a rename into it survives a
/// power loss. Directories are opened for this on Unix only; elsewhere the
/// file system orders the rename after the file's own flush.
fn sync_parent(path: &std::path::Path) -> std::io::Result<()> {
    #[cfg(unix)]
    if let Some(parent) = path.parent() {
        std::fs::File::open(parent)?.sync_all()?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

/// [`fetch_relay_record`], retried with backoff while the relay is
/// unreachable or has no record yet. A record that fails its checks is
/// refused at once.
async fn fetch_relay_record_patiently(url: &Url) -> IrohResult<EndpointRecord> {
    let deadline = tokio::time::Instant::now() + RELAY_ADMISSION_WAIT;
    let mut backoff = Duration::from_millis(500);
    loop {
        match fetch_relay_record(url).await {
            Err(e @ (IrohError::NotFound(_) | IrohError::Backend(_)))
                if tokio::time::Instant::now() + backoff < deadline =>
            {
                tracing::debug!(relay = %url, error = %e, "relay record not available yet; retrying");
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_secs(8));
            }
            other => return other,
        }
    }
}

/// The relay role: where the relay listener binds, and the URL the operator
/// publishes for it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayRoleConfig {
    /// Address the relay's HTTP listener binds. Reaching it from outside,
    /// and terminating TLS for `public_url`, is the operator's choice.
    pub bind_addr: SocketAddr,
    /// The URL peers reach the relay at, announced in this machine's signed
    /// record.
    pub public_url: Url,
}

/// How often the record loop runs.
const TICK: Duration = Duration::from_secs(60);

/// How often the record loop runs while a relay the node waits for has not
/// answered but another is in use.
const RELAY_RETRY: Duration = Duration::from_secs(20);

/// Most relays a node takes on from other validators' records.
pub const MAX_LEARNED_RELAYS: usize = 4;

/// Most relay URLs one dialed address carries.
const MAX_DIAL_RELAYS: usize = 4;

/// Most direct addresses one dialed address carries.
const MAX_DIAL_DIRECT: usize = 4;

/// What every address this process dials is given beside what its record
/// names: the relays in use (a peer whose relay failed moved to another one,
/// and its record may not say so yet) and the direct addresses its path last
/// used or the operator fixed.
#[derive(Default)]
struct DialHints {
    relays: Vec<Url>,
    direct: std::collections::HashMap<EndpointId, Vec<SocketAddr>>,
    fixed: std::collections::BTreeMap<String, Vec<SocketAddr>>,
    version: u64,
}

struct SharedHints(std::sync::RwLock<DialHints>);

fn dial_hints() -> &'static SharedHints {
    static HINTS: std::sync::OnceLock<SharedHints> = std::sync::OnceLock::new();
    HINTS.get_or_init(|| SharedHints(std::sync::RwLock::new(DialHints::default())))
}

impl SharedHints {
    fn read(&self) -> std::sync::RwLockReadGuard<'_, DialHints> {
        self.0.read().unwrap_or_else(|e| e.into_inner())
    }

    fn write(&self) -> std::sync::RwLockWriteGuard<'_, DialHints> {
        self.0.write().unwrap_or_else(|e| e.into_inner())
    }

    fn add_to(&self, addr: &mut EndpointAddr, did: &str) {
        add_relays(addr, &self.read().relays);
        self.add_direct_to(addr, did);
    }

    fn add_direct_to(&self, addr: &mut EndpointAddr, did: &str) {
        let h = self.read();
        let fixed = h.fixed.get(did).into_iter().flatten();
        let direct = h.direct.get(&addr.id).into_iter().flatten();
        for sa in fixed
            .chain(direct)
            .take(MAX_DIAL_DIRECT)
            .copied()
            .collect::<Vec<_>>()
        {
            *addr = addr.clone().with_ip_addr(sa);
        }
    }

    fn add_relays(&self, urls: &[Url]) {
        let mut h = self.write();
        for url in urls {
            if !h.relays.contains(url) {
                h.relays.push(url.clone());
            }
        }
    }

    fn set_fixed(&self, fixed: std::collections::BTreeMap<String, Vec<SocketAddr>>) {
        self.write().fixed = fixed;
    }

    fn set_direct(&self, id: EndpointId, mut addrs: Vec<SocketAddr>) {
        addrs.truncate(MAX_DIAL_DIRECT);
        let mut h = self.write();
        if h.direct.get(&id) != Some(&addrs) {
            h.direct.insert(id, addrs);
            h.version += 1;
        }
    }

    /// Writes the remembered direct addresses to `path` when they changed
    /// since `saved`; returns the version now saved.
    fn save(&self, path: &std::path::Path, saved: u64) -> u64 {
        let h = self.read();
        if h.version == saved {
            return saved;
        }
        let map: std::collections::BTreeMap<String, &Vec<SocketAddr>> =
            h.direct.iter().map(|(id, a)| (id.to_string(), a)).collect();
        let Ok(json) = serde_json::to_vec(&map) else {
            return saved;
        };
        let tmp = path.with_extension("tmp");
        let wrote = path
            .parent()
            .is_none_or(|d| std::fs::create_dir_all(d).is_ok())
            && std::fs::write(&tmp, json).is_ok()
            && std::fs::rename(&tmp, path).is_ok();
        if wrote { h.version } else { saved }
    }

    /// Takes back what [`Self::save`] wrote; a missing or damaged file adds nothing.
    fn restore(&self, path: &std::path::Path) {
        let Ok(bytes) = std::fs::read(path) else {
            return;
        };
        let Ok(map) =
            serde_json::from_slice::<std::collections::BTreeMap<String, Vec<SocketAddr>>>(&bytes)
        else {
            return;
        };
        for (id, addrs) in map {
            if let Ok(id) = id.parse::<EndpointId>() {
                self.set_direct(id, addrs);
            }
        }
    }
}

/// Gives `addr` the relays among `urls` it does not name yet, up to the most
/// one dialed address carries.
fn add_relays(addr: &mut EndpointAddr, urls: &[Url]) {
    let mut relays = addr.relay_urls().count();
    for url in urls {
        if relays >= MAX_DIAL_RELAYS {
            break;
        }
        let url = RelayUrl::from(url.clone());
        if !addr.relay_urls().any(|u| *u == url) {
            *addr = addr.clone().with_relay_url(url);
            relays += 1;
        }
    }
}

/// How often the record loop runs while a boot identity is unresolved.
const BOOT_RETRY: Duration = Duration::from_secs(5);

/// Most peers one round of the record loop exchanges records with.
const SYNC_FANOUT: usize = 16;

/// Most peers one round asks where they see this node.
const OBSERVE_FANOUT: usize = 8;

/// Most forwarders a node keeps connections to.
pub const MAX_FORWARDERS: usize = 2;

/// Most peers one round tries to punch a direct path to.
const PUNCH_FANOUT: usize = 4;

/// Most forwarders tried each round.
const MAX_FORWARDER_CANDIDATES: usize = 6;

/// Most staked edge operators tried as relays at start.
pub const MAX_STAKED_RELAYS: usize = 8;

/// How long one exchange with a peer may take.
const ASK_TIMEOUT: Duration = Duration::from_secs(15);

/// Transport tag of an iroh endpoint key: the 32-byte Ed25519 `EndpointId`.
pub const TRANSPORT_IROH: &str = "iroh/ed25519";

/// `endpoint` as the key an [`EndpointRecord`] names.
pub fn iroh_endpoint_key(endpoint: EndpointId) -> EndpointKey {
    EndpointKey {
        transport: TRANSPORT_IROH.to_string(),
        key: endpoint.as_bytes().to_vec(),
    }
}

/// The iroh endpoint a record names, if it names one.
pub fn iroh_endpoint(record: &EndpointRecord) -> IrohResult<EndpointId> {
    if record.endpoint.transport != TRANSPORT_IROH {
        return Err(IrohError::Backend(format!(
            "record names a {} endpoint",
            record.endpoint.transport
        )));
    }
    let bytes: [u8; 32] = record
        .endpoint
        .key
        .as_slice()
        .try_into()
        .map_err(|_| IrohError::Backend("iroh endpoint key is not 32 bytes".to_string()))?;
    EndpointId::from_bytes(&bytes)
        .map_err(|e| IrohError::Backend(format!("iroh endpoint key: {e}")))
}

/// How to dial the iroh endpoint a record names: its id and the relays it
/// names, its own relay first when it serves one. Never an IP address.
pub fn endpoint_addr(record: &EndpointRecord) -> IrohResult<EndpointAddr> {
    addr_with(record, |addr| {
        dial_hints().add_to(addr, &record.machine_did())
    })
}

/// The address a record names, with what `hints` adds to it.
fn addr_with(
    record: &EndpointRecord,
    hints: impl FnOnce(&mut EndpointAddr),
) -> IrohResult<EndpointAddr> {
    let id = iroh_endpoint(record)?;
    let mut addr = EndpointAddr::new(id);
    for relay in &record.relays {
        addr = addr.with_relay_url(RelayUrl::from(relay.url.clone()));
    }
    hints(&mut addr);
    let forwarders = record
        .forwarders
        .iter()
        .filter_map(|k| endpoint_id_of(k).ok());
    addr = addr.with_addrs(
        forwarders.map(|f| iroh::TransportAddr::Custom(crate::paths::peer_relay_addr(f, id))),
    );
    Ok(addr)
}

/// The iroh endpoint id an endpoint key names.
pub fn endpoint_id_of(key: &EndpointKey) -> IrohResult<EndpointId> {
    if key.transport != TRANSPORT_IROH {
        return Err(IrohError::Backend(format!(
            "transport {} is not iroh",
            key.transport
        )));
    }
    let bytes: [u8; 32] = key
        .key
        .as_slice()
        .try_into()
        .map_err(|_| IrohError::Backend("an iroh endpoint key is 32 bytes".into()))?;
    EndpointId::from_bytes(&bytes).map_err(|e| IrohError::Backend(format!("endpoint key: {e}")))
}

/// Configures `builder` to relay through `relays` and to find endpoints
/// through `store`. With no relays the endpoint relays nothing; with no
/// store it looks nothing up.
pub fn with_relays(
    builder: Builder,
    relays: &[RelayRef],
    store: Option<Arc<DiscoveryStore>>,
) -> Builder {
    let urls: Vec<Url> = relays.iter().map(|r| r.url.clone()).collect();
    with_relay_urls(builder, &urls, store)
}

/// [`with_relays`] for relays named by URL alone: the admitted ones and those
/// still waited on.
pub fn with_relay_urls(
    mut builder: Builder,
    relays: &[Url],
    store: Option<Arc<DiscoveryStore>>,
) -> Builder {
    if relays.is_empty() {
        builder = builder.relay_mode(RelayMode::Disabled);
    } else {
        let map: RelayMap = relays
            .iter()
            .map(|url| RelayConfig::new(RelayUrl::from(url.clone()), None))
            .collect();
        builder = builder.relay_mode(RelayMode::Custom(map));
    }
    if let Some(store) = store {
        builder = builder.address_lookup(store);
    }
    builder
}

/// The TLS provider between two Tenzro endpoints: aws-lc-rs offering and
/// accepting only the X25519MLKEM768 post-quantum hybrid. A peer that offers
/// X25519 alone, on a fresh or a resumed session, has no group in common and
/// its handshake fails; a session store holding a classical group as its hint
/// cannot make this side send one.
pub fn peer_crypto_provider() -> rustls::crypto::CryptoProvider {
    use rustls::crypto::aws_lc_rs::{default_provider, kx_group};
    let mut provider = default_provider();
    provider.kx_groups = vec![kx_group::X25519MLKEM768];
    provider
}

/// The TLS provider for HTTPS to relays, their records and address lookup:
/// aws-lc-rs, offering the X25519MLKEM768 hybrid first and X25519 for a TLS
/// terminator that cannot do the hybrid. Never used between endpoints.
pub fn relay_crypto_provider() -> rustls::crypto::CryptoProvider {
    use rustls::crypto::aws_lc_rs::{default_provider, kx_group};
    let mut provider = default_provider();
    provider.kx_groups = vec![kx_group::X25519MLKEM768, kx_group::X25519];
    provider
}

/// An endpoint builder with the hybrid-only TLS provider between endpoints,
/// port mapping and the platform's certificate store: the endpoint asks the local router
/// (UPnP IGD, PCP or NAT-PMP, whichever it answers) to map its UDP port, so
/// peers can reach it directly behind a NAT, and verifies relays' HTTPS
/// certificates against the roots the operating system trusts, so a network
/// whose proxy re-signs TLS with a CA the machine trusts still reaches its
/// relays. No relay, no address lookup, nothing beyond the local router that
/// the operator did not choose.
pub fn base_builder() -> Builder {
    base_builder_with(&ConnectionLimits::default(), false)
}

/// `builder` bound to one IPv4 loopback socket on a port the system picks,
/// with no port mapping: an endpoint that only talks to peers on this host.
/// It opens nothing on another interface, so the host's firewall has no
/// listener to ask the user about.
pub fn on_loopback(builder: Builder) -> Builder {
    builder
        .clear_ip_transports()
        .bind_addr(SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, 0)))
        .expect("a loopback socket address is a valid bind address")
        .portmapper_config(iroh::endpoint::PortmapperConfig::Disabled)
}

/// [`base_builder`] with the QUIC limits of `limits` (idle timeout, stream
/// counts, receive window) on every connection the endpoint makes or accepts.
pub fn base_builder_with(limits: &ConnectionLimits, serves_peer_relay: bool) -> Builder {
    Endpoint::builder(presets::Minimal)
        .crypto_provider(Arc::new(relay_crypto_provider()))
        .peer_crypto_provider(Arc::new(peer_crypto_provider()))
        .portmapper_config(iroh::endpoint::PortmapperConfig::default())
        .ca_tls_config(iroh_relay::tls::CaTlsConfig::system())
        .transport_config(limits.transport_config(serves_peer_relay))
}

/// A rustls client configuration that verifies servers against the
/// platform's certificate store, as the endpoint's relay client does.
pub fn platform_tls() -> IrohResult<rustls::ClientConfig> {
    let provider = Arc::new(relay_crypto_provider());
    let verifier = iroh_relay::tls::CaTlsConfig::system()
        .server_cert_verifier(provider.clone())
        .map_err(|e| IrohError::Backend(format!("platform certificate store: {e}")))?;
    Ok(rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| IrohError::Backend(format!("tls: {e}")))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth())
}

/// A node's identity-addressed view of the network.
pub struct IdentityTransport {
    store: Arc<DiscoveryStore>,
    boot: Vec<BootIdentity>,
    relays: Vec<RelayRef>,
    /// Relays admitted after the endpoint was bound.
    late: Mutex<Vec<RelayRef>>,
    /// Where the sequence of the last record this machine signed is kept
    /// across boots.
    sequence_file: std::sync::OnceLock<std::path::PathBuf>,
    /// The highest sequence saved there; below the current record's while a
    /// save has failed, which the next round tries again.
    saved_sequence_up_to: std::sync::atomic::AtomicU64,
    /// Relay URLs this node waits to admit: named at start or learned from a
    /// validator's record, and not answering yet.
    pending: Mutex<Vec<Url>>,
    /// Operators whose record may name a further relay (the boot list, and
    /// the validators the node adds).
    relay_operators: Mutex<std::collections::HashSet<String>>,
    own_relay: Option<Url>,
    /// Held so the relay role keeps serving while the transport lives.
    _relay_server: Option<RelayServer>,
    /// Who may use the relay this node serves, when it runs the role.
    relay_admission: crate::relay::RelayAdmission,
    scope: Mutex<RecordScope>,
    accepted_licences: Mutex<Vec<String>>,
    /// The software this machine states in its record, once the node declared it.
    update: Mutex<Option<crate::update_advert::UpdateAdvert>>,
    current: Mutex<Option<EndpointRecord>>,
    /// The addresses peers saw this node at.
    observations: Mutex<Observations>,
    /// The addresses peers confirmed, added to the endpoint.
    external: Mutex<Vec<SocketAddr>>,
    /// The latest check of each staked relay, by URL.
    relay_checks: Mutex<std::collections::BTreeMap<String, RelayCheck>>,
    /// The paths this node adds to iroh: peer relays.
    paths: crate::paths::Paths,
    /// The forwarding service, when this node serves the relay role.
    peer_relay: std::sync::OnceLock<crate::paths::PeerRelayService>,
    /// The machine's hardware ML-DSA key, once the node binds its records
    /// with it (see [`crate::pq_endpoint`]).
    machine_pq: std::sync::OnceLock<Arc<dyn crate::pq_endpoint::MachinePqKey>>,
    /// The records and ML-DSA endpoint key the versioned RPC ALPNs use.
    pq_channel: crate::pq_endpoint::PqChannel,
    /// The peer gate whose rule ([`IdentityGate::may_dial`]) says which
    /// peers this node reaches out to, once the node installs it.
    dial_gate: std::sync::OnceLock<IdentityGate>,
}

impl IdentityTransport {
    /// Who may use the relay this node serves; it lets everyone in until the
    /// node installs its identity gate.
    pub fn relay_admission(&self) -> &crate::relay::RelayAdmission {
        &self.relay_admission
    }

    /// What this node's relay is carrying, when it serves the relay role.
    pub fn relay_load(&self) -> Option<crate::relay::RelayLoad> {
        self._relay_server.as_ref().map(RelayServer::load)
    }

    /// Starts the relay role when `relay_role` is set (it announces itself
    /// under `machine_did`, so a machine without an identity cannot run it)
    /// and admits every relay the boot list names, keeping each operator's
    /// record as the first entries of the discovery store.
    ///
    /// `staked_relays` are the URLs staked edge operators publish on chain,
    /// most bonded first. Each is admitted the same way, by its operator's
    /// record, when it answers at once; an edge operator that serves no
    /// relay at its URL is skipped. At most [`MAX_STAKED_RELAYS`] are tried.
    pub async fn start(
        boot: Vec<BootIdentity>,
        staked_relays: &[Url],
        relay_role: Option<&RelayRoleConfig>,
        machine_did: Option<String>,
    ) -> IrohResult<Arc<Self>> {
        Self::start_with_limits(
            boot,
            staked_relays,
            relay_role,
            machine_did,
            crate::relay::RelayLimits::default(),
        )
        .await
    }

    /// [`Self::start`] with the limits the relay role runs under.
    pub async fn start_with_limits(
        boot: Vec<BootIdentity>,
        staked_relays: &[Url],
        relay_role: Option<&RelayRoleConfig>,
        machine_did: Option<String>,
        relay_limits: crate::relay::RelayLimits,
    ) -> IrohResult<Arc<Self>> {
        let store = Arc::new(DiscoveryStore::new());
        let relay_admission = crate::relay::RelayAdmission::default();
        let mut relays = Vec::new();
        let (relay_server, own_relay) = match relay_role {
            Some(role) => {
                let did = machine_did.ok_or_else(|| {
                    IrohError::Unauthorized(
                        "the relay role is announced by machine identity, and this machine has no \
                         hardware key to hold one"
                            .to_string(),
                    )
                })?;
                let server = RelayServer::spawn(
                    role.bind_addr,
                    store.clone(),
                    did.clone(),
                    relay_limits,
                    relay_admission.clone(),
                )
                .await?;
                tracing::info!(listen = %server.local_addr(), url = %role.public_url, "relay role serving");
                relays.push(RelayRef {
                    did,
                    url: role.public_url.clone(),
                });
                (Some(server), Some(role.public_url.clone()))
            }
            None => (None, None),
        };
        let mut candidates: Vec<&Url> = boot.iter().filter_map(|b| b.relay.as_ref()).collect();
        candidates.sort();
        candidates.dedup();
        let candidates: Vec<&Url> = candidates
            .into_iter()
            .filter(|url| Some(*url) != own_relay.as_ref())
            .collect();
        let mut staked: Vec<&Url> = staked_relays
            .iter()
            .filter(|url| Some(*url) != own_relay.as_ref() && !candidates.contains(url))
            .take(MAX_STAKED_RELAYS)
            .collect();
        let mut seen = std::collections::HashSet::new();
        staked.retain(|url| seen.insert(*url));
        let patient = candidates.len();
        let mut pending: Vec<Url> = Vec::new();
        let fetched = futures::future::join_all(
            candidates
                .iter()
                .map(|url| futures::future::Either::Left(fetch_relay_record_patiently(url)))
                .chain(
                    staked
                        .iter()
                        .map(|url| futures::future::Either::Right(fetch_relay_record(url))),
                ),
        )
        .await;
        for (i, (url, fetched)) in candidates
            .into_iter()
            .chain(staked)
            .zip(fetched)
            .enumerate()
        {
            if i >= patient && fetched.is_err() {
                tracing::debug!(relay = %url, "staked edge operator serves no relay at its URL");
                continue;
            }
            match fetched {
                Ok(record) => {
                    let relay = RelayRef {
                        did: record.machine_did(),
                        url: url.clone(),
                    };
                    tracing::info!(relay = %relay.url, operator = %relay.did, "relay admitted by its operator's record");
                    if let Err(e) = store.offer(record) {
                        tracing::warn!(relay = %url, error = %e, "relay operator record not kept");
                    }
                    relays.push(relay);
                }
                Err(e) => {
                    tracing::warn!(relay = %url, error = %e, "relay not admitted; asking again each round");
                    pending.push(url.clone());
                }
            }
        }
        let pq_channel = crate::pq_endpoint::PqChannel::new(store.clone());
        let relay_operators = boot.iter().map(|b| b.did.clone()).collect();
        let transport = Arc::new(Self {
            store,
            pq_channel,
            machine_pq: std::sync::OnceLock::new(),
            boot,
            relays,
            late: Mutex::new(Vec::new()),
            sequence_file: std::sync::OnceLock::new(),
            saved_sequence_up_to: std::sync::atomic::AtomicU64::new(0),
            pending: Mutex::new(pending),
            relay_operators: Mutex::new(relay_operators),
            own_relay,
            _relay_server: relay_server,
            relay_admission,
            scope: Mutex::new(RecordScope::Network),
            accepted_licences: Mutex::new(Vec::new()),
            update: Mutex::new(None),
            current: Mutex::new(None),
            observations: Mutex::new(Observations::default()),
            external: Mutex::new(Vec::new()),
            relay_checks: Mutex::new(std::collections::BTreeMap::new()),
            paths: crate::paths::Paths::new(),
            peer_relay: std::sync::OnceLock::new(),
            dial_gate: std::sync::OnceLock::new(),
        });
        transport.publish_relay_hints();
        Ok(transport)
    }

    /// Binds this node's records with the machine's hardware ML-DSA key
    /// `machine`: every record signed from here carries the binding, and the
    /// versioned RPC ALPNs prove possession with `channel`, the machine's
    /// hardware P-256 key, and `machine` on each connection. Returns false
    /// when a key was already bound.
    pub fn enable_pq_binding(
        &self,
        machine: Arc<dyn crate::pq_endpoint::MachinePqKey>,
        channel: Arc<dyn tenzro_device_key::signer::HardwareSigner>,
    ) -> bool {
        if self.machine_pq.set(machine.clone()).is_err() {
            return false;
        }
        self.pq_channel
            .set_own_key(crate::pq_endpoint::ChannelKeys {
                p256: channel,
                ml_dsa: machine,
            })
    }

    /// The records and ML-DSA endpoint key the versioned RPC ALPNs use.
    pub fn pq_channel(&self) -> &crate::pq_endpoint::PqChannel {
        &self.pq_channel
    }

    /// Holds `did`'s records to the hardware ML-DSA key it registered on
    /// chain (tagged with its scheme), from its first record on.
    pub fn pin_pq_key(&self, did: &str, machine_pq_key: Vec<u8>) {
        self.store.pin_pq_key(did, machine_pq_key);
    }

    /// The relays this node uses: its own first when it serves one, then
    /// every admitted boot relay.
    pub fn relays(&self) -> &[RelayRef] {
        &self.relays
    }

    /// Every relay this node uses now: those admitted at start, then those
    /// admitted since.
    pub fn live_relays(&self) -> Vec<RelayRef> {
        let mut all = self.relays.clone();
        all.extend(self.late.lock().iter().cloned());
        all
    }

    /// The URLs the endpoint's relay map holds: the relays in use and those
    /// still waited on.
    pub fn endpoint_relay_urls(&self) -> Vec<Url> {
        let mut urls: Vec<Url> = self.live_relays().into_iter().map(|r| r.url).collect();
        for url in self.pending.lock().iter() {
            if !urls.contains(url) {
                urls.push(url.clone());
            }
        }
        urls
    }

    /// Adds relays to wait for beside the boot list's: `urls` are admitted by
    /// their operators' records, each round until they answer. Returns how
    /// many were new.
    pub fn add_relay_candidates(&self, urls: &[Url]) -> usize {
        let live: Vec<Url> = self.live_relays().into_iter().map(|r| r.url).collect();
        let mut pending = self.pending.lock();
        let mut added = 0;
        for url in urls {
            if Some(url) != self.own_relay.as_ref() && !live.contains(url) && !pending.contains(url)
            {
                pending.push(url.clone());
                added += 1;
            }
        }
        added
    }

    /// Lets the records of `dids` name further relays (`serves_relay`): the
    /// validators of the network, which each may serve one beside the
    /// primary. The boot list's identities are trusted already.
    pub fn trust_relay_operators(&self, dids: impl IntoIterator<Item = String>) {
        self.relay_operators.lock().extend(dids);
    }

    /// Direct addresses to try for the machines in `fixed`, beside the
    /// relays their records name.
    pub fn set_static_addrs(&self, fixed: std::collections::BTreeMap<String, Vec<SocketAddr>>) {
        dial_hints().set_fixed(fixed);
    }

    /// Takes relays named by the records of trusted operators as candidates:
    /// at most [`MAX_LEARNED_RELAYS`] in all.
    fn learn_relays(&self) {
        let operators = self.relay_operators.lock().clone();
        let known: Vec<Url> = self.endpoint_relay_urls();
        let mut fresh = Vec::new();
        for record in self.store.records() {
            let Some(url) = record.serves_relay.clone() else {
                continue;
            };
            if operators.contains(&record.machine_did())
                && Some(&url) != self.own_relay.as_ref()
                && !known.contains(&url)
                && !fresh.contains(&url)
            {
                fresh.push(url);
            }
        }
        let room =
            MAX_LEARNED_RELAYS.saturating_sub(self.late.lock().len() + self.pending.lock().len());
        fresh.truncate(room);
        if !fresh.is_empty() {
            tracing::info!(
                relays = fresh.len(),
                "relays named by validators' records are candidates"
            );
            self.add_relay_candidates(&fresh);
        }
    }

    /// Admits each relay still waited on whose operator's record can be
    /// fetched now, and adds it to the running endpoint's relay map, so a
    /// relay that was down at start, or that a validator announced later,
    /// carries traffic without a restart.
    pub async fn admit_pending(&self, endpoint: &Endpoint) {
        self.learn_relays();
        let urls = self.pending.lock().clone();
        if urls.is_empty() {
            return;
        }
        let fetched = futures::future::join_all(urls.iter().map(|url| async move {
            tokio::time::timeout(ASK_TIMEOUT, fetch_relay_record(url))
                .await
                .map_err(|_| IrohError::Backend("timed out".into()))
                .and_then(|r| r)
        }))
        .await;
        for (url, fetched) in urls.into_iter().zip(fetched) {
            match fetched {
                Ok(record) => {
                    let relay = RelayRef {
                        did: record.machine_did(),
                        url: url.clone(),
                    };
                    if let Err(e) = self.store.offer(record) {
                        tracing::warn!(relay = %url, error = %e, "relay operator record not kept");
                    }
                    self.pending.lock().retain(|u| *u != url);
                    {
                        let mut late = self.late.lock();
                        if !late.contains(&relay) && !self.relays.contains(&relay) {
                            late.push(relay.clone());
                        }
                    }
                    let id = RelayUrl::from(url.clone());
                    endpoint
                        .insert_relay(id.clone(), Arc::new(RelayConfig::new(id, None)))
                        .await;
                    tracing::info!(relay = %url, operator = %relay.did, "relay admitted by its operator's record");
                }
                Err(e) => tracing::debug!(relay = %url, error = %e, "relay not answering yet"),
            }
        }
        self.publish_relay_hints();
    }

    /// How this node dials the endpoint a record names: as [`endpoint_addr`]
    /// does, with the relays this node uses now, whatever else runs in the
    /// process.
    pub fn dial_addr(&self, record: &EndpointRecord) -> IrohResult<EndpointAddr> {
        let urls: Vec<Url> = self.live_relays().into_iter().map(|r| r.url).collect();
        addr_with(record, |addr| {
            add_relays(addr, &urls);
            dial_hints().add_direct_to(addr, &record.machine_did());
        })
    }

    /// Makes every address this process dials carry the relays in use.
    fn publish_relay_hints(&self) {
        let urls: Vec<Url> = self.live_relays().into_iter().map(|r| r.url).collect();
        dial_hints().add_relays(&urls);
    }

    /// Remembers the direct addresses the paths to peers are using now, so a
    /// dial can try them without any relay, and the next start can too.
    pub async fn remember_direct_addrs(&self, endpoint: &Endpoint) {
        for record in self.store.records().into_iter().take(SYNC_FANOUT * 2) {
            let Ok(id) = iroh_endpoint(&record) else {
                continue;
            };
            if id == endpoint.id() {
                continue;
            }
            if let Some(info) = endpoint.remote_info(id).await {
                let direct: Vec<SocketAddr> = info
                    .addrs()
                    .filter(|a| matches!(a.usage(), iroh::endpoint::TransportAddrUsage::Active))
                    .filter_map(|a| match a.addr() {
                        iroh::TransportAddr::Ip(sa) => Some(*sa),
                        _ => None,
                    })
                    .collect();
                if !direct.is_empty() {
                    dial_hints().set_direct(id, direct);
                }
            }
        }
    }

    /// Takes back the direct addresses saved at `path` and keeps them saved
    /// while the node runs.
    pub fn keep_direct_addrs(self: &Arc<Self>, path: std::path::PathBuf) {
        dial_hints().restore(&path);
        let this = Arc::downgrade(self);
        tokio::spawn(async move {
            let mut saved = 0u64;
            loop {
                tokio::time::sleep(Duration::from_secs(30)).await;
                if this.upgrade().is_none() {
                    return;
                }
                saved = dial_hints().save(&path, saved);
            }
        });
    }

    /// Keeps the sequence of the last record this machine signed at `path`,
    /// so the first record of a boot follows the last record of the boot
    /// before it. Peers refuse a record with a lower sequence than the one
    /// they hold, and a sequence read from the clock alone goes down when
    /// the clock is set back between boots.
    pub fn keep_record_sequence(&self, path: std::path::PathBuf) {
        let _ = self.sequence_file.set(path);
    }

    /// The sequence saved by [`Self::keep_record_sequence`], if any. A file
    /// that is there and holds no sequence is reported: the next record
    /// then takes its sequence from the clock, which peers refuse when the
    /// clock reads earlier than the record they hold.
    fn saved_sequence(&self) -> Option<u64> {
        let path = self.sequence_file.get()?;
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
            Err(e) => {
                tracing::warn!(path = %path.display(), error = %e, "this machine's saved record sequence could not be read");
                return None;
            }
        };
        let sequence: Option<u64> = text.trim().parse().ok();
        // A sequence comes from a clock reading plus one per record, so a
        // value a century past the clock came from no clock: a corrupt or
        // hand-written file. Followed, a value at the top of the range would
        // freeze every later sequence. Anything nearer is followed, a value
        // left by a clock that was set back included.
        let ceiling = now_ms().saturating_add(SEQUENCE_CEILING_AHEAD_MS);
        if let Some(far) = sequence.filter(|s| *s > ceiling) {
            tracing::warn!(path = %path.display(), saved = far, "this machine's saved record sequence lies past any clock reading; it is not followed");
            return None;
        }
        if sequence.is_none() {
            tracing::warn!(path = %path.display(), "this machine's saved record sequence is not a number; the next record takes its sequence from the clock");
        }
        sequence
    }

    /// Saves `sequence` for the boots after this one: written beside the
    /// file, flushed to disk and moved over it, so a crash or a power loss
    /// leaves the old value or the new and never an empty file.
    fn save_sequence(&self, sequence: u64) {
        use std::io::Write as _;
        let Some(path) = self.sequence_file.get() else {
            return;
        };
        let tmp = path.with_extension("tmp");
        let saved = path
            .parent()
            .map_or(Ok(()), std::fs::create_dir_all)
            .and_then(|()| std::fs::File::create(&tmp))
            .and_then(|mut file| {
                file.write_all(sequence.to_string().as_bytes())?;
                file.sync_all()
            })
            .and_then(|()| std::fs::rename(&tmp, path))
            .and_then(|()| sync_parent(path));
        if let Err(e) = saved {
            tracing::warn!(error = %e, "this machine's record sequence was not saved; saving it again next round");
            return;
        }
        self.saved_sequence_up_to
            .fetch_max(sequence, std::sync::atomic::Ordering::AcqRel);
    }

    /// This node's discovery store.
    pub fn store(&self) -> &Arc<DiscoveryStore> {
        &self.store
    }

    /// Scopes this machine's record, and the records this node answers, to
    /// the epoch set `members`: from the next renewal the record is shared
    /// only with peers a member certifies and with the machines on this
    /// node's own boot list. A private node keeps sharing its record with
    /// its counterparties only.
    ///
    /// A machine that serves a relay keeps its own record network-scoped: its
    /// relay is reached by every node of the network, which admits it by that
    /// record, so the record is public for as long as the relay is.
    pub fn share_within_epoch_set(&self, members: std::collections::HashSet<String>) {
        self.store.set_epoch_set(members);
        if self.own_relay.is_some() {
            return;
        }
        let rescoped = {
            let mut scope = self.scope.lock();
            let network = matches!(*scope, RecordScope::Network);
            if network {
                *scope = RecordScope::EpochSet;
            }
            network
        };
        if rescoped {
            *self.current.lock() = None;
        }
    }

    /// Makes this a private node: from the next renewal its record lists
    /// `counterparties` (signed with it), is published only to them, and is
    /// answered only to them.
    pub fn share_with_counterparties(&self, mut counterparties: Vec<String>) {
        counterparties.sort();
        counterparties.dedup();
        *self.scope.lock() = RecordScope::Counterparties(counterparties);
        *self.current.lock() = None;
    }

    /// States in this machine's record, from the next renewal, the model
    /// licences its operator accepted, so providers of weights gated behind
    /// one of them serve this machine. An id not in the record form, or past
    /// [`MAX_ACCEPTED_LICENCES`](crate::identity_record::MAX_ACCEPTED_LICENCES),
    /// is refused and stated nowhere.
    pub fn declare_accepted_licences(&self, ids: &[String]) -> IrohResult<()> {
        let mut ids = ids.to_vec();
        ids.sort();
        ids.dedup();
        if let Some(bad) = ids
            .iter()
            .find(|id| !crate::identity_record::is_licence_id(id))
        {
            return Err(IrohError::Backend(format!(
                "licence id {bad:?} is not in the record form"
            )));
        }
        if ids.len() > crate::identity_record::MAX_ACCEPTED_LICENCES {
            return Err(IrohError::Backend(format!(
                "{} accepted licences; a record states at most {}",
                ids.len(),
                crate::identity_record::MAX_ACCEPTED_LICENCES
            )));
        }
        let mut held = self.accepted_licences.lock();
        if *held != ids {
            *held = ids;
            drop(held);
            *self.current.lock() = None;
        }
        Ok(())
    }

    /// States in this machine's record, from the next renewal, the software it
    /// runs. A record already signed is replaced only when the advert changed.
    pub fn declare_update(&self, advert: crate::update_advert::UpdateAdvert) {
        let mut held = self.update.lock();
        if held.as_ref() != Some(&advert) {
            *held = Some(advert);
            drop(held);
            *self.current.lock() = None;
        }
    }

    /// Holds every peer this transport reaches out to (discovery sync,
    /// record fetches, relay forwarders) to `gate`'s rule: an isolated node
    /// dials only the boot list and the validators' machines.
    pub fn hold_dials_to(&self, gate: IdentityGate) {
        let _ = self.dial_gate.set(gate);
    }

    /// Whether this node may reach out to the machine `did`.
    fn may_dial(&self, did: &str) -> bool {
        self.dial_gate.get().is_none_or(|g| g.may_dial(Some(did)))
    }

    /// Whether this machine's record, under its current scope, may be
    /// published to `did`. A record scoped to the epoch set also goes to the
    /// machines on this node's own boot list, the entry points its operator
    /// chose: a boot machine admits this node in full, relays for it and
    /// dials it only when it holds the record that names this node's
    /// endpoint. A boot machine outside the set keeps the record and answers
    /// it only to the members of the validator committee it reads from the
    /// chain (see [`DiscoveryStore::set_committee`]).
    fn publishes_to(&self, did: &str) -> bool {
        match &*self.scope.lock() {
            RecordScope::Network => true,
            RecordScope::EpochSet => {
                self.store.in_epoch_set(did) || self.boot.iter().any(|b| b.did == did)
            }
            RecordScope::Counterparties(list) => list.iter().any(|d| d == did),
        }
    }

    /// The boot identities resolved so far, each with the iroh address its
    /// current record names.
    pub fn peer_addrs(&self) -> Vec<(String, EndpointAddr)> {
        self.boot
            .iter()
            .filter_map(|b| {
                self.store
                    .lookup(&b.did)
                    .and_then(|r| self.dial_addr(&r).ok())
                    .map(|a| (b.did.clone(), a))
            })
            .collect()
    }

    /// Fetches the record of `machine` from the peer itself, when that peer
    /// disclosed its endpoint `peer` to this node and no record of it naming
    /// that endpoint is held yet. A record scoped to the epoch set reaches
    /// no one outside it but its owner's boot machines, which pass it on
    /// only to committee members, so a member outside the committee (or one
    /// whose boot machines know no committee) first learns the record of
    /// another from that member: it reaches the endpoint through the relay
    /// the boot list names for the machine, or else through its own relays,
    /// hands it this node's record so the peer can certify it, and asks for
    /// the peer's. True once a record naming `peer` is held.
    pub async fn fetch_disclosed_record(
        &self,
        endpoint: &Endpoint,
        peer: EndpointId,
        machine: &str,
    ) -> bool {
        self.fetch_record(endpoint, peer, machine, true).await
    }

    /// [`Self::fetch_disclosed_record`] even when a record naming `peer` is
    /// held: for a peer the held record did not reach. The peer may have
    /// moved to other relays in the same boot, which changes its record but
    /// not the endpoint it names. The held record stays if no newer one
    /// comes.
    pub async fn refetch_disclosed_record(
        &self,
        endpoint: &Endpoint,
        peer: EndpointId,
        machine: &str,
    ) -> bool {
        self.fetch_record(endpoint, peer, machine, false).await
    }

    async fn fetch_record(
        &self,
        endpoint: &Endpoint,
        peer: EndpointId,
        machine: &str,
        held_is_enough: bool,
    ) -> bool {
        let names_peer = |r: &EndpointRecord| iroh_endpoint(r).is_ok_and(|id| id == peer);
        if held_is_enough && self.store.lookup(machine).is_some_and(|r| names_peer(&r)) {
            return true;
        }
        if !self.may_dial(machine) {
            return false;
        }
        let hinted: Vec<Url> = self
            .boot
            .iter()
            .filter(|b| b.did == machine)
            .filter_map(|b| b.relay.clone())
            .collect();
        let mut addr = hinted.into_iter().fold(EndpointAddr::new(peer), |a, url| {
            a.with_relay_url(RelayUrl::from(url))
        });
        // The hinted relay may be the one that stopped: the admitted relays
        // follow it so the dial has another way to the peer.
        let admitted: Vec<Url> = self.relays.iter().map(|r| r.url.clone()).collect();
        add_relays(&mut addr, &admitted);
        if addr.relay_urls().next().is_none() {
            return false;
        }
        let own = self.current.lock().clone();
        if let Some(own) = own.filter(|_| self.publishes_to(machine)) {
            let publish = DiscoveryRequest::Publish(own);
            if let Err(e) =
                tokio::time::timeout(ASK_TIMEOUT, ask(endpoint, addr.clone(), &publish)).await
            {
                tracing::debug!(peer = %machine, error = %e, "publish timed out");
            }
        }
        let lookup = DiscoveryRequest::Lookup(machine.to_string());
        match tokio::time::timeout(ASK_TIMEOUT, ask(endpoint, addr, &lookup)).await {
            Ok(Ok(DiscoveryResponse::Record(Some(r)))) if names_peer(&r) => {
                let _ = self.store.offer(r);
            }
            Ok(Ok(_)) => tracing::debug!(peer = %machine, "the peer did not answer its record"),
            Ok(Err(e)) => tracing::debug!(peer = %machine, error = %e, "record lookup failed"),
            Err(e) => tracing::debug!(peer = %machine, error = %e, "record lookup timed out"),
        }
        self.store.lookup(machine).is_some_and(|r| names_peer(&r))
    }

    /// The endpoints of the boot identities resolved so far, other than
    /// `own`: the peers a node starting on a fresh network links to first,
    /// gossip included.
    pub fn boot_endpoints(&self, own: EndpointId) -> Vec<EndpointId> {
        self.peer_addrs()
            .into_iter()
            .map(|(_, addr)| addr.id)
            .filter(|id| *id != own)
            .collect()
    }

    /// The admitted relays among `home`, the relays the endpoint keeps a
    /// connection to. An endpoint is reached through a relay only while it
    /// is connected there, so its record names those and no others.
    fn reachable_through(&self, home: &[Url]) -> Vec<RelayRef> {
        self.live_relays()
            .into_iter()
            .filter(|r| home.contains(&r.url))
            .collect()
    }

    /// This machine's current record for `endpoint` reached through the
    /// `home` relays, signing a fresh one when there is none, it is past half
    /// its lifetime, or the endpoint moved to other relays. Signing uses the
    /// hardware key, so this runs on a blocking thread.
    fn own_record(
        &self,
        endpoint: EndpointId,
        home: &[Url],
        signer: &dyn HardwareSigner,
    ) -> Option<EndpointRecord> {
        // Nothing waits on a record under a deadline: its signatures go
        // behind votes at the TPM, and are held back while the chip stalls.
        let _defer = tenzro_device_key::defer_tpm();
        let now = now_ms();
        let relays = self.reachable_through(home);
        let forwarders: Vec<EndpointKey> = self
            .paths
            .forwarders()
            .into_iter()
            .map(iroh_endpoint_key)
            .collect();
        let mut current = self.current.lock();
        // Until the endpoint holds a connection to one of its relays (or has a
        // forwarder), a record would name no way to reach it, and a peer that
        // took it (a relay's `/identity` fetch at startup, say) could never dial
        // the endpoint to learn a better one. Sign none until it does.
        // A record signed while its sequence could not be saved is saved now;
        // until then a boot after this one would start below it.
        if let Some(r) = current.as_ref()
            && r.sequence
                > self
                    .saved_sequence_up_to
                    .load(std::sync::atomic::Ordering::Acquire)
        {
            self.save_sequence(r.sequence);
        }
        if relays.is_empty() && forwarders.is_empty() && !self.relays.is_empty() {
            return current.clone();
        }
        if let Some(r) = current.as_ref().filter(|r| {
            !r.due_for_renewal(now)
                && r.relays == relays
                && r.forwarders == forwarders
                && r.pq.is_some() == self.machine_pq.get().is_some()
                && r.update.as_ref().map(|u| &u.advert) == self.update.lock().as_ref()
        }) {
            return Some(r.clone());
        }
        let last = current
            .as_ref()
            .map(|r| r.sequence)
            .max(self.saved_sequence());
        let sequence = last.map_or(now, |s| s.max(now - 1).saturating_add(1));
        match EndpointRecord::sign(
            signer,
            iroh_endpoint_key(endpoint),
            relays,
            forwarders,
            self.own_relay.clone(),
            self.scope.lock().clone(),
            self.accepted_licences.lock().clone(),
            sequence,
            now,
        ) {
            Ok(mut record) => {
                if let (Some(machine), Some(_)) = (self.machine_pq.get(), self.pq_channel.own_key())
                    && let Err(e) = record.bind_pq(machine.as_ref())
                {
                    // An unbound record would be refused by every peer
                    // that holds this identity's key, so none is signed.
                    tracing::warn!(error = %e, "binding this machine's endpoint record failed");
                    return current.clone();
                }
                if let Some(advert) = self.update.lock().clone()
                    && let Err(e) = record.attach_update(signer, advert)
                {
                    // The advert is informational: the record is still good without it.
                    tracing::warn!(error = %e, "stating this machine's software in its endpoint record failed");
                }
                if let Err(e) = self.store.offer(record.clone()) {
                    tracing::warn!(error = %e, "own endpoint record not kept");
                }
                self.save_sequence(record.sequence);
                *current = Some(record.clone());
                Some(record)
            }
            Err(e) => {
                tracing::warn!(error = %e, "signing this machine's endpoint record failed");
                None
            }
        }
    }

    /// One round: renew this machine's record, then with each of up to
    /// [`SYNC_FANOUT`] known peers (boot identities first) publish it and
    /// take their snapshot. Every record received is verified before it is
    /// kept.
    pub async fn sync_once(
        self: &Arc<Self>,
        endpoint: &Endpoint,
        signer: Option<&'static dyn HardwareSigner>,
    ) {
        let silent = self.choose_forwarders(endpoint).await;
        let own = match signer {
            Some(s) => {
                let (this, id) = (self.clone(), endpoint.id());
                let home: Vec<Url> = endpoint
                    .addr()
                    .relay_urls()
                    .map(|u| Url::from(u.clone()))
                    .collect();
                tokio::task::spawn_blocking(move || this.own_record(id, &home, s))
                    .await
                    .ok()
                    .flatten()
            }
            None => None,
        };
        let own_did = own.as_ref().map(EndpointRecord::machine_did);
        let mut peers: Vec<EndpointRecord> = self
            .boot
            .iter()
            .filter_map(|b| self.store.lookup(&b.did))
            .collect();
        for r in self.store.records() {
            if !peers.iter().any(|p| p.machine_did() == r.machine_did()) {
                peers.push(r);
            }
        }
        // A peer held by record only, outside what this node may dial (an
        // isolated validator: the boot list and the validators' machines),
        // is learned from the snapshots and never asked itself.
        peers.retain(|r| {
            Some(r.machine_did()) != own_did
                && self.may_dial(&r.machine_did())
                && iroh_endpoint(r).is_ok_and(|id| id != endpoint.id() && !silent.contains(&id))
        });
        peers.truncate(SYNC_FANOUT);
        // The peers are asked at once, and one that lets a question time out,
        // here or as a forwarder before, is asked nothing more this round: a
        // peer that is gone costs the round one timeout and holds no other
        // peer back.
        let exchanges = peers.into_iter().map(|peer| {
            let own = own
                .as_ref()
                .filter(|_| self.publishes_to(&peer.machine_did()))
                .cloned();
            async move {
                let addr = self.dial_addr(&peer).ok()?;
                if let Some(own) = own {
                    let publish = DiscoveryRequest::Publish(own);
                    if let Err(e) =
                        tokio::time::timeout(ASK_TIMEOUT, ask(endpoint, addr.clone(), &publish))
                            .await
                    {
                        tracing::debug!(peer = %peer.machine_did(), error = %e, "publish timed out");
                        return None;
                    }
                }
                match tokio::time::timeout(
                    ASK_TIMEOUT,
                    ask(endpoint, addr, &DiscoveryRequest::Snapshot),
                )
                .await
                {
                    Ok(Ok(DiscoveryResponse::Records(records))) => {
                        for r in records {
                            // A stale or foreign record is refused by the store.
                            let _ = self.store.offer(r);
                        }
                    }
                    Ok(Ok(_)) => {}
                    Ok(Err(e)) => {
                        tracing::debug!(peer = %peer.machine_did(), error = %e, "snapshot failed")
                    }
                    Err(e) => {
                        tracing::debug!(peer = %peer.machine_did(), error = %e, "snapshot timed out");
                        return None;
                    }
                }
                Some(peer)
            }
        });
        let answering: Vec<EndpointRecord> = futures::future::join_all(exchanges)
            .await
            .into_iter()
            .flatten()
            .collect();
        self.observe(endpoint, &answering).await;
        self.punch_peers(endpoint, &answering).await;
    }

    /// Behind an endpoint-dependent NAT, tries to punch a direct path to
    /// each peer this round talked to that has none, one at a time; the
    /// transport bounds the attempts.
    async fn punch_peers(&self, endpoint: &Endpoint, peers: &[EndpointRecord]) {
        let mut tried = 0;
        for peer in peers {
            if tried >= PUNCH_FANOUT {
                return;
            }
            let Ok(addr) = self.dial_addr(peer) else {
                continue;
            };
            if !self.paths.punch_due(&addr.id) {
                continue;
            }
            if let Some(info) = endpoint.remote_info(addr.id).await
                && info.addrs().any(|a| {
                    a.addr().is_ip()
                        && matches!(a.usage(), iroh::endpoint::TransportAddrUsage::Active)
                })
            {
                continue;
            }
            tried += 1;
            self.paths.punch(addr).await;
        }
    }

    /// Asks each of `peers` where it sees this node, then offers every
    /// address enough machines agree on as an external address of
    /// `endpoint` and withdraws the ones they no longer report.
    async fn observe(&self, endpoint: &Endpoint, peers: &[EndpointRecord]) {
        let asks = peers.iter().take(OBSERVE_FANOUT).filter_map(|peer| {
            let addr = self.dial_addr(peer).ok()?;
            let did = peer.machine_did();
            Some(async move {
                match tokio::time::timeout(
                    ASK_TIMEOUT,
                    ask(endpoint, addr, &DiscoveryRequest::Observe),
                )
                .await
                {
                    Ok(Ok(DiscoveryResponse::Observed(Some(seen)))) => Some((did, seen)),
                    _ => None,
                }
            })
        });
        let reports: Vec<(String, SocketAddr)> = futures::future::join_all(asks)
            .await
            .into_iter()
            .flatten()
            .collect();
        let now = now_ms();
        let local = reachability::local_ips(endpoint);
        let confirmed = {
            let mut observations = self.observations.lock();
            for (did, seen) in &reports {
                observations.record(did, *seen, now);
            }
            observations.confirmed(&local, now)
        };
        let side = {
            let observations = self.observations.lock();
            match observations.nat_kind(&local, now) {
                reachability::NatKind::None | reachability::NatKind::EndpointIndependent => {
                    crate::paths::NatSide::Easy
                }
                reachability::NatKind::EndpointDependent => observations
                    .list(now)
                    .iter()
                    .map(|o| o.addr.ip())
                    .find(|ip| ip.is_ipv4() && !local.contains(ip))
                    .map_or(crate::paths::NatSide::Unknown, crate::paths::NatSide::Hard),
                reachability::NatKind::Unknown => crate::paths::NatSide::Unknown,
            }
        };
        self.paths.set_nat(side);
        let previous = std::mem::replace(&mut *self.external.lock(), confirmed.clone());
        for gone in previous.iter().filter(|a| !confirmed.contains(a)) {
            endpoint.remove_external_addr(gone).await;
        }
        for new in confirmed.iter().filter(|a| !previous.contains(a)) {
            tracing::info!(addr = %new, "peers confirm this node's address; offering it for direct paths");
            endpoint.add_external_addr(*new).await;
        }
    }

    /// Checks every relay in `urls` now and keeps the results, dropping
    /// checks of relays no longer listed.
    pub async fn check_relays(&self, urls: &[Url]) {
        let checks = futures::future::join_all(urls.iter().map(check_relay)).await;
        let mut held = self.relay_checks.lock();
        held.retain(|url, _| urls.iter().any(|u| u.as_str() == url));
        for c in checks {
            held.insert(c.url.clone(), c);
        }
    }

    /// The latest check of each relay, by URL.
    pub fn relay_checks(&self) -> Vec<RelayCheck> {
        self.relay_checks.lock().values().cloned().collect()
    }

    /// The paths this node adds to its endpoint.
    pub fn paths(&self) -> &crate::paths::Paths {
        &self.paths
    }

    /// Whether this node serves the relay role, and with it forwards for the
    /// peer relay.
    pub fn serves_peer_relay(&self) -> bool {
        self.own_relay.is_some()
    }

    /// The forwarding service of a node that serves the relay role: its
    /// endpoint also forwards packets between endpoints that cannot reach
    /// each other directly.
    pub fn peer_relay_service(&self) -> Option<crate::paths::PeerRelayService> {
        self.serves_peer_relay().then_some(())?;
        Some(
            self.peer_relay
                .get_or_init(|| crate::paths::PeerRelayService::new(Default::default()))
                .clone(),
        )
    }

    /// Keeps connections to the [`MAX_FORWARDERS`] forwarders with the
    /// lowest round-trip time among the relay operators this node admitted,
    /// counting only those reached on a direct path (a forwarder reached
    /// through a relay adds nothing). A node peers reach directly at its own
    /// address keeps none. Returns the candidates that let the connection
    /// time out.
    pub async fn choose_forwarders(&self, endpoint: &Endpoint) -> Vec<EndpointId> {
        let local = reachability::local_ips(endpoint);
        if self.observations.lock().nat_kind(&local, now_ms()) == reachability::NatKind::None {
            self.paths.offer(&[]);
            return Vec::new();
        }
        let candidates: Vec<EndpointAddr> = self
            .live_relays()
            .iter()
            .filter(|r| Some(&r.url) != self.own_relay.as_ref())
            .filter(|r| self.may_dial(&r.did))
            .filter_map(|r| self.store.lookup(&r.did))
            .filter_map(|record| self.dial_addr(&record).ok())
            .filter(|addr| addr.id != endpoint.id())
            .take(MAX_FORWARDER_CANDIDATES)
            .collect();
        let tried = futures::future::join_all(candidates.into_iter().map(|addr| async move {
            let id = addr.id;
            let connected = tokio::time::timeout(ASK_TIMEOUT, self.paths.connect_forwarder(addr))
                .await
                .map(|r| r.is_ok());
            (id, connected)
        }))
        .await;
        let silent: Vec<EndpointId> = tried
            .iter()
            .filter(|(_, connected)| connected.is_err())
            .map(|(id, _)| *id)
            .collect();
        // Give hole punching to the forwarders a moment before judging.
        if tried.iter().any(|(_, connected)| *connected == Ok(true)) {
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
        let mut direct: Vec<(EndpointId, Duration)> = self
            .paths
            .forwarder_rtts()
            .into_iter()
            .filter(|(id, _)| self.paths.forwarder_is_direct(id))
            .collect();
        direct.sort_by_key(|(_, rtt)| *rtt);
        let keep: Vec<EndpointId> = direct
            .into_iter()
            .take(MAX_FORWARDERS)
            .map(|(id, _)| id)
            .collect();
        self.paths.offer(&keep);
        silent
    }

    /// Whether this node admitted `url` as one of its relays.
    pub fn uses_relay(&self, url: &str) -> bool {
        self.live_relays().iter().any(|r| r.url.as_str() == url)
    }

    /// What this node knows about its reachability on `endpoint`.
    pub fn connectivity(&self, endpoint: &Endpoint) -> Connectivity {
        let external = self.external.lock().clone();
        let offered = self.paths.forwarders();
        let forwarders = self
            .paths
            .forwarder_rtts()
            .into_iter()
            .filter(|(id, _)| offered.contains(id))
            .map(|(id, rtt)| reachability::ForwarderState {
                endpoint: id.to_string(),
                rtt_ms: rtt.as_millis() as u64,
                direct: self.paths.forwarder_is_direct(&id),
            })
            .collect();
        let punched = self.paths.punched_peers().len();
        reachability::connectivity(
            endpoint,
            &self.observations.lock(),
            &external,
            forwarders,
            self.paths.latency(),
            punched,
            now_ms(),
        )
    }

    /// Runs [`Self::sync_once`] every minute until `endpoint` closes, and
    /// every few seconds while a boot identity is still unresolved, so the
    /// nodes of a network starting together find each other as soon as
    /// their records are up. With no `signer` the machine has no identity to
    /// publish and only learns.
    pub async fn run(
        self: Arc<Self>,
        endpoint: Endpoint,
        signer: Option<&'static dyn HardwareSigner>,
    ) {
        // This machine's identity, read from the hardware once: it cannot
        // change while the node runs, so every round reuses it.
        let own = match signer {
            Some(s) => tokio::task::spawn_blocking(move || s.public_key_sec1().ok())
                .await
                .ok()
                .flatten()
                .map(|pk| tenzro_types::did_derivation::machine_did(&pk)),
            None => None,
        };
        loop {
            self.sync_once(&endpoint, signer).await;
            self.admit_pending(&endpoint).await;
            self.remember_direct_addrs(&endpoint).await;
            let unresolved = self
                .boot
                .iter()
                .any(|b| Some(&b.did) != own.as_ref() && self.store.lookup(&b.did).is_none());
            let (relayless, waiting) = (
                self.live_relays().is_empty(),
                !self.pending.lock().is_empty(),
            );
            let wait = if unresolved || (relayless && waiting) {
                BOOT_RETRY
            } else if waiting {
                RELAY_RETRY
            } else {
                TICK
            };
            tokio::select! {
                _ = endpoint.closed() => return,
                _ = tokio::time::sleep(wait) => {}
            }
        }
    }
}

#[cfg(test)]
#[expect(
    clippy::disallowed_methods,
    reason = "the test runner bounds every wait in a test"
)]
mod tests {
    use super::*;
    use crate::discovery::{ALPN_DISCOVERY, DiscoveryProtocol};
    use crate::identity_record::tests::TestMachineKey;
    use crate::test_ports;
    use iroh::Watcher;
    use iroh::endpoint::Connection;
    use iroh::protocol::{AcceptError, ProtocolHandler, Router};

    const ECHO_ALPN: &[u8] = b"tenzro/test/echo";

    #[derive(Debug, Clone)]
    struct Echo;

    impl ProtocolHandler for Echo {
        async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
            while let Ok((mut send, mut recv)) = conn.accept_bi().await {
                let msg = recv
                    .read_to_end(1024)
                    .await
                    .map_err(AcceptError::from_err)?;
                send.write_all(&msg).await.map_err(AcceptError::from_err)?;
                send.finish().map_err(AcceptError::from_err)?;
            }
            Ok(())
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn endpoints_negotiate_the_post_quantum_hybrid() {
        let groups: Vec<_> = peer_crypto_provider()
            .kx_groups
            .iter()
            .map(|g| g.name())
            .collect();
        assert_eq!(
            groups,
            [rustls::NamedGroup::X25519MLKEM768],
            "the hybrid alone"
        );

        // A server that accepts nothing but the hybrid: the dial succeeds only
        // if the client negotiated X25519MLKEM768.
        let server = on_loopback(Endpoint::builder(presets::Minimal))
            .crypto_provider(Arc::new(peer_crypto_provider()))
            .bind()
            .await
            .unwrap();
        let router = Router::builder(server.clone())
            .accept(ECHO_ALPN, Echo)
            .spawn();
        let client = on_loopback(base_builder()).bind().await.unwrap();
        let conn = client
            .connect(server.addr(), ECHO_ALPN)
            .await
            .expect("hybrid key exchange");
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        send.write_all(b"pq").await.unwrap();
        send.finish().unwrap();
        assert_eq!(recv.read_to_end(64).await.unwrap(), b"pq");
        conn.close(0u32.into(), b"done");
        router.shutdown().await.unwrap();
    }

    /// Forwards datagrams between a client and `server` and logs each one:
    /// `true` for client to server, with its length.
    async fn logging_proxy(server: SocketAddr) -> (SocketAddr, Arc<Mutex<Vec<(bool, usize)>>>) {
        let front = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let back = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let log: Arc<Mutex<Vec<(bool, usize)>>> = Arc::default();
        let client: Arc<Mutex<Option<SocketAddr>>> = Arc::default();
        {
            let (front, back, log, client) =
                (front.clone(), back.clone(), log.clone(), client.clone());
            tokio::spawn(async move {
                let mut buf = vec![0u8; 65_536];
                while let Ok((n, from)) = front.recv_from(&mut buf).await {
                    *client.lock() = Some(from);
                    log.lock().push((true, n));
                    back.send_to(&buf[..n], server).await.ok();
                }
            });
        }
        {
            let (front, log) = (front.clone(), log.clone());
            tokio::spawn(async move {
                let mut buf = vec![0u8; 65_536];
                while let Ok(n) = back.recv(&mut buf).await {
                    log.lock().push((false, n));
                    let to = *client.lock();
                    if let Some(to) = to {
                        front.send_to(&buf[..n], to).await.ok();
                    }
                }
            });
        }
        (front.local_addr().unwrap(), log)
    }

    /// The client's first flight (datagrams before the server's first) and
    /// the server's answer to it (datagrams before the client's next), as
    /// (datagrams, bytes) each.
    fn first_flights(log: &[(bool, usize)]) -> ((usize, usize), (usize, usize)) {
        let client: Vec<usize> = log
            .iter()
            .take_while(|(c, _)| *c)
            .map(|(_, n)| *n)
            .collect();
        let server: Vec<usize> = log[client.len()..]
            .iter()
            .take_while(|(c, _)| !*c)
            .map(|(_, n)| *n)
            .collect();
        (
            (client.len(), client.iter().sum()),
            (server.len(), server.iter().sum()),
        )
    }

    /// Measures the first flights of the X25519MLKEM768 handshake through a
    /// logging proxy, against classical X25519. The server must answer the
    /// client's first flight within QUIC's anti-amplification limit (three
    /// times what it received) and the hybrid client's first flight is at
    /// most two datagrams. The sizes are printed as MEASURE lines.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_hybrid_handshake_first_flights_stay_within_the_amplification_limit() {
        for hybrid in [true, false] {
            let (server, client) = if hybrid {
                let server = on_loopback(
                    Endpoint::builder(presets::Minimal)
                        .crypto_provider(Arc::new(peer_crypto_provider())),
                )
                .bind()
                .await
                .unwrap();
                (server, on_loopback(base_builder()).bind().await.unwrap())
            } else {
                (classical_endpoint().await, classical_endpoint().await)
            };
            let router = Router::builder(server.clone())
                .accept(ECHO_ALPN, Echo)
                .spawn();
            let port = server
                .bound_sockets()
                .iter()
                .find(|s| s.is_ipv4())
                .unwrap()
                .port();
            let (proxy, log) = logging_proxy(SocketAddr::from(([127, 0, 0, 1], port))).await;
            let conn = client
                .connect(
                    EndpointAddr::new(server.id()).with_addrs([iroh::TransportAddr::Ip(proxy)]),
                    ECHO_ALPN,
                )
                .await
                .expect("handshake through the proxy");
            let (mut send, mut recv) = conn.open_bi().await.unwrap();
            send.write_all(b"pq").await.unwrap();
            send.finish().unwrap();
            assert_eq!(recv.read_to_end(64).await.unwrap(), b"pq");
            let ((c_n, c_bytes), (s_n, s_bytes)) = first_flights(&log.lock());
            let kind = if hybrid { "x25519mlkem768" } else { "x25519" };
            eprintln!(
                "MEASURE handshake {kind}: client first flight {c_n} datagrams {c_bytes} bytes; \
                 server answer {s_n} datagrams {s_bytes} bytes; ratio {:.2}",
                s_bytes as f64 / c_bytes as f64
            );
            assert!(
                s_bytes <= 3 * c_bytes,
                "{kind}: the server sent more than 3x before validation"
            );
            if hybrid {
                assert!(
                    c_n <= 2,
                    "the hybrid client's first flight took {c_n} datagrams"
                );
            }
            conn.close(0u32.into(), b"done");
            router.shutdown().await.unwrap();
            client.close().await;
        }
    }

    /// An endpoint that speaks only classical X25519, as a downgraded or
    /// non-Tenzro peer would.
    async fn classical_endpoint() -> Endpoint {
        let mut classical = rustls::crypto::aws_lc_rs::default_provider();
        classical.kx_groups = vec![rustls::crypto::aws_lc_rs::kx_group::X25519];
        on_loopback(Endpoint::builder(presets::Minimal))
            .crypto_provider(Arc::new(classical))
            .bind()
            .await
            .unwrap()
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_classical_only_peer_is_refused() {
        let tenzro = on_loopback(base_builder()).bind().await.unwrap();
        let router = Router::builder(tenzro.clone())
            .accept(ECHO_ALPN, Echo)
            .spawn();
        let classical = classical_endpoint().await;
        let classical_router = Router::builder(classical.clone())
            .accept(ECHO_ALPN, Echo)
            .spawn();
        let wait = std::time::Duration::from_secs(20);

        let inbound = tokio::time::timeout(wait, classical.connect(tenzro.addr(), ECHO_ALPN)).await;
        assert!(
            !matches!(inbound, Ok(Ok(_))),
            "a Tenzro endpoint accepted an X25519-only handshake"
        );
        let outbound =
            tokio::time::timeout(wait, tenzro.connect(classical.addr(), ECHO_ALPN)).await;
        assert!(
            !matches!(outbound, Ok(Ok(_))),
            "a Tenzro endpoint completed an X25519-only handshake"
        );

        router.shutdown().await.unwrap();
        classical_router.shutdown().await.unwrap();
    }

    /// A session store that keeps tickets but reports X25519 as the group
    /// every server chose last time: what a forged ServerHello leaves behind.
    #[derive(Debug)]
    struct ClassicalHint(rustls::client::ClientSessionMemoryCache);

    impl rustls::client::ClientSessionStore for ClassicalHint {
        fn set_kx_hint(&self, _: rustls::pki_types::ServerName<'static>, _: rustls::NamedGroup) {}
        fn kx_hint(&self, _: &rustls::pki_types::ServerName<'_>) -> Option<rustls::NamedGroup> {
            Some(rustls::NamedGroup::X25519)
        }
        fn set_tls12_session(
            &self,
            name: rustls::pki_types::ServerName<'static>,
            value: rustls::client::Tls12ClientSessionValue,
        ) {
            self.0.set_tls12_session(name, value)
        }
        fn tls12_session(
            &self,
            name: &rustls::pki_types::ServerName<'_>,
        ) -> Option<rustls::client::Tls12ClientSessionValue> {
            self.0.tls12_session(name)
        }
        fn remove_tls12_session(&self, name: &rustls::pki_types::ServerName<'static>) {
            self.0.remove_tls12_session(name)
        }
        fn insert_tls13_ticket(
            &self,
            name: rustls::pki_types::ServerName<'static>,
            value: rustls::client::Tls13ClientSessionValue,
        ) {
            self.0.insert_tls13_ticket(name, value)
        }
        fn take_tls13_ticket(
            &self,
            name: &rustls::pki_types::ServerName<'static>,
        ) -> Option<rustls::client::Tls13ClientSessionValue> {
            self.0.take_tls13_ticket(name)
        }
    }

    /// Drives a client and a server handshake over memory until both finish
    /// and the server's tickets have reached the client.
    fn handshake(
        client: &mut rustls::ClientConnection,
        server: &mut rustls::ServerConnection,
    ) -> Result<(), rustls::Error> {
        fn pump(
            from: &mut impl std::ops::DerefMut<Target = rustls::ConnectionCommon<impl Sized>>,
            to: &mut impl std::ops::DerefMut<Target = rustls::ConnectionCommon<impl Sized>>,
        ) -> Result<bool, rustls::Error> {
            let mut buf = Vec::new();
            while from.wants_write() {
                from.write_tls(&mut buf).unwrap();
            }
            let mut rd = &buf[..];
            while !rd.is_empty() {
                to.read_tls(&mut rd).unwrap();
                to.process_new_packets()?;
            }
            Ok(!buf.is_empty())
        }
        for _ in 0..16 {
            let sent = pump(client, server)?;
            let answered = pump(server, client)?;
            if !sent && !answered && !client.is_handshaking() && !server.is_handshaking() {
                return Ok(());
            }
        }
        Err(rustls::Error::General("handshake did not finish".into()))
    }

    #[test]
    fn a_classical_hint_neither_downgrades_nor_resumes_classically() {
        use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
        let certified =
            rcgen::generate_simple_self_signed(vec!["peer.tenzro.test".into()]).unwrap();
        let cert = CertificateDer::from(certified.cert.der().to_vec());
        let key = PrivateKeyDer::try_from(certified.signing_key.serialize_der()).unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert.clone()).unwrap();
        let name = ServerName::try_from("peer.tenzro.test").unwrap();

        let server_config = Arc::new(
            rustls::ServerConfig::builder_with_provider(Arc::new(peer_crypto_provider()))
                .with_protocol_versions(&[&rustls::version::TLS13])
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(vec![cert], key)
                .unwrap(),
        );
        let store: Arc<dyn rustls::client::ClientSessionStore> = Arc::new(ClassicalHint(
            rustls::client::ClientSessionMemoryCache::new(8),
        ));
        let client_config = |provider: rustls::crypto::CryptoProvider| {
            let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
                .with_protocol_versions(&[&rustls::version::TLS13])
                .unwrap()
                .with_root_certificates(roots.clone())
                .with_no_client_auth();
            config.resumption = rustls::client::Resumption::store(store.clone());
            config.enable_early_data = true;
            Arc::new(config)
        };
        let tenzro_client = client_config(peer_crypto_provider());

        // A full handshake with the poisoned hint.
        let mut client =
            rustls::ClientConnection::new(tenzro_client.clone(), name.clone()).unwrap();
        let mut server = rustls::ServerConnection::new(server_config.clone()).unwrap();
        handshake(&mut client, &mut server).unwrap();
        assert_eq!(
            client.handshake_kind(),
            Some(rustls::HandshakeKind::Full),
            "the first ClientHello carried a classical share"
        );
        assert_eq!(
            client.negotiated_key_exchange_group().map(|g| g.name()),
            Some(rustls::NamedGroup::X25519MLKEM768),
            "a classical hint downgraded a full handshake"
        );

        // The resumed handshake with the same poisoned hint.
        let mut client = rustls::ClientConnection::new(tenzro_client, name.clone()).unwrap();
        let mut server = rustls::ServerConnection::new(server_config.clone()).unwrap();
        handshake(&mut client, &mut server).unwrap();
        assert_eq!(
            client.handshake_kind(),
            Some(rustls::HandshakeKind::Resumed),
            "the second handshake did not resume"
        );
        assert_eq!(
            client.negotiated_key_exchange_group().map(|g| g.name()),
            Some(rustls::NamedGroup::X25519MLKEM768),
            "a classical hint downgraded a resumed handshake"
        );

        // A classical-only client holding a valid ticket tries to resume.
        let mut classical = rustls::crypto::aws_lc_rs::default_provider();
        classical.kx_groups = vec![rustls::crypto::aws_lc_rs::kx_group::X25519];
        let mut client = rustls::ClientConnection::new(client_config(classical), name).unwrap();
        let mut server = rustls::ServerConnection::new(server_config).unwrap();
        assert!(
            handshake(&mut client, &mut server).is_err(),
            "a Tenzro server resumed a session over X25519 alone"
        );
    }

    #[tokio::test]
    async fn an_endpoint_with_no_relays_reaches_no_relay_or_discovery_host() {
        let endpoint = with_relays(on_loopback(base_builder()), &[], None)
            .bind()
            .await
            .unwrap();
        assert!(endpoint.addr().relay_urls().next().is_none());
        assert!(endpoint.home_relay_status().get().is_empty());
        endpoint.close().await;
    }

    /// One node of the test cluster: its identity transport, its endpoint
    /// serving discovery and echo, and its machine key.
    struct TestNode {
        transport: Arc<IdentityTransport>,
        endpoint: Endpoint,
        _router: Router,
        key: &'static TestMachineKey,
        /// The endpoints that opened the discovery protocol to this node.
        asked_by: Arc<Mutex<std::collections::HashSet<EndpointId>>>,
    }

    /// The discovery protocol, noting each endpoint that opens it.
    #[derive(Debug, Clone)]
    struct NotedDiscovery {
        inner: DiscoveryProtocol,
        asked_by: Arc<Mutex<std::collections::HashSet<EndpointId>>>,
    }

    impl ProtocolHandler for NotedDiscovery {
        async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
            self.asked_by.lock().insert(conn.remote_id());
            self.inner.accept(conn).await
        }
    }

    impl TestNode {
        async fn start(
            seed: u8,
            boot: Vec<BootIdentity>,
            role: Option<RelayRoleConfig>,
            relay_only: bool,
        ) -> Self {
            Self::start_on(seed, boot, role, relay_only, None).await
        }

        /// As [`Self::start`], with the endpoint's IPv4 and IPv6 sockets on
        /// `port` when given.
        async fn start_on(
            seed: u8,
            boot: Vec<BootIdentity>,
            role: Option<RelayRoleConfig>,
            relay_only: bool,
            port: Option<u16>,
        ) -> Self {
            let key: &'static TestMachineKey = Box::leak(Box::new(TestMachineKey::from_seed(seed)));
            let transport = IdentityTransport::start(boot, &[], role.as_ref(), Some(key.did()))
                .await
                .unwrap();
            let base = match port {
                // A NAT lab machine listens on its network namespace's
                // interfaces, at the port the lab forwards.
                Some(port) => {
                    base_builder_with(&ConnectionLimits::default(), transport.serves_peer_relay())
                        .clear_ip_transports()
                        .bind_addr(std::net::SocketAddr::from(([0, 0, 0, 0], port)))
                        .unwrap()
                        .bind_addr(std::net::SocketAddr::from(([0u16; 8], port)))
                        .unwrap()
                }
                None => on_loopback(base_builder_with(
                    &ConnectionLimits::default(),
                    transport.serves_peer_relay(),
                )),
            };
            let mut builder = transport.paths().install(with_relay_urls(
                base,
                &transport.endpoint_relay_urls(),
                Some(transport.store().clone()),
            ));
            if relay_only {
                builder = builder.clear_ip_transports();
            }
            let endpoint = builder.bind().await.unwrap();
            transport
                .paths()
                .attach(&endpoint, &ConnectionLimits::default());
            if !transport.relays().is_empty() {
                tokio::time::timeout(Duration::from_secs(20), endpoint.online())
                    .await
                    .expect("reaches its relay");
            }
            let asked_by = Arc::new(Mutex::new(std::collections::HashSet::new()));
            let mut router = Router::builder(endpoint.clone())
                .accept(
                    ALPN_DISCOVERY,
                    NotedDiscovery {
                        inner: DiscoveryProtocol::new(transport.store().clone()),
                        asked_by: asked_by.clone(),
                    },
                )
                .accept(ECHO_ALPN, Echo);
            if let Some(service) = transport.peer_relay_service() {
                router = router.accept(crate::paths::ALPN_PEER_RELAY, service);
            }
            router = router.accept(
                crate::paths::ALPN_PUNCH,
                crate::paths::PunchService::new(transport.paths().clone()),
            );
            let router = router.spawn();
            Self {
                transport,
                endpoint,
                _router: router,
                key,
                asked_by,
            }
        }

        async fn sync(&self) {
            self.transport
                .sync_once(&self.endpoint, Some(self.key))
                .await;
        }
    }

    /// One machine of the NAT lab (`scripts/netlab/nat-lab.sh`), not a unit
    /// test: the lab starts this test in several network namespaces, behind
    /// NATs and firewalls it builds, and reads the lines it prints.
    ///
    /// With `NAT_LAB_SERVE_URL` the machine serves the relay role at that
    /// URL (its listener behind the lab's TCP forwarder); with
    /// `NAT_LAB_RELAY_URL` and `NAT_LAB_RELAY_SEED` it joins through the
    /// relay of that machine. With `NAT_LAB_TARGET` set to another machine's
    /// seed it dials it and prints the path the connection settles on:
    /// `PATH direct <addr>` or `PATH relay`, after `PATHTIME`: the time from
    /// the dial to that path.
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "runs as one node inside the NAT lab: scripts/netlab/nat-lab.sh starts it with --ignored"]
    async fn nat_lab_node() {
        let var = |k: &str| std::env::var(k).unwrap_or_default();
        let seed: u8 = var("NAT_LAB_SEED").parse().expect("NAT_LAB_SEED");
        let secs: u64 = var("NAT_LAB_SECS").parse().unwrap_or(120);
        // Dial once peers have had rounds to report this node's address.
        let dial_after = Duration::from_secs(var("NAT_LAB_DIAL_AFTER").parse().unwrap_or(90));
        let role = Url::parse(&var("NAT_LAB_SERVE_URL"))
            .ok()
            .map(|public_url| RelayRoleConfig {
                bind_addr: "127.0.0.1:3340".parse().unwrap(),
                public_url,
            });
        let boot: Vec<BootIdentity> = match (
            Url::parse(&var("NAT_LAB_RELAY_URL")),
            var("NAT_LAB_RELAY_SEED").parse::<u8>(),
        ) {
            (Ok(url), Ok(relay_seed)) => {
                vec![
                    format!("{}@{url}", TestMachineKey::from_seed(relay_seed).did())
                        .parse()
                        .unwrap(),
                ]
            }
            _ => Vec::new(),
        };
        let port = var("NAT_LAB_UDP_PORT").parse::<u16>().ok();
        let node = TestNode::start_on(seed, boot, role, false, port).await;
        println!("UP {} {}", node.key.did(), node.endpoint.id());
        let target = var("NAT_LAB_TARGET")
            .parse::<u8>()
            .ok()
            .map(|t| TestMachineKey::from_seed(t).did());
        let start = tokio::time::Instant::now();
        let mut dialed = false;
        let mut held: Option<iroh::endpoint::Connection> = None;
        while start.elapsed() < Duration::from_secs(secs) {
            node.sync().await;
            let report = node.transport.connectivity(&node.endpoint);
            println!("REPORT {}", serde_json::to_string(&report).unwrap());
            println!(
                "PATHSTATS {:?} {:?}",
                node.transport.paths().stats(),
                node.transport
                    .peer_relay_service()
                    .map(|s| (s.stats(), s.clients()))
            );
            println!(
                "PUNCH {:?} {:?}",
                node.transport.paths().nat_side(),
                node.transport.paths().punch_log()
            );
            if let (Some(did), false) = (&target, dialed)
                && let Some(record) = node
                    .transport
                    .store()
                    .lookup(did)
                    .filter(|_| start.elapsed() > dial_after)
            {
                dialed = true;
                let dialed_at = tokio::time::Instant::now();
                let conn = node
                    .endpoint
                    .connect(node.transport.dial_addr(&record).unwrap(), ECHO_ALPN)
                    .await
                    .expect("dial the target");
                let (mut send, mut recv) = conn.open_bi().await.unwrap();
                send.write_all(b"nat lab").await.unwrap();
                send.finish().unwrap();
                assert_eq!(recv.read_to_end(64).await.unwrap(), b"nat lab");
                let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
                let mut path = None;
                while path.is_none() && tokio::time::Instant::now() < deadline {
                    path = conn.paths().iter().find_map(|p| {
                        match (p.is_selected(), p.remote_addr()) {
                            (true, iroh::TransportAddr::Ip(a)) => Some(format!("direct {a}")),
                            (true, iroh::TransportAddr::Custom(c)) => {
                                crate::paths::parse_peer_relay_addr(c)
                                    .map(|(f, _)| format!("peer {}", f.fmt_short()))
                                    .or_else(|| {
                                        crate::paths::parse_punched_addr(c)
                                            .map(|_| "punched".to_string())
                                    })
                            }
                            _ => None,
                        }
                    });
                    if path.is_none() {
                        tokio::time::sleep(Duration::from_millis(20)).await;
                    }
                }
                // From the dial to the first selected path that is not the
                // relay, or how long it waited for one.
                println!(
                    "PATHTIME {} {}",
                    if path.is_some() {
                        "direct_after_ms"
                    } else {
                        "none_within_ms"
                    },
                    dialed_at.elapsed().as_millis()
                );
                println!("PATH {}", path.unwrap_or_else(|| "relay".to_string()));
                let all: Vec<String> = conn
                    .paths()
                    .iter()
                    .map(|p| {
                        format!(
                            "{}{} {:?}",
                            if p.is_selected() { "*" } else { "" },
                            p.remote_addr(),
                            p.rtt()
                        )
                    })
                    .collect();
                println!("PATHS {}", all.join(" | "));
                // Kept open to the end, so the final path list shows where
                // the connection settled.
                held = Some(conn);
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
        if let Some(conn) = held {
            let all: Vec<String> = conn
                .paths()
                .iter()
                .map(|p| {
                    format!(
                        "{}{} {:?}",
                        if p.is_selected() { "*" } else { "" },
                        p.remote_addr(),
                        p.rtt()
                    )
                })
                .collect();
            println!("FINALPATHS {}", all.join(" | "));
        }
    }

    /// A node that uses relays signs no record before it holds a connection to
    /// one: a record naming no relay would leave every peer holding it unable
    /// to dial the node. Once the node is homed at a relay, its record names it.
    #[tokio::test(flavor = "multi_thread")]
    async fn no_record_names_no_way_to_reach_the_node() {
        let port = test_ports::tcp();
        let url = Url::parse(&format!("http://127.0.0.1:{port}/")).unwrap();
        let role = RelayRoleConfig {
            bind_addr: format!("127.0.0.1:{port}").parse().unwrap(),
            public_url: url.clone(),
        };
        let key: &'static TestMachineKey = Box::leak(Box::new(TestMachineKey::from_seed(80)));
        let transport = IdentityTransport::start(vec![], &[], Some(&role), Some(key.did()))
            .await
            .unwrap();
        let endpoint = iroh::SecretKey::from_bytes(&[7; 32]).public();
        assert!(
            transport.own_record(endpoint, &[], key).is_none(),
            "no relay yet"
        );
        assert!(
            transport.store().lookup(&key.did()).is_none(),
            "nothing served at /identity"
        );
        let record = transport
            .own_record(endpoint, std::slice::from_ref(&url), key)
            .expect("homed at its relay");
        assert_eq!(
            record
                .relays
                .iter()
                .map(|r| r.url.clone())
                .collect::<Vec<_>>(),
            vec![url.clone()]
        );
        assert!(
            endpoint_addr(&record)
                .unwrap()
                .relay_urls()
                .next()
                .is_some()
        );
        // Losing every relay connection keeps the last record that names one.
        assert_eq!(transport.own_record(endpoint, &[], key), Some(record));
    }

    /// A record signed while its sequence cannot be saved (here the file's
    /// directory is a file) is saved on a later round once saving works, so
    /// the next boot still starts above it.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_sequence_that_could_not_be_saved_is_saved_on_a_later_round() {
        let dir = std::env::temp_dir().join(format!(
            "tenzro-record-sequence-retry-{}-{}",
            std::process::id(),
            now_ms()
        ));
        let blocked = dir.join("iroh");
        let path = blocked.join("record-sequence");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(&blocked, b"not a directory").unwrap();
        let key: &'static TestMachineKey = Box::leak(Box::new(TestMachineKey::from_seed(85)));
        let port = test_ports::tcp();
        let url = Url::parse(&format!("http://127.0.0.1:{port}/")).unwrap();
        let role = RelayRoleConfig {
            bind_addr: format!("127.0.0.1:{port}").parse().unwrap(),
            public_url: url.clone(),
        };
        let transport = IdentityTransport::start(vec![], &[], Some(&role), Some(key.did()))
            .await
            .unwrap();
        let endpoint = iroh::SecretKey::from_bytes(&[13; 32]).public();
        transport.keep_record_sequence(path.clone());
        let record = transport
            .own_record(endpoint, std::slice::from_ref(&url), key)
            .unwrap();
        assert!(!path.exists(), "saved through a file");

        std::fs::remove_file(&blocked).unwrap();
        let again = transport
            .own_record(endpoint, std::slice::from_ref(&url), key)
            .unwrap();
        assert_eq!(again.sequence, record.sequence, "a new record was signed");
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            record.sequence.to_string()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A machine restarted with its clock set back signs a record that
    /// follows the last one it signed before the restart, so the peers
    /// holding that one take the new one; read from the clock alone, its
    /// sequence would be lower and the record refused as stale.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_first_record_of_a_boot_follows_the_last_of_the_boot_before() {
        let dir = std::env::temp_dir().join(format!(
            "tenzro-record-sequence-{}-{}",
            std::process::id(),
            now_ms()
        ));
        let path = dir.join("record-sequence");
        let key: &'static TestMachineKey = Box::leak(Box::new(TestMachineKey::from_seed(84)));
        let boot = |endpoint: u8| async move {
            let port = test_ports::tcp();
            let url = Url::parse(&format!("http://127.0.0.1:{port}/")).unwrap();
            let role = RelayRoleConfig {
                bind_addr: format!("127.0.0.1:{port}").parse().unwrap(),
                public_url: url.clone(),
            };
            let transport = IdentityTransport::start(vec![], &[], Some(&role), Some(key.did()))
                .await
                .unwrap();
            let endpoint = iroh::SecretKey::from_bytes(&[endpoint; 32]).public();
            (transport, endpoint, url)
        };
        // The boot before ran with its clock an hour fast.
        let fast = now_ms() + 3_600_000;
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(&path, fast.to_string()).unwrap();

        let (transport, endpoint, url) = boot(9).await;
        transport.keep_record_sequence(path.clone());
        let first = transport
            .own_record(endpoint, std::slice::from_ref(&url), key)
            .unwrap();
        assert_eq!(first.sequence, fast + 1);
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            (fast + 1).to_string()
        );

        // The next boot, a new endpoint: its record follows again.
        let (transport, endpoint, url) = boot(10).await;
        transport.keep_record_sequence(path.clone());
        let second = transport
            .own_record(endpoint, std::slice::from_ref(&url), key)
            .unwrap();
        assert_eq!(second.sequence, fast + 2);

        // A value no peer can hold, at the top of the range, is not
        // followed either: the sequence would never rise again.
        std::fs::write(&path, u64::MAX.to_string()).unwrap();
        let (transport, endpoint, url) = boot(14).await;
        transport.keep_record_sequence(path.clone());
        let after_max = transport
            .own_record(endpoint, std::slice::from_ref(&url), key)
            .unwrap();
        assert!(after_max.sequence < fast, "a frozen sequence was followed");

        // A file that holds no number is passed over, not followed.
        std::fs::write(&path, "").unwrap();
        let (transport, endpoint, url) = boot(12).await;
        transport.keep_record_sequence(path.clone());
        let after_empty = transport
            .own_record(endpoint, std::slice::from_ref(&url), key)
            .unwrap();
        assert!(after_empty.sequence < fast);
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            after_empty.sequence.to_string(),
            "the file was not written again"
        );

        // With nothing kept, the sequence is the clock's reading.
        let (transport, endpoint, url) = boot(11).await;
        let unkept = transport
            .own_record(endpoint, std::slice::from_ref(&url), key)
            .unwrap();
        assert!(unkept.sequence < fast);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Once the node binds its records with its machine ML-DSA key, the next
    /// record it signs carries the binding, verifies, and is the one it
    /// serves; the versioned RPC ALPNs then hold its ML-DSA endpoint key.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_node_that_binds_its_records_signs_them_with_the_binding() {
        let port = test_ports::tcp();
        let url = Url::parse(&format!("http://127.0.0.1:{port}/")).unwrap();
        let role = RelayRoleConfig {
            bind_addr: format!("127.0.0.1:{port}").parse().unwrap(),
            public_url: url.clone(),
        };
        let key: &'static TestMachineKey = Box::leak(Box::new(TestMachineKey::from_seed(81)));
        let transport = IdentityTransport::start(vec![], &[], Some(&role), Some(key.did()))
            .await
            .unwrap();
        let endpoint = iroh::SecretKey::from_bytes(&[8; 32]).public();
        let plain = transport
            .own_record(endpoint, std::slice::from_ref(&url), key)
            .unwrap();
        assert!(plain.pq.is_none());
        assert!(transport.pq_channel().own_key().is_none());

        assert!(transport.enable_pq_binding(
            Arc::new(crate::pq_endpoint::tests::TestMachinePq::generate()),
            Arc::new(TestMachineKey::from_seed(81)),
        ));
        let bound = transport
            .own_record(endpoint, std::slice::from_ref(&url), key)
            .unwrap();
        assert!(bound.pq.is_some(), "bound");
        bound.check_pq_binding().unwrap();
        assert_eq!(
            transport
                .pq_channel()
                .own_key()
                .unwrap()
                .p256
                .public_key_sec1()
                .unwrap()
                .to_vec(),
            bound.machine_key
        );
        assert_eq!(transport.store().lookup(&key.did()), Some(bound.clone()));
        // A newer record without the binding is now refused for this
        // identity.
        let _ = plain;
        let stripped = EndpointRecord::sign(
            key,
            iroh_endpoint_key(endpoint),
            Vec::new(),
            Vec::new(),
            None,
            RecordScope::Network,
            Vec::new(),
            bound.sequence + 1,
            now_ms(),
        )
        .unwrap();
        assert_eq!(
            transport.store().offer(stripped),
            Err(crate::identity_record::RecordError::PqBindingMissing)
        );
    }

    /// A relay operator's record is fetched from its relay before its endpoint
    /// is homed there; the node joining through that relay must still reach it,
    /// and the operator must learn the joining node's record in return.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_node_joining_through_a_relay_reaches_its_operator_and_back() {
        let port = test_ports::tcp();
        let url = Url::parse(&format!("http://127.0.0.1:{port}/")).unwrap();
        let role = RelayRoleConfig {
            bind_addr: format!("127.0.0.1:{port}").parse().unwrap(),
            public_url: url.clone(),
        };
        let operator_key = TestMachineKey::from_seed(81).did();
        let joiner_key = TestMachineKey::from_seed(82).did();
        let operator = TestNode::start(
            81,
            vec![format!("{joiner_key}@{url}").parse().unwrap()],
            Some(role),
            true,
        )
        .await;
        operator.sync().await;
        let joiner = TestNode::start(
            82,
            vec![format!("{operator_key}@{url}").parse().unwrap()],
            None,
            true,
        )
        .await;
        for _ in 0..3 {
            joiner.sync().await;
            operator.sync().await;
        }
        let theirs = joiner
            .transport
            .store()
            .lookup(&operator_key)
            .expect("the operator's record");
        assert!(
            endpoint_addr(&theirs)
                .unwrap()
                .relay_urls()
                .next()
                .is_some(),
            "names its relay"
        );
        assert!(
            operator.transport.store().lookup(&joiner_key).is_some(),
            "the operator learned the joiner's record"
        );
        assert_eq!(
            operator.transport.boot_endpoints(operator.endpoint.id()),
            vec![joiner.endpoint.id()]
        );
    }

    /// Two members of an epoch set that know each other only from the
    /// disclosed endpoint and machine identity, both reachable only through
    /// a relay whose operator is outside the set, still come to hold each
    /// other's record: neither record travels through the operator.
    #[tokio::test(flavor = "multi_thread")]
    async fn epoch_set_members_fetch_each_others_record_from_each_other() {
        let port = test_ports::tcp();
        let url = Url::parse(&format!("http://127.0.0.1:{port}/")).unwrap();
        let role = RelayRoleConfig {
            bind_addr: format!("127.0.0.1:{port}").parse().unwrap(),
            public_url: url.clone(),
        };
        let operator_did = TestMachineKey::from_seed(91).did();
        let operator = TestNode::start(91, vec![], Some(role), true).await;
        operator.sync().await;
        let boot = || vec![format!("{operator_did}@{url}").parse().unwrap()];
        let a = TestNode::start(92, boot(), None, true).await;
        let b = TestNode::start(93, boot(), None, true).await;
        let set: std::collections::HashSet<String> =
            [a.key.did(), b.key.did()].into_iter().collect();
        a.transport.share_within_epoch_set(set.clone());
        b.transport.share_within_epoch_set(set);
        for _ in 0..3 {
            a.sync().await;
            b.sync().await;
            operator.sync().await;
        }
        assert!(
            a.transport.store().lookup(&b.key.did()).is_none(),
            "an epoch-set record does not travel through an outside operator"
        );
        assert!(
            a.transport
                .fetch_disclosed_record(&a.endpoint, b.endpoint.id(), &b.key.did())
                .await,
            "a member fetches the other's record from it"
        );
        let held = a.transport.store().lookup(&b.key.did()).unwrap();
        assert_eq!(iroh_endpoint(&held).unwrap(), b.endpoint.id());
        assert!(
            b.transport.store().lookup(&a.key.did()).is_some(),
            "and hands it its own on the way"
        );
        let outsider = TestNode::start(94, boot(), None, true).await;
        outsider.sync().await;
        assert!(
            !outsider
                .transport
                .fetch_disclosed_record(&outsider.endpoint, b.endpoint.id(), &b.key.did())
                .await,
            "an outsider is not answered"
        );
    }

    /// A validator scopes its record to the epoch set and still hands it to
    /// the machine on its own boot list. That machine then names the
    /// validator's endpoint, and passes the record to no one: a node that
    /// boots from the same machine never comes to hold it.
    #[tokio::test]
    async fn an_epoch_set_record_reaches_the_boot_machine_and_stops_there() {
        let port = test_ports::tcp();
        let url = Url::parse(&format!("http://127.0.0.1:{port}/")).unwrap();
        let role = RelayRoleConfig {
            bind_addr: format!("127.0.0.1:{port}").parse().unwrap(),
            public_url: url.clone(),
        };
        let operator_did = TestMachineKey::from_seed(95).did();
        let operator = TestNode::start(95, vec![], Some(role), true).await;
        operator.sync().await;
        let boot = || vec![format!("{operator_did}@{url}").parse().unwrap()];
        let validator = TestNode::start(96, boot(), None, true).await;
        let bystander = TestNode::start(97, boot(), None, true).await;
        validator
            .transport
            .share_within_epoch_set([validator.key.did()].into_iter().collect());
        for _ in 0..3 {
            validator.sync().await;
            bystander.sync().await;
            operator.sync().await;
        }

        let held = operator
            .transport
            .store()
            .lookup(&validator.key.did())
            .expect("the boot machine holds the validator's record");
        assert_eq!(held.scope, RecordScope::EpochSet);
        assert_eq!(
            operator
                .transport
                .store()
                .naming(validator.endpoint.id())
                .map(|r| r.machine_did()),
            Some(validator.key.did()),
            "the boot machine names the validator's endpoint"
        );
        assert!(
            validator
                .transport
                .store()
                .lookup(&bystander.key.did())
                .is_some(),
            "the validator and the bystander did meet through the boot machine"
        );
        assert!(
            bystander
                .transport
                .store()
                .lookup(&validator.key.did())
                .is_none(),
            "neither the validator nor the boot machine hands the record on"
        );
        let operator_record = bystander
            .transport
            .store()
            .lookup(&operator_did)
            .expect("the bystander holds the boot machine's record");
        let lookup = DiscoveryRequest::Lookup(validator.key.did());
        let answer = ask(
            &bystander.endpoint,
            bystander.transport.dial_addr(&operator_record).unwrap(),
            &lookup,
        )
        .await
        .unwrap();
        assert!(
            matches!(answer, DiscoveryResponse::Record(None)),
            "the boot machine does not answer a lookup for it either"
        );
    }

    /// Two validators of a fresh network whose only shared entry point is a
    /// boot machine outside the committee, each naming the other by identity
    /// alone. While the boot machine knows no committee it answers their
    /// epoch-set records to no one and neither resolves the other; once every
    /// node reads the committee, the boot machine hands each member's record
    /// to the other member and to no one else.
    #[tokio::test]
    async fn committee_members_meet_through_a_boot_machine_and_no_one_else_does() {
        let port = test_ports::tcp();
        let url = Url::parse(&format!("http://127.0.0.1:{port}/")).unwrap();
        let role = RelayRoleConfig {
            bind_addr: format!("127.0.0.1:{port}").parse().unwrap(),
            public_url: url.clone(),
        };
        let operator_did = TestMachineKey::from_seed(110).did();
        let (a_did, b_did) = (
            TestMachineKey::from_seed(111).did(),
            TestMachineKey::from_seed(112).did(),
        );
        let operator = TestNode::start(110, vec![], Some(role), true).await;
        operator.sync().await;
        let boot = |other: &str| {
            vec![
                format!("{operator_did}@{url}").parse().unwrap(),
                other.parse().unwrap(),
            ]
        };
        let a = TestNode::start(111, boot(&b_did), None, true).await;
        let b = TestNode::start(112, boot(&a_did), None, true).await;
        let bystander = TestNode::start(
            113,
            vec![format!("{operator_did}@{url}").parse().unwrap()],
            None,
            true,
        )
        .await;
        for v in [&a, &b] {
            v.transport
                .share_within_epoch_set([v.key.did()].into_iter().collect());
        }
        let rounds = || async {
            for _ in 0..3 {
                a.sync().await;
                b.sync().await;
                bystander.sync().await;
                operator.sync().await;
            }
        };
        rounds().await;
        assert!(
            a.transport.store().lookup(&b_did).is_none()
                && b.transport.store().lookup(&a_did).is_none(),
            "with no committee known the boot machine hands neither record on"
        );

        let committee: std::collections::HashSet<String> =
            [a_did.clone(), b_did.clone()].into_iter().collect();
        for n in [&operator, &a, &b, &bystander] {
            n.transport.store().set_committee(committee.clone());
        }
        rounds().await;
        assert_eq!(
            a.transport.store().lookup(&b_did).map(|r| r.machine_did()),
            Some(b_did.clone()),
            "the first member resolves the second through the boot machine"
        );
        assert_eq!(
            b.transport.store().lookup(&a_did).map(|r| r.machine_did()),
            Some(a_did.clone()),
            "the second member resolves the first through the boot machine"
        );
        assert_eq!(
            a.transport.boot_endpoints(a.endpoint.id()),
            vec![operator.endpoint.id(), b.endpoint.id()],
            "the first member links to the boot machine and the second member"
        );
        for did in [&a_did, &b_did] {
            assert!(
                bystander.transport.store().lookup(did).is_none(),
                "a node outside the committee never holds a member's record"
            );
        }
        let operator_record = bystander
            .transport
            .store()
            .lookup(&operator_did)
            .expect("the bystander holds the boot machine's record");
        let answer = ask(
            &bystander.endpoint,
            bystander.transport.dial_addr(&operator_record).unwrap(),
            &DiscoveryRequest::Lookup(a_did.clone()),
        )
        .await
        .unwrap();
        assert!(
            matches!(answer, DiscoveryResponse::Record(None)),
            "the boot machine answers a member's record to no one outside the committee"
        );
    }

    /// A validator in enforce mode is isolated: it learns a non-validator
    /// peer's record from its boot machine's snapshot and never dials that
    /// peer, while it keeps syncing with the boot machine.
    #[tokio::test]
    async fn an_isolated_validator_never_dials_a_discovered_peer_off_its_boot_list() {
        let port = test_ports::tcp();
        let url = Url::parse(&format!("http://127.0.0.1:{port}/")).unwrap();
        let role = RelayRoleConfig {
            bind_addr: format!("127.0.0.1:{port}").parse().unwrap(),
            public_url: url.clone(),
        };
        let operator_did = TestMachineKey::from_seed(98).did();
        let operator = TestNode::start(98, vec![], Some(role), true).await;
        operator.sync().await;
        let boot = || vec![format!("{operator_did}@{url}").parse().unwrap()];
        let validator = TestNode::start(99, boot(), None, true).await;
        let full_node = TestNode::start(100, boot(), None, true).await;
        let gate = IdentityGate::new(
            tenzro_onboarding_types::onboarding::OnboardingPolicy::default(),
            Some(validator.transport.store().clone()),
        );
        gate.protect([operator_did.clone()]);
        gate.isolate(true);
        validator.transport.hold_dials_to(gate);
        validator
            .transport
            .share_within_epoch_set([validator.key.did()].into_iter().collect());
        for _ in 0..3 {
            full_node.sync().await;
            operator.sync().await;
            validator.sync().await;
        }

        assert!(
            validator
                .transport
                .store()
                .lookup(&full_node.key.did())
                .is_some(),
            "the validator discovered the full node through its boot machine"
        );
        assert!(
            operator.asked_by.lock().contains(&validator.endpoint.id()),
            "the validator syncs with its boot machine"
        );
        assert!(
            !full_node.asked_by.lock().contains(&validator.endpoint.id()),
            "the validator never dials a peer off its boot list and outside the validator set"
        );
    }

    /// A member's record changes within one boot (here it states licences;
    /// moving to other relays changes it the same way) while the other
    /// already holds the earlier one, which still names the same endpoint.
    /// A fetch is satisfied by the held record; a refetch, which the
    /// dialler makes after a connection to the held address failed, brings
    /// the newer one.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_refetch_brings_a_record_newer_than_the_one_held() {
        let port = crate::test_ports::tcp();
        let url = Url::parse(&format!("http://127.0.0.1:{port}/")).unwrap();
        let role = RelayRoleConfig {
            bind_addr: format!("127.0.0.1:{port}").parse().unwrap(),
            public_url: url.clone(),
        };
        let operator_did = TestMachineKey::from_seed(86).did();
        let operator = TestNode::start(86, vec![], Some(role), true).await;
        operator.sync().await;
        let boot = || vec![format!("{operator_did}@{url}").parse().unwrap()];
        let a = TestNode::start(87, boot(), None, true).await;
        let b = TestNode::start(88, boot(), None, true).await;
        let set: std::collections::HashSet<String> =
            [a.key.did(), b.key.did()].into_iter().collect();
        a.transport.share_within_epoch_set(set.clone());
        b.transport.share_within_epoch_set(set);
        for _ in 0..2 {
            a.sync().await;
            b.sync().await;
            operator.sync().await;
        }
        assert!(
            a.transport
                .fetch_disclosed_record(&a.endpoint, b.endpoint.id(), &b.key.did())
                .await
        );
        let held = a.transport.store().lookup(&b.key.did()).unwrap();
        assert!(held.accepted_licences.is_empty());

        // b signs a newer record, which a does not hear of.
        b.transport
            .declare_accepted_licences(&["gemma".to_string()])
            .unwrap();
        let home: Vec<Url> = b
            .endpoint
            .addr()
            .relay_urls()
            .map(|u| Url::from(u.clone()))
            .collect();
        let newer = b
            .transport
            .own_record(b.endpoint.id(), &home, b.key)
            .expect("b signs a newer record");
        assert!(newer.sequence > held.sequence);

        assert!(
            a.transport
                .fetch_disclosed_record(&a.endpoint, b.endpoint.id(), &b.key.did())
                .await
        );
        assert_eq!(
            a.transport.store().lookup(&b.key.did()).unwrap().sequence,
            held.sequence,
            "a fetch asked although a record was held"
        );
        assert!(
            a.transport
                .refetch_disclosed_record(&a.endpoint, b.endpoint.id(), &b.key.did())
                .await
        );
        assert_eq!(
            a.transport.store().lookup(&b.key.did()).unwrap().sequence,
            newer.sequence,
            "a refetch kept the older record"
        );
    }

    /// Two members that know each other's records; one restarts with the
    /// same machine key and a new endpoint, and scopes its record to the
    /// epoch set at once, as a restarted validator does. The other must come
    /// to hold the new record, and the restarted one the other's, through
    /// the same disclosure path members first met by.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_member_that_restarts_with_a_new_endpoint_is_found_again() {
        let port = test_ports::tcp();
        let url = Url::parse(&format!("http://127.0.0.1:{port}/")).unwrap();
        let role = RelayRoleConfig {
            bind_addr: format!("127.0.0.1:{port}").parse().unwrap(),
            public_url: url.clone(),
        };
        let operator_did = TestMachineKey::from_seed(81).did();
        let operator = TestNode::start(81, vec![], Some(role), true).await;
        operator.sync().await;
        let boot = || vec![format!("{operator_did}@{url}").parse().unwrap()];
        let a = TestNode::start(82, boot(), None, true).await;
        let b = TestNode::start(83, boot(), None, true).await;
        let set: std::collections::HashSet<String> =
            [a.key.did(), b.key.did()].into_iter().collect();
        a.transport.share_within_epoch_set(set.clone());
        b.transport.share_within_epoch_set(set.clone());
        for _ in 0..2 {
            a.sync().await;
            b.sync().await;
            operator.sync().await;
        }
        assert!(
            a.transport
                .fetch_disclosed_record(&a.endpoint, b.endpoint.id(), &b.key.did())
                .await
        );
        let old_a = a.endpoint.id();
        drop(a);

        // a restarts: same machine key, new endpoint, epoch set known at once.
        let a2 = TestNode::start(82, boot(), None, true).await;
        assert_ne!(a2.endpoint.id(), old_a, "a new endpoint per boot");
        a2.transport.share_within_epoch_set(set.clone());
        for _ in 0..3 {
            a2.sync().await;
            b.sync().await;
            operator.sync().await;
        }
        // b learns a's new endpoint from a's announcement and asks a for it.
        let b_gets_a = b
            .transport
            .fetch_disclosed_record(&b.endpoint, a2.endpoint.id(), &a2.key.did())
            .await;
        let a_gets_b = a2
            .transport
            .fetch_disclosed_record(&a2.endpoint, b.endpoint.id(), &b.key.did())
            .await;
        let b_holds_new = b
            .transport
            .store()
            .lookup(&a2.key.did())
            .and_then(|r| iroh_endpoint(&r).ok())
            == Some(a2.endpoint.id());
        assert!(
            b_gets_a && a_gets_b && b_holds_new,
            "after a restart: b fetched a {b_gets_a}, a fetched b {a_gets_b}, b holds a's new endpoint {b_holds_new}"
        );
    }

    /// Two endpoints connected to a forwarder reach each other through it
    /// with nothing else to go on: the dial names only the path through the
    /// forwarder, and the echo comes back over it. A forwarder addressed by
    /// its own client answers the forwarding check.
    #[tokio::test(flavor = "multi_thread")]
    async fn endpoints_reach_each_other_through_a_peer_relay() {
        let port = test_ports::tcp();
        let url = Url::parse(&format!("http://127.0.0.1:{port}/")).unwrap();
        let role = RelayRoleConfig {
            bind_addr: format!("127.0.0.1:{port}").parse().unwrap(),
            public_url: url.clone(),
        };
        let forwarder = TestNode::start(70, vec![], Some(role), false).await;
        forwarder.sync().await;
        let boot: Vec<BootIdentity> =
            vec![format!("{}@{}", forwarder.key.did(), url).parse().unwrap()];
        let a = TestNode::start(71, boot.clone(), None, false).await;
        let b = TestNode::start(72, boot, None, false).await;
        for node in [&a, &b] {
            node.sync().await;
            assert_eq!(
                node.transport.paths().forwarders(),
                vec![forwarder.endpoint.id()],
                "the admitted relay's operator forwards"
            );
        }
        a.sync().await;
        let through = crate::paths::peer_relay_addr(forwarder.endpoint.id(), b.endpoint.id());
        let addr =
            EndpointAddr::new(b.endpoint.id()).with_addrs([iroh::TransportAddr::Custom(through)]);
        let conn =
            tokio::time::timeout(Duration::from_secs(20), a.endpoint.connect(addr, ECHO_ALPN))
                .await
                .expect("dial in time")
                .expect("dial through the forwarder");
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        send.write_all(b"peer relay").await.unwrap();
        send.finish().unwrap();
        assert_eq!(recv.read_to_end(64).await.unwrap(), b"peer relay");
        let forwarder_record = forwarder
            .transport
            .store()
            .lookup(&forwarder.key.did())
            .unwrap();
        assert!(
            crate::paths::forwarder_answers(
                &a.endpoint,
                a.transport.dial_addr(&forwarder_record).unwrap(),
                Duration::from_secs(10)
            )
            .await
        );
        // The record a peer resolves names the forwarder.
        let record = a.transport.store().lookup(&b.key.did()).unwrap();
        assert!(
            endpoint_addr(&record)
                .unwrap()
                .addrs
                .iter()
                .any(|t| matches!(t, iroh::TransportAddr::Custom(_)))
        );
    }

    /// Whether `conn` has a path through a forwarder.
    fn has_forwarded_path(conn: &Connection) -> bool {
        conn.paths()
            .iter()
            .any(|p| matches!(p.remote_addr(), iroh::TransportAddr::Custom(_)))
    }

    /// A connection that started on the relay gets a path through a
    /// forwarder named afterwards: naming the path opens it on the connections
    /// already open to that remote, not only on the next one.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_path_named_after_a_connection_started_is_opened_on_it() {
        let port = crate::test_ports::tcp();
        let url = Url::parse(&format!("http://127.0.0.1:{port}/")).unwrap();
        let role = RelayRoleConfig {
            bind_addr: format!("127.0.0.1:{port}").parse().unwrap(),
            public_url: url.clone(),
        };
        let forwarder = TestNode::start(140, vec![], Some(role), false).await;
        forwarder.sync().await;
        let boot: Vec<BootIdentity> =
            vec![format!("{}@{}", forwarder.key.did(), url).parse().unwrap()];
        // Both nodes keep their IP sockets: a forwards only over a connection
        // to the forwarder that runs on a direct path, and b offers a path
        // through the forwarder only when it reaches it directly. a joins
        // first; b starts but has not yet published a record naming the
        // forwarder, so a dials it over the relay.
        let a = TestNode::start(141, boot.clone(), None, false).await;
        a.sync().await;
        assert!(
            a.transport
                .paths()
                .connected_forwarders()
                .contains(&forwarder.endpoint.id()),
            "a holds a connection to the forwarder"
        );
        let b = TestNode::start(142, boot, None, false).await;
        let over_relay = EndpointAddr::new(b.endpoint.id()).with_relay_url(url.clone().into());
        let on_relay = tokio::time::timeout(
            Duration::from_secs(20),
            a.endpoint.connect(over_relay, ECHO_ALPN),
        )
        .await
        .expect("dial in time")
        .expect("dial over the relay");
        assert!(
            !has_forwarded_path(&on_relay),
            "it starts with no path through the forwarder"
        );
        // Hole punching has found the direct path before the forwarder is
        // named, so it opens no further path by itself: the named path
        // reaches the connection only when naming it opens it there.
        let direct = tokio::time::timeout(Duration::from_secs(20), async {
            while !on_relay
                .paths()
                .iter()
                .any(|p| p.is_selected() && p.is_ip())
            {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await;
        assert!(direct.is_ok(), "the connection never reached a direct path");

        // b connects to the forwarder; the path through it is then named by a
        // dial that names only it.
        b.sync().await;
        assert_eq!(
            b.transport.paths().forwarders(),
            vec![forwarder.endpoint.id()],
            "b holds a path through the forwarder"
        );
        let through = crate::paths::peer_relay_addr(forwarder.endpoint.id(), b.endpoint.id());
        let named =
            EndpointAddr::new(b.endpoint.id()).with_addrs([iroh::TransportAddr::Custom(through)]);
        let _through_forwarder = tokio::time::timeout(
            Duration::from_secs(20),
            a.endpoint.connect(named, ECHO_ALPN),
        )
        .await
        .expect("dial in time")
        .expect("dial through the forwarder");
        // Well inside the five seconds between hole punching rounds, so a
        // later round that opens the path by itself cannot pass for it.
        let moved = tokio::time::timeout(Duration::from_secs(2), async {
            while !has_forwarded_path(&on_relay) {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await;
        assert!(
            moved.is_ok(),
            "the connection that started on the relay got no path through the forwarder"
        );
    }

    /// An external address peers confirmed, even one that cannot be reached,
    /// never stops a dial: the connection still opens on the relay.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_unreachable_external_address_does_not_stop_a_dial() {
        let port = test_ports::tcp();
        let url = Url::parse(&format!("http://127.0.0.1:{port}/")).unwrap();
        let role = RelayRoleConfig {
            bind_addr: format!("127.0.0.1:{port}").parse().unwrap(),
            public_url: url.clone(),
        };
        let relay = TestNode::start(60, vec![], Some(role), false).await;
        relay.sync().await;
        let boot: Vec<BootIdentity> = vec![format!("{}@{}", relay.key.did(), url).parse().unwrap()];
        let a = TestNode::start(61, boot.clone(), None, false).await;
        let b = TestNode::start(62, boot, None, false).await;
        a.endpoint
            .add_external_addr("203.0.113.99:4000".parse().unwrap())
            .await;
        b.endpoint
            .add_external_addr("203.0.113.98:4000".parse().unwrap())
            .await;
        for _ in 0..2 {
            for node in [&a, &b, &relay] {
                node.sync().await;
            }
        }
        let record = a.transport.store().lookup(&b.key.did()).unwrap();
        let conn = tokio::time::timeout(
            Duration::from_secs(20),
            a.endpoint
                .connect(a.transport.dial_addr(&record).unwrap(), ECHO_ALPN),
        )
        .await
        .expect("dial in time")
        .expect("dial b");
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        send.write_all(b"x").await.unwrap();
        send.finish().unwrap();
        assert_eq!(recv.read_to_end(8).await.unwrap(), b"x");
    }

    /// The answer of `to` to `request`. A connection that is lost before the
    /// answer arrives (on a loaded machine one can time out mid-read) says
    /// nothing about the answer, so the question is asked again on a new
    /// connection, a few times at most.
    async fn answer_of(
        from: &Endpoint,
        to: &EndpointAddr,
        request: &DiscoveryRequest,
    ) -> DiscoveryResponse {
        let mut lost = Vec::new();
        for _ in 0..5 {
            match ask(from, to.clone(), request).await {
                Ok(answer) => return answer,
                Err(e) => lost.push(e.to_string()),
            }
        }
        panic!("no answer on five connections in a row: {lost:?}");
    }

    /// A new connection to a known peer on the same network is on a direct
    /// path within half a second, and until then the relay carries its
    /// traffic: echoes sent every 20 ms never stop for as long as a second.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_new_connection_to_a_known_peer_goes_direct_within_half_a_second() {
        let port = crate::test_ports::tcp();
        let url = Url::parse(&format!("http://127.0.0.1:{port}/")).unwrap();
        let role = RelayRoleConfig {
            bind_addr: format!("127.0.0.1:{port}").parse().unwrap(),
            public_url: url.clone(),
        };
        let relay = TestNode::start(160, vec![], Some(role), false).await;
        relay.sync().await;
        let boot: Vec<BootIdentity> = vec![format!("{}@{}", relay.key.did(), url).parse().unwrap()];
        let a = TestNode::start(161, boot.clone(), None, false).await;
        let b = TestNode::start(162, boot, None, false).await;
        for _ in 0..2 {
            for node in [&a, &b] {
                node.sync().await;
            }
        }
        let record = a.transport.store().lookup(&b.key.did()).unwrap();
        let b_addr = a.transport.dial_addr(&record).unwrap();

        let started = std::time::Instant::now();
        let conn = tokio::time::timeout(
            Duration::from_secs(10),
            a.endpoint.connect(b_addr, ECHO_ALPN),
        )
        .await
        .expect("dial in time")
        .expect("dial");
        let replies = Arc::new(Mutex::new(vec![started]));
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let pinger = {
            let (conn, replies, stop) = (conn.clone(), replies.clone(), stop.clone());
            tokio::spawn(async move {
                while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                    let echo = async {
                        let (mut send, mut recv) = conn.open_bi().await.ok()?;
                        send.write_all(b"ping").await.ok()?;
                        send.finish().ok()?;
                        recv.read_to_end(8).await.ok().filter(|r| r == b"ping")
                    };
                    if tokio::time::timeout(Duration::from_secs(2), echo)
                        .await
                        .is_ok_and(|r| r.is_some())
                    {
                        replies.lock().push(std::time::Instant::now());
                    }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            })
        };
        let direct = tokio::time::timeout(Duration::from_secs(10), async {
            while !conn.paths().iter().any(|p| p.is_selected() && p.is_ip()) {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await;
        let took = started.elapsed();
        tokio::time::sleep(Duration::from_secs(1)).await;
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        pinger.await.unwrap();
        assert!(direct.is_ok(), "no direct path within 10 s");
        assert!(
            took < Duration::from_millis(500),
            "the direct path took {took:?}"
        );
        let replies = replies.lock();
        let gap = replies
            .windows(2)
            .map(|w| w[1] - w[0])
            .max()
            .unwrap_or_default();
        assert!(
            replies.len() > 20,
            "only {} echoes came back",
            replies.len() - 1
        );
        assert!(
            gap < Duration::from_secs(1),
            "the echoes stopped for {gap:?}"
        );
    }

    /// A peer that reaches a node over a direct path tells it the address it
    /// sees; over a relay it can tell nothing. The node's connectivity report
    /// names the relay it is connected to.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_peer_reports_the_address_it_sees_on_a_direct_path_only() {
        let port = test_ports::tcp();
        let url = Url::parse(&format!("http://127.0.0.1:{port}/")).unwrap();
        let role = RelayRoleConfig {
            bind_addr: format!("127.0.0.1:{port}").parse().unwrap(),
            public_url: url.clone(),
        };
        let relay = TestNode::start(50, vec![], Some(role), false).await;
        relay.sync().await;
        let boot: Vec<BootIdentity> = vec![format!("{}@{}", relay.key.did(), url).parse().unwrap()];
        let a = TestNode::start(51, boot.clone(), None, false).await;
        let b = TestNode::start(52, boot.clone(), None, false).await;
        let private = TestNode::start(53, boot, None, true).await;
        for _ in 0..2 {
            for node in [&a, &b, &private, &relay] {
                node.sync().await;
            }
        }
        let b_record = a.transport.store().lookup(&b.key.did()).unwrap();
        let b_addr = a.transport.dial_addr(&b_record).unwrap();
        // A new connection starts on the relay and moves to a direct path once
        // one is found, which on a loaded machine can take a few attempts.
        let mut direct = None;
        for _ in 0..40 {
            match answer_of(&a.endpoint, &b_addr, &DiscoveryRequest::Observe).await {
                DiscoveryResponse::Observed(Some(seen)) => {
                    direct = Some(seen);
                    break;
                }
                DiscoveryResponse::Observed(None) => {
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await
                }
                other => panic!("unexpected answer {other:?}"),
            }
        }
        let seen = direct.expect("a direct path between two hosts on one machine");
        let a_ports: Vec<u16> = a
            .endpoint
            .bound_sockets()
            .iter()
            .map(SocketAddr::port)
            .collect();
        assert!(
            a_ports.contains(&seen.port()),
            "b sees a at one of a's own sockets: {seen} vs {a_ports:?}"
        );
        let b_addr = private.transport.dial_addr(&b_record).unwrap();
        match answer_of(&private.endpoint, &b_addr, &DiscoveryRequest::Observe).await {
            DiscoveryResponse::Observed(seen) => {
                assert_eq!(seen, None, "a relayed connection shows no address")
            }
            other => panic!("unexpected answer {other:?}"),
        }
        let report = a.transport.connectivity(&a.endpoint);
        assert!(
            report
                .relays
                .iter()
                .any(|r| r.connected && r.url.starts_with(url.as_str())),
            "{report:?}"
        );
        assert_eq!(
            report.external,
            Vec::<SocketAddr>::new(),
            "loopback reports never become external addresses"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_node_that_knows_one_peer_finds_the_whole_cluster_through_tenzro_nodes_only() {
        let port = test_ports::tcp();
        let url = Url::parse(&format!("http://127.0.0.1:{port}/")).unwrap();
        let role = RelayRoleConfig {
            bind_addr: format!("127.0.0.1:{port}").parse().unwrap(),
            public_url: url.clone(),
        };

        // The relay operator: the only node anyone is told about.
        let relay = TestNode::start(40, vec![], Some(role), false).await;
        relay.sync().await;
        let boot: Vec<BootIdentity> = vec![format!("{}@{}", relay.key.did(), url).parse().unwrap()];

        // The relay is admitted only through its operator's record.
        let admitted = fetch_relay_record(&url).await.unwrap();
        assert_eq!(admitted.machine_did(), relay.key.did());

        let a = TestNode::start(41, boot.clone(), None, false).await;
        let b = TestNode::start(42, boot.clone(), None, false).await;
        let private = TestNode::start(43, boot.clone(), None, true).await;
        assert!(
            private.endpoint.addr().ip_addrs().next().is_none(),
            "the private node has no IP address"
        );

        // Each node tells the relay operator about itself; a second round
        // brings everyone's records back to everyone.
        for _ in 0..2 {
            for node in [&a, &b, &private, &relay] {
                node.sync().await;
            }
        }

        for node in [&a, &b, &private] {
            for other in [&relay, &a, &b, &private] {
                let record = node
                    .transport
                    .store()
                    .lookup(&other.key.did())
                    .expect("every identity is known");
                record
                    .verify(
                        &other.key.did(),
                        &iroh_endpoint_key(other.endpoint.id()),
                        now_ms(),
                    )
                    .unwrap();
                assert!(
                    endpoint_addr(&record).unwrap().ip_addrs().next().is_none(),
                    "no record carries an IP"
                );
            }
        }
        assert_eq!(a.transport.peer_addrs()[0].0, relay.key.did());

        // A reaches the private node by its identity, through the relay.
        let record = a.transport.store().lookup(&private.key.did()).unwrap();
        let conn = tokio::time::timeout(
            Duration::from_secs(20),
            a.endpoint
                .connect(a.transport.dial_addr(&record).unwrap(), ECHO_ALPN),
        )
        .await
        .expect("dial in time")
        .expect("dial the private node through the relay");
        assert_eq!(conn.remote_id(), private.endpoint.id());
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        send.write_all(b"by identity").await.unwrap();
        send.finish().unwrap();
        assert_eq!(recv.read_to_end(64).await.unwrap(), b"by identity");

        // B dials A by its EndpointId alone: the discovery store resolves it.
        let conn = tokio::time::timeout(
            Duration::from_secs(20),
            b.endpoint.connect(a.endpoint.id(), ECHO_ALPN),
        )
        .await
        .expect("dial in time")
        .expect("dial by EndpointId through Tenzro discovery");
        assert_eq!(conn.remote_id(), a.endpoint.id());
    }

    #[derive(Debug)]
    struct AcceptAll;

    impl crate::gossip::GossipValidator for AcceptAll {
        fn admit(&self, _: &str, _: EndpointId) -> crate::gossip::Verdict {
            crate::gossip::Verdict::Accept
        }
        fn duplicate(&self, _: &str, _: EndpointId, _: usize) {}
        fn check(&self, _: &str, _: EndpointId, _: &[u8]) -> crate::gossip::Verdict {
            crate::gossip::Verdict::Accept
        }
        fn verdict(&self, _: EndpointId, _: crate::gossip::Verdict) {}
        fn allows(&self, _: EndpointId) -> bool {
            true
        }
        fn score(&self, _: EndpointId) -> i32 {
            0
        }
    }

    /// A genesis validator of a fresh network: identity transport, gossip and
    /// discovery on one endpoint, and nothing else it was told.
    struct MeshNode {
        transport: Arc<IdentityTransport>,
        endpoint: Endpoint,
        _router: Router,
        key: &'static TestMachineKey,
        layer: Arc<crate::gossip::GossipLayer>,
        inbound: tokio::sync::mpsc::Receiver<crate::gossip::Inbound>,
    }

    impl MeshNode {
        async fn start(seed: u8, boot: Vec<BootIdentity>, role: Option<RelayRoleConfig>) -> Self {
            use crate::gossip::{ALPN_GOSSIP, GossipGate, GossipLayer, GossipTransport};
            let key: &'static TestMachineKey = Box::leak(Box::new(TestMachineKey::from_seed(seed)));
            let transport = IdentityTransport::start(boot, &[], role.as_ref(), Some(key.did()))
                .await
                .unwrap();
            let gate = GossipGate::default();
            let endpoint = with_relays(
                on_loopback(base_builder()),
                transport.relays(),
                Some(transport.store().clone()),
            )
            .hooks(gate.clone())
            .bind()
            .await
            .unwrap();
            if !transport.relays().is_empty() {
                tokio::time::timeout(Duration::from_secs(20), endpoint.online())
                    .await
                    .expect("reaches its relay");
            }
            let gossip = GossipTransport::spawn(&endpoint, gate);
            let router = Router::builder(endpoint.clone())
                .accept(
                    ALPN_DISCOVERY,
                    DiscoveryProtocol::new(transport.store().clone()),
                )
                .accept(ALPN_GOSSIP, gossip.protocol())
                .spawn();
            let (layer, inbound) = GossipLayer::new(Arc::new(AcceptAll));
            layer.attach(gossip, 7).unwrap();
            layer.join("tenzro/blocks");
            Self {
                transport,
                endpoint,
                _router: router,
                key,
                layer,
                inbound,
            }
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_fresh_network_forms_its_gossip_mesh_from_its_genesis_identities_alone() {
        // Three genesis validators. The first serves the relay its genesis
        // entry names; the other two are named by identity only. No node is
        // told any address or endpoint of another.
        let port = test_ports::tcp();
        let url = Url::parse(&format!("http://127.0.0.1:{port}/")).unwrap();
        let role = RelayRoleConfig {
            bind_addr: format!("127.0.0.1:{port}").parse().unwrap(),
            public_url: url.clone(),
        };
        let dids: Vec<String> = (60..63u8)
            .map(|s| TestMachineKey::from_seed(s).did())
            .collect();
        let genesis = |me: usize| -> Vec<BootIdentity> {
            (0..3)
                .filter(|i| *i != me)
                .map(|i| {
                    if i == 0 {
                        format!("{}@{url}", dids[i])
                    } else {
                        dids[i].clone()
                    }
                    .parse()
                    .unwrap()
                })
                .collect()
        };
        let first = MeshNode::start(60, genesis(0), Some(role)).await;
        first
            .transport
            .sync_once(&first.endpoint, Some(first.key))
            .await;
        let mut nodes = vec![first];
        for i in 1..3 {
            nodes.push(MeshNode::start(60 + i as u8, genesis(i), None).await);
        }
        for _ in 0..2 {
            for n in &nodes {
                n.transport.sync_once(&n.endpoint, Some(n.key)).await;
            }
        }
        // Each links to the genesis identities it resolved: the whole mesh.
        for n in &nodes {
            let peers = n.transport.boot_endpoints(n.endpoint.id());
            assert_eq!(peers.len(), 2, "every other genesis validator resolves");
            n.layer.add_peers(peers).await;
        }
        // A message published before the mesh has formed goes nowhere.
        let meshed = async {
            while !nodes
                .iter()
                .all(|n| n.layer.neighbour_count("tenzro/blocks").unwrap_or(0) >= 1)
            {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        };
        tokio::time::timeout(Duration::from_secs(60), meshed)
            .await
            .expect("every node has a neighbour on the topic");
        nodes[1]
            .layer
            .publish("tenzro/blocks", bytes::Bytes::from_static(b"block 1"))
            .await
            .unwrap();
        for i in [0, 2] {
            let got = tokio::time::timeout(Duration::from_secs(20), nodes[i].inbound.recv())
                .await
                .expect("the message crosses the mesh")
                .unwrap();
            assert_eq!(&got.content[..], b"block 1");
        }
    }

    /// [`ask`], tried again when the dial itself did not finish: a loaded host
    /// can keep a loopback dial past its bound, which says nothing about what
    /// the peer answers. An answer, a refusal included, is never asked again.
    async fn ask_patiently(
        endpoint: &Endpoint,
        peer: EndpointAddr,
        request: &DiscoveryRequest,
    ) -> IrohResult<DiscoveryResponse> {
        let mut last = ask(endpoint, peer.clone(), request).await;
        for _ in 0..3 {
            match &last {
                Err(e) if e.to_string().contains("did not finish within") => {
                    last = ask(endpoint, peer.clone(), request).await;
                }
                _ => break,
            }
        }
        last
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_private_node_is_resolvable_only_by_its_counterparties() {
        let port = test_ports::tcp();
        let url = Url::parse(&format!("http://127.0.0.1:{port}/")).unwrap();
        let role = RelayRoleConfig {
            bind_addr: format!("127.0.0.1:{port}").parse().unwrap(),
            public_url: url.clone(),
        };
        let relay = TestNode::start(70, vec![], Some(role), false).await;
        relay.sync().await;
        let boot: Vec<BootIdentity> = vec![format!("{}@{}", relay.key.did(), url).parse().unwrap()];

        let counterparty = TestNode::start(71, boot.clone(), None, false).await;
        let stranger = TestNode::start(72, boot.clone(), None, false).await;
        let private = TestNode::start(73, boot.clone(), None, true).await;
        private
            .transport
            .share_with_counterparties(vec![counterparty.key.did()]);

        for _ in 0..3 {
            for node in [&counterparty, &stranger, &private, &relay] {
                node.sync().await;
            }
        }

        // Public records still propagate everywhere.
        assert!(
            stranger
                .transport
                .store()
                .lookup(&counterparty.key.did())
                .is_some()
        );
        assert!(
            private
                .transport
                .store()
                .lookup(&stranger.key.did())
                .is_some()
        );

        // The counterparty holds the private record; nobody else does.
        let held = counterparty
            .transport
            .store()
            .lookup(&private.key.did())
            .expect("the counterparty resolves it");
        assert_eq!(
            held.scope,
            RecordScope::Counterparties(vec![counterparty.key.did()])
        );
        assert!(
            stranger
                .transport
                .store()
                .lookup(&private.key.did())
                .is_none()
        );
        assert!(
            relay.transport.store().lookup(&private.key.did()).is_none(),
            "not even its relay operator"
        );

        // Asked directly, the private node and its counterparty answer the
        // counterparty and refuse the stranger; no snapshot carries it.
        let lookup = DiscoveryRequest::Lookup(private.key.did());
        for holder in [&private, &counterparty] {
            let holder_record = holder.transport.store().lookup(&holder.key.did()).unwrap();
            let to_stranger = ask_patiently(
                &stranger.endpoint,
                stranger.transport.dial_addr(&holder_record).unwrap(),
                &lookup,
            )
            .await
            .unwrap();
            assert!(
                matches!(to_stranger, DiscoveryResponse::Record(None)),
                "a non-counterparty cannot resolve it"
            );
            let snapshot = ask_patiently(
                &stranger.endpoint,
                stranger.transport.dial_addr(&holder_record).unwrap(),
                &DiscoveryRequest::Snapshot,
            )
            .await
            .unwrap();
            match snapshot {
                DiscoveryResponse::Records(records) => {
                    assert!(
                        records.iter().all(|r| r.machine_did() != private.key.did()),
                        "never in a snapshot"
                    )
                }
                other => panic!("unexpected {other:?}"),
            }
        }
        let to_counterparty = ask_patiently(
            &counterparty.endpoint,
            counterparty.transport.dial_addr(&held).unwrap(),
            &lookup,
        )
        .await
        .unwrap();
        assert!(
            matches!(to_counterparty, DiscoveryResponse::Record(Some(_))),
            "a certified counterparty can"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn forged_and_stale_records_are_refused_by_a_peer() {
        let node = TestNode::start(50, vec![], None, false).await;
        let asker = on_loopback(base_builder()).bind().await.unwrap();
        node.sync().await;
        let own = node.transport.store().lookup(&node.key.did()).unwrap();

        // A record for the node's identity signed by another machine.
        let forger = TestMachineKey::from_seed(51);
        let mut forged = EndpointRecord::sign(
            &forger,
            iroh_endpoint_key(asker.id()),
            vec![],
            Vec::new(),
            None,
            RecordScope::Network,
            vec![],
            own.sequence + 1,
            now_ms(),
        )
        .unwrap();
        forged.machine_key = own.machine_key.clone();
        let reply = ask(
            &asker,
            node.endpoint.addr(),
            &DiscoveryRequest::Publish(forged),
        )
        .await
        .unwrap();
        assert!(
            matches!(reply, DiscoveryResponse::Published(Err(_))),
            "a forged record is refused"
        );

        // An older record of the node's own.
        let stale = EndpointRecord::sign(
            node.key,
            iroh_endpoint_key(node.endpoint.id()),
            vec![],
            Vec::new(),
            None,
            RecordScope::Network,
            vec![],
            own.sequence - 1,
            now_ms(),
        )
        .unwrap();
        let reply = ask(
            &asker,
            node.endpoint.addr(),
            &DiscoveryRequest::Publish(stale),
        )
        .await
        .unwrap();
        assert!(
            matches!(reply, DiscoveryResponse::Published(Err(_))),
            "a lower sequence is refused"
        );

        let reply = ask(
            &asker,
            node.endpoint.addr(),
            &DiscoveryRequest::Lookup(node.key.did()),
        )
        .await
        .unwrap();
        match reply {
            DiscoveryResponse::Record(Some(r)) => {
                assert_eq!(r, own, "the held record is unchanged")
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_validator_serving_the_relay_stays_admissible_and_a_node_started_first_waits_for_it()
    {
        let port = test_ports::tcp();
        let url = Url::parse(&format!("http://127.0.0.1:{port}/")).unwrap();
        let boot: Vec<BootIdentity> = vec![
            format!("{}@{}", TestMachineKey::from_seed(70).did(), url)
                .parse()
                .unwrap(),
        ];
        // A node that starts before the relay operator is up still admits it.
        let early = tokio::spawn(IdentityTransport::start(
            boot,
            &[],
            None,
            Some(TestMachineKey::from_seed(71).did()),
        ));
        tokio::time::sleep(Duration::from_secs(2)).await;
        let role = RelayRoleConfig {
            bind_addr: format!("127.0.0.1:{port}").parse().unwrap(),
            public_url: url.clone(),
        };
        let relay = TestNode::start(70, vec![], Some(role), false).await;
        // The operator is a validator: its committee scopes its record.
        relay
            .transport
            .share_within_epoch_set([relay.key.did()].into_iter().collect());
        relay.sync().await;
        assert_eq!(
            relay
                .transport
                .store()
                .lookup(&relay.key.did())
                .unwrap()
                .scope,
            RecordScope::Network
        );
        assert_eq!(
            fetch_relay_record(&url).await.unwrap().machine_did(),
            relay.key.did()
        );
        let early = early.await.unwrap().unwrap();
        assert!(
            early.relays().iter().any(|r| r.url == url),
            "the relay was never admitted"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn an_epoch_set_record_is_answered_only_to_a_member() {
        let validator = TestNode::start(60, vec![], None, false).await;
        let member_key = TestMachineKey::from_seed(61);
        let member = on_loopback(base_builder()).bind().await.unwrap();
        let outsider = on_loopback(base_builder()).bind().await.unwrap();
        let member_record = EndpointRecord::sign(
            &member_key,
            iroh_endpoint_key(member.id()),
            vec![],
            Vec::new(),
            None,
            RecordScope::EpochSet,
            vec![],
            1,
            now_ms(),
        )
        .unwrap();
        validator.transport.store().offer(member_record).unwrap();
        validator.transport.share_within_epoch_set(
            [validator.key.did(), member_key.did()]
                .into_iter()
                .collect(),
        );
        validator.sync().await;
        assert_eq!(
            validator
                .transport
                .store()
                .lookup(&validator.key.did())
                .unwrap()
                .scope,
            RecordScope::EpochSet
        );

        let lookup = DiscoveryRequest::Lookup(validator.key.did());
        let to_member = ask(&member, validator.endpoint.addr(), &lookup)
            .await
            .unwrap();
        assert!(
            matches!(to_member, DiscoveryResponse::Record(Some(_))),
            "a member is answered"
        );
        let to_outsider = ask(&outsider, validator.endpoint.addr(), &lookup)
            .await
            .unwrap();
        assert!(
            matches!(to_outsider, DiscoveryResponse::Record(None)),
            "an outsider is not"
        );
        assert_eq!(
            validator
                .transport
                .store()
                .certified_in(member.id(), &[member_key.did()].into_iter().collect()),
            Some(member_key.did())
        );
    }

    /// Whether `from` reaches `to` through the record it holds for it.
    async fn echo_reaches(from: &TestNode, to: &TestNode) -> bool {
        let Some(record) = from.transport.store().lookup(&to.key.did()) else {
            return false;
        };
        let Ok(addr) = from.transport.dial_addr(&record) else {
            return false;
        };
        let dial = async {
            let conn = from.endpoint.connect(addr, ECHO_ALPN).await.ok()?;
            let (mut send, mut recv) = conn.open_bi().await.ok()?;
            send.write_all(b"x").await.ok()?;
            send.finish().ok()?;
            recv.read_to_end(8).await.ok()
        };
        matches!(tokio::time::timeout(Duration::from_secs(5), dial).await, Ok(Some(echo)) if echo == b"x")
    }

    /// Whether each of two nodes gets an echo from the other within
    /// `within`, with what they hold now: nothing is exchanged while waiting.
    async fn reach_each_other(a: &TestNode, b: &TestNode, within: Duration) -> bool {
        let both = async {
            while !(echo_reaches(a, b).await && echo_reaches(b, a).await) {
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        };
        tokio::time::timeout(within, both).await.is_ok()
    }

    /// Nodes that know one relay take on a second while running, and keep
    /// reaching each other, over relay-only paths, when the first stops.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_relay_that_joins_late_carries_the_nodes_when_the_first_relay_stops() {
        let (p1, p2) = (test_ports::tcp(), test_ports::tcp());
        let url = |p: u16| Url::parse(&format!("http://127.0.0.1:{p}/")).unwrap();
        let role = |p: u16| RelayRoleConfig {
            bind_addr: format!("127.0.0.1:{p}").parse().unwrap(),
            public_url: url(p),
        };
        let r1 = TestNode::start(80, vec![], Some(role(p1)), false).await;
        let r2 = TestNode::start(81, vec![], Some(role(p2)), false).await;
        r1.sync().await;
        r2.sync().await;
        let boot: Vec<BootIdentity> =
            vec![format!("{}@{}", r1.key.did(), url(p1)).parse().unwrap()];
        let a = TestNode::start(82, boot.clone(), None, true).await;
        let b = TestNode::start(83, boot, None, true).await;
        for _ in 0..2 {
            for n in [&a, &b, &r1] {
                n.sync().await;
            }
        }
        // The nodes hold each other's records now; the first echo through
        // the relay is waited for, as the one through the second relay is
        // below, rather than given a single attempt.
        assert!(
            reach_each_other(&a, &b, Duration::from_secs(30)).await,
            "the nodes reach each other through the first relay"
        );

        // The second relay is added to the running endpoints.
        for n in [&a, &b] {
            assert_eq!(n.transport.add_relay_candidates(&[url(p2)]), 1);
            n.transport.admit_pending(&n.endpoint).await;
            assert!(
                n.transport.uses_relay(url(p2).as_str()),
                "admitted without a restart"
            );
        }

        // The first relay stops.
        r1._router.shutdown().await.unwrap();
        r1.endpoint.close().await;
        drop(r1);
        assert!(
            fetch_relay_record(&url(p1)).await.is_err(),
            "the first relay is gone"
        );

        let second = RelayUrl::from(url(p2));
        let stopped = tokio::time::Instant::now();
        let moved = async {
            loop {
                let on_second = |n: &TestNode| {
                    n.endpoint.addr().relay_urls().all(|u| *u == second)
                        && n.endpoint.addr().relay_urls().next().is_some()
                };
                if on_second(&a) && on_second(&b) {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        };
        tokio::time::timeout(Duration::from_secs(60), moved)
            .await
            .expect("both nodes move to the second relay");
        // No record has been exchanged since the first relay stopped: the
        // addresses the nodes dial carry the relays in use.
        assert!(
            reach_each_other(&a, &b, Duration::from_secs(30)).await,
            "the nodes reach each other through the second relay"
        );
        eprintln!(
            "relay stop: reconnected through the second relay after {:?}",
            stopped.elapsed()
        );

        // A round with the stopped relay among its peers stays short, and
        // the records the rounds leave name the second relay.
        let names_second = |from: &TestNode, to: &TestNode| {
            from.transport
                .store()
                .lookup(&to.key.did())
                .is_some_and(|r| {
                    r.relays.iter().map(|r| r.url.clone()).collect::<Vec<_>>() == vec![url(p2)]
                })
        };
        let converged = async {
            loop {
                for n in [&a, &b, &r2] {
                    n.transport.admit_pending(&n.endpoint).await;
                    let round = tokio::time::Instant::now();
                    n.sync().await;
                    assert!(
                        round.elapsed() < 2 * ASK_TIMEOUT,
                        "a round with one stopped peer took {:?}",
                        round.elapsed()
                    );
                }
                if names_second(&a, &b) && names_second(&b, &a) {
                    return;
                }
            }
        };
        tokio::time::timeout(Duration::from_secs(120), converged)
            .await
            .expect("the records come to name the second relay");
        assert!(
            reach_each_other(&a, &b, Duration::from_secs(30)).await,
            "the nodes reach each other by the new records"
        );
    }

    /// A dialed address carries the relays in use and the direct addresses a
    /// path last used or the operator fixed; the direct ones survive a restart.
    #[test]
    fn a_dialed_address_carries_the_relays_in_use_and_the_direct_addresses_known() {
        let hints = SharedHints(std::sync::RwLock::new(DialHints::default()));
        let id = iroh::SecretKey::from_bytes(&[3u8; 32]).public();
        let did = format!("did:tenzro:machine:{}", "ab".repeat(32));
        let first = Url::parse("https://one.example.net/").unwrap();
        let second = Url::parse("https://two.example.net/").unwrap();
        hints.add_relays(&[first.clone(), second.clone()]);
        hints.set_fixed([(did.clone(), vec!["192.0.2.7:9001".parse().unwrap()])].into());
        hints.set_direct(id, vec!["198.51.100.4:9001".parse().unwrap()]);

        // The record names only the relay that failed.
        let mut addr = EndpointAddr::new(id).with_relay_url(RelayUrl::from(first.clone()));
        hints.add_to(&mut addr, &did);
        assert_eq!(addr.relay_urls().count(), 2, "the second relay is added");
        let ips: Vec<SocketAddr> = addr.ip_addrs().copied().collect();
        assert_eq!(ips.len(), 2, "{ips:?}");

        let dir = std::env::temp_dir().join(format!("dial-hints-{}", std::process::id()));
        let path = dir.join("direct-addrs.json");
        let saved = hints.save(&path, 0);
        assert!(saved > 0);
        assert_eq!(
            hints.save(&path, saved),
            saved,
            "nothing changed, nothing written"
        );
        let restarted = SharedHints(std::sync::RwLock::new(DialHints::default()));
        restarted.restore(&path);
        let mut again = EndpointAddr::new(id);
        restarted.add_to(&mut again, "other");
        assert_eq!(
            again.ip_addrs().copied().collect::<Vec<_>>(),
            vec!["198.51.100.4:9001".parse::<SocketAddr>().unwrap()]
        );
        let _ = std::fs::remove_dir_all(dir);
    }
}
