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
use crate::identity_record::{BootIdentity, EndpointKey, EndpointRecord, RecordScope, RelayRef};
use crate::reachability::{self, Connectivity, Observations};
use crate::relay::{RelayCheck, RelayServer, check_relay, fetch_relay_record, now_ms};

/// How long a boot relay that has not signed or served its record yet is
/// waited for: nodes of a network start in no particular order, and one that
/// starts first must still admit the relays that come up just after it.
const RELAY_ADMISSION_WAIT: Duration = Duration::from_secs(60);

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
    let id = iroh_endpoint(record)?;
    let mut addr = EndpointAddr::new(id);
    for relay in &record.relays {
        addr = addr.with_relay_url(RelayUrl::from(relay.url.clone()));
    }
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
    mut builder: Builder,
    relays: &[RelayRef],
    store: Option<Arc<DiscoveryStore>>,
) -> Builder {
    if relays.is_empty() {
        builder = builder.relay_mode(RelayMode::Disabled);
    } else {
        let map: RelayMap = relays
            .iter()
            .map(|r| RelayConfig::new(RelayUrl::from(r.url.clone()), None))
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
    base_builder_with(&ConnectionLimits::default())
}

/// [`base_builder`] with the QUIC limits of `limits` (idle timeout, stream
/// counts, receive window) on every connection the endpoint makes or accepts.
pub fn base_builder_with(limits: &ConnectionLimits) -> Builder {
    Endpoint::builder(presets::Minimal)
        .crypto_provider(Arc::new(relay_crypto_provider()))
        .peer_crypto_provider(Arc::new(peer_crypto_provider()))
        .portmapper_config(iroh::endpoint::PortmapperConfig::default())
        .ca_tls_config(iroh_relay::tls::CaTlsConfig::system())
        .transport_config(limits.transport_config())
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
    own_relay: Option<Url>,
    /// Held so the relay role keeps serving while the transport lives.
    _relay_server: Option<RelayServer>,
    scope: Mutex<RecordScope>,
    accepted_licences: Mutex<Vec<String>>,
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
}

impl IdentityTransport {
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
        let store = Arc::new(DiscoveryStore::new());
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
                    crate::relay::RelayLimits::default(),
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
                Err(e) => tracing::warn!(relay = %url, error = %e, "relay not admitted"),
            }
        }
        let pq_channel = crate::pq_endpoint::PqChannel::new(store.clone());
        Ok(Arc::new(Self {
            store,
            pq_channel,
            machine_pq: std::sync::OnceLock::new(),
            boot,
            relays,
            own_relay,
            _relay_server: relay_server,
            scope: Mutex::new(RecordScope::Network),
            accepted_licences: Mutex::new(Vec::new()),
            current: Mutex::new(None),
            observations: Mutex::new(Observations::default()),
            external: Mutex::new(Vec::new()),
            relay_checks: Mutex::new(std::collections::BTreeMap::new()),
            paths: crate::paths::Paths::new(),
            peer_relay: std::sync::OnceLock::new(),
        }))
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
        self.pq_channel.set_own_key(crate::pq_endpoint::ChannelKeys {
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

    /// This node's discovery store.
    pub fn store(&self) -> &Arc<DiscoveryStore> {
        &self.store
    }

    /// Scopes this machine's record, and the records this node answers, to
    /// the epoch set `members`: from the next renewal the record is shared
    /// only with peers a member certifies. A private node keeps sharing its
    /// record with its counterparties only.
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

    /// Whether this machine's record, under its current scope, may be
    /// published to `did`.
    fn publishes_to(&self, did: &str) -> bool {
        match &*self.scope.lock() {
            RecordScope::Network => true,
            RecordScope::EpochSet => self.store.in_epoch_set(did),
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
                    .and_then(|r| endpoint_addr(&r).ok())
                    .map(|a| (b.did.clone(), a))
            })
            .collect()
    }

    /// Fetches the record of `machine` from the peer itself, when that peer
    /// disclosed its endpoint `peer` to this node and no record of it naming
    /// that endpoint is held yet. A record scoped to the epoch set reaches
    /// no one outside it, so a member first learns the record of another
    /// from that member: it reaches the endpoint through the relay the boot
    /// list names for the machine, or else through its own relays, hands it
    /// this node's record so the peer can certify it, and asks for the
    /// peer's. True once a record naming `peer` is held.
    pub async fn fetch_disclosed_record(
        &self,
        endpoint: &Endpoint,
        peer: EndpointId,
        machine: &str,
    ) -> bool {
        let names_peer = |r: &EndpointRecord| iroh_endpoint(r).is_ok_and(|id| id == peer);
        if self.store.lookup(machine).is_some_and(|r| names_peer(&r)) {
            return true;
        }
        let hinted: Vec<Url> = self
            .boot
            .iter()
            .filter(|b| b.did == machine)
            .filter_map(|b| b.relay.clone())
            .collect();
        let relays = if hinted.is_empty() {
            self.relays.iter().map(|r| r.url.clone()).collect()
        } else {
            hinted
        };
        if relays.is_empty() {
            return false;
        }
        let addr = relays.into_iter().fold(EndpointAddr::new(peer), |a, url| {
            a.with_relay_url(RelayUrl::from(url))
        });
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
        self.relays
            .iter()
            .filter(|r| home.contains(&r.url))
            .cloned()
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
        if relays.is_empty() && forwarders.is_empty() && !self.relays.is_empty() {
            return current.clone();
        }
        if let Some(r) = current.as_ref().filter(|r| {
            !r.due_for_renewal(now)
                && r.relays == relays
                && r.forwarders == forwarders
                && r.pq.is_some() == self.machine_pq.get().is_some()
        }) {
            return Some(r.clone());
        }
        let sequence = current
            .as_ref()
            .map_or(now, |r| r.sequence.max(now - 1) + 1);
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
                if let (Some(machine), Some(_)) =
                    (self.machine_pq.get(), self.pq_channel.own_key())
                    && let Err(e) = record.bind_pq(machine.as_ref())
                {
                    // An unbound record would be refused by every peer
                    // that holds this identity's key, so none is signed.
                    tracing::warn!(error = %e, "binding this machine's endpoint record failed");
                    return current.clone();
                }
                if let Err(e) = self.store.offer(record.clone()) {
                    tracing::warn!(error = %e, "own endpoint record not kept");
                }
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
        self.choose_forwarders(endpoint).await;
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
        peers.retain(|r| {
            Some(r.machine_did()) != own_did && iroh_endpoint(r).is_ok_and(|id| id != endpoint.id())
        });
        peers.truncate(SYNC_FANOUT);
        let observers = peers.clone();
        for peer in peers {
            let Ok(addr) = endpoint_addr(&peer) else {
                continue;
            };
            if let Some(own) = own
                .as_ref()
                .filter(|_| self.publishes_to(&peer.machine_did()))
            {
                let publish = DiscoveryRequest::Publish(own.clone());
                if let Err(e) =
                    tokio::time::timeout(ASK_TIMEOUT, ask(endpoint, addr.clone(), &publish)).await
                {
                    tracing::debug!(peer = %peer.machine_did(), error = %e, "publish timed out");
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
                    tracing::debug!(peer = %peer.machine_did(), error = %e, "snapshot timed out")
                }
            }
        }
        self.observe(endpoint, &observers).await;
        self.punch_peers(endpoint, &observers).await;
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
            let Ok(addr) = endpoint_addr(peer) else {
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
            let addr = endpoint_addr(peer).ok()?;
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

    /// The forwarding service of a node that serves the relay role: its
    /// endpoint also forwards packets between endpoints that cannot reach
    /// each other directly.
    pub fn peer_relay_service(&self) -> Option<crate::paths::PeerRelayService> {
        self.own_relay.as_ref()?;
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
    /// address keeps none.
    pub async fn choose_forwarders(&self, endpoint: &Endpoint) {
        let local = reachability::local_ips(endpoint);
        if self.observations.lock().nat_kind(&local, now_ms()) == reachability::NatKind::None {
            self.paths.offer(&[]);
            return;
        }
        let candidates: Vec<EndpointAddr> = self
            .relays
            .iter()
            .filter(|r| Some(&r.url) != self.own_relay.as_ref())
            .filter_map(|r| self.store.lookup(&r.did))
            .filter_map(|record| endpoint_addr(&record).ok())
            .filter(|addr| addr.id != endpoint.id())
            .take(MAX_FORWARDER_CANDIDATES)
            .collect();
        let tried = futures::future::join_all(candidates.into_iter().map(|addr| async move {
            let id = addr.id;
            tokio::time::timeout(ASK_TIMEOUT, self.paths.connect_forwarder(addr))
                .await
                .ok()
                .and_then(Result::ok)
                .map(|_| id)
        }))
        .await;
        // Give hole punching to the forwarders a moment before judging.
        if tried.iter().any(Option::is_some) {
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
    }

    /// Whether this node admitted `url` as one of its relays.
    pub fn uses_relay(&self, url: &str) -> bool {
        self.relays.iter().any(|r| r.url.as_str() == url)
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
            let unresolved = self
                .boot
                .iter()
                .any(|b| Some(&b.did) != own.as_ref() && self.store.lookup(&b.did).is_none());
            let wait = if unresolved { BOOT_RETRY } else { TICK };
            tokio::select! {
                _ = endpoint.closed() => return,
                _ = tokio::time::sleep(wait) => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery::{ALPN_DISCOVERY, DiscoveryProtocol};
    use crate::identity_record::tests::TestMachineKey;
    use iroh::Watcher;
    use iroh::endpoint::Connection;
    use iroh::protocol::{AcceptError, ProtocolHandler, Router};

    const ECHO_ALPN: &[u8] = b"tenzro/test/echo";

    #[derive(Debug, Clone)]
    struct Echo;

    impl ProtocolHandler for Echo {
        async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
            let (mut send, mut recv) = conn.accept_bi().await.map_err(AcceptError::from_err)?;
            let msg = recv
                .read_to_end(1024)
                .await
                .map_err(AcceptError::from_err)?;
            send.write_all(&msg).await.map_err(AcceptError::from_err)?;
            send.finish().map_err(AcceptError::from_err)?;
            conn.closed().await;
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
        let server = Endpoint::builder(presets::Minimal)
            .crypto_provider(Arc::new(peer_crypto_provider()))
            .bind()
            .await
            .unwrap();
        let router = Router::builder(server.clone())
            .accept(ECHO_ALPN, Echo)
            .spawn();
        let client = base_builder().bind().await.unwrap();
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

    /// An endpoint that speaks only classical X25519, as a downgraded or
    /// non-Tenzro peer would.
    async fn classical_endpoint() -> Endpoint {
        let mut classical = rustls::crypto::aws_lc_rs::default_provider();
        classical.kx_groups = vec![rustls::crypto::aws_lc_rs::kx_group::X25519];
        Endpoint::builder(presets::Minimal)
            .crypto_provider(Arc::new(classical))
            .bind()
            .await
            .unwrap()
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_classical_only_peer_is_refused() {
        let tenzro = base_builder().bind().await.unwrap();
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
        let endpoint = with_relays(base_builder(), &[], None).bind().await.unwrap();
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
            let mut builder = transport.paths().install(with_relays(
                base_builder(),
                transport.relays(),
                Some(transport.store().clone()),
            ));
            if relay_only {
                builder = builder.clear_ip_transports();
            }
            if let Some(port) = port {
                builder = builder
                    .clear_ip_transports()
                    .bind_addr(std::net::SocketAddr::from(([0, 0, 0, 0], port)))
                    .unwrap()
                    .bind_addr(std::net::SocketAddr::from(([0u16; 8], port)))
                    .unwrap();
            }
            let endpoint = builder.bind().await.unwrap();
            transport.paths().attach(&endpoint);
            if !transport.relays().is_empty() {
                tokio::time::timeout(Duration::from_secs(20), endpoint.online())
                    .await
                    .expect("reaches its relay");
            }
            let mut router = Router::builder(endpoint.clone())
                .accept(
                    ALPN_DISCOVERY,
                    DiscoveryProtocol::new(transport.store().clone()),
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
            }
        }

        async fn sync(&self) {
            self.transport
                .sync_once(&self.endpoint, Some(self.key))
                .await;
        }
    }

    fn free_port() -> u16 {
        std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
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
    /// `PATH direct <addr>` or `PATH relay`.
    #[tokio::test(flavor = "multi_thread")]
    #[ignore]
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
                let conn = node
                    .endpoint
                    .connect(endpoint_addr(&record).unwrap(), ECHO_ALPN)
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
                    tokio::time::sleep(Duration::from_millis(250)).await;
                }
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
        let port = free_port();
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

    /// Once the node binds its records with its machine ML-DSA key, the next
    /// record it signs carries the binding, verifies, and is the one it
    /// serves; the versioned RPC ALPNs then hold its ML-DSA endpoint key.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_node_that_binds_its_records_signs_them_with_the_binding() {
        let port = free_port();
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
        let port = free_port();
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
        let port = free_port();
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

    /// Two members that know each other's records; one restarts with the
    /// same machine key and a new endpoint, and scopes its record to the
    /// epoch set at once, as a restarted validator does. The other must come
    /// to hold the new record, and the restarted one the other's, through
    /// the same disclosure path members first met by.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_member_that_restarts_with_a_new_endpoint_is_found_again() {
        let port = free_port();
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
        let port = free_port();
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
        assert!(
            crate::paths::forwarder_answers(
                &a.endpoint,
                endpoint_addr(
                    &forwarder
                        .transport
                        .store()
                        .lookup(&forwarder.key.did())
                        .unwrap()
                )
                .unwrap(),
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

    /// An external address peers confirmed, even one that cannot be reached,
    /// never stops a dial: the connection still opens on the relay.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_unreachable_external_address_does_not_stop_a_dial() {
        let port = free_port();
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
                .connect(endpoint_addr(&record).unwrap(), ECHO_ALPN),
        )
        .await
        .expect("dial in time")
        .expect("dial b");
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        send.write_all(b"x").await.unwrap();
        send.finish().unwrap();
        assert_eq!(recv.read_to_end(8).await.unwrap(), b"x");
    }

    /// A peer that reaches a node over a direct path tells it the address it
    /// sees; over a relay it can tell nothing. The node's connectivity report
    /// names the relay it is connected to.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_peer_reports_the_address_it_sees_on_a_direct_path_only() {
        let port = free_port();
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
        let b_addr = endpoint_addr(&a.transport.store().lookup(&b.key.did()).unwrap()).unwrap();
        let seen = match ask(&a.endpoint, b_addr.clone(), &DiscoveryRequest::Observe)
            .await
            .unwrap()
        {
            DiscoveryResponse::Observed(seen) => {
                seen.expect("a direct path between two hosts on one machine")
            }
            other => panic!("unexpected answer {other:?}"),
        };
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
        match ask(&private.endpoint, b_addr, &DiscoveryRequest::Observe)
            .await
            .unwrap()
        {
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
        let port = free_port();
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
                .connect(endpoint_addr(&record).unwrap(), ECHO_ALPN),
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
        fn duplicate(&self, _: EndpointId) {}
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
                base_builder(),
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
        let port = free_port();
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
        for _ in 0..200 {
            if nodes
                .iter()
                .all(|n| n.layer.neighbour_count("tenzro/blocks").unwrap_or(0) >= 1)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
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

    #[tokio::test(flavor = "multi_thread")]
    async fn a_private_node_is_resolvable_only_by_its_counterparties() {
        let port = free_port();
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
            let to_stranger = ask(
                &stranger.endpoint,
                endpoint_addr(&holder.transport.store().lookup(&holder.key.did()).unwrap())
                    .unwrap(),
                &lookup,
            )
            .await
            .unwrap();
            assert!(
                matches!(to_stranger, DiscoveryResponse::Record(None)),
                "a non-counterparty cannot resolve it"
            );
            let snapshot = ask(
                &stranger.endpoint,
                endpoint_addr(&holder.transport.store().lookup(&holder.key.did()).unwrap())
                    .unwrap(),
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
        let to_counterparty = ask(
            &counterparty.endpoint,
            endpoint_addr(&held).unwrap(),
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
        let asker = base_builder().bind().await.unwrap();
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
        let port = free_port();
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
        let member = base_builder().bind().await.unwrap();
        let outsider = base_builder().bind().await.unwrap();
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
}
