//! The app transport: a WebTransport listener through which the devices of
//! applications sign in to this node and open streams to each other.
//!
//! Nothing here runs unless the operator configures `[app_transport]`. A
//! device connects, is sent a nonce, and signs in on the session's control
//! stream with the access token this node issued it and a proof of
//! possession made over that nonce. Until it has, nothing else it sends is
//! read. A signed-in device opens streams to devices of other identities
//! signed in to this node; the node carries the bytes, which the devices
//! seal end to end, and counts them for the identity that opened the stream
//! ([`tenzro_iroh::app_stream`]).
//!
//! The listener serves the operator's certificate when the configuration
//! names one, and otherwise a short-lived certificate of its own that a
//! device pins by hash ([`crate::pinned_cert`]). The key exchange prefers
//! X25519MLKEM768, so a client that offers the hybrid group gets it.

pub mod devices;
mod flows;
mod payments;
mod peers;
pub(crate) mod rpc;
mod session;
mod sign_in;

use std::collections::HashMap;
use std::hash::Hash;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use parking_lot::Mutex;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tenzro_auth::TokenSigner;
use tenzro_iroh::app_stream::{BoxedRead, BoxedWrite, ByteMeter};
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;
use wtransport::endpoint::endpoint_side::Server;
use wtransport::{Endpoint, ServerConfig};

use crate::config::AppTransportConfig;
use crate::pinned_cert::{PinnedCerts, PinnedHash, Publication};
use devices::{DeviceLimits, Devices};

pub use payments::NodePayments;
pub use peers::{NodePeerStreams, NodePeers};
pub use sign_in::{NodeRelayDevices, NodeSignIn};

/// How long a connection may stay silent before it is dropped.
const IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// The two halves of a stream to a device, as the node carries them.
/// A device's end of a carried stream, and of its datagram flow when it has
/// one.
pub(crate) type Carried = (
    wtransport::RecvStream,
    wtransport::SendStream,
    Option<flows::FlowSide>,
);

/// Who a device signed in as.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Admitted {
    /// The identity its access token names.
    pub did: String,
    /// The device: the thumbprint of the key the token is bound to.
    pub device: String,
    /// When the token ends, seconds since the epoch.
    pub expires_at: u64,
}

/// Why a sign-in was not admitted outright.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// Refused; the reason is given to the device.
    No(String),
    /// The device is who it says, and the access policy asks it to pay
    /// `price` of `asset` for each mebibyte carried.
    Pay {
        admitted: Admitted,
        price: String,
        asset: String,
    },
}

/// Decides who may sign in to the app transport.
pub trait SignIn: Send + Sync + 'static {
    /// Checks an access token and a proof of possession naming `htu`: the
    /// session's nonce, and its TLS binding when the device gave one.
    fn admit(&self, htu: &str, access_token: &str, dpop: &str) -> Result<Admitted, Refusal>;

    /// Signs a welcome's digest with the node's keys. May block on the
    /// machine's key hardware.
    fn vouch(&self, digest: &[u8; 32]) -> Result<Vouch, String>;
}

/// What a paying device's credential bought before anything was carried.
#[derive(Debug, Clone)]
pub struct Hold {
    /// The credential, as the device presented it (JSON).
    pub credential: String,
    /// The price of one mebibyte, in the smallest unit of the asset.
    pub price: u128,
    /// The bytes the credential's ceiling pays for.
    pub bytes: u64,
}

/// Takes payment for carriage when the access policy asks it.
#[async_trait]
pub trait Payments: Send + Sync + 'static {
    /// The challenge (JSON) a device pays to sign in at `price` of `asset`
    /// per mebibyte.
    async fn quote(&self, price: &str, asset: &str) -> Result<String, String>;
    /// Checks `credential` before anything is carried, and says what it buys.
    async fn hold(&self, credential: &str, price: &str, asset: &str) -> Result<Hold, String>;
    /// Charges `hold` for the `mebibytes` carried.
    async fn settle(&self, hold: Hold, mebibytes: u64);
}

/// A node's signatures over a welcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Vouch {
    /// ECDSA P-256 `r || s`, base64url.
    pub signature: String,
    /// ML-DSA-65, base64url.
    pub pq_signature: String,
}

/// What each key holds at once, up to a cap: connections that have not
/// signed in by the address they come from, streams by the node that carried
/// them here.
struct Tally<K: Hash + Eq + Clone> {
    cap: u32,
    held: Mutex<HashMap<K, u32>>,
}

/// One thing a key holds, counted until dropped.
struct Held<K: Hash + Eq + Clone> {
    tally: Arc<Tally<K>>,
    key: K,
}

/// A connection that has not signed in yet.
type Pending = Held<IpAddr>;

impl<K: Hash + Eq + Clone> Drop for Held<K> {
    fn drop(&mut self) {
        let mut held = self.tally.held.lock();
        if let Some(count) = held.get_mut(&self.key) {
            *count -= 1;
            if *count == 0 {
                held.remove(&self.key);
            }
        }
    }
}

impl<K: Hash + Eq + Clone> Tally<K> {
    fn new(cap: u32) -> Arc<Self> {
        Arc::new(Self {
            cap,
            held: Mutex::new(HashMap::new()),
        })
    }

    /// Counts one more for `key`, unless `key` already holds as many as it
    /// may.
    fn admit(self: &Arc<Self>, key: K) -> Option<Held<K>> {
        let mut held = self.held.lock();
        let count = held.entry(key.clone()).or_insert(0);
        if *count >= self.cap {
            return None;
        }
        *count += 1;
        Some(Held {
            tally: self.clone(),
            key,
        })
    }
}

/// Both halves of a stream to or from another node.
pub type Pipe = (BoxedRead, BoxedWrite);

/// Reaches the app transport of other nodes.
#[async_trait]
pub trait Peers: Send + Sync + 'static {
    /// Opens a stream to the app transport of the node `did`.
    async fn dial(&self, did: &str) -> Result<Pipe, String>;
}

/// Streams between nodes, when this node carries them.
struct Between {
    peers: Arc<dyn Peers>,
    by_peer: Arc<Tally<String>>,
}

/// What every session of the listener shares.
struct Shared {
    path: String,
    sign_in: Arc<dyn SignIn>,
    devices: Arc<Devices<Carried>>,
    /// Streams each identity has open now.
    streams: Arc<Tally<String>>,
    meter: Arc<ByteMeter>,
    between: Option<Between>,
    payments: Arc<dyn Payments>,
    /// Identities in a paid session now: one at a time each.
    paying: Mutex<std::collections::HashSet<String>>,
}

/// A running app transport listener. Dropping it stops the listener and
/// ends its sessions.
pub struct AppTransport {
    local_addr: SocketAddr,
    url: String,
    pinned: Option<Arc<PinnedCerts>>,
    meter: Arc<ByteMeter>,
    shared: Arc<Shared>,
    accepting: JoinHandle<()>,
    rotating: Option<JoinHandle<()>>,
}

impl Drop for AppTransport {
    fn drop(&mut self) {
        self.accepting.abort();
        if let Some(rotating) = &self.rotating {
            rotating.abort();
        }
    }
}

/// The TLS configuration of the listener: TLS 1.3, HTTP/3, the hybrid
/// post-quantum key exchange ahead of the classical ones.
fn tls_builder()
-> Result<rustls::ConfigBuilder<rustls::ServerConfig, rustls::server::WantsServerCert>, String> {
    use rustls::crypto::aws_lc_rs::kx_group::{SECP256R1, X25519, X25519MLKEM768};
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    provider.kx_groups = vec![X25519MLKEM768, X25519, SECP256R1];
    Ok(
        rustls::ServerConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|e| format!("app transport TLS: {e}"))?
            .with_no_client_auth(),
    )
}

fn with_alpn(mut tls: rustls::ServerConfig) -> rustls::ServerConfig {
    tls.alpn_protocols = vec![wtransport::tls::WEBTRANSPORT_ALPN.to_vec()];
    tls
}

/// The name the listener's certificates are published under.
pub const LISTENER: &str = "app-transport";

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl AppTransport {
    /// Binds the listener `config` describes and serves it, admitting
    /// devices through `sign_in`. With `peer_streams` configured it carries
    /// streams to and from other nodes through `peers`; when the access
    /// policy asks payment, it takes it through `payments`.
    pub fn start(
        config: &AppTransportConfig,
        sign_in: Arc<dyn SignIn>,
        peers: Arc<dyn Peers>,
        payments: Arc<dyn Payments>,
    ) -> Result<Self, String> {
        let listen: SocketAddr = config
            .listen
            .parse()
            .map_err(|e| format!("app_transport.listen {}: {e}", config.listen))?;
        let url = url::Url::parse(&config.url)
            .map_err(|e| format!("app_transport.url {}: {e}", config.url))?;
        if url.scheme() != "https" {
            return Err(format!("app_transport.url {}: must be https", config.url));
        }
        let host = url
            .host_str()
            .ok_or_else(|| format!("app_transport.url {}: names no host", config.url))?
            .trim_matches(|c| c == '[' || c == ']')
            .to_string();

        let (tls, pinned) = match (&config.cert, &config.key) {
            (Some(cert), Some(key)) => {
                let chain = CertificateDer::pem_file_iter(cert)
                    .and_then(|certs| certs.collect::<Result<Vec<_>, _>>())
                    .map_err(|e| format!("app_transport.cert {}: {e}", cert.display()))?;
                let key = PrivateKeyDer::from_pem_file(key)
                    .map_err(|e| format!("app_transport.key {}: {e}", key.display()))?;
                let tls = tls_builder()?
                    .with_single_cert(chain, key)
                    .map_err(|e| format!("app transport certificate: {e}"))?;
                (tls, None)
            }
            (None, None) => {
                let certs = Arc::new(PinnedCerts::mint(vec![host], unix_now())?);
                (
                    tls_builder()?.with_cert_resolver(certs.clone()),
                    Some(certs),
                )
            }
            _ => {
                return Err(
                    "app_transport: give both cert and key, or neither for a pinned certificate"
                        .to_string(),
                );
            }
        };

        let server = ServerConfig::builder()
            .with_bind_address(listen)
            .with_custom_tls(with_alpn(tls))
            .max_idle_timeout(Some(IDLE_TIMEOUT))
            .map_err(|e| format!("app transport idle timeout: {e}"))?
            .build();
        let endpoint: Endpoint<Server> = Endpoint::server(server)
            .map_err(|e| format!("app transport listener on {listen}: {e}"))?;
        let local_addr = endpoint
            .local_addr()
            .map_err(|e| format!("app transport listener address: {e}"))?;

        if config.idle_secs == 0 || config.streams_per_identity == 0 {
            return Err(
                "app_transport: idle_secs and streams_per_identity must be above zero".to_string(),
            );
        }
        let meter = Arc::new(
            ByteMeter::new(config.bytes_per_second, config.burst_bytes)
                .with_idle(Duration::from_secs(config.idle_secs)),
        );
        let shared = Arc::new(Shared {
            path: url.path().to_string(),
            sign_in,
            devices: Devices::new(DeviceLimits {
                max_sessions: config.max_sessions,
                opens_per_minute: config.opens_per_minute,
                pending_per_device: config.pending_per_device,
                sessions_per_identity: config.sessions_per_identity,
            }),
            streams: Tally::new(config.streams_per_identity),
            meter: meter.clone(),
            between: config.peer_streams.map(|cap| Between {
                peers,
                by_peer: Tally::new(cap),
            }),
            payments,
            paying: Mutex::new(std::collections::HashSet::new()),
        });
        let connections = Arc::new(Semaphore::new(config.max_sessions));
        let unsigned = Tally::new(config.pending_per_ip);
        let serving = shared.clone();
        let accepting = tokio::spawn(async move {
            loop {
                let incoming = endpoint.accept().await;
                let Some(pending) = unsigned.admit(incoming.remote_address().ip()) else {
                    incoming.refuse();
                    continue;
                };
                let Ok(permit) = connections.clone().try_acquire_owned() else {
                    incoming.refuse();
                    continue;
                };
                tokio::spawn(session::serve(serving.clone(), incoming, permit, pending));
            }
        });
        let rotating = pinned.clone().map(|certs| tokio::spawn(certs.run()));
        Ok(Self {
            local_addr,
            url: config.url.clone(),
            pinned,
            meter,
            shared,
            accepting,
            rotating,
        })
    }

    /// Serves a stream the node `peer` carries to a device signed in here.
    pub async fn serve_peer(&self, peer: String, pipe: Pipe) {
        session::serve_peer(self.shared.clone(), peer, pipe).await;
    }

    /// The address the listener is bound to.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// The URL devices reach the listener under.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// The hashes of the certificates a device may pin, when the node mints
    /// its own: the one served now, then the one served next.
    pub fn pinned_hashes(&self) -> Option<Vec<PinnedHash>> {
        self.pinned.as_ref().map(|certs| certs.hashes())
    }

    /// What has been carried, by identity.
    pub fn meter(&self) -> &Arc<ByteMeter> {
        &self.meter
    }

    /// The hashes a device may pin, signed by `signer` for `issuer`, when the
    /// node mints its own certificates.
    pub fn publish(
        &self,
        signer: &dyn TokenSigner,
        issuer: &str,
    ) -> Option<Result<Publication, String>> {
        self.pinned
            .as_ref()
            .map(|certs| certs.publish(signer, issuer, LISTENER, unix_now()))
    }
}

#[cfg(test)]
mod tests;
