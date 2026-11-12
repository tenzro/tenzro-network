//! The gossip service a node publishes and subscribes through.

use crate::{
    error::Result, gossip::NetworkGossip, gossip_validation::GossipLimits, message::NetworkMessage,
    metrics::NetworkMetrics,
};
use async_trait::async_trait;
use parking_lot::Mutex;
use prometheus_client::registry::Registry;
use std::sync::Arc;
use tokio::sync::mpsc;

/// The hardware that holds the key vouching for this node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityRoot {
    Tpm,
    SecureEnclave,
    /// A TPM in another machine the operator owns, reached through a
    /// provider. A weaker tier than a TPM in this machine.
    TpmDelegated,
}

impl IdentityRoot {
    /// The wire form carried in `TrustProfile::identity_root`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tpm => "tpm",
            Self::SecureEnclave => "secure-enclave",
            Self::TpmDelegated => "tpm-delegated",
        }
    }
}

static IDENTITY_ROOT: std::sync::OnceLock<IdentityRoot> = std::sync::OnceLock::new();

/// What holds the key vouching for this node: `None` before the network
/// service has probed the hardware, and on a machine with neither a TPM nor a
/// Secure Enclave, which consumers read as the weakest tier.
pub fn identity_root() -> Option<IdentityRoot> {
    IDENTITY_ROOT.get().copied()
}

/// Declares what holds this node's identity key, before the network service
/// probes the hardware: a machine whose key lives in a provider's TPM has no
/// local backend to probe.
pub fn declare_identity_root(root: IdentityRoot) {
    let _ = IDENTITY_ROOT.set(root);
}

/// Network service trait
#[async_trait]
pub trait NetworkService: Send + Sync {
    /// Broadcasts a message to all peers subscribed to a topic
    async fn broadcast(&self, topic: &str, message: NetworkMessage) -> Result<()>;

    /// Subscribes to a topic and returns a receiver for messages
    async fn subscribe(&self, topic: &str) -> Result<mpsc::Receiver<NetworkMessage>>;
}

/// Gossip over the node's iroh endpoint, with its metrics.
pub struct TenzroNetworkService {
    /// Prometheus metrics bundle — exposed for `/metrics` endpoint.
    metrics: Arc<NetworkMetrics>,
    /// Metrics registry — exposed so the node can add its own subsystems
    /// and serialize all metrics to the Prometheus text format.
    metrics_registry: Arc<Mutex<Registry>>,
    /// Gossip topics, carried over the node's iroh endpoint once attached.
    gossip: NetworkGossip,
}

impl TenzroNetworkService {
    /// Creates a new network service with a fresh metrics registry and
    /// per-neighbour gossip budgets `limits`.
    pub async fn new(limits: GossipLimits) -> Result<Self> {
        let mut registry = Registry::default();
        let metrics = NetworkMetrics::register(&mut registry);
        Self::new_with_registry(Arc::new(Mutex::new(registry)), metrics, limits).await
    }

    /// Creates a new network service using a caller-provided metrics registry.
    /// Use this when the node already has a shared Prometheus registry that
    /// aggregates metrics from consensus, storage, VM, etc.
    pub async fn new_with_registry(
        metrics_registry: Arc<Mutex<Registry>>,
        metrics: Arc<NetworkMetrics>,
        limits: GossipLimits,
    ) -> Result<Self> {
        // On a blocking thread: the hardware probe opens the TPM or the enclave.
        let root = tokio::task::spawn_blocking(tenzro_device_key::signer::platform_backend)
            .await
            .map_err(|e| {
                crate::error::NetworkError::NoHardwareRoot(format!(
                    "hardware probe task failed: {e}"
                ))
            })?;
        if let Some(backend) = root {
            let _ = IDENTITY_ROOT.set(match backend {
                tenzro_device_key::HardwareBackend::Tpm => IdentityRoot::Tpm,
                tenzro_device_key::HardwareBackend::SecureEnclave => IdentityRoot::SecureEnclave,
                tenzro_device_key::HardwareBackend::RemoteTpm => IdentityRoot::TpmDelegated,
            });
        }

        Ok(Self {
            gossip: NetworkGossip::new(metrics.clone(), limits),
            metrics,
            metrics_registry,
        })
    }

    /// Carries the gossip topics over `transport`, the gossip protocol on
    /// the node's iroh endpoint, for the chain `chain_id`. Topics subscribed
    /// earlier open now.
    pub fn attach_gossip(
        &self,
        transport: tenzro_iroh::gossip::GossipTransport,
        chain_id: u64,
    ) -> Result<()> {
        self.gossip.attach(transport, chain_id)
    }

    /// Names the machine identities behind gossip neighbours; see
    /// [`NetworkGossip::set_identities`].
    pub fn set_gossip_identities(
        &self,
        identities: Arc<dyn crate::gossip_validation::PeerIdentities>,
    ) {
        self.gossip.set_identities(identities);
    }

    /// Turns on delivery from registered neighbours only; see
    /// [`NetworkGossip::set_registered_only`].
    pub fn set_gossip_registered_only(&self, on: bool) {
        self.gossip.set_registered_only(on);
    }

    /// Replaces the per-neighbour gossip budgets.
    pub fn set_gossip_limits(&self, limits: GossipLimits) {
        self.gossip.set_limits(limits);
    }

    /// Joins the gossip topics through `peers` (iroh endpoint ids this node
    /// knows and trusts to relay).
    pub async fn add_gossip_peers(&self, peers: &[tenzro_iroh::EndpointId]) {
        self.gossip.add_peers(peers).await;
    }

    /// Returns a handle to the Prometheus metrics bundle for external
    /// instrumentation (e.g., RPC call counters that live outside the
    /// networking layer can be incremented through this handle).
    pub fn metrics(&self) -> Arc<NetworkMetrics> {
        self.metrics.clone()
    }

    /// Returns the shared metrics registry — useful for callers that need
    /// to register additional metric families or serialize the registry to
    /// the Prometheus text format.
    pub fn metrics_registry(&self) -> Arc<Mutex<Registry>> {
        self.metrics_registry.clone()
    }

    /// Direct gossip neighbours on `topic`; an error if this node has not
    /// joined the topic.
    pub async fn mesh_peer_count(&self, topic: &str) -> Result<usize> {
        self.gossip.neighbour_count(topic)
    }

    /// The peers this node met as gossip neighbours or joined through, that
    /// its gossip rules still allow, best scored first.
    pub fn gossip_peers(&self) -> Vec<tenzro_iroh::EndpointId> {
        self.gossip.peers()
    }

    /// Peers this node gossips with directly: its neighbours on
    /// `tenzro/status`, the topic every node joins. Zero before it is joined.
    pub fn peer_count(&self) -> usize {
        self.gossip.neighbour_count("tenzro/status").unwrap_or(0)
    }

    /// Subscribes to a topic whose messages this node judges before they are
    /// passed on to other nodes. Each message arrives with a ticket; the
    /// message is passed on only if the ticket is accepted. Subscribing again
    /// replaces the previous judge.
    pub async fn subscribe_validated(
        &self,
        topic: &str,
    ) -> Result<mpsc::Receiver<crate::gossip_validation::ValidatedMessage>> {
        Ok(self.gossip.subscribe_validated(topic))
    }
}

#[async_trait]
impl NetworkService for TenzroNetworkService {
    async fn broadcast(&self, topic: &str, message: NetworkMessage) -> Result<()> {
        self.gossip.broadcast(topic, message).await
    }

    async fn subscribe(&self, topic: &str) -> Result<mpsc::Receiver<NetworkMessage>> {
        Ok(self.gossip.subscribe(topic))
    }
}
