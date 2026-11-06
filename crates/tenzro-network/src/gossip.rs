//! Gossip topics, carried over the node's iroh endpoint.
//!
//! [`NetworkGossip`] is the node's gossip surface: [`NetworkGossip::broadcast`],
//! [`NetworkGossip::subscribe`] and [`NetworkGossip::subscribe_validated`] on
//! the `tenzro/...` topic names. Each name maps to one iroh-gossip topic of
//! the node's chain (see [`tenzro_iroh::gossip`]). Every received message
//! passes the [`GossipGuard`] before it is decoded and delivered, and a
//! message is passed on to other nodes only after it passed.
//!
//! Topics can be subscribed before the endpoint exists; they open once the
//! node attaches the endpoint's gossip protocol with [`NetworkGossip::attach`].

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::Mutex;
use tenzro_iroh::EndpointId;
use tenzro_iroh::gossip::{GossipLayer, GossipTransport, Inbound};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::error::{NetworkError, Result};
use crate::gossip_validation::{GossipGuard, GossipLimits, ValidatedMessage};
use crate::message::NetworkMessage;
use crate::metrics::NetworkMetrics;

/// Where decoded messages go, per topic.
#[derive(Default)]
struct Routes {
    subscribers: HashMap<Arc<str>, Vec<mpsc::Sender<NetworkMessage>>>,
    judges: HashMap<Arc<str>, mpsc::Sender<ValidatedMessage>>,
    // Messages dropped because their subscriber or judge had fallen
    // SUBSCRIBER_CAPACITY behind.
    dropped: u64,
}

/// Most messages held for one subscriber of a topic. A subscriber further
/// behind loses the newest (a judged message is then neither passed on nor
/// blamed) rather than holding them in memory without bound.
pub const SUBSCRIBER_CAPACITY: usize = 4_096;

/// The node's gossip topics.
pub struct NetworkGossip {
    layer: Arc<GossipLayer>,
    guard: Arc<GossipGuard>,
    routes: Arc<Mutex<Routes>>,
    metrics: Arc<NetworkMetrics>,
    dispatch: JoinHandle<()>,
}

impl std::fmt::Debug for NetworkGossip {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NetworkGossip").finish_non_exhaustive()
    }
}

impl NetworkGossip {
    /// Gossip with per-neighbour budgets `limits`, counting its traffic in
    /// `metrics`. Must be called inside a tokio runtime.
    pub fn new(metrics: Arc<NetworkMetrics>, limits: GossipLimits) -> Self {
        let guard = Arc::new(GossipGuard::new(metrics.clone(), limits));
        let (layer, inbound) = GossipLayer::new(guard.clone());
        let routes = Arc::new(Mutex::new(Routes::default()));
        let dispatch = tokio::spawn(dispatch(inbound, routes.clone()));
        Self {
            layer,
            guard,
            routes,
            metrics,
            dispatch,
        }
    }

    /// Opens every subscribed topic, and every later one, on the endpoint's
    /// gossip protocol for the chain `chain_id`; the guard's scores then
    /// decide which peers may hold gossip connections.
    pub fn attach(&self, transport: GossipTransport, chain_id: u64) -> Result<()> {
        self.layer
            .attach(transport, chain_id)
            .map_err(|e| NetworkError::SubscriptionError(e.to_string()))
    }

    /// Names the machine identities behind neighbours: bans and scores then
    /// follow the machine, and consensus topics take messages only from
    /// neighbours a verified endpoint record names.
    pub fn set_identities(&self, identities: Arc<dyn crate::gossip_validation::PeerIdentities>) {
        self.guard.set_identities(identities);
    }

    /// Replaces the per-neighbour budgets.
    pub fn set_limits(&self, limits: GossipLimits) {
        self.guard.set_limits(limits);
    }

    /// Joins the node's topics through `peers`. They are protected by the
    /// guard: never budgeted, penalised or banned.
    pub async fn add_peers(&self, peers: &[EndpointId]) {
        self.guard.protect(peers);
        self.layer.add_peers(peers.iter().copied()).await;
    }

    /// Publishes `message` on `topic`.
    pub async fn broadcast(&self, topic: &str, message: NetworkMessage) -> Result<()> {
        let bytes = message.to_bytes().map_err(NetworkError::Serialization)?;
        self.layer
            .publish(topic, bytes)
            .await
            .map_err(|e| NetworkError::PublishError(e.to_string()))?;
        self.metrics.gossip_published.inc();
        Ok(())
    }

    /// Every message accepted on `topic` from now on.
    pub fn subscribe(&self, topic: &str) -> mpsc::Receiver<NetworkMessage> {
        let (tx, rx) = mpsc::channel(SUBSCRIBER_CAPACITY);
        self.routes
            .lock()
            .subscribers
            .entry(Arc::from(topic))
            .or_default()
            .push(tx);
        self.layer.join(topic);
        rx
    }

    /// Every message accepted on `topic`, held for the node's verdict: it is
    /// passed on to other nodes only when its ticket is accepted. One judge
    /// per topic; a later call replaces the earlier one.
    pub fn subscribe_validated(&self, topic: &str) -> mpsc::Receiver<ValidatedMessage> {
        let (tx, rx) = mpsc::channel(SUBSCRIBER_CAPACITY);
        self.routes.lock().judges.insert(Arc::from(topic), tx);
        self.layer.join_judged(topic);
        rx
    }

    /// The peers this node met as gossip neighbours or joined through, that
    /// its rules still allow, best scored first.
    pub fn peers(&self) -> Vec<EndpointId> {
        self.layer.peers()
    }

    /// Direct neighbours on `topic`.
    pub fn neighbour_count(&self, topic: &str) -> Result<usize> {
        self.layer
            .neighbour_count(topic)
            .ok_or_else(|| NetworkError::SubscriptionError(format!("not subscribed to {topic}")))
    }
}

impl Drop for NetworkGossip {
    fn drop(&mut self) {
        self.dispatch.abort();
    }
}

/// Decodes each accepted message and hands it to the topic's subscribers
/// and judge.
async fn dispatch(mut inbound: mpsc::Receiver<Inbound>, routes: Arc<Mutex<Routes>>) {
    while let Some(Inbound {
        topic,
        content,
        ticket,
        ..
    }) = inbound.recv().await
    {
        let message = match NetworkMessage::from_bytes(&content) {
            Ok(message) => message,
            Err(e) => {
                tracing::warn!(topic = %topic, error = %e, "undecodable gossip message");
                if let Some(ticket) = ticket {
                    ticket.reject();
                }
                continue;
            }
        };
        let mut routes = routes.lock();
        let mut dropped = 0u64;
        if let Some(subscribers) = routes.subscribers.get_mut(&topic) {
            subscribers.retain(|tx| match tx.try_send(message.clone()) {
                Ok(()) => true,
                Err(mpsc::error::TrySendError::Full(_)) => {
                    dropped += 1;
                    true
                }
                Err(mpsc::error::TrySendError::Closed(_)) => false,
            });
        }
        // Without a judge nothing can vouch for the message, so the dropped
        // ticket ignores it and it is not passed on.
        if let Some(ticket) = ticket
            && let Some(judge) = routes.judges.get(&topic)
        {
            match judge.try_send(ValidatedMessage { message, ticket }) {
                Ok(()) => {}
                Err(mpsc::error::TrySendError::Full(_)) => dropped += 1,
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    routes.judges.remove(&topic);
                }
            }
        }
        if dropped > 0 {
            let before = routes.dropped;
            routes.dropped += dropped;
            if (before + 1..=routes.dropped).any(u64::is_power_of_two) {
                tracing::warn!(topic = %topic, dropped = routes.dropped, "a gossip subscriber is behind; dropping messages");
            }
        }
    }
}
