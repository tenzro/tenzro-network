//! Inter-agent messaging system for Tenzro Network.
//!
//! This module provides message routing, queuing, and delivery between
//! agents on the network, with support for request-response patterns
//! and message signing.

use crate::error::{AgentError, Result};
use async_trait::async_trait;
use dashmap::DashMap;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, RwLock};
use tenzro_crypto::composite::{
    CompositePublicKey, CompositeSignature, HybridSigner, HybridVerifier, InMemoryHybridSigner,
    StandardHybridVerifier,
};
use tenzro_crypto::PublicKey;
use tenzro_storage::kv::{KvStore, CF_AGENTS};
use tenzro_storage::{
    compute_commitment, InlineFallbackBackend, ReceiptEnvelope, ReceiptKind, ReceiptStorageMode,
    ReceiptSummary,
};
use tenzro_types::{AgentIdentity, AgentMessage, AgentMessageType};
use tracing::{debug, info, warn};

/// RocksDB key prefix for persisted agent-message receipts. Lives in
/// [`CF_AGENTS`] alongside the agent / lifecycle / spawn-tree records.
/// Layout: `message:<agent_id>:<timestamp_ms_be>:<message_id>` so a
/// per-agent prefix scan returns chronologically-ordered receipts.
const MESSAGE_KEY_PREFIX: &[u8] = b"message:";

/// DA namespace used when offloading agent-message receipts via the
/// inline-fallback backend.
const AGENT_MESSAGE_DA_NAMESPACE: &[u8] = b"tenzro/agent_message";

/// Default message queue capacity per agent
const DEFAULT_QUEUE_CAPACITY: usize = 1000;

/// Default per-sender rate limit — messages per second sustained
const DEFAULT_PER_SENDER_RATE: u32 = 20;
/// Default per-sender burst — max messages allowed in a burst
const DEFAULT_PER_SENDER_BURST: u32 = 40;
/// Default per-recipient rate limit — messages per second sustained
const DEFAULT_PER_RECIPIENT_RATE: u32 = 100;
/// Default per-recipient burst — max messages allowed in a burst
const DEFAULT_PER_RECIPIENT_BURST: u32 = 200;
/// Default global rate limit — messages per second sustained across the router
const DEFAULT_GLOBAL_RATE: u32 = 1000;
/// Default global burst — max messages allowed in a burst across the router
const DEFAULT_GLOBAL_BURST: u32 = 2000;

/// Token-bucket rate limiter (HIGH #107).
///
/// Maintains a bucket of tokens that refills at `rate` tokens per second up
/// to `burst` capacity. Each call to `try_acquire` consumes one token if
/// available; otherwise it returns the duration the caller must wait before
/// a token becomes available. This is the canonical token-bucket algorithm
/// as described in "An Architecture for Differentiated Services" (RFC 2475).
///
/// The bucket is protected by a `parking_lot::Mutex` rather than an async
/// primitive because all operations are non-blocking arithmetic.
#[derive(Debug)]
struct TokenBucket {
    /// Refill rate in tokens per second
    rate: f64,
    /// Maximum bucket capacity (burst size)
    burst: f64,
    /// Current token count (can be fractional for sub-second accuracy)
    tokens: Mutex<BucketState>,
}

#[derive(Debug)]
struct BucketState {
    tokens: f64,
    last_refill: Instant,
}

impl TokenBucket {
    /// Creates a new token bucket with the given refill rate and burst capacity.
    ///
    /// The bucket starts full (at `burst` tokens) so the first `burst`
    /// requests are always admitted even if they arrive back-to-back.
    fn new(rate: u32, burst: u32) -> Self {
        Self {
            rate: rate as f64,
            burst: burst as f64,
            tokens: Mutex::new(BucketState {
                tokens: burst as f64,
                last_refill: Instant::now(),
            }),
        }
    }

    /// Attempts to acquire one token from the bucket.
    ///
    /// Returns `Ok(())` if a token was available and consumed.
    /// Returns `Err(retry_after)` with the duration the caller must wait
    /// before the next token becomes available.
    fn try_acquire(&self) -> std::result::Result<(), Duration> {
        let mut state = self.tokens.lock();
        let now = Instant::now();
        let elapsed = now.duration_since(state.last_refill).as_secs_f64();

        // Refill the bucket based on elapsed time, clamped to burst capacity
        state.tokens = (state.tokens + elapsed * self.rate).min(self.burst);
        state.last_refill = now;

        if state.tokens >= 1.0 {
            state.tokens -= 1.0;
            Ok(())
        } else {
            // Compute how long until we have 1 full token
            let deficit = 1.0 - state.tokens;
            let wait_secs = deficit / self.rate;
            // Round up to at least 1 second for caller-friendly retry hints;
            // the internal calculation is still precise
            let wait = Duration::from_secs_f64(wait_secs.max(0.001));
            Err(wait)
        }
    }

    /// Returns the current token count (for observability/tests).
    #[cfg(test)]
    fn available(&self) -> f64 {
        let mut state = self.tokens.lock();
        let now = Instant::now();
        let elapsed = now.duration_since(state.last_refill).as_secs_f64();
        state.tokens = (state.tokens + elapsed * self.rate).min(self.burst);
        state.last_refill = now;
        state.tokens
    }
}

/// Rate-limit configuration for the message router (HIGH #107).
///
/// All limits are token-bucket based. A rate of 0 disables that scope's
/// limit entirely. Set `enable_rate_limiting = false` to disable all
/// rate limiting (useful for trusted single-node deployments and tests).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Whether rate limiting is enabled at all
    pub enabled: bool,
    /// Sustained messages per second per sending agent
    pub per_sender_rate: u32,
    /// Burst capacity per sending agent
    pub per_sender_burst: u32,
    /// Sustained messages per second per receiving agent
    pub per_recipient_rate: u32,
    /// Burst capacity per receiving agent
    pub per_recipient_burst: u32,
    /// Sustained messages per second across the entire router
    pub global_rate: u32,
    /// Burst capacity across the entire router
    pub global_burst: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            per_sender_rate: DEFAULT_PER_SENDER_RATE,
            per_sender_burst: DEFAULT_PER_SENDER_BURST,
            per_recipient_rate: DEFAULT_PER_RECIPIENT_RATE,
            per_recipient_burst: DEFAULT_PER_RECIPIENT_BURST,
            global_rate: DEFAULT_GLOBAL_RATE,
            global_burst: DEFAULT_GLOBAL_BURST,
        }
    }
}

impl RateLimitConfig {
    /// Creates a config with rate limiting disabled (useful for tests).
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            ..Self::default()
        }
    }

    /// Sets the per-sender rate and burst.
    pub fn with_per_sender(mut self, rate: u32, burst: u32) -> Self {
        self.per_sender_rate = rate;
        self.per_sender_burst = burst;
        self
    }

    /// Sets the per-recipient rate and burst.
    pub fn with_per_recipient(mut self, rate: u32, burst: u32) -> Self {
        self.per_recipient_rate = rate;
        self.per_recipient_burst = burst;
        self
    }

    /// Sets the global rate and burst.
    pub fn with_global(mut self, rate: u32, burst: u32) -> Self {
        self.global_rate = rate;
        self.global_burst = burst;
        self
    }
}

/// Message handler trait for processing incoming messages
#[async_trait]
pub trait MessageHandler: Send + Sync {
    /// Handles an incoming message
    async fn handle_message(&self, message: AgentMessage) -> Result<Option<AgentMessage>>;
}

/// Network transport trait for cross-node messaging
#[async_trait]
pub trait NetworkTransport: Send + Sync {
    /// Sends a message to a remote peer
    async fn send_remote(&self, peer_id: String, message: AgentMessage) -> Result<()>;

    /// Receives a message from the network
    async fn receive_remote(&self) -> Result<Option<AgentMessage>>;

    /// Checks if a peer is reachable
    async fn is_peer_reachable(&self, peer_id: &str) -> bool;
}

/// Bundle of agent verifying keys used for hybrid signature verification.
///
/// Wave 3d: every agent registered with the router carries BOTH a
/// classical Ed25519 verifying key and an ML-DSA-65 verifying key
/// (1952 bytes). The router looks both up via [`PublicKeyResolver`]
/// and feeds them into `StandardHybridVerifier`.
#[derive(Debug, Clone)]
pub struct AgentVerifyingKeys {
    /// Classical Ed25519 public key.
    pub classical: PublicKey,
    /// ML-DSA-65 (FIPS 204) verifying key bytes (1952 bytes).
    pub pq_verifying_key: Vec<u8>,
}

impl AgentVerifyingKeys {
    /// Constructs a new key bundle.
    pub fn new(classical: PublicKey, pq_verifying_key: Vec<u8>) -> Self {
        Self {
            classical,
            pq_verifying_key,
        }
    }
}

/// Resolver trait for looking up an agent's hybrid signing keys (CRITICAL #54,
/// extended for Wave 3d hybrid post-quantum signing).
///
/// The message router does not embed public keys in `AgentIdentity` (which
/// stays serialization-friendly and small), so the router needs an external
/// way to find the keys associated with a given `agent_id` in order to
/// verify the hybrid signature on the message.
///
/// Implementations may be:
/// - **In-memory** (`LocalPublicKeyResolver`) — useful in single-process
///   tests and trusted single-node deployments where keys are registered
///   alongside `register_agent`.
/// - **TDIP-backed** — production deployments should plug a resolver that
///   looks the agent up in `tenzro_identity::IdentityRegistry` and pulls
///   the keypair from the agent's W3C DID document. The node binary is
///   responsible for wiring such a resolver into the runtime.
///
/// `resolve()` returns `None` for unknown agents; the router treats this
/// as a "no key on file" condition and rejects the message with
/// `AgentError::InvalidMessageSignature`.
#[async_trait]
pub trait PublicKeyResolver: Send + Sync {
    /// Resolves an agent's hybrid public signing keys by `agent_id`.
    ///
    /// Returns `None` if the agent is unknown or has no on-file key.
    async fn resolve(&self, agent_id: &str) -> Option<AgentVerifyingKeys>;
}

/// Default in-memory implementation of [`PublicKeyResolver`].
///
/// Backed by a `DashMap` so registration and lookup are lock-free across
/// concurrent senders and receivers. Suitable for tests, single-node
/// setups, and as a local cache layered in front of a real TDIP resolver.
#[derive(Default)]
pub struct LocalPublicKeyResolver {
    keys: DashMap<String, AgentVerifyingKeys>,
}

impl LocalPublicKeyResolver {
    /// Creates an empty resolver.
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a hybrid verifying-key bundle for the given agent.
    /// Replaces any existing entry; intentional, so an agent that rotates
    /// its key is not stuck with a stale binding.
    pub fn register(&self, agent_id: String, keys: AgentVerifyingKeys) {
        self.keys.insert(agent_id, keys);
    }

    /// Removes an agent's key registration. No-op for unknown agents.
    pub fn forget(&self, agent_id: &str) {
        self.keys.remove(agent_id);
    }

    /// Returns the number of agents currently registered (for tests).
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Returns true when no agents are registered.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

#[async_trait]
impl PublicKeyResolver for LocalPublicKeyResolver {
    async fn resolve(&self, agent_id: &str) -> Option<AgentVerifyingKeys> {
        self.keys.get(agent_id).map(|kv| kv.value().clone())
    }
}

/// Gossipsub-backed network transport for inter-node agent messaging.
///
/// This transport bridges agent messages to/from the libp2p gossipsub network.
/// The node binary injects an outbound sender channel connected to the
/// `tenzro-network` `NetworkService::broadcast()` method, enabling agent
/// messages to be published on the `tenzro/agents` gossipsub topic.
///
/// Inbound messages arrive via the `inbound_tx` channel, which the node
/// populates from gossipsub subscription events.
///
/// If no outbound sender is configured (e.g., in tests), messages are
/// delivered locally via the inbound channel as a loopback.
pub struct GossipsubTransport {
    /// Topic for agent messages
    topic: String,
    /// Inbound message queue (received from gossipsub or loopback)
    inbound_rx: Arc<RwLock<mpsc::Receiver<AgentMessage>>>,
    /// Sender for injecting inbound messages (used by the node's gossipsub listener)
    inbound_tx: mpsc::Sender<AgentMessage>,
    /// Outbound sender for publishing to gossipsub (injected by the node)
    /// Sends serialized (topic, data) pairs for the node to broadcast
    outbound_tx: Option<mpsc::Sender<(String, Vec<u8>)>>,
}

impl GossipsubTransport {
    /// Creates a new gossipsub transport in local-only (loopback) mode.
    ///
    /// Messages sent via `send_remote()` are looped back to the local
    /// inbound queue. Suitable for single-node setups and testing.
    pub fn new() -> Self {
        let (tx, rx) = mpsc::channel(1000);
        Self {
            topic: "tenzro/agents".to_string(),
            inbound_rx: Arc::new(RwLock::new(rx)),
            inbound_tx: tx,
            outbound_tx: None,
        }
    }

    /// Creates a gossipsub transport wired to a real gossipsub network.
    ///
    /// - `outbound_tx`: The node sends serialized messages through this channel
    ///   to `NetworkService::broadcast()` on the agents topic.
    /// - Returns `(transport, inbound_tx)` — the node must feed incoming
    ///   gossipsub messages into `inbound_tx` after deserializing them.
    pub fn with_network(
        outbound_tx: mpsc::Sender<(String, Vec<u8>)>,
    ) -> (Self, mpsc::Sender<AgentMessage>) {
        let (tx, rx) = mpsc::channel(1000);
        let transport = Self {
            topic: "tenzro/agents".to_string(),
            inbound_rx: Arc::new(RwLock::new(rx)),
            inbound_tx: tx.clone(),
            outbound_tx: Some(outbound_tx),
        };
        (transport, tx)
    }

    /// Gets the gossipsub topic name
    pub fn topic(&self) -> &str {
        &self.topic
    }

    /// Returns a sender for injecting inbound messages (from gossipsub listener)
    pub fn inbound_sender(&self) -> mpsc::Sender<AgentMessage> {
        self.inbound_tx.clone()
    }
}

impl Default for GossipsubTransport {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NetworkTransport for GossipsubTransport {
    async fn send_remote(&self, peer_id: String, message: AgentMessage) -> Result<()> {
        // Serialize message for network transport
        let serialized = serde_json::to_vec(&message)
            .map_err(|e| AgentError::MessageDeliveryFailed(format!("Serialization failed: {}", e)))?;

        if let Some(ref outbound) = self.outbound_tx {
            // Publish to real gossipsub via the node's network service
            outbound
                .send((self.topic.clone(), serialized))
                .await
                .map_err(|_| {
                    AgentError::MessageDeliveryFailed(
                        "Gossipsub outbound channel closed".to_string(),
                    )
                })?;

            debug!(
                "Published agent message {} to gossipsub topic {} (target peer: {})",
                message.message_id, self.topic, peer_id
            );
        } else {
            // Loopback mode: deliver locally for testing
            debug!(
                "Loopback: agent message {} for peer {}",
                message.message_id, peer_id
            );
            let _ = self.inbound_tx.try_send(message);
        }

        Ok(())
    }

    async fn receive_remote(&self) -> Result<Option<AgentMessage>> {
        let mut rx = self.inbound_rx.write().await;
        Ok(rx.recv().await)
    }

    async fn is_peer_reachable(&self, peer_id: &str) -> bool {
        if self.outbound_tx.is_some() {
            // With a real network, assume peers on the gossipsub mesh are reachable
            debug!("Peer {} reachability: true (gossipsub connected)", peer_id);
            true
        } else {
            debug!("Peer {} reachability: false (loopback mode)", peer_id);
            false
        }
    }
}

/// Message routing configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageRouterConfig {
    /// Maximum queue size per agent
    pub max_queue_size: usize,
    /// Enable message signing
    pub enable_signing: bool,
    /// Maximum message size in bytes
    pub max_message_size: usize,
    /// Message retention period in seconds
    pub message_retention_secs: u64,
    /// Rate limiting configuration (HIGH #107)
    pub rate_limit: RateLimitConfig,
}

impl Default for MessageRouterConfig {
    fn default() -> Self {
        Self {
            max_queue_size: DEFAULT_QUEUE_CAPACITY,
            enable_signing: true,
            max_message_size: 1024 * 1024, // 1 MB
            message_retention_secs: 3600,   // 1 hour
            rate_limit: RateLimitConfig::default(),
        }
    }
}

impl MessageRouterConfig {
    /// Sets the rate-limit configuration.
    pub fn with_rate_limit(mut self, rate_limit: RateLimitConfig) -> Self {
        self.rate_limit = rate_limit;
        self
    }

    /// Disables rate limiting entirely (useful for tests).
    pub fn without_rate_limiting(mut self) -> Self {
        self.rate_limit = RateLimitConfig::disabled();
        self
    }
}

/// Message queue for an agent
struct AgentMessageQueue {
    /// Sender for the message queue
    tx: mpsc::Sender<AgentMessage>,
    /// Receiver for the message queue
    rx: Arc<RwLock<mpsc::Receiver<AgentMessage>>>,
}

impl AgentMessageQueue {
    /// Creates a new message queue
    fn new(capacity: usize) -> Self {
        let (tx, rx) = mpsc::channel(capacity);
        Self {
            tx,
            rx: Arc::new(RwLock::new(rx)),
        }
    }

    /// Sends a message to the queue
    async fn send(&self, message: AgentMessage) -> Result<()> {
        self.tx
            .send(message)
            .await
            .map_err(|_| AgentError::MessageDeliveryFailed("Queue closed".to_string()))
    }

    /// Receives a message from the queue
    async fn recv(&self) -> Option<AgentMessage> {
        self.rx.write().await.recv().await
    }

    /// Tries to send without blocking
    fn try_send(&self, message: AgentMessage) -> Result<()> {
        self.tx.try_send(message).map_err(|e| match e {
            mpsc::error::TrySendError::Full(_) => {
                AgentError::MessageQueueFull("Queue at capacity".to_string())
            }
            mpsc::error::TrySendError::Closed(_) => {
                AgentError::MessageDeliveryFailed("Queue closed".to_string())
            }
        })
    }
}

/// Routes messages between agents on the network
pub struct MessageRouter {
    /// Message queues for each agent
    queues: Arc<DashMap<String, AgentMessageQueue>>,
    /// Message history
    history: Arc<DashMap<String, Vec<AgentMessage>>>,
    /// Message handlers by agent ID
    handlers: Arc<DashMap<String, Arc<dyn MessageHandler>>>,
    /// Network transport for cross-node messaging
    network_transport: Option<Arc<dyn NetworkTransport>>,
    /// Per-sender token buckets (HIGH #107)
    sender_buckets: Arc<DashMap<String, Arc<TokenBucket>>>,
    /// Per-recipient token buckets (HIGH #107)
    recipient_buckets: Arc<DashMap<String, Arc<TokenBucket>>>,
    /// Global token bucket shared across the router (HIGH #107)
    global_bucket: Arc<TokenBucket>,
    /// Counter of messages rejected due to rate limiting (HIGH #107)
    rate_limited_count: Arc<Mutex<u64>>,
    /// Resolver for sender public keys (CRITICAL #54). Always present;
    /// defaults to an in-memory `LocalPublicKeyResolver` so unit tests
    /// and trusted single-node deployments work out of the box.
    key_resolver: Arc<dyn PublicKeyResolver>,
    /// Strongly-typed handle to the local resolver, when in use
    /// (CRITICAL #54). `None` after `with_key_resolver()` swaps in a
    /// custom resolver. Lets `register_local_key` populate keys
    /// without needing to downcast a trait object.
    local_resolver: Option<Arc<LocalPublicKeyResolver>>,
    /// Counter of messages rejected due to invalid signatures (CRITICAL #54)
    rejected_signature_count: Arc<Mutex<u64>>,
    /// Optional persistent storage. When `Some`, every accepted agent message
    /// is wrapped in a [`ReceiptEnvelope`] (kind = `AgentMessage`,
    /// storage_mode = `OffloadedDA`) and written to [`CF_AGENTS`] under
    /// `message:<agent_id>:<timestamp_ms_be>:<message_id>`. The full message
    /// payload lives in the DA backend (inline-fallback by default, mirrored
    /// to `CF_METADATA / da_fallback:<locator>` for cross-restart durability).
    storage: Option<Arc<dyn KvStore>>,
    /// DA backend used to offload agent-message payloads. Always present; when
    /// `storage` is also wired, the backend shares that `KvStore` so payloads
    /// survive restarts.
    da_backend: Arc<InlineFallbackBackend>,
    /// Configuration
    config: MessageRouterConfig,
}

impl MessageRouter {
    /// Creates a new message router
    pub fn new() -> Self {
        Self::with_config(MessageRouterConfig::default())
    }

    /// Creates a new message router with custom configuration
    pub fn with_config(config: MessageRouterConfig) -> Self {
        let global_bucket = Arc::new(TokenBucket::new(
            config.rate_limit.global_rate,
            config.rate_limit.global_burst,
        ));
        // CRITICAL #54: default to an in-memory resolver so unit tests
        // and trusted single-node deployments work without extra wiring.
        // We keep a strongly-typed `Arc<LocalPublicKeyResolver>` in
        // `local_resolver` so callers can register keys via
        // `register_local_key` without needing to downcast a trait
        // object. The same Arc is also stored in `key_resolver` so the
        // verifier path goes through the trait. When a production
        // resolver is plugged in via `with_key_resolver`, `local_resolver`
        // is cleared so callers know the local register path is a no-op.
        let local = Arc::new(LocalPublicKeyResolver::new());
        let key_resolver: Arc<dyn PublicKeyResolver> = local.clone();
        Self {
            queues: Arc::new(DashMap::new()),
            history: Arc::new(DashMap::new()),
            handlers: Arc::new(DashMap::new()),
            network_transport: None,
            sender_buckets: Arc::new(DashMap::new()),
            recipient_buckets: Arc::new(DashMap::new()),
            global_bucket,
            rate_limited_count: Arc::new(Mutex::new(0)),
            key_resolver,
            local_resolver: Some(local),
            rejected_signature_count: Arc::new(Mutex::new(0)),
            storage: None,
            da_backend: Arc::new(InlineFallbackBackend::new()),
            config,
        }
    }

    /// Wires a durable [`KvStore`] for agent-message receipt persistence.
    ///
    /// Subsequent accepted messages are wrapped in a [`ReceiptEnvelope`]
    /// (kind = [`ReceiptKind::AgentMessage`], storage_mode =
    /// [`ReceiptStorageMode::OffloadedDA`]) and written to [`CF_AGENTS`]
    /// under `message:<agent_id>:<timestamp_ms_be>:<message_id>`. The DA
    /// backend (always [`InlineFallbackBackend`] until external DA layers
    /// land) shares the same `KvStore` so offloaded payloads survive
    /// restarts via `CF_METADATA / da_fallback:<locator>`.
    ///
    /// Without this call the router is in-memory only — useful for unit
    /// tests and trusted single-process deployments where the `history`
    /// DashMap suffices.
    pub fn with_storage(mut self, storage: Arc<dyn KvStore>) -> Self {
        let da = Arc::new(InlineFallbackBackend::new().with_storage(storage.clone()));
        self.storage = Some(storage);
        self.da_backend = da;
        self
    }

    /// Access the DA backend used for agent-message receipt offload.
    pub fn da_backend(&self) -> Arc<InlineFallbackBackend> {
        self.da_backend.clone()
    }

    /// Replaces the public-key resolver used for verifying inbound
    /// agent message signatures (CRITICAL #54).
    ///
    /// The default resolver is an in-memory [`LocalPublicKeyResolver`]
    /// that accepts keys via [`Self::register_local_key`]. Production
    /// node binaries should supply a TDIP-backed resolver here so
    /// signature verification uses the canonical on-chain keys rather
    /// than ad-hoc local state. Calling this method clears the local
    /// resolver handle so subsequent calls to `register_local_key`
    /// return `false` and serve as a debugging signal.
    pub fn with_key_resolver(mut self, resolver: Arc<dyn PublicKeyResolver>) -> Self {
        self.key_resolver = resolver;
        self.local_resolver = None;
        self
    }

    /// Registers a hybrid verifying-key bundle for an agent in the
    /// local in-memory resolver, if it is still in use
    /// (CRITICAL #54 + Wave 3d hybrid PQ migration).
    ///
    /// Returns `true` when the keys were registered, `false` when the
    /// router has been wired with a custom resolver via
    /// [`Self::with_key_resolver`] (in which case the caller is
    /// responsible for populating that resolver out-of-band).
    pub fn register_local_key(&self, agent_id: String, keys: AgentVerifyingKeys) -> bool {
        match &self.local_resolver {
            Some(local) => {
                local.register(agent_id, keys);
                true
            }
            None => false,
        }
    }

    /// Forgets a public key from the local in-memory resolver, if it
    /// is still in use (CRITICAL #54). No-op when a custom resolver
    /// has been plugged in.
    pub fn forget_local_key(&self, agent_id: &str) {
        if let Some(local) = &self.local_resolver {
            local.forget(agent_id);
        }
    }

    /// Returns the number of messages rejected because their signature
    /// failed verification (CRITICAL #54). Used by tests and metrics.
    pub fn rejected_signature_count(&self) -> u64 {
        *self.rejected_signature_count.lock()
    }

    /// Checks rate limits for an outgoing message. (HIGH #107)
    ///
    /// This enforces three scopes in order:
    ///   1. Global — catches runaway router-wide floods
    ///   2. Per-sender — prevents a single misbehaving agent from
    ///      exhausting recipient capacity or global budget
    ///   3. Per-recipient — protects a victim agent from targeted
    ///      message flooding ("mail bomb" attack)
    ///
    /// If any scope rejects the message, the router returns
    /// `AgentError::RateLimitExceeded` with the scope name, offending
    /// agent id, and retry-after hint in seconds so the caller can
    /// back off intelligently. The `rate_limited_count` counter is
    /// incremented for observability.
    ///
    /// A rate of 0 in the config effectively disables that scope (since
    /// `TokenBucket::new(0, 0)` always returns an error but `enabled=false`
    /// short-circuits the check). Each scope is checked independently, so
    /// setting e.g. `per_sender_rate = 0` with `per_recipient_rate = 100`
    /// is a config error — prefer `enabled = false` for full bypass.
    fn check_rate_limit(&self, sender_id: &str, recipient_id: &str) -> Result<()> {
        if !self.config.rate_limit.enabled {
            return Ok(());
        }

        // Global scope first — catches router-wide floods.
        if let Err(retry) = self.global_bucket.try_acquire() {
            *self.rate_limited_count.lock() += 1;
            return Err(AgentError::RateLimitExceeded {
                scope: "global".to_string(),
                agent_id: String::new(),
                retry_after_secs: retry.as_secs().max(1),
            });
        }

        // Per-sender scope.
        let sender_bucket = self
            .sender_buckets
            .entry(sender_id.to_string())
            .or_insert_with(|| {
                Arc::new(TokenBucket::new(
                    self.config.rate_limit.per_sender_rate,
                    self.config.rate_limit.per_sender_burst,
                ))
            })
            .clone();

        if let Err(retry) = sender_bucket.try_acquire() {
            *self.rate_limited_count.lock() += 1;
            return Err(AgentError::RateLimitExceeded {
                scope: "sender".to_string(),
                agent_id: sender_id.to_string(),
                retry_after_secs: retry.as_secs().max(1),
            });
        }

        // Per-recipient scope.
        let recipient_bucket = self
            .recipient_buckets
            .entry(recipient_id.to_string())
            .or_insert_with(|| {
                Arc::new(TokenBucket::new(
                    self.config.rate_limit.per_recipient_rate,
                    self.config.rate_limit.per_recipient_burst,
                ))
            })
            .clone();

        if let Err(retry) = recipient_bucket.try_acquire() {
            *self.rate_limited_count.lock() += 1;
            return Err(AgentError::RateLimitExceeded {
                scope: "recipient".to_string(),
                agent_id: recipient_id.to_string(),
                retry_after_secs: retry.as_secs().max(1),
            });
        }

        Ok(())
    }

    /// Returns the number of messages rejected due to rate limiting.
    /// Used by observability and tests.
    pub fn rate_limited_count(&self) -> u64 {
        *self.rate_limited_count.lock()
    }

    /// Removes a sender's rate-limit bucket (HIGH #107).
    ///
    /// Called when an agent is unregistered so its bucket doesn't leak
    /// memory indefinitely. Safe to call for senders that never had a
    /// bucket (no-op).
    pub fn forget_sender_rate_limit(&self, sender_id: &str) {
        self.sender_buckets.remove(sender_id);
    }

    /// Removes a recipient's rate-limit bucket (HIGH #107).
    pub fn forget_recipient_rate_limit(&self, recipient_id: &str) {
        self.recipient_buckets.remove(recipient_id);
    }

    /// Sets the network transport for cross-node messaging
    pub fn with_network_transport(mut self, transport: Arc<dyn NetworkTransport>) -> Self {
        self.network_transport = Some(transport);
        self
    }

    /// Sends a message to a remote node via network transport
    pub async fn send_remote_message(&self, peer_id: String, message: AgentMessage) -> Result<()> {
        let transport = self
            .network_transport
            .as_ref()
            .ok_or_else(|| AgentError::MessageDeliveryFailed("No network transport configured".to_string()))?;

        transport.send_remote(peer_id, message).await
    }

    /// Checks if network transport is available
    pub fn has_network_transport(&self) -> bool {
        self.network_transport.is_some()
    }

    /// Registers an agent with the message router
    pub fn register_agent(&self, agent_id: String) -> Result<()> {
        if self.queues.contains_key(&agent_id) {
            return Err(AgentError::AgentAlreadyExists(agent_id));
        }

        let queue = AgentMessageQueue::new(self.config.max_queue_size);
        self.queues.insert(agent_id.clone(), queue);
        self.history.insert(agent_id.clone(), Vec::new());

        info!("Agent {} registered with message router", agent_id);
        Ok(())
    }

    /// Unregisters an agent from the message router
    pub fn unregister_agent(&self, agent_id: &str) -> Result<()> {
        self.queues.remove(agent_id);
        self.history.remove(agent_id);
        self.handlers.remove(agent_id);
        // HIGH #107: drop the rate-limit buckets so they don't leak memory
        self.sender_buckets.remove(agent_id);
        self.recipient_buckets.remove(agent_id);
        // CRITICAL #54: drop the cached public key so a re-registered
        // agent does not inherit a stale binding
        self.forget_local_key(agent_id);

        info!("Agent {} unregistered from message router", agent_id);
        Ok(())
    }

    /// Registers a message handler for an agent
    pub fn register_handler(&self, agent_id: String, handler: Arc<dyn MessageHandler>) -> Result<()> {
        self.handlers.insert(agent_id, handler);
        Ok(())
    }

    /// Validates a message — size check plus full cryptographic
    /// signature verification when signing is enabled (CRITICAL #54).
    ///
    /// When `config.enable_signing == true`, this method:
    ///   1. Rejects messages that carry no signature.
    ///   2. Resolves the sender's public key via `key_resolver`.
    ///      Unknown senders are rejected.
    ///   3. Reconstructs a `CryptoSignature` from the raw bytes,
    ///      using the sender public key's `KeyType` so Ed25519 and
    ///      Secp256k1 are both supported.
    ///   4. Calls `tenzro_crypto::signatures::verify` against the
    ///      canonical message hash from `AgentMessage::hash()`.
    ///   5. On rejection, increments `rejected_signature_count` and
    ///      returns `AgentError::InvalidMessageSignature` so the
    ///      caller can audit/log the offending sender.
    ///
    /// When `config.enable_signing == false`, the signature is
    /// ignored and only the size check is enforced. This branch
    /// exists so trusted single-process tests don't have to plumb
    /// signing keys.
    async fn validate_message(&self, message: &AgentMessage) -> Result<()> {
        // Check message size
        if message.payload.len() > self.config.max_message_size {
            return Err(AgentError::MessageDeliveryFailed(
                "Message exceeds maximum size".to_string(),
            ));
        }

        // CRITICAL #54 + Wave 3d hybrid PQ: when signing is enabled, BOTH the
        // classical Ed25519 leg and the post-quantum ML-DSA-65 leg are
        // mandatory. They must either both be present (signed) or both be
        // absent (rejected — `enable_signing == true` requires signatures).
        // Mixed mode (one set, the other unset) is rejected to prevent
        // downgrade attacks where an attacker drops the PQ leg.
        if self.config.enable_signing {
            let sender_id = message.from.agent_id.clone();

            // Both legs must be present together. Reject any unsigned or
            // half-signed message.
            let (classical_bytes, pq_bytes) =
                match (&message.signature, &message.pq_signature) {
                    (Some(c), Some(p)) => (c.clone(), p.clone()),
                    (None, None) => {
                        *self.rejected_signature_count.lock() += 1;
                        return Err(AgentError::InvalidMessageSignature {
                            agent_id: sender_id,
                            reason: "missing signature".to_string(),
                        });
                    }
                    (Some(_), None) | (None, Some(_)) => {
                        *self.rejected_signature_count.lock() += 1;
                        return Err(AgentError::InvalidMessageSignature {
                            agent_id: sender_id,
                            reason:
                                "mixed-mode signature: both classical and PQ legs are required"
                                    .to_string(),
                        });
                    }
                };

            let keys = match self.key_resolver.resolve(&sender_id).await {
                Some(k) => k,
                None => {
                    *self.rejected_signature_count.lock() += 1;
                    return Err(AgentError::InvalidMessageSignature {
                        agent_id: sender_id,
                        reason: "no public key on file".to_string(),
                    });
                }
            };

            // Build a composite public key carrying both verifying keys, and
            // a composite signature carrying both signature bytes. The
            // hybrid verifier checks each leg independently and requires
            // BOTH to verify.
            let composite_pk =
                CompositePublicKey::new(keys.classical, keys.pq_verifying_key);
            let composite_sig = CompositeSignature {
                classical: classical_bytes,
                pq: pq_bytes,
            };
            let verifier = StandardHybridVerifier::new(composite_pk);
            let hash = message.hash();

            if let Err(e) = verifier.verify(hash.as_bytes(), &composite_sig) {
                *self.rejected_signature_count.lock() += 1;
                return Err(AgentError::InvalidMessageSignature {
                    agent_id: sender_id,
                    reason: format!("hybrid verify failed: {}", e),
                });
            }

            debug!(
                "Verified hybrid signature on message {} from agent {}",
                message.message_id, message.from.agent_id
            );
        }

        Ok(())
    }

    /// Signs a message in place using the supplied hybrid signer
    /// (CRITICAL #54 + Wave 3d post-quantum migration).
    ///
    /// Computes the canonical hash via [`AgentMessage::hash`] (which
    /// excludes the existing `signature` and `pq_signature` fields, so
    /// calling this method twice is idempotent), signs the hash with
    /// the composite Ed25519 + ML-DSA-65 signer, and stores the
    /// classical signature in `message.signature` and the
    /// post-quantum signature in `message.pq_signature`.
    ///
    /// The router uses the same hash on the verify path, so
    /// signing → verifying always agrees as long as the sender's
    /// hybrid keys are registered with the router's
    /// [`PublicKeyResolver`].
    pub fn sign_message(
        message: &mut AgentMessage,
        signer: &InMemoryHybridSigner,
    ) -> Result<()> {
        let message_hash = message.hash();
        let composite = signer.sign(message_hash.as_bytes())?;
        if composite.pq.is_empty() {
            return Err(AgentError::CryptoError(
                "hybrid signer produced no PQ signature leg".to_string(),
            ));
        }
        message.signature = Some(composite.classical);
        message.pq_signature = Some(composite.pq);
        Ok(())
    }

    /// Sends a message to another agent
    pub async fn send_message(&self, message: AgentMessage) -> Result<()> {
        // Validate the message (size + signature verification)
        self.validate_message(&message).await?;

        let recipient_id = &message.to.agent_id;
        let sender_id = &message.from.agent_id;

        // HIGH #107: enforce rate limits before touching the queue. Rate
        // limit tokens are consumed even if the recipient does not exist,
        // matching the MPP/x402 precedent where auth checks happen before
        // resource lookups. Rejecting here keeps the hot path cheap and
        // denies the sender the ability to probe for recipient existence.
        self.check_rate_limit(sender_id, recipient_id)?;

        // Get recipient's queue
        let queue = self
            .queues
            .get(recipient_id)
            .ok_or_else(|| AgentError::AgentNotFound(recipient_id.clone()))?;

        // Try to send the message
        match queue.try_send(message.clone()) {
            Ok(_) => {
                debug!(
                    "Message {} sent from {} to {}",
                    message.message_id, message.from.agent_id, message.to.agent_id
                );

                // Store in history
                let sender_id = message.from.agent_id.clone();
                self.add_to_history(recipient_id, message.clone());
                self.add_to_history(&sender_id, message);

                Ok(())
            }
            Err(AgentError::MessageQueueFull(_)) => {
                // Queue full, try async send
                queue.send(message.clone()).await?;

                let sender_id = message.from.agent_id.clone();
                self.add_to_history(recipient_id, message.clone());
                self.add_to_history(&sender_id, message);

                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    /// Broadcasts a message to multiple agents
    pub async fn broadcast_message(
        &self,
        sender: AgentIdentity,
        recipients: Vec<AgentIdentity>,
        message_type: AgentMessageType,
        payload: Vec<u8>,
    ) -> Result<Vec<String>> {
        let mut message_ids = Vec::new();

        for recipient in recipients {
            let message = AgentMessage::new(sender.clone(), recipient, message_type, payload.clone());
            message_ids.push(message.message_id.clone());
            self.send_message(message).await?;
        }

        Ok(message_ids)
    }

    /// Subscribes to messages for an agent
    pub async fn subscribe_to_messages(&self, agent_id: &str) -> Result<mpsc::Receiver<AgentMessage>> {
        let queue = self
            .queues
            .get(agent_id)
            .ok_or_else(|| AgentError::AgentNotFound(agent_id.to_string()))?;

        // Create a new channel for subscription
        let (tx, rx) = mpsc::channel(self.config.max_queue_size);

        // Spawn a task to forward messages
        let queue_rx = queue.rx.clone();
        tokio::spawn(async move {
            loop {
                let message = {
                    let mut rx = queue_rx.write().await;
                    rx.recv().await
                };

                match message {
                    Some(msg) => {
                        if tx.send(msg).await.is_err() {
                            break;
                        }
                    }
                    None => break,
                }
            }
        });

        Ok(rx)
    }

    /// Receives the next message for an agent
    pub async fn receive_message(&self, agent_id: &str) -> Result<Option<AgentMessage>> {
        let queue = self
            .queues
            .get(agent_id)
            .ok_or_else(|| AgentError::AgentNotFound(agent_id.to_string()))?;

        Ok(queue.recv().await)
    }

    /// Gets message history for an agent
    pub fn get_message_history(&self, agent_id: &str, limit: Option<usize>) -> Result<Vec<AgentMessage>> {
        let history = self
            .history
            .get(agent_id)
            .ok_or_else(|| AgentError::AgentNotFound(agent_id.to_string()))?;

        let messages = history.value().clone();

        if let Some(limit) = limit {
            Ok(messages.into_iter().rev().take(limit).rev().collect())
        } else {
            Ok(messages)
        }
    }

    /// Adds a message to in-memory history and (when wired) persists an
    /// [`ReceiptEnvelope`] for it to RocksDB.
    ///
    /// The in-memory `history` DashMap is the fast read path. When
    /// [`Self::with_storage`] is configured, the message is additionally
    /// wrapped in a [`ReceiptKind::AgentMessage`] /
    /// [`ReceiptStorageMode::OffloadedDA`] envelope: the bincode-serialized
    /// payload is submitted to the DA backend, and the resulting envelope
    /// (commitment + summary + DA pointer) is written to [`CF_AGENTS`] under
    /// `message:<agent_id>:<timestamp_ms_be>:<message_id>`. Persistence
    /// failures are logged at `warn` rather than propagated — message
    /// delivery is the contract on this hot path; durable receipt logging
    /// is a side-effect that must not break delivery.
    fn add_to_history(&self, agent_id: &str, message: AgentMessage) {
        if let Some(mut history) = self.history.get_mut(agent_id) {
            history.value_mut().push(message.clone());

            // Trim history if it gets too large
            if history.value().len() > 10000 {
                history.value_mut().drain(0..1000);
            }
        }

        if let Some(storage) = &self.storage {
            if let Err(e) = self.persist_message_receipt(agent_id, &message, storage) {
                warn!(
                    "Failed to persist agent-message receipt for {} / msg {}: {}",
                    agent_id, message.message_id, e
                );
            }
        }
    }

    /// Wraps a message in a [`ReceiptEnvelope`] and writes it to RocksDB.
    fn persist_message_receipt(
        &self,
        agent_id: &str,
        message: &AgentMessage,
        storage: &Arc<dyn KvStore>,
    ) -> Result<()> {
        // Canonical payload: bincode-serialize the full message (signatures
        // included so verifiers can re-check the chain of custody).
        let payload = bincode::serialize(message).map_err(|e| {
            AgentError::SerializationError(format!(
                "Failed to serialize agent message for receipt: {}",
                e
            ))
        })?;

        let summary = ReceiptSummary {
            // 32-byte digest of the message_id keeps the on-chain summary
            // shape uniform across receipt kinds.
            receipt_id: compute_commitment(message.message_id.as_bytes()),
            payer: Some(message.from.agent_id.clone()),
            payee: Some(message.to.agent_id.clone()),
            amount_wei: None,
            timestamp: message.timestamp,
            principal_chain_summary: None,
        };

        let kind = ReceiptKind::AgentMessage;
        debug_assert_eq!(kind.default_mode(), ReceiptStorageMode::OffloadedDA);

        let commitment = compute_commitment(&payload);
        let pointer = self
            .da_backend
            .submit_sync(AGENT_MESSAGE_DA_NAMESPACE, &payload);
        let envelope = ReceiptEnvelope::offloaded(kind, summary, pointer, commitment);

        envelope.validate().map_err(|e| {
            AgentError::SerializationError(format!(
                "AgentMessage receipt envelope invalid: {}",
                e
            ))
        })?;

        let value = bincode::serialize(&envelope).map_err(|e| {
            AgentError::SerializationError(format!(
                "Failed to serialize agent-message receipt envelope: {}",
                e
            ))
        })?;

        // Key layout: `message:<agent_id>:<ts_ms_be>:<message_id>`. Big-endian
        // timestamp keeps a per-agent prefix scan chronologically ordered.
        let mut key = Vec::with_capacity(
            MESSAGE_KEY_PREFIX.len()
                + agent_id.len()
                + 1
                + 8
                + 1
                + message.message_id.len(),
        );
        key.extend_from_slice(MESSAGE_KEY_PREFIX);
        key.extend_from_slice(agent_id.as_bytes());
        key.push(b':');
        key.extend_from_slice(&(message.timestamp.0 as u64).to_be_bytes());
        key.push(b':');
        key.extend_from_slice(message.message_id.as_bytes());

        storage
            .put(CF_AGENTS, &key, &value)
            .map_err(|e| AgentError::StorageError(format!("Failed to persist receipt: {}", e)))?;

        Ok(())
    }

    /// Processes messages with registered handlers
    pub async fn process_messages(&self, agent_id: &str) -> Result<()> {
        let handler = self
            .handlers
            .get(agent_id)
            .ok_or_else(|| AgentError::AgentNotFound(format!("No handler for {}", agent_id)))?
            .clone();

        let queue = self
            .queues
            .get(agent_id)
            .ok_or_else(|| AgentError::AgentNotFound(agent_id.to_string()))?;

        while let Some(message) = queue.recv().await {
            match handler.handle_message(message.clone()).await {
                Ok(Some(response)) => {
                    self.send_message(response).await?;
                }
                Ok(None) => {
                    // No response needed
                }
                Err(e) => {
                    warn!(
                        "Error handling message {} for agent {}: {}",
                        message.message_id, agent_id, e
                    );
                }
            }
        }

        Ok(())
    }

    /// Clears message history for an agent
    pub fn clear_history(&self, agent_id: &str) -> Result<()> {
        self.history
            .get_mut(agent_id)
            .ok_or_else(|| AgentError::AgentNotFound(agent_id.to_string()))?
            .value_mut()
            .clear();
        Ok(())
    }

    /// Gets the number of pending messages for an agent
    pub fn pending_message_count(&self, _agent_id: &str) -> Result<usize> {
        // This is an approximation since we can't directly query mpsc queue length
        Ok(0) // In a real implementation, we'd track this separately
    }
}

impl Default for MessageRouter {
    fn default() -> Self {
        Self::new()
    }
}

/// Simple echo message handler for testing
pub struct EchoMessageHandler;

#[async_trait]
impl MessageHandler for EchoMessageHandler {
    async fn handle_message(&self, message: AgentMessage) -> Result<Option<AgentMessage>> {
        // Echo the message back to sender
        let response = AgentMessage::new(
            message.to,
            message.from,
            AgentMessageType::QueryResponse,
            message.payload,
        )
        .as_reply_to(message.message_id);

        Ok(Some(response))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_crypto::signatures::Signer;
    use tenzro_types::primitives::Address;

    fn create_test_identity(id: &str) -> AgentIdentity {
        AgentIdentity::new(
            id.to_string(),
            Address::from([0u8; 32]),
            id.to_string(),
            Address::from([1u8; 32]),
        )
    }

    /// Build a router with signing disabled. Used by legacy routing /
    /// rate-limit / history tests that pre-date CRITICAL #54 and were
    /// written against unsigned `AgentMessage`s. New tests that need to
    /// exercise signature verification should use `build_signing_router`.
    fn unsigned_test_router() -> MessageRouter {
        let config = MessageRouterConfig {
            enable_signing: false,
            ..MessageRouterConfig::default()
        };
        MessageRouter::with_config(config)
    }

    #[tokio::test]
    async fn test_agent_registration() {
        let router = MessageRouter::new();
        let agent_id = "test_agent".to_string();

        router.register_agent(agent_id.clone()).unwrap();

        // Cannot register twice
        let result = router.register_agent(agent_id);
        assert!(matches!(result, Err(AgentError::AgentAlreadyExists(_))));
    }

    #[tokio::test]
    async fn test_message_routing() {
        let router = unsigned_test_router();

        let sender = create_test_identity("sender");
        let recipient = create_test_identity("recipient");

        router.register_agent(sender.agent_id.clone()).unwrap();
        router.register_agent(recipient.agent_id.clone()).unwrap();

        let message = AgentMessage::new(
            sender.clone(),
            recipient.clone(),
            AgentMessageType::Query,
            b"Hello".to_vec(),
        );

        router.send_message(message).await.unwrap();

        let received = router.receive_message(&recipient.agent_id).await.unwrap();
        assert!(received.is_some());
        assert_eq!(received.unwrap().payload, b"Hello");
    }

    #[tokio::test]
    async fn test_broadcast() {
        let router = unsigned_test_router();

        let sender = create_test_identity("sender");
        let recipient1 = create_test_identity("recipient1");
        let recipient2 = create_test_identity("recipient2");

        router.register_agent(sender.agent_id.clone()).unwrap();
        router.register_agent(recipient1.agent_id.clone()).unwrap();
        router.register_agent(recipient2.agent_id.clone()).unwrap();

        let recipients = vec![recipient1.clone(), recipient2.clone()];
        let message_ids = router
            .broadcast_message(sender, recipients, AgentMessageType::Notification, b"Broadcast".to_vec())
            .await
            .unwrap();

        assert_eq!(message_ids.len(), 2);
    }

    #[tokio::test]
    async fn test_message_history() {
        let router = unsigned_test_router();

        let sender = create_test_identity("sender");
        let recipient = create_test_identity("recipient");

        router.register_agent(sender.agent_id.clone()).unwrap();
        router.register_agent(recipient.agent_id.clone()).unwrap();

        let message = AgentMessage::new(
            sender.clone(),
            recipient.clone(),
            AgentMessageType::Query,
            b"Test".to_vec(),
        );

        router.send_message(message).await.unwrap();

        let history = router.get_message_history(&recipient.agent_id, None).unwrap();
        assert_eq!(history.len(), 1);
    }

    // ============================================================
    // HIGH #107: Rate limiting tests
    // ============================================================

    /// Token bucket admits up to burst immediately, then refuses until refill.
    #[test]
    fn test_token_bucket_burst_then_refuses() {
        let bucket = TokenBucket::new(10, 5);
        // Burst of 5 should all succeed immediately
        for _ in 0..5 {
            assert!(bucket.try_acquire().is_ok());
        }
        // 6th should fail with a retry-after hint
        let err = bucket.try_acquire().unwrap_err();
        assert!(err.as_secs_f64() > 0.0);
    }

    /// Token bucket refills over time.
    #[test]
    fn test_token_bucket_refills() {
        let bucket = TokenBucket::new(1000, 1);
        assert!(bucket.try_acquire().is_ok());
        assert!(bucket.try_acquire().is_err());
        // Wait long enough for ~50 tokens to refill (50ms at 1000 tok/s),
        // clamped to burst=1
        std::thread::sleep(std::time::Duration::from_millis(50));
        assert!(bucket.try_acquire().is_ok());
    }

    /// Token bucket caps at burst capacity even after long idle period.
    #[test]
    fn test_token_bucket_caps_at_burst() {
        let bucket = TokenBucket::new(100, 3);
        std::thread::sleep(std::time::Duration::from_millis(100));
        // Despite 100ms idle, we should only have 3 tokens (burst cap)
        let available = bucket.available();
        assert!(available <= 3.0 + 0.01, "available={}", available);
        assert!(available >= 2.9, "available={}", available);
    }

    /// Rate limiting blocks a sender that exceeds the per-sender burst.
    #[tokio::test]
    async fn test_rate_limit_per_sender_burst() {
        let mut config = MessageRouterConfig::default().with_rate_limit(
            RateLimitConfig::default()
                .with_per_sender(10, 3) // small burst
                .with_per_recipient(1000, 1000)
                .with_global(1000, 1000),
        );
        config.enable_signing = false;
        let router = MessageRouter::with_config(config);

        let sender = create_test_identity("sender");
        let recipient = create_test_identity("recipient");
        router.register_agent(sender.agent_id.clone()).unwrap();
        router.register_agent(recipient.agent_id.clone()).unwrap();

        // First 3 should succeed (burst capacity)
        for _ in 0..3 {
            let msg = AgentMessage::new(
                sender.clone(),
                recipient.clone(),
                AgentMessageType::Notification,
                b"x".to_vec(),
            );
            router.send_message(msg).await.unwrap();
        }

        // 4th should be rate limited with sender scope
        let msg = AgentMessage::new(
            sender.clone(),
            recipient.clone(),
            AgentMessageType::Notification,
            b"x".to_vec(),
        );
        let err = router.send_message(msg).await.unwrap_err();
        match err {
            AgentError::RateLimitExceeded { scope, agent_id, retry_after_secs } => {
                assert_eq!(scope, "sender");
                assert_eq!(agent_id, sender.agent_id);
                assert!(retry_after_secs >= 1);
            }
            other => panic!("expected RateLimitExceeded, got {:?}", other),
        }

        assert_eq!(router.rate_limited_count(), 1);
    }

    /// Rate limiting blocks a recipient targeted by multiple senders (mail bomb).
    #[tokio::test]
    async fn test_rate_limit_per_recipient_burst() {
        let mut config = MessageRouterConfig::default().with_rate_limit(
            RateLimitConfig::default()
                .with_per_sender(1000, 1000)
                .with_per_recipient(10, 2) // very small recipient burst
                .with_global(1000, 1000),
        );
        config.enable_signing = false;
        let router = MessageRouter::with_config(config);

        let sender_a = create_test_identity("sender_a");
        let sender_b = create_test_identity("sender_b");
        let victim = create_test_identity("victim");
        router.register_agent(sender_a.agent_id.clone()).unwrap();
        router.register_agent(sender_b.agent_id.clone()).unwrap();
        router.register_agent(victim.agent_id.clone()).unwrap();

        // Sender A sends 2 messages — both succeed (burst=2)
        for _ in 0..2 {
            let msg = AgentMessage::new(
                sender_a.clone(),
                victim.clone(),
                AgentMessageType::Notification,
                b"flood".to_vec(),
            );
            router.send_message(msg).await.unwrap();
        }

        // Sender B attempts the 3rd — should be blocked at recipient scope
        let msg = AgentMessage::new(
            sender_b.clone(),
            victim.clone(),
            AgentMessageType::Notification,
            b"flood".to_vec(),
        );
        let err = router.send_message(msg).await.unwrap_err();
        match err {
            AgentError::RateLimitExceeded { scope, agent_id, .. } => {
                assert_eq!(scope, "recipient");
                assert_eq!(agent_id, victim.agent_id);
            }
            other => panic!("expected RateLimitExceeded recipient, got {:?}", other),
        }
    }

    /// Global rate limit protects the router from aggregate floods.
    #[tokio::test]
    async fn test_rate_limit_global_burst() {
        let mut config = MessageRouterConfig::default().with_rate_limit(
            RateLimitConfig::default()
                .with_per_sender(1000, 1000)
                .with_per_recipient(1000, 1000)
                .with_global(5, 3), // tight global cap
        );
        config.enable_signing = false;
        let router = MessageRouter::with_config(config);

        let sender = create_test_identity("sender");
        let recipient = create_test_identity("recipient");
        router.register_agent(sender.agent_id.clone()).unwrap();
        router.register_agent(recipient.agent_id.clone()).unwrap();

        // First 3 messages consume the global burst
        for _ in 0..3 {
            let msg = AgentMessage::new(
                sender.clone(),
                recipient.clone(),
                AgentMessageType::Notification,
                b"g".to_vec(),
            );
            router.send_message(msg).await.unwrap();
        }

        // 4th should trip global scope
        let msg = AgentMessage::new(
            sender.clone(),
            recipient.clone(),
            AgentMessageType::Notification,
            b"g".to_vec(),
        );
        let err = router.send_message(msg).await.unwrap_err();
        match err {
            AgentError::RateLimitExceeded { scope, agent_id, .. } => {
                assert_eq!(scope, "global");
                assert_eq!(agent_id, "");
            }
            other => panic!("expected RateLimitExceeded global, got {:?}", other),
        }
    }

    /// Per-sender buckets are isolated — one noisy sender does not
    /// prevent another from sending (assuming recipient/global have room).
    #[tokio::test]
    async fn test_rate_limit_per_sender_isolation() {
        let mut config = MessageRouterConfig::default().with_rate_limit(
            RateLimitConfig::default()
                .with_per_sender(1, 1)
                .with_per_recipient(1000, 1000)
                .with_global(1000, 1000),
        );
        config.enable_signing = false;
        let router = MessageRouter::with_config(config);

        let sender_a = create_test_identity("sender_a");
        let sender_b = create_test_identity("sender_b");
        let recipient = create_test_identity("recipient");
        router.register_agent(sender_a.agent_id.clone()).unwrap();
        router.register_agent(sender_b.agent_id.clone()).unwrap();
        router.register_agent(recipient.agent_id.clone()).unwrap();

        // Sender A uses its single token
        let msg_a = AgentMessage::new(
            sender_a.clone(),
            recipient.clone(),
            AgentMessageType::Notification,
            b"a".to_vec(),
        );
        router.send_message(msg_a).await.unwrap();

        // Sender A's 2nd message is rejected
        let msg_a2 = AgentMessage::new(
            sender_a.clone(),
            recipient.clone(),
            AgentMessageType::Notification,
            b"a".to_vec(),
        );
        assert!(matches!(
            router.send_message(msg_a2).await,
            Err(AgentError::RateLimitExceeded { .. })
        ));

        // Sender B still has its own fresh bucket and succeeds
        let msg_b = AgentMessage::new(
            sender_b.clone(),
            recipient.clone(),
            AgentMessageType::Notification,
            b"b".to_vec(),
        );
        router.send_message(msg_b).await.unwrap();
    }

    /// Rate limiting can be disabled entirely via config.
    #[tokio::test]
    async fn test_rate_limit_disabled() {
        let mut config = MessageRouterConfig::default().without_rate_limiting();
        config.enable_signing = false;
        let router = MessageRouter::with_config(config);

        let sender = create_test_identity("sender");
        let recipient = create_test_identity("recipient");
        router.register_agent(sender.agent_id.clone()).unwrap();
        router.register_agent(recipient.agent_id.clone()).unwrap();

        // Send far more than default burst — should all succeed
        for i in 0..100 {
            let msg = AgentMessage::new(
                sender.clone(),
                recipient.clone(),
                AgentMessageType::Notification,
                format!("msg{}", i).into_bytes(),
            );
            router.send_message(msg).await.unwrap();
        }
        assert_eq!(router.rate_limited_count(), 0);
    }

    /// Unregistering an agent drops its rate-limit buckets.
    #[tokio::test]
    async fn test_unregister_agent_drops_rate_limit_buckets() {
        let router = unsigned_test_router();
        let sender = create_test_identity("sender");
        let recipient = create_test_identity("recipient");
        router.register_agent(sender.agent_id.clone()).unwrap();
        router.register_agent(recipient.agent_id.clone()).unwrap();

        // Send a message to materialize buckets
        let msg = AgentMessage::new(
            sender.clone(),
            recipient.clone(),
            AgentMessageType::Notification,
            b"x".to_vec(),
        );
        router.send_message(msg).await.unwrap();
        assert!(router.sender_buckets.contains_key(&sender.agent_id));
        assert!(router.recipient_buckets.contains_key(&recipient.agent_id));

        // Unregister — buckets should be dropped
        router.unregister_agent(&sender.agent_id).unwrap();
        router.unregister_agent(&recipient.agent_id).unwrap();
        assert!(!router.sender_buckets.contains_key(&sender.agent_id));
        assert!(!router.recipient_buckets.contains_key(&recipient.agent_id));
    }

    /// Counter correctly reflects rejected messages.
    #[tokio::test]
    async fn test_rate_limited_counter() {
        let mut config = MessageRouterConfig::default().with_rate_limit(
            RateLimitConfig::default()
                .with_per_sender(1, 1)
                .with_per_recipient(1000, 1000)
                .with_global(1000, 1000),
        );
        config.enable_signing = false;
        let router = MessageRouter::with_config(config);

        let sender = create_test_identity("sender");
        let recipient = create_test_identity("recipient");
        router.register_agent(sender.agent_id.clone()).unwrap();
        router.register_agent(recipient.agent_id.clone()).unwrap();

        // First succeeds, next 3 are rejected
        for i in 0..4 {
            let msg = AgentMessage::new(
                sender.clone(),
                recipient.clone(),
                AgentMessageType::Notification,
                format!("m{}", i).into_bytes(),
            );
            let _ = router.send_message(msg).await;
        }
        assert_eq!(router.rate_limited_count(), 3);
    }

    // ============================================================
    // CRITICAL #54: Signature verification tests
    // ============================================================

    /// Builds a hybrid Ed25519 + ML-DSA-65 signer for tests. The
    /// classical leg is generated by `Ed25519SignerImpl::generate()`,
    /// the PQ leg by `MlDsaSigningKey::generate()`. Returns the
    /// hybrid signer plus its `AgentVerifyingKeys` bundle so callers
    /// can register it with the router.
    fn build_test_hybrid_signer() -> (InMemoryHybridSigner, AgentVerifyingKeys) {
        let classical =
            tenzro_crypto::signatures::Ed25519SignerImpl::generate().unwrap();
        let classical_pk = classical.public_key().clone();
        let pq = tenzro_crypto::pq::MlDsaSigningKey::generate();
        let pq_vk = pq.verifying_key_bytes().to_vec();
        let signer = InMemoryHybridSigner::new(Box::new(classical), pq);
        let keys = AgentVerifyingKeys::new(classical_pk, pq_vk);
        (signer, keys)
    }

    /// Builds a default-signing router pre-loaded with one hybrid
    /// keypair for `sender_id` and one bare recipient. Returns the
    /// router, the sender identity, the sender's hybrid signer, and
    /// the recipient identity. Test setup helper for the cases below.
    fn build_signing_router(
        sender_id: &str,
        recipient_id: &str,
    ) -> (
        MessageRouter,
        AgentIdentity,
        InMemoryHybridSigner,
        AgentIdentity,
    ) {
        // Disable rate limiting so the tests focus on signature verification
        let config = MessageRouterConfig::default().without_rate_limiting();
        let router = MessageRouter::with_config(config);

        let (signer, keys) = build_test_hybrid_signer();
        let sender = create_test_identity(sender_id);
        let recipient = create_test_identity(recipient_id);

        router.register_agent(sender.agent_id.clone()).unwrap();
        router.register_agent(recipient.agent_id.clone()).unwrap();

        // Bind the sender's hybrid keys in the router's local resolver so
        // validate_message can find them on verification.
        let registered = router.register_local_key(sender.agent_id.clone(), keys);
        assert!(registered, "default router should expose local resolver");

        (router, sender, signer, recipient)
    }

    /// A signed message that matches its signature is accepted and
    /// reaches the recipient queue.
    #[tokio::test]
    async fn test_signed_message_verifies_and_delivers() {
        let (router, sender, signer, recipient) =
            build_signing_router("sig_sender", "sig_recipient");

        let mut msg = AgentMessage::new(
            sender.clone(),
            recipient.clone(),
            AgentMessageType::Query,
            b"hello signed world".to_vec(),
        );
        MessageRouter::sign_message(&mut msg, &signer).unwrap();

        router.send_message(msg).await.unwrap();
        assert_eq!(router.rejected_signature_count(), 0);

        let received = router.receive_message(&recipient.agent_id).await.unwrap();
        assert!(received.is_some());
        assert_eq!(received.unwrap().payload, b"hello signed world");
    }

    /// A message with no signature is rejected when signing is enabled.
    #[tokio::test]
    async fn test_unsigned_message_rejected() {
        let (router, sender, _signer, recipient) =
            build_signing_router("noSig_sender", "noSig_recipient");

        let msg = AgentMessage::new(
            sender.clone(),
            recipient.clone(),
            AgentMessageType::Query,
            b"unsigned".to_vec(),
        );

        let err = router.send_message(msg).await.unwrap_err();
        match err {
            AgentError::InvalidMessageSignature { agent_id, reason } => {
                assert_eq!(agent_id, sender.agent_id);
                assert!(reason.contains("missing signature"));
            }
            other => panic!("expected InvalidMessageSignature, got {:?}", other),
        }
        assert_eq!(router.rejected_signature_count(), 1);
    }

    /// A signed message whose payload is tampered with after signing
    /// fails verification because the canonical hash changes.
    #[tokio::test]
    async fn test_tampered_message_rejected() {
        let (router, sender, signer, recipient) =
            build_signing_router("tamper_sender", "tamper_recipient");

        let mut msg = AgentMessage::new(
            sender.clone(),
            recipient.clone(),
            AgentMessageType::Query,
            b"original payload".to_vec(),
        );
        MessageRouter::sign_message(&mut msg, &signer).unwrap();

        // Tamper with the payload after signing — the hash now differs
        msg.payload = b"tampered payload".to_vec();

        let err = router.send_message(msg).await.unwrap_err();
        match err {
            AgentError::InvalidMessageSignature { agent_id, reason } => {
                assert_eq!(agent_id, sender.agent_id);
                assert!(reason.contains("hybrid verify failed"));
            }
            other => panic!("expected InvalidMessageSignature, got {:?}", other),
        }
        assert_eq!(router.rejected_signature_count(), 1);
    }

    /// A message signed with a different keypair than the one
    /// registered for the sender is rejected.
    #[tokio::test]
    async fn test_wrong_key_rejected() {
        let (router, sender, _correct_signer, recipient) =
            build_signing_router("wrongkey_sender", "wrongkey_recipient");

        // Generate an unrelated hybrid signer — its public keys are NOT registered
        let (attacker_signer, _attacker_keys) = build_test_hybrid_signer();

        let mut msg = AgentMessage::new(
            sender.clone(),
            recipient.clone(),
            AgentMessageType::Query,
            b"impostor".to_vec(),
        );
        MessageRouter::sign_message(&mut msg, &attacker_signer).unwrap();

        let err = router.send_message(msg).await.unwrap_err();
        match err {
            AgentError::InvalidMessageSignature { agent_id, reason } => {
                assert_eq!(agent_id, sender.agent_id);
                assert!(reason.contains("hybrid verify failed"));
            }
            other => panic!("expected InvalidMessageSignature, got {:?}", other),
        }
    }

    /// A message from an agent whose key is not on file is rejected
    /// with a "no public key on file" reason.
    #[tokio::test]
    async fn test_unknown_sender_rejected() {
        let config = MessageRouterConfig::default().without_rate_limiting();
        let router = MessageRouter::with_config(config);

        let (signer, _keys) = build_test_hybrid_signer();
        let sender = create_test_identity("ghost_sender");
        let recipient = create_test_identity("ghost_recipient");

        router.register_agent(sender.agent_id.clone()).unwrap();
        router.register_agent(recipient.agent_id.clone()).unwrap();
        // Note: NO register_local_key call — sender has no on-file key

        let mut msg = AgentMessage::new(
            sender.clone(),
            recipient.clone(),
            AgentMessageType::Query,
            b"who am i".to_vec(),
        );
        MessageRouter::sign_message(&mut msg, &signer).unwrap();

        let err = router.send_message(msg).await.unwrap_err();
        match err {
            AgentError::InvalidMessageSignature { agent_id, reason } => {
                assert_eq!(agent_id, sender.agent_id);
                assert!(reason.contains("no public key on file"));
            }
            other => panic!("expected InvalidMessageSignature, got {:?}", other),
        }
    }

    /// When `enable_signing = false`, unsigned messages bypass
    /// verification and are delivered normally.
    #[tokio::test]
    async fn test_signing_disabled_bypasses_verification() {
        let mut config = MessageRouterConfig::default().without_rate_limiting();
        config.enable_signing = false;
        let router = MessageRouter::with_config(config);

        let sender = create_test_identity("nosig_sender");
        let recipient = create_test_identity("nosig_recipient");
        router.register_agent(sender.agent_id.clone()).unwrap();
        router.register_agent(recipient.agent_id.clone()).unwrap();

        let msg = AgentMessage::new(
            sender,
            recipient.clone(),
            AgentMessageType::Notification,
            b"plain".to_vec(),
        );
        router.send_message(msg).await.unwrap();
        assert_eq!(router.rejected_signature_count(), 0);

        let received = router.receive_message(&recipient.agent_id).await.unwrap();
        assert!(received.is_some());
    }

    /// `sign_message` is idempotent: calling it twice produces the
    /// same classical signature because `hash()` excludes both the
    /// `signature` and `pq_signature` fields. (The PQ leg, ML-DSA-65,
    /// is intentionally non-deterministic per FIPS 204 so its
    /// signature bytes differ across calls; only the classical leg
    /// is asserted idempotent here.)
    #[tokio::test]
    async fn test_sign_message_idempotent() {
        let (signer, _keys) = build_test_hybrid_signer();
        let sender = create_test_identity("idempo_sender");
        let recipient = create_test_identity("idempo_recipient");

        let mut msg = AgentMessage::new(
            sender,
            recipient,
            AgentMessageType::Query,
            b"idempotent".to_vec(),
        );

        MessageRouter::sign_message(&mut msg, &signer).unwrap();
        let first_sig = msg.signature.clone().unwrap();
        assert!(msg.pq_signature.is_some());

        MessageRouter::sign_message(&mut msg, &signer).unwrap();
        let second_sig = msg.signature.clone().unwrap();
        assert!(msg.pq_signature.is_some());

        assert_eq!(
            first_sig, second_sig,
            "classical leg of sign_message should be idempotent because hash() excludes signature fields"
        );
    }

    /// `AgentMessage::hash()` is stable: identical messages produce
    /// identical hashes, and changing any field changes the hash.
    #[test]
    fn test_message_hash_is_canonical() {
        let sender = create_test_identity("a");
        let recipient = create_test_identity("b");
        let msg1 = AgentMessage::new(
            sender.clone(),
            recipient.clone(),
            AgentMessageType::Query,
            b"data".to_vec(),
        );
        // Same fields → identical hash (use the same message_id and timestamp)
        let mut msg2 = msg1.clone();
        assert_eq!(msg1.hash(), msg2.hash());

        // Mutating the payload changes the hash
        msg2.payload = b"different".to_vec();
        assert_ne!(msg1.hash(), msg2.hash());

        // Setting a signature does NOT change the hash (idempotent signing)
        let mut msg3 = msg1.clone();
        msg3.signature = Some(vec![1, 2, 3, 4]);
        assert_eq!(
            msg1.hash(),
            msg3.hash(),
            "hash() must exclude signature field"
        );
    }

    /// `with_key_resolver` clears the local resolver handle, so
    /// subsequent `register_local_key` calls return false.
    #[test]
    fn test_with_key_resolver_clears_local() {
        let custom: Arc<dyn PublicKeyResolver> = Arc::new(LocalPublicKeyResolver::new());
        let router = MessageRouter::new().with_key_resolver(custom);

        let dummy_classical = tenzro_crypto::signatures::Ed25519SignerImpl::generate()
            .unwrap()
            .public_key()
            .clone();
        let dummy_pq_vk = tenzro_crypto::pq::MlDsaSigningKey::generate()
            .verifying_key_bytes()
            .to_vec();
        let dummy_keys = AgentVerifyingKeys::new(dummy_classical, dummy_pq_vk);
        let registered = router.register_local_key("x".to_string(), dummy_keys);
        assert!(
            !registered,
            "register_local_key should be a no-op after with_key_resolver"
        );
    }

    /// Unregistering an agent forgets its local public key so a
    /// re-registered agent does not inherit a stale binding.
    #[tokio::test]
    async fn test_unregister_forgets_local_key() {
        let router = MessageRouter::new();
        let (_signer, keys) = build_test_hybrid_signer();
        router.register_agent("rotating".to_string()).unwrap();
        router.register_local_key("rotating".to_string(), keys);

        // Sanity: key is on file
        assert!(router
            .key_resolver
            .resolve("rotating")
            .await
            .is_some());

        router.unregister_agent("rotating").unwrap();

        // After unregistration, the key is no longer resolvable
        assert!(router
            .key_resolver
            .resolve("rotating")
            .await
            .is_none());
    }
}
