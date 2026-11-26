//! `tenzro/gossip` ALPN: topic broadcast between nodes over iroh-gossip.
//!
//! Every topic name maps to one iroh-gossip topic whose id is derived from
//! the name and the chain id ([`topic_id`]), so two chains never share a
//! swarm. iroh-gossip keeps the membership of each topic: a small active set
//! of direct neighbours per node.
//!
//! Messages travel validate-then-forward. A publisher sends a message to
//! every direct neighbour of the topic (a flood publish), and a receiver
//! hands it to the node's [`GossipValidator`] and passes it on to its own
//! neighbours only if the validator accepts it. On a topic the subscriber
//! judges itself ([`GossipLayer::join_judged`]) the message is passed on only
//! when the subscriber accepts its [`ValidationTicket`]. A neighbour that
//! delivers a message has therefore vouched for it, which is what lets the
//! validator score the neighbour on it. A cache of recently seen content
//! hashes stops a message from circulating.
//!
//! Every message is sent to direct neighbours only, never through
//! iroh-gossip's tree broadcast, so each neighbour stays in the set a
//! publish reaches. A neighbour that sends tree-broadcast traffic is
//! breaking the protocol and is scored as sending an invalid message.
//!
//! Scores act on connections through the [`GossipGate`], installed as an
//! endpoint hook: a neighbour the validator no longer allows has its gossip
//! connections closed and new ones refused in both directions, and topics
//! bootstrap through the best-scored known peers first.
//!
//! The layer exists before the node's endpoint does: topics can be joined
//! and subscribed early and are opened on the transport once it is attached
//! with [`GossipLayer::attach`].

use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::fmt;
use std::future::Future;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

use bytes::Bytes;
use futures::StreamExt;
use iroh::endpoint::{
    AfterHandshakeOutcome, Connection, ConnectionError, EndpointHooks, VarInt, WeakConnectionHandle,
};
use iroh::{Endpoint, EndpointId};
use iroh_gossip::api::{Event, GossipSender};
use iroh_gossip::proto::DeliveryScope;
use iroh_gossip::{Gossip, TopicId};
use parking_lot::{Mutex, RwLock};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tracing::{debug, info, trace, warn};

use crate::error::{IrohError, IrohResult};

/// ALPN of the gossip protocol.
pub const ALPN_GOSSIP: &[u8] = b"tenzro/gossip";

/// Largest message content a node publishes or accepts.
pub const MAX_GOSSIP_MESSAGE: usize = 1 << 20;

/// Room on the wire for iroh-gossip's framing around the content.
const FRAME_HEADROOM: usize = 4096;

/// Content hashes remembered for loop suppression, and for how long.
const SEEN_CAPACITY: usize = 100_000;

/// Most accepted messages held for the layer's subscriber.
pub const INBOUND_CAPACITY: usize = 4_096;
const SEEN_EXPIRY: Duration = Duration::from_secs(300);

/// Peers remembered as bootstrap candidates for topics joined later.
const MAX_KNOWN_PEERS: usize = 256;

/// Peers a topic is opened through, best scored first.
const BOOTSTRAP_PEERS: usize = 8;

/// How long a publish waits for a freshly opened topic to be ready.
const OPEN_TIMEOUT: Duration = Duration::from_secs(5);

/// Pause before a closed topic subscription is opened again.
const REJOIN_DELAY: Duration = Duration::from_secs(1);

/// How often a topic with fewer than [`MIN_NEIGHBOURS`] neighbours joins
/// the known peers it is not connected to again.
const REJOIN_CHECK: Duration = Duration::from_secs(5);

/// Below this many neighbours a topic keeps joining the peers it knows.
const MIN_NEIGHBOURS: usize = 3;

/// Close code sent on a gossip connection to a peer that is not allowed.
const REFUSED: u32 = 1;

/// Reason sent with [`REFUSED`].
const REFUSED_REASON: &[u8] = b"gossip peer not allowed";

/// How long a peer that refused this node as a gossip neighbour is not
/// asked again after its first refusal; each further refusal doubles it.
const REFUSAL_PAUSE: Duration = Duration::from_secs(30);

/// The longest a refusing peer is left alone before it is asked again.
const REFUSAL_PAUSE_MAX: Duration = Duration::from_secs(15 * 60);

/// Peers whose refusals, given or received, are remembered.
const MAX_REFUSALS: usize = 1024;

/// The pause after the `count`th time in a row: `first`, doubled each
/// further time, up to [`REFUSAL_PAUSE_MAX`].
fn growing_pause(first: Duration, count: u32) -> Duration {
    let doublings = count.saturating_sub(1).min(16);
    first.saturating_mul(1 << doublings).min(REFUSAL_PAUSE_MAX)
}

/// The peers that refused this node as a gossip neighbour, and until when
/// each is left alone.
#[derive(Default)]
struct Refusals {
    by_peer: HashMap<EndpointId, Refusal>,
}

struct Refusal {
    count: u32,
    until: Instant,
}

impl Refusals {
    /// Records that `peer` refused this node at `now`. A refusal met while
    /// the peer is already left alone changes nothing; otherwise it starts a
    /// longer pause than the one before and returns the refusals in a row
    /// and the pause.
    fn note(&mut self, peer: EndpointId, now: Instant) -> Option<(u32, Duration)> {
        self.note_from(peer, now, REFUSAL_PAUSE)
    }

    /// [`Self::note`] with the pause starting at `first`.
    fn note_from(
        &mut self,
        peer: EndpointId,
        now: Instant,
        first: Duration,
    ) -> Option<(u32, Duration)> {
        if self.paused(peer, now) {
            return None;
        }
        if self.by_peer.len() >= MAX_REFUSALS && !self.by_peer.contains_key(&peer) {
            self.by_peer.retain(|_, r| now < r.until);
            if self.by_peer.len() >= MAX_REFUSALS {
                return None;
            }
        }
        let refusal = self.by_peer.entry(peer).or_insert(Refusal {
            count: 0,
            until: now,
        });
        refusal.count = refusal.count.saturating_add(1);
        let pause = growing_pause(first, refusal.count);
        refusal.until = now + pause;
        Some((refusal.count, pause))
    }

    /// Whether `peer` is left alone at `now`.
    fn paused(&self, peer: EndpointId, now: Instant) -> bool {
        self.by_peer.get(&peer).is_some_and(|r| now < r.until)
    }

    /// Forgets the refusals of `peer`: it took this node as a neighbour.
    fn forgive(&mut self, peer: EndpointId) {
        self.by_peer.remove(&peer);
    }
}

/// The iroh-gossip topic carrying `name` on the chain `chain_id`.
pub fn topic_id(chain_id: u64, name: &str) -> TopicId {
    let mut hasher = blake3::Hasher::new_derive_key("tenzro gossip topic");
    hasher.update(&chain_id.to_be_bytes());
    hasher.update(name.as_bytes());
    TopicId::from_bytes(*hasher.finalize().as_bytes())
}

/// A verdict on one received message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Valid: deliver it and pass it on.
    Accept,
    /// Invalid: drop it; the neighbour that delivered it is at fault.
    Reject,
    /// Cannot be judged here: drop it without blame and do not pass it on.
    Ignore,
}

/// The node's rules for received gossip and its scores of the neighbours
/// that deliver it.
pub trait GossipValidator: Send + Sync + fmt::Debug + 'static {
    /// Judges the neighbour `from` before its message on `topic` is looked
    /// at (bans, per-topic budgets).
    fn admit(&self, topic: &str, from: EndpointId) -> Verdict;

    /// Hears that `from` delivered a message this node has already seen.
    fn duplicate(&self, topic: &str, from: EndpointId, bytes: usize);

    /// Judges a message on `topic` delivered by `from`.
    fn check(&self, topic: &str, from: EndpointId, content: &[u8]) -> Verdict;

    /// Hears a verdict on a message from `from` reached outside
    /// [`Self::check`]: a subscriber's [`ValidationTicket`], or a delivery
    /// that broke the protocol.
    fn verdict(&self, from: EndpointId, verdict: Verdict);

    /// Whether `peer` may be a gossip neighbour at all.
    fn allows(&self, peer: EndpointId) -> bool;

    /// The standing of `peer`; higher is better.
    fn score(&self, peer: EndpointId) -> i32;
}

/// Endpoint hook screening gossip connections by the validator's scores.
/// Install it on the endpoint builder with `.hooks(gate.clone())`; it acts
/// once a [`GossipLayer`] is attached with it.
#[derive(Clone, Default)]
pub struct GossipGate {
    inner: Arc<GateInner>,
}

#[derive(Default)]
struct GateInner {
    validator: RwLock<Option<Arc<dyn GossipValidator>>>,
    connections: Mutex<HashMap<EndpointId, Vec<WeakConnectionHandle>>>,
    /// Peers that refused this node.
    refusals: Mutex<Refusals>,
    /// Peers this node refused and said so about.
    refused: Mutex<HashSet<EndpointId>>,
}

impl fmt::Debug for GossipGate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GossipGate").finish_non_exhaustive()
    }
}

impl GossipGate {
    fn install(&self, validator: Arc<dyn GossipValidator>) {
        *self.inner.validator.write() = Some(validator);
    }

    fn allows(&self, peer: EndpointId) -> bool {
        self.inner
            .validator
            .read()
            .as_ref()
            .is_none_or(|v| v.allows(peer))
    }

    /// Closes every gossip connection with `peer`.
    fn disconnect(&self, peer: EndpointId) {
        let handles = self
            .inner
            .connections
            .lock()
            .remove(&peer)
            .unwrap_or_default();
        for handle in handles {
            if let Some(conn) = handle.upgrade() {
                conn.close(VarInt::from_u32(REFUSED), REFUSED_REASON);
            }
        }
    }

    /// Whether `peer` refused this node and is still left alone.
    fn paused(&self, peer: EndpointId, now: Instant) -> bool {
        self.inner.refusals.lock().paused(peer, now)
    }

    /// `peer` took this node as a neighbour: its earlier refusals are
    /// forgotten.
    fn forgive(&self, peer: EndpointId) {
        self.inner.refusals.lock().forgive(peer);
    }

    /// `peer` closed a gossip connection as not allowed: it is not asked
    /// again until a pause that grows with each refusal is over. The reason
    /// is said once for the peer.
    fn refused_by(&self, peer: EndpointId) {
        let Some((count, pause)) = self.inner.refusals.lock().note(peer, Instant::now()) else {
            return;
        };
        if count == 1 {
            info!(
                target: "tenzro_iroh::gossip",
                peer = %peer,
                pause_secs = pause.as_secs(),
                "peer refused this node as a gossip neighbour: it accepts only the peers its rules allow (a validator: its boot list and the validators); it is asked again after a growing pause"
            );
        } else {
            debug!(target: "tenzro_iroh::gossip", peer = %peer, count, pause_secs = pause.as_secs(), "peer refused this node as a gossip neighbour again");
        }
    }

    /// Watches `conn` for the peer closing it as not allowed.
    fn watch_for_refusal(&self, conn: &Connection) {
        let peer = conn.remote_id();
        let closed = conn.weak_handle().closed();
        let gate = self.clone();
        tokio::spawn(async move {
            let Some(closed) = closed.await else {
                return;
            };
            if let ConnectionError::ApplicationClosed(close) = &closed.reason
                && close.error_code == VarInt::from_u32(REFUSED)
                && close.reason.as_ref() == REFUSED_REASON
            {
                gate.refused_by(peer);
            }
        });
    }

    /// Whether this is the first gossip connection of `peer` this node
    /// refuses, of the peers it remembers refusing.
    fn first_refusal_of(&self, peer: EndpointId) -> bool {
        let mut refused = self.inner.refused.lock();
        refused.len() < MAX_REFUSALS && refused.insert(peer)
    }
}

impl EndpointHooks for GossipGate {
    #[allow(clippy::manual_async_fn)] // the trait's signature carries the lifetime and the Send bound
    fn after_handshake<'a>(
        &'a self,
        conn: &'a Connection,
    ) -> impl Future<Output = AfterHandshakeOutcome> + Send + 'a {
        async move {
            if conn.alpn() != ALPN_GOSSIP {
                return AfterHandshakeOutcome::accept();
            }
            let remote = conn.remote_id();
            if !self.allows(remote) {
                if self.first_refusal_of(remote) {
                    info!(target: "tenzro_iroh::gossip", peer = %remote, "gossip connection refused: this node's rules do not allow the peer as a gossip neighbour (said once for this peer)");
                } else {
                    debug!(target: "tenzro_iroh::gossip", peer = %remote, "gossip connection refused");
                }
                return AfterHandshakeOutcome::Reject {
                    error_code: VarInt::from_u32(REFUSED),
                    reason: REFUSED_REASON.to_vec(),
                };
            }
            self.watch_for_refusal(conn);
            let mut connections = self.inner.connections.lock();
            let handles = connections.entry(remote).or_default();
            handles.retain(|h| h.upgrade().is_some());
            handles.push(conn.weak_handle());
            AfterHandshakeOutcome::accept()
        }
    }
}

/// The gossip protocol on one endpoint and the gate screening its
/// connections.
#[derive(Debug, Clone)]
pub struct GossipTransport {
    gossip: Gossip,
    gate: GossipGate,
}

impl GossipTransport {
    /// Starts the gossip protocol on `endpoint`, which must have been built
    /// with `gate` as a hook. Register [`Self::protocol`] on the endpoint's
    /// router under [`ALPN_GOSSIP`].
    pub fn spawn(endpoint: &Endpoint, gate: GossipGate) -> Self {
        let gossip = Gossip::builder()
            .alpn(ALPN_GOSSIP)
            .max_message_size(MAX_GOSSIP_MESSAGE + FRAME_HEADROOM)
            .spawn(endpoint.clone());
        Self { gossip, gate }
    }

    /// The protocol handler for the endpoint's router.
    pub fn protocol(&self) -> Gossip {
        self.gossip.clone()
    }
}

/// A message that passed the validator.
#[derive(Debug)]
pub struct Inbound {
    /// Topic name.
    pub topic: Arc<str>,
    /// The neighbour that delivered it.
    pub from: EndpointId,
    /// The message content.
    pub content: Bytes,
    /// Present on a judged topic: the message is passed on only when this is
    /// accepted.
    pub ticket: Option<ValidationTicket>,
}

/// The right to report the verdict on one message of a judged topic.
/// Dropped without a verdict, it reports [`Verdict::Ignore`].
#[derive(Debug)]
pub struct ValidationTicket {
    content: Bytes,
    from: EndpointId,
    sender: GossipSender,
    layer: Weak<GossipLayer>,
    reported: bool,
}

impl ValidationTicket {
    fn report(&mut self, verdict: Verdict) {
        if self.reported {
            return;
        }
        self.reported = true;
        if let Some(layer) = self.layer.upgrade() {
            layer.record(self.from, verdict);
        }
        if verdict == Verdict::Accept
            && let Ok(runtime) = tokio::runtime::Handle::try_current()
        {
            let sender = self.sender.clone();
            let content = self.content.clone();
            runtime.spawn(async move {
                if let Err(e) = sender.broadcast_neighbors(content).await {
                    debug!(target: "tenzro_iroh::gossip", error = %e, "accepted message not passed on");
                }
            });
        }
    }

    /// The neighbour that delivered the message.
    pub fn from(&self) -> EndpointId {
        self.from
    }

    /// The message checked out: pass it on to this node's neighbours.
    pub fn accept(mut self) {
        self.report(Verdict::Accept);
    }

    /// The message is invalid: drop it and blame the neighbour that
    /// delivered it.
    pub fn reject(mut self) {
        self.report(Verdict::Reject);
    }

    /// The message cannot be judged here: drop it without blame.
    pub fn ignore(mut self) {
        self.report(Verdict::Ignore);
    }
}

impl Drop for ValidationTicket {
    fn drop(&mut self) {
        self.report(Verdict::Ignore);
    }
}

/// Recently seen content hashes, oldest first.
#[derive(Default)]
struct SeenCache {
    order: VecDeque<([u8; 32], Instant)>,
    set: HashSet<[u8; 32]>,
}

impl SeenCache {
    /// Forgets what expired, and the oldest entries of a full cache.
    fn prune(&mut self, now: Instant) {
        while let Some(&(hash, at)) = self.order.front() {
            if now.duration_since(at) <= SEEN_EXPIRY && self.order.len() < SEEN_CAPACITY {
                break;
            }
            self.order.pop_front();
            self.set.remove(&hash);
        }
    }

    /// Whether `content` is recorded.
    fn contains(&mut self, content: &[u8]) -> bool {
        self.prune(Instant::now());
        self.set.contains(blake3::hash(content).as_bytes())
    }

    /// Records `content`; false if it was already recorded.
    fn insert(&mut self, content: &[u8]) -> bool {
        let now = Instant::now();
        self.prune(now);
        let hash = *blake3::hash(content).as_bytes();
        if !self.set.insert(hash) {
            return false;
        }
        self.order.push_back((hash, now));
        true
    }
}

struct Topic {
    judged: bool,
    sender: watch::Receiver<Option<GossipSender>>,
    neighbours: Arc<AtomicUsize>,
    task: Option<JoinHandle<()>>,
    ready: Option<watch::Sender<Option<GossipSender>>>,
}

struct Attached {
    gossip: Gossip,
    gate: GossipGate,
    chain_id: u64,
}

#[derive(Default)]
struct State {
    transport: Option<Attached>,
    known: BTreeSet<EndpointId>,
    topics: HashMap<Arc<str>, Topic>,
    /// The topics each peer is a direct neighbour on.
    around: HashMap<EndpointId, usize>,
    /// Known peers asked to be a neighbour again while a neighbour on no
    /// topic, and until when each is left alone.
    unanswered: Refusals,
}

/// Topic broadcast over iroh-gossip with the node's validation rules on
/// every received message.
pub struct GossipLayer {
    validator: Arc<dyn GossipValidator>,
    inbound: mpsc::Sender<Inbound>,
    // Accepted messages dropped because the subscriber had fallen
    // INBOUND_CAPACITY behind.
    dropped: AtomicU64,
    state: Mutex<State>,
    seen: Mutex<SeenCache>,
}

impl fmt::Debug for GossipLayer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GossipLayer").finish_non_exhaustive()
    }
}

impl GossipLayer {
    /// A layer judging messages with `validator`. Every accepted message
    /// arrives on the returned receiver while it keeps up; one that has
    /// fallen [`INBOUND_CAPACITY`] messages behind loses the newest (a
    /// judged message is then neither passed on nor blamed) rather than
    /// holding them in memory without bound.
    pub fn new(validator: Arc<dyn GossipValidator>) -> (Arc<Self>, mpsc::Receiver<Inbound>) {
        let (inbound, rx) = mpsc::channel(INBOUND_CAPACITY);
        let layer = Arc::new(Self {
            validator,
            inbound,
            dropped: AtomicU64::new(0),
            state: Mutex::new(State::default()),
            seen: Mutex::new(SeenCache::default()),
        });
        (layer, rx)
    }

    /// Opens every joined topic, and every topic joined later, on
    /// `transport` for the chain `chain_id`, and screens its connections
    /// with this layer's validator.
    pub fn attach(self: &Arc<Self>, transport: GossipTransport, chain_id: u64) -> IrohResult<()> {
        let mut state = self.state.lock();
        if state.transport.is_some() {
            return Err(IrohError::Backend(
                "gossip transport already attached".into(),
            ));
        }
        transport.gate.install(self.validator.clone());
        state.transport = Some(Attached {
            gossip: transport.gossip,
            gate: transport.gate,
            chain_id,
        });
        let names: Vec<Arc<str>> = state.topics.keys().cloned().collect();
        for name in names {
            self.open(&mut state, &name);
        }
        Ok(())
    }

    /// Joins `name`: this node receives, validates and passes on its messages.
    pub fn join(self: &Arc<Self>, name: &str) {
        self.register(name, false);
    }

    /// Joins `name` as a topic whose messages the subscriber judges: each
    /// accepted message arrives with a [`ValidationTicket`] and is passed on
    /// only when the ticket is accepted.
    pub fn join_judged(self: &Arc<Self>, name: &str) {
        self.register(name, true);
    }

    fn register(
        self: &Arc<Self>,
        name: &str,
        judged: bool,
    ) -> watch::Receiver<Option<GossipSender>> {
        let mut state = self.state.lock();
        let key: Arc<str> = Arc::from(name);
        let topic = state.topics.entry(key.clone()).or_insert_with(|| {
            let (ready, sender) = watch::channel(None);
            Topic {
                judged,
                sender,
                neighbours: Arc::new(AtomicUsize::new(0)),
                task: None,
                ready: Some(ready),
            }
        });
        topic.judged |= judged;
        let sender = topic.sender.clone();
        self.open(&mut state, &key);
        sender
    }

    /// Starts the subscription task of `name` if the transport is attached
    /// and the topic is not open yet.
    fn open(self: &Arc<Self>, state: &mut State, name: &Arc<str>) {
        let Some(transport) = state.transport.as_ref() else {
            return;
        };
        let gossip = transport.gossip.clone();
        let id = topic_id(transport.chain_id, name);
        let Some(topic) = state.topics.get_mut(name) else {
            return;
        };
        let Some(ready) = topic.ready.take() else {
            return;
        };
        let neighbours = topic.neighbours.clone();
        topic.task = Some(tokio::spawn(run_topic(
            Arc::downgrade(self),
            name.clone(),
            gossip,
            id,
            ready,
            neighbours,
        )));
    }

    /// Publishes `content` on `name` to every direct neighbour of the topic,
    /// joining the topic if needed.
    pub async fn publish(self: &Arc<Self>, name: &str, content: Bytes) -> IrohResult<()> {
        self.publish_if(name, content, false).await.map(|_| ())
    }

    /// [`Self::publish`], unless this node has already seen `content`,
    /// delivered by a neighbour or published by itself: a message several
    /// nodes hold byte for byte goes out from the first of them only.
    /// Returns whether it was published.
    pub async fn publish_unseen(self: &Arc<Self>, name: &str, content: Bytes) -> IrohResult<bool> {
        self.publish_if(name, content, true).await
    }

    async fn publish_if(
        self: &Arc<Self>,
        name: &str,
        content: Bytes,
        unseen_only: bool,
    ) -> IrohResult<bool> {
        if content.len() > MAX_GOSSIP_MESSAGE {
            return Err(IrohError::Backend(format!(
                "gossip message of {} bytes exceeds {MAX_GOSSIP_MESSAGE}",
                content.len()
            )));
        }
        if self.state.lock().transport.is_none() {
            return Err(IrohError::Backend("gossip transport not attached".into()));
        }
        let mut ready = self.register(name, false);
        let sender = tokio::time::timeout(OPEN_TIMEOUT, ready.wait_for(Option::is_some))
            .await
            .map_err(|_| IrohError::Backend(format!("gossip topic {name} did not open")))?
            .map_err(|_| IrohError::Backend(format!("gossip topic {name} closed")))?
            .clone()
            .ok_or_else(|| IrohError::Backend(format!("gossip topic {name} closed")))?;
        if !self.seen.lock().insert(&content) && unseen_only {
            return Ok(false);
        }
        sender
            .broadcast_neighbors(content)
            .await
            .map_err(|e| IrohError::Backend(format!("gossip publish on {name}: {e}")))?;
        Ok(true)
    }

    /// Adds peers this node joins its topics through: they are asked to
    /// become neighbours on every open topic and bootstrap topics opened
    /// later. A peer the validator does not allow is not dialled.
    pub async fn add_peers(&self, peers: impl IntoIterator<Item = EndpointId>) {
        let (fresh, senders) = {
            let mut state = self.state.lock();
            let fresh: Vec<EndpointId> = peers
                .into_iter()
                .filter(|p| self.validator.allows(*p) && state.known.insert(*p))
                .collect();
            let senders: Vec<GossipSender> = state
                .topics
                .values()
                .filter_map(|t| t.sender.borrow().clone())
                .collect();
            (fresh, senders)
        };
        if fresh.is_empty() {
            return;
        }
        for sender in senders {
            if let Err(e) = sender.join_peers(fresh.clone()).await {
                debug!(target: "tenzro_iroh::gossip", error = %e, "peers not joined");
            }
        }
    }

    /// Direct neighbours on `name`, or `None` if the topic is not joined.
    pub fn neighbour_count(&self, name: &str) -> Option<usize> {
        self.state
            .lock()
            .topics
            .get(name)
            .map(|t| t.neighbours.load(Ordering::Relaxed))
    }

    /// The peers this node met as gossip neighbours or was given to join
    /// through, that its rules still allow, best scored first.
    pub fn peers(&self) -> Vec<EndpointId> {
        let known: Vec<EndpointId> = self.state.lock().known.iter().copied().collect();
        let mut ranked: Vec<(i32, EndpointId)> = known
            .into_iter()
            .filter(|p| self.validator.allows(*p))
            .map(|p| (self.validator.score(p), p))
            .collect();
        ranked.sort_by_key(|r| std::cmp::Reverse(r.0));
        ranked.into_iter().map(|(_, p)| p).collect()
    }

    /// The allowed known peers, best scored first, that a topic opens
    /// through. A peer that refused this node is left out until its pause
    /// is over.
    fn bootstrap(&self) -> Vec<EndpointId> {
        let mut peers = self.peers();
        if let Some(gate) = self.gate() {
            let now = Instant::now();
            peers.retain(|p| !gate.paused(*p, now));
        }
        peers.truncate(BOOTSTRAP_PEERS);
        peers
    }

    /// The known peers a topic short of neighbours asks again: the ones not
    /// in `around`, its own neighbours. A peer that is a neighbour on some
    /// other topic is asked every time. One that is a neighbour on no topic
    /// is asked, then left alone for a pause that starts at one check, doubles
    /// each time it is asked and ends for good once it becomes a neighbour:
    /// an endpoint key lasts one boot, so the id of a peer that restarted
    /// never answers again.
    fn ask_again(&self, around: &HashSet<EndpointId>, now: Instant) -> Vec<EndpointId> {
        let candidates = self.bootstrap();
        let mut state = self.state.lock();
        candidates
            .into_iter()
            .filter(|p| !around.contains(p))
            .filter(|p| {
                state.around.contains_key(p)
                    || state.unanswered.note_from(*p, now, REJOIN_CHECK).is_some()
            })
            .collect()
    }

    /// `peer` became a direct neighbour on one more topic.
    fn neighbour_up(&self, peer: EndpointId) {
        let mut state = self.state.lock();
        *state.around.entry(peer).or_default() += 1;
        state.unanswered.forgive(peer);
    }

    /// `peer` stopped being a direct neighbour on one topic.
    fn neighbour_down(&self, peer: EndpointId) {
        let mut state = self.state.lock();
        if let Some(topics) = state.around.get_mut(&peer) {
            *topics -= 1;
            if *topics == 0 {
                state.around.remove(&peer);
            }
        }
    }

    /// The gate screening this layer's connections, once a transport is
    /// attached.
    fn gate(&self) -> Option<GossipGate> {
        self.state.lock().transport.as_ref().map(|t| t.gate.clone())
    }

    /// Remembers a neighbour met on some topic as a bootstrap candidate.
    fn learn(&self, peer: EndpointId) {
        let mut state = self.state.lock();
        if state.known.len() < MAX_KNOWN_PEERS {
            state.known.insert(peer);
        }
    }

    /// Reports `verdict` on `from` and, once the validator no longer
    /// allows it, drops it as a neighbour.
    fn record(&self, from: EndpointId, verdict: Verdict) {
        self.validator.verdict(from, verdict);
        self.drop_if_disallowed(from);
    }

    fn drop_if_disallowed(&self, peer: EndpointId) {
        if self.validator.allows(peer) {
            return;
        }
        self.state.lock().known.remove(&peer);
        if let Some(gate) = self.gate() {
            debug!(target: "tenzro_iroh::gossip", peer = %peer, "dropping gossip neighbour");
            gate.disconnect(peer);
        }
    }

    async fn on_message(
        self: &Arc<Self>,
        topic: &Arc<str>,
        sender: &GossipSender,
        from: EndpointId,
        scope: DeliveryScope,
        content: Bytes,
    ) {
        if !matches!(scope, DeliveryScope::Neighbors) {
            self.record(from, Verdict::Reject);
            return;
        }
        if self.validator.admit(topic, from) != Verdict::Accept {
            self.drop_if_disallowed(from);
            return;
        }
        if self.seen.lock().contains(&content) {
            trace!(target: "tenzro_iroh::gossip", topic = %topic, "duplicate dropped");
            self.validator.duplicate(topic, from, content.len());
            return;
        }
        let verdict = self.validator.check(topic, from, &content);
        // A message the validator could not judge from this neighbour is not
        // recorded as seen: another neighbour may deliver the same content
        // and be heard for it. An accepted or an invalid one is recorded, so
        // its replays cost nothing. Replays of an ignored one are judged
        // again, each charged to the neighbour's budget by `admit` above.
        if verdict != Verdict::Ignore && !self.seen.lock().insert(&content) {
            trace!(target: "tenzro_iroh::gossip", topic = %topic, "duplicate dropped");
            self.validator.duplicate(topic, from, content.len());
            return;
        }
        if verdict != Verdict::Accept {
            self.drop_if_disallowed(from);
            return;
        }
        let judged = self
            .state
            .lock()
            .topics
            .get(topic)
            .is_some_and(|t| t.judged);
        let ticket = if judged {
            Some(ValidationTicket {
                content: content.clone(),
                from,
                sender: sender.clone(),
                layer: Arc::downgrade(self),
                reported: false,
            })
        } else {
            if let Err(e) = sender.broadcast_neighbors(content.clone()).await {
                debug!(target: "tenzro_iroh::gossip", topic = %topic, error = %e, "message not passed on");
            }
            None
        };
        let message = Inbound {
            topic: topic.clone(),
            from,
            content,
            ticket,
        };
        if let Err(mpsc::error::TrySendError::Full(_)) = self.inbound.try_send(message) {
            let dropped = self.dropped.fetch_add(1, Ordering::Relaxed) + 1;
            if dropped.is_power_of_two() {
                warn!(target: "tenzro_iroh::gossip", topic = %topic, dropped, "gossip subscriber is behind; dropping accepted messages");
            }
        }
    }
}

impl Drop for GossipLayer {
    fn drop(&mut self) {
        for topic in self.state.get_mut().topics.values_mut() {
            if let Some(task) = topic.task.take() {
                task.abort();
            }
        }
    }
}

/// Keeps one topic subscribed, feeding its messages to the layer and
/// reopening the subscription if it closes.
async fn run_topic(
    layer: Weak<GossipLayer>,
    name: Arc<str>,
    gossip: Gossip,
    id: TopicId,
    ready: watch::Sender<Option<GossipSender>>,
    neighbours: Arc<AtomicUsize>,
) {
    loop {
        let Some(bootstrap) = layer.upgrade().map(|l| l.bootstrap()) else {
            return;
        };
        let (sender, mut receiver) = match gossip.subscribe(id, bootstrap.clone()).await {
            Ok(topic) => topic.split(),
            Err(e) => {
                warn!(target: "tenzro_iroh::gossip", topic = %name, error = %e, "gossip topic not opened");
                tokio::time::sleep(REJOIN_DELAY).await;
                continue;
            }
        };
        ready.send_replace(Some(sender.clone()));
        // Peers added while the subscription was opening saw no sender to
        // join through; join them now.
        let Some(known) = layer.upgrade().map(|l| l.bootstrap()) else {
            return;
        };
        let missed: Vec<EndpointId> = known
            .into_iter()
            .filter(|p| !bootstrap.contains(p))
            .collect();
        if !missed.is_empty()
            && let Err(e) = sender.join_peers(missed).await
        {
            debug!(target: "tenzro_iroh::gossip", topic = %name, error = %e, "peers not joined");
        }
        debug!(target: "tenzro_iroh::gossip", topic = %name, "gossip topic open");
        // A peer is joined once; if the link to it is lost (a partition, or
        // the peer restarting on the same endpoint key, which changes
        // nothing that would join it again) neither side asks again. So
        // while the topic has few neighbours, the known peers it lacks are
        // joined again.
        let mut around: HashSet<EndpointId> = HashSet::new();
        let mut check = tokio::time::interval(REJOIN_CHECK);
        check.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            let event = tokio::select! {
                event = receiver.next() => match event {
                    Some(event) => event,
                    None => break,
                },
                _ = check.tick() => {
                    if around.len() < MIN_NEIGHBOURS {
                        let Some(layer) = layer.upgrade() else {
                            return;
                        };
                        let lost = layer.ask_again(&around, Instant::now());
                        if !lost.is_empty()
                            && let Err(e) = sender.join_peers(lost).await
                        {
                            debug!(target: "tenzro_iroh::gossip", topic = %name, error = %e, "peers not joined again");
                        }
                    }
                    continue;
                }
            };
            let Some(layer) = layer.upgrade() else {
                return;
            };
            match event {
                Ok(Event::Received(message)) => {
                    layer
                        .on_message(
                            &name,
                            &sender,
                            message.delivered_from,
                            message.scope,
                            message.content,
                        )
                        .await
                }
                Ok(Event::NeighborUp(peer)) => {
                    if around.insert(peer) {
                        layer.neighbour_up(peer);
                    }
                    neighbours.store(around.len(), Ordering::Relaxed);
                    if layer.validator.allows(peer) {
                        layer.learn(peer);
                        if let Some(gate) = layer.gate() {
                            gate.forgive(peer);
                        }
                    } else {
                        layer.drop_if_disallowed(peer);
                    }
                }
                Ok(Event::NeighborDown(peer)) => {
                    if around.remove(&peer) {
                        layer.neighbour_down(peer);
                    }
                    neighbours.store(around.len(), Ordering::Relaxed);
                }
                Ok(Event::Lagged) => {
                    warn!(target: "tenzro_iroh::gossip", topic = %name, "gossip subscriber lagged; messages were missed");
                }
                // The event type can grow; this layer acts on the ones above.
                Ok(_) => {}
                Err(e) => {
                    debug!(target: "tenzro_iroh::gossip", topic = %name, error = %e, "gossip topic stream ended");
                    break;
                }
            }
        }
        ready.send_replace(None);
        neighbours.store(0, Ordering::Relaxed);
        if let Some(layer) = layer.upgrade() {
            for peer in around {
                layer.neighbour_down(peer);
            }
        }
        warn!(target: "tenzro_iroh::gossip", topic = %name, "gossip topic closed; reopening");
        tokio::time::sleep(REJOIN_DELAY).await;
    }
}

#[cfg(test)]
#[expect(
    clippy::disallowed_methods,
    reason = "the test runner bounds every wait in a test"
)]
mod tests {
    use super::*;
    use iroh::address_lookup::memory::MemoryLookup;
    use iroh::endpoint::presets;
    use iroh::protocol::Router;

    /// Accepts everything except content starting with `b"bad"`, and bans a
    /// neighbour after two rejected messages. With `only_from` set, messages
    /// delivered by any other neighbour are ignored, which pins the path a
    /// message takes whatever links the membership layer forms. With `named`
    /// set, only those endpoints are allowed as neighbours at all. With
    /// `unjudged_from` set, the content check ignores what that neighbour
    /// delivers.
    #[derive(Debug, Default)]
    struct Rules {
        only_from: Mutex<Option<EndpointId>>,
        named: Mutex<Option<HashSet<EndpointId>>>,
        unjudged_from: Mutex<Option<EndpointId>>,
        rejected: AtomicUsize,
        strikes: Mutex<HashMap<EndpointId, i32>>,
    }

    impl Rules {
        fn strike(&self, peer: EndpointId) {
            *self.strikes.lock().entry(peer).or_default() += 1;
        }
    }

    impl GossipValidator for Rules {
        fn admit(&self, _topic: &str, from: EndpointId) -> Verdict {
            if !self.allows(from) {
                return Verdict::Reject;
            }
            match *self.only_from.lock() {
                Some(only) if only != from => Verdict::Ignore,
                _ => Verdict::Accept,
            }
        }
        fn duplicate(&self, _topic: &str, _from: EndpointId, _bytes: usize) {}
        fn check(&self, _topic: &str, from: EndpointId, content: &[u8]) -> Verdict {
            if *self.unjudged_from.lock() == Some(from) {
                return Verdict::Ignore;
            }
            if content.starts_with(b"bad") {
                self.rejected.fetch_add(1, Ordering::Relaxed);
                self.strike(from);
                Verdict::Reject
            } else {
                Verdict::Accept
            }
        }
        fn verdict(&self, from: EndpointId, verdict: Verdict) {
            if verdict == Verdict::Reject {
                self.strike(from);
            }
        }
        fn allows(&self, peer: EndpointId) -> bool {
            self.strikes.lock().get(&peer).copied().unwrap_or(0) < 2
                && self
                    .named
                    .lock()
                    .as_ref()
                    .is_none_or(|named| named.contains(&peer))
        }
        fn score(&self, peer: EndpointId) -> i32 {
            -self.strikes.lock().get(&peer).copied().unwrap_or(0)
        }
    }

    struct Node {
        endpoint: Endpoint,
        _router: Router,
        layer: Arc<GossipLayer>,
        inbound: mpsc::Receiver<Inbound>,
        rules: Arc<Rules>,
    }

    async fn node(lookup: &MemoryLookup) -> Node {
        node_with_key(lookup, iroh::SecretKey::generate()).await
    }

    async fn node_with_key(lookup: &MemoryLookup, key: iroh::SecretKey) -> Node {
        let gate = GossipGate::default();
        let endpoint = crate::identity_transport::on_loopback(Endpoint::builder(presets::Minimal))
            .secret_key(key)
            .hooks(gate.clone())
            .bind()
            .await
            .unwrap();
        endpoint.address_lookup().unwrap().add(lookup.clone());
        lookup.add_endpoint_info(endpoint.addr());
        let transport = GossipTransport::spawn(&endpoint, gate);
        let router = Router::builder(endpoint.clone())
            .accept(ALPN_GOSSIP, transport.protocol())
            .spawn();
        let rules = Arc::new(Rules::default());
        let (layer, inbound) = GossipLayer::new(rules.clone());
        layer.attach(transport, 7).unwrap();
        Node {
            endpoint,
            _router: router,
            layer,
            inbound,
            rules,
        }
    }

    async fn next(rx: &mut mpsc::Receiver<Inbound>) -> Inbound {
        tokio::time::timeout(Duration::from_secs(10), rx.recv())
            .await
            .expect("message arrives")
            .unwrap()
    }

    async fn wait_for_neighbours(layer: &GossipLayer, topic: &str, n: usize) {
        for _ in 0..200 {
            if layer.neighbour_count(topic).unwrap_or(0) >= n {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("{topic} never reached {n} neighbours");
    }

    #[test]
    fn topic_ids_differ_by_name_and_chain() {
        assert_eq!(topic_id(1, "tenzro/blocks"), topic_id(1, "tenzro/blocks"));
        assert_ne!(topic_id(1, "tenzro/blocks"), topic_id(2, "tenzro/blocks"));
        assert_ne!(
            topic_id(1, "tenzro/blocks"),
            topic_id(1, "tenzro/transactions")
        );
    }

    #[test]
    fn seen_cache_suppresses_repeats() {
        let mut seen = SeenCache::default();
        assert!(seen.insert(b"one"));
        assert!(!seen.insert(b"one"));
        assert!(seen.insert(b"two"));
    }

    #[test]
    fn bootstrap_prefers_the_best_scored_allowed_peers() {
        let rules = Arc::new(Rules::default());
        let (layer, _rx) = GossipLayer::new(rules.clone());
        let peers: Vec<EndpointId> = (1..=10u8)
            .map(|n| iroh::SecretKey::from_bytes(&[n; 32]).public())
            .collect();
        layer.state.lock().known.extend(peers.iter().copied());
        rules.strike(peers[0]);
        rules.strike(peers[0]);
        rules.strike(peers[1]);
        let chosen = layer.bootstrap();
        assert_eq!(chosen.len(), BOOTSTRAP_PEERS);
        assert!(
            !chosen.contains(&peers[0]),
            "a disallowed peer is never a bootstrap peer"
        );
        assert!(
            !chosen.contains(&peers[1]),
            "a penalised peer ranks below clean ones"
        );
    }

    #[tokio::test]
    async fn publishing_before_attach_fails_and_joining_works() {
        let (layer, _rx) = GossipLayer::new(Arc::new(Rules::default()));
        layer.join("tenzro/status");
        assert_eq!(layer.neighbour_count("tenzro/status"), Some(0));
        assert!(
            layer
                .publish("tenzro/status", Bytes::from_static(b"x"))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn messages_cross_a_line_of_nodes_and_rejected_ones_stop() {
        let lookup = MemoryLookup::new();
        let mut a = node(&lookup).await;
        let mut b = node(&lookup).await;
        let mut c = node(&lookup).await;
        for n in [&a, &b, &c] {
            n.layer.join("t");
        }
        // a - b - c: c takes a's messages only through b.
        *c.rules.only_from.lock() = Some(b.endpoint.id());
        b.layer.add_peers([a.endpoint.id()]).await;
        c.layer.add_peers([b.endpoint.id()]).await;
        wait_for_neighbours(&b.layer, "t", 2).await;

        a.layer
            .publish("t", Bytes::from_static(b"hello"))
            .await
            .unwrap();
        assert_eq!(&next(&mut b.inbound).await.content[..], b"hello");
        let at_c = next(&mut c.inbound).await;
        assert_eq!(&at_c.content[..], b"hello");
        assert_eq!(at_c.from, b.endpoint.id(), "b passed it on");
        assert!(at_c.ticket.is_none());

        a.layer
            .publish("t", Bytes::from_static(b"bad one"))
            .await
            .unwrap();
        a.layer
            .publish("t", Bytes::from_static(b"after"))
            .await
            .unwrap();
        assert_eq!(
            &next(&mut c.inbound).await.content[..],
            b"after",
            "the rejected message never reached c"
        );
        assert_eq!(b.rules.rejected.load(Ordering::Relaxed), 1);
        assert_eq!(c.rules.rejected.load(Ordering::Relaxed), 0);
        assert!(
            a.inbound.try_recv().is_err(),
            "a's own messages are not delivered back to it"
        );
    }

    #[tokio::test]
    async fn judged_messages_move_on_only_when_accepted() {
        let lookup = MemoryLookup::new();
        let a = node(&lookup).await;
        let mut b = node(&lookup).await;
        let mut c = node(&lookup).await;
        a.layer.join("blocks");
        b.layer.join_judged("blocks");
        c.layer.join("blocks");
        *c.rules.only_from.lock() = Some(b.endpoint.id());
        b.layer.add_peers([a.endpoint.id()]).await;
        c.layer.add_peers([b.endpoint.id()]).await;
        wait_for_neighbours(&b.layer, "blocks", 2).await;

        a.layer
            .publish("blocks", Bytes::from_static(b"one"))
            .await
            .unwrap();
        let held = next(&mut b.inbound).await;
        held.ticket.expect("judged topic carries a ticket").reject();
        assert_eq!(
            b.rules.score(a.endpoint.id()),
            -1,
            "the rejection counted against a"
        );

        a.layer
            .publish("blocks", Bytes::from_static(b"two"))
            .await
            .unwrap();
        let held = next(&mut b.inbound).await;
        assert_eq!(&held.content[..], b"two");
        held.ticket.unwrap().accept();
        assert_eq!(
            &next(&mut c.inbound).await.content[..],
            b"two",
            "only the accepted message reached c"
        );
    }

    /// A publish goes to every direct neighbour: each of the publisher's
    /// neighbours takes messages only from the publisher and still gets it.
    #[tokio::test]
    async fn a_publish_reaches_every_direct_neighbour() {
        let lookup = MemoryLookup::new();
        let hub = node(&lookup).await;
        hub.layer.join("blocks");
        let mut spokes = Vec::new();
        for _ in 0..4 {
            let s = node(&lookup).await;
            *s.rules.only_from.lock() = Some(hub.endpoint.id());
            s.layer.join("blocks");
            s.layer.add_peers([hub.endpoint.id()]).await;
            spokes.push(s);
        }
        wait_for_neighbours(&hub.layer, "blocks", 4).await;
        hub.layer
            .publish("blocks", Bytes::from_static(b"proposal"))
            .await
            .unwrap();
        for s in &mut spokes {
            let got = next(&mut s.inbound).await;
            assert_eq!(&got.content[..], b"proposal");
            assert_eq!(got.from, hub.endpoint.id());
        }
    }

    /// Two nodes hold the same message byte for byte. The one that has had
    /// it delivered does not publish it again; a message it has not seen it
    /// publishes, and `publish` goes out whatever was seen.
    #[tokio::test]
    async fn a_message_already_delivered_is_not_published_again() {
        let lookup = MemoryLookup::new();
        let first = node(&lookup).await;
        let mut second = node(&lookup).await;
        first.layer.join("blocks");
        second.layer.join("blocks");
        second.layer.add_peers([first.endpoint.id()]).await;
        wait_for_neighbours(&first.layer, "blocks", 1).await;
        let block = Bytes::from_static(b"block 7");
        assert!(
            first
                .layer
                .publish_unseen("blocks", block.clone())
                .await
                .unwrap()
        );
        assert_eq!(&next(&mut second.inbound).await.content[..], b"block 7");
        assert!(
            !second
                .layer
                .publish_unseen("blocks", block.clone())
                .await
                .unwrap(),
            "published again by the node it was delivered to"
        );
        assert!(
            !first
                .layer
                .publish_unseen("blocks", block.clone())
                .await
                .unwrap(),
            "published twice by one node"
        );
        assert!(
            second
                .layer
                .publish_unseen("blocks", Bytes::from_static(b"block 8"))
                .await
                .unwrap()
        );
        second.layer.publish("blocks", block).await.unwrap();
    }

    /// However often a peer is dialled again, the connections neither side
    /// sends on are closed: at most one stays open for each direction.
    /// Keep-alives would otherwise hold every spare one open, and pairs of
    /// validators gathered hundreds of them.
    #[tokio::test]
    async fn spare_connections_to_a_peer_are_closed() {
        let lookup = MemoryLookup::new();
        let a = node(&lookup).await;
        let mut b = node(&lookup).await;
        a.layer.join("blocks");
        b.layer.join("blocks");
        a.layer.add_peers([b.endpoint.id()]).await;
        wait_for_neighbours(&a.layer, "blocks", 1).await;
        wait_for_neighbours(&b.layer, "blocks", 1).await;
        a.layer
            .publish("blocks", Bytes::from_static(b"one"))
            .await
            .unwrap();
        assert_eq!(&next(&mut b.inbound).await.content[..], b"one");

        let (gossip, gate) = {
            let state = a.layer.state.lock();
            let t = state.transport.as_ref().unwrap();
            (t.gossip.clone(), t.gate.clone())
        };
        let first: Vec<Connection> = gate
            .inner
            .connections
            .lock()
            .get(&b.endpoint.id())
            .into_iter()
            .flatten()
            .filter_map(|h| h.upgrade())
            .collect();
        assert_eq!(
            first.len(),
            1,
            "one gossip connection before dialling again"
        );

        let mut all = first;
        for _ in 0..4 {
            let again = a
                .endpoint
                .connect(b.endpoint.addr(), ALPN_GOSSIP)
                .await
                .unwrap();
            gossip.handle_connection(again.clone()).await.unwrap();
            all.push(again);
        }

        // A connection goes ten seconds after the last stream on it.
        let mut open = all.len();
        for _ in 0..800 {
            open = all.iter().filter(|c| c.close_reason().is_none()).count();
            if open <= 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(
            (1..=2).contains(&open),
            "five gossip connections to one peer: {open} still open after 40s"
        );
        a.layer
            .publish("blocks", Bytes::from_static(b"two"))
            .await
            .unwrap();
        assert_eq!(&next(&mut b.inbound).await.content[..], b"two");
    }

    #[test]
    fn the_pause_after_a_refusal_doubles_up_to_its_limit() {
        assert_eq!(growing_pause(REFUSAL_PAUSE, 1), REFUSAL_PAUSE);
        assert_eq!(growing_pause(REFUSAL_PAUSE, 2), REFUSAL_PAUSE * 2);
        assert_eq!(growing_pause(REFUSAL_PAUSE, 3), REFUSAL_PAUSE * 4);
        assert_eq!(growing_pause(REFUSAL_PAUSE, 6), REFUSAL_PAUSE_MAX);
        assert_eq!(growing_pause(REFUSAL_PAUSE, u32::MAX), REFUSAL_PAUSE_MAX);
    }

    #[test]
    fn a_refusing_peer_is_left_alone_for_a_growing_pause() {
        let peer = iroh::SecretKey::from_bytes(&[1; 32]).public();
        let other = iroh::SecretKey::from_bytes(&[2; 32]).public();
        let start = Instant::now();
        let mut refusals = Refusals::default();
        assert!(!refusals.paused(peer, start));

        assert_eq!(refusals.note(peer, start), Some((1, REFUSAL_PAUSE)));
        assert!(refusals.paused(peer, start + REFUSAL_PAUSE - Duration::from_secs(1)));
        assert!(!refusals.paused(other, start));
        // A refusal met while the peer is left alone starts no new pause.
        assert_eq!(refusals.note(peer, start + Duration::from_secs(1)), None);

        let again = start + REFUSAL_PAUSE;
        assert!(!refusals.paused(peer, again));
        assert_eq!(refusals.note(peer, again), Some((2, REFUSAL_PAUSE * 2)));
        assert!(refusals.paused(peer, again + REFUSAL_PAUSE));
        assert!(!refusals.paused(peer, again + REFUSAL_PAUSE * 2));

        refusals.forgive(peer);
        assert!(!refusals.paused(peer, again));
        assert_eq!(refusals.note(peer, again), Some((1, REFUSAL_PAUSE)));
    }

    #[test]
    fn a_known_peer_that_never_answers_is_asked_again_on_a_growing_pause() {
        let (layer, _rx) = GossipLayer::new(Arc::new(Rules::default()));
        let gone = iroh::SecretKey::from_bytes(&[1; 32]).public();
        let here = iroh::SecretKey::from_bytes(&[2; 32]).public();
        layer.state.lock().known.extend([gone, here]);
        // `here` is a neighbour on another topic; `gone` is one on none.
        layer.neighbour_up(here);
        let around = HashSet::new();
        let t0 = Instant::now();

        let mut asked = layer.ask_again(&around, t0);
        asked.sort();
        let mut both = vec![gone, here];
        both.sort();
        assert_eq!(asked, both, "every missing known peer is asked once");

        // The silent peer is asked one check later, then two, then four;
        // the peer known to be there at every check.
        let mut asks = Vec::new();
        for check in 1..=40u64 {
            let at = t0 + REJOIN_CHECK * check as u32;
            let asked = layer.ask_again(&around, at);
            assert!(asked.contains(&here), "check {check}");
            if asked.contains(&gone) {
                asks.push(check);
            }
        }
        assert_eq!(asks, vec![1, 3, 7, 15, 31]);

        // Once it is a neighbour its silence is forgotten: after it is lost
        // on every topic it is asked at the next check.
        layer.neighbour_up(gone);
        layer.neighbour_down(gone);
        let later = t0 + REJOIN_CHECK * 41;
        assert!(layer.ask_again(&around, later).contains(&gone));
        assert!(
            !layer
                .ask_again(&around, later + Duration::from_secs(1))
                .contains(&gone)
        );
    }

    #[test]
    fn a_neighbour_on_several_topics_is_one_until_the_last_is_lost() {
        let (layer, _rx) = GossipLayer::new(Arc::new(Rules::default()));
        let peer = iroh::SecretKey::from_bytes(&[3; 32]).public();
        layer.state.lock().known.insert(peer);
        layer.neighbour_up(peer);
        layer.neighbour_up(peer);
        layer.neighbour_down(peer);
        assert!(layer.state.lock().around.contains_key(&peer));
        layer.neighbour_down(peer);
        assert!(layer.state.lock().around.is_empty());
        // A report for a peer that is no neighbour changes nothing.
        layer.neighbour_down(peer);
        assert!(layer.state.lock().around.is_empty());
    }

    #[test]
    fn remembered_refusals_are_bounded() {
        let start = Instant::now();
        let mut refusals = Refusals::default();
        let peer = |n: usize| {
            let mut key = [0u8; 32];
            key[..8].copy_from_slice(&(n as u64 + 1).to_be_bytes());
            iroh::SecretKey::from_bytes(&key).public()
        };
        for n in 0..MAX_REFUSALS {
            assert!(refusals.note(peer(n), start).is_some());
        }
        assert_eq!(refusals.note(peer(MAX_REFUSALS), start), None);
        // Once the pauses are over the old entries make room.
        let later = start + REFUSAL_PAUSE;
        assert!(refusals.note(peer(MAX_REFUSALS), later).is_some());
        assert_eq!(refusals.by_peer.len(), 1);
    }

    /// A peer whose rules do not allow this node refuses its gossip
    /// connection; this node then stops opening topics through it.
    #[tokio::test]
    async fn a_peer_that_refuses_this_node_is_not_asked_again_at_once() {
        let lookup = MemoryLookup::new();
        let closed = node(&lookup).await;
        let asker = node(&lookup).await;
        closed.rules.strike(asker.endpoint.id());
        closed.rules.strike(asker.endpoint.id());
        closed.layer.join("t");
        asker.layer.join("t");
        asker.layer.add_peers([closed.endpoint.id()]).await;

        let gate = asker.layer.gate().unwrap();
        for _ in 0..200 {
            if gate.paused(closed.endpoint.id(), Instant::now()) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(
            gate.paused(closed.endpoint.id(), Instant::now()),
            "the refusal was noticed"
        );
        assert!(
            asker.layer.peers().contains(&closed.endpoint.id()),
            "the peer stays known"
        );
        assert!(
            !asker.layer.bootstrap().contains(&closed.endpoint.id()),
            "a peer that refused is not joined again while it is left alone"
        );
        assert_eq!(closed.layer.neighbour_count("t"), Some(0));
    }

    /// A neighbour that keeps sending invalid messages loses its gossip
    /// connections and cannot come back.
    #[tokio::test]
    async fn a_disallowed_neighbour_is_dropped_and_refused() {
        let lookup = MemoryLookup::new();
        let honest = node(&lookup).await;
        let spammer = node(&lookup).await;
        honest.layer.join("t");
        spammer.layer.join("t");
        spammer.layer.add_peers([honest.endpoint.id()]).await;
        wait_for_neighbours(&honest.layer, "t", 1).await;

        spammer
            .layer
            .publish("t", Bytes::from_static(b"bad 1"))
            .await
            .unwrap();
        spammer
            .layer
            .publish("t", Bytes::from_static(b"bad 2"))
            .await
            .unwrap();
        for _ in 0..200 {
            if honest.layer.neighbour_count("t") == Some(0) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert_eq!(
            honest.layer.neighbour_count("t"),
            Some(0),
            "the spammer was dropped"
        );
        assert!(!honest.rules.allows(spammer.endpoint.id()));

        match spammer
            .endpoint
            .connect(honest.endpoint.addr(), ALPN_GOSSIP)
            .await
        {
            Err(_) => {}
            Ok(conn) => {
                tokio::time::timeout(Duration::from_secs(10), conn.closed())
                    .await
                    .expect("the honest node closes a new gossip connection from the spammer");
            }
        }
    }

    /// A node that takes only the machines it names as gossip neighbours is
    /// asked by a crowd of endpoints nobody named, each on a key of its own.
    /// None becomes its neighbour, none of what they publish reaches it, none
    /// is kept as a peer to join through, and the neighbour it named still
    /// delivers.
    ///
    /// The rule that names machines is a test double here: this shows that
    /// the gossip layer holds every connection, delivery and remembered peer
    /// to whatever its validator's `allows` answers. The rule a node runs is
    /// `tenzro-network`'s `GossipGuard::allows`, which asks the node's
    /// identity source (`PeerIdentities::may_neighbour`); only a node set to
    /// keep to its boot list and the validators' machines refuses an
    /// endpoint no record names, and that is tested there
    /// (`an_isolated_node_keeps_no_gossip_neighbour_outside_its_allowed_peers`).
    #[tokio::test(flavor = "multi_thread")]
    async fn a_crowd_of_unnamed_endpoints_gains_no_neighbour_and_delivers_nothing() {
        const CROWD: usize = 24;
        let lookup = MemoryLookup::new();
        let mut honest = node(&lookup).await;
        let named = node(&lookup).await;
        *honest.rules.named.lock() = Some([named.endpoint.id()].into());
        honest.layer.join("t");
        named.layer.join("t");
        named.layer.add_peers([honest.endpoint.id()]).await;
        wait_for_neighbours(&honest.layer, "t", 1).await;

        let mut crowd = Vec::new();
        for _ in 0..CROWD {
            let s = node(&lookup).await;
            s.layer.join("t");
            s.layer.add_peers([honest.endpoint.id()]).await;
            crowd.push(s);
        }
        // Each asks again on a connection of its own, and publishes; with no
        // neighbour a publish may fail, which is the point.
        let honest_addr = honest.endpoint.addr();
        let honest_addr = &honest_addr;
        futures::future::join_all(crowd.iter().enumerate().map(|(i, s)| async move {
            let _ = s.endpoint.connect(honest_addr.clone(), ALPN_GOSSIP).await;
            let _ = s
                .layer
                .publish("t", Bytes::from(format!("from the crowd {i}")))
                .await;
        }))
        .await;

        named
            .layer
            .publish("t", Bytes::from_static(b"from the named machine"))
            .await
            .unwrap();
        let got = next(&mut honest.inbound).await;
        assert_eq!(&got.content[..], b"from the named machine");
        assert_eq!(got.from, named.endpoint.id());
        assert!(
            tokio::time::timeout(Duration::from_millis(500), honest.inbound.recv())
                .await
                .is_err(),
            "something from the crowd was delivered"
        );
        assert_eq!(honest.layer.neighbour_count("t"), Some(1));
        let kept = honest.layer.peers();
        assert!(
            crowd.iter().all(|s| !kept.contains(&s.endpoint.id())),
            "an unnamed endpoint is kept as a peer to join through"
        );
    }

    /// A peer that went away and came back on the same endpoint key, knowing
    /// nobody, is joined again by the node that knew it: nothing waits for
    /// the peer to find its way back on its own.
    #[tokio::test]
    async fn a_peer_that_returns_on_the_same_key_is_joined_again() {
        let lookup = MemoryLookup::new();
        let a = node(&lookup).await;
        a.layer.join("t");
        let key = iroh::SecretKey::generate();
        let b = node_with_key(&lookup, key.clone()).await;
        b.layer.join("t");
        a.layer.add_peers([b.endpoint.id()]).await;
        wait_for_neighbours(&a.layer, "t", 1).await;

        b._router.shutdown().await.unwrap();
        drop(b);
        for _ in 0..400 {
            if a.layer.neighbour_count("t") == Some(0) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert_eq!(a.layer.neighbour_count("t"), Some(0), "b is gone");

        let mut back = node_with_key(&lookup, key).await;
        back.layer.join("t");
        let mut joined = false;
        for _ in 0..400 {
            if back.layer.neighbour_count("t").unwrap_or(0) >= 1 {
                joined = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(joined, "a joined the returning peer again");
        // The publisher counts the returning peer too before it publishes:
        // a message sent while only the returning side has the link is lost.
        wait_for_neighbours(&a.layer, "t", 1).await;
        a.layer
            .publish("t", Bytes::from_static(b"after the return"))
            .await
            .unwrap();
        assert_eq!(
            &next(&mut back.inbound).await.content[..],
            b"after the return"
        );
    }

    /// Content a neighbour delivered that the validator could not judge
    /// from it is still heard from another neighbour, and passed on.
    #[tokio::test]
    async fn content_ignored_from_one_neighbour_is_heard_from_another() {
        let lookup = MemoryLookup::new();
        let mut hearer = node(&lookup).await;
        let mut next_hop = node(&lookup).await;
        hearer.layer.join("t");
        next_hop.layer.join("t");
        next_hop.layer.add_peers([hearer.endpoint.id()]).await;
        wait_for_neighbours(&hearer.layer, "t", 1).await;

        let unjudged = iroh::SecretKey::from_bytes(&[7; 32]).public();
        let trusted = iroh::SecretKey::from_bytes(&[8; 32]).public();
        *hearer.rules.unjudged_from.lock() = Some(unjudged);
        let topic: Arc<str> = Arc::from("t");
        let sender = {
            let state = hearer.layer.state.lock();
            state.topics["t"].sender.borrow().clone().unwrap()
        };
        let content = Bytes::from_static(b"a transfer someone else made");

        hearer
            .layer
            .on_message(
                &topic,
                &sender,
                unjudged,
                DeliveryScope::Neighbors,
                content.clone(),
            )
            .await;
        assert!(
            hearer.inbound.try_recv().is_err(),
            "nothing is delivered from the neighbour that is not judged"
        );

        hearer
            .layer
            .on_message(
                &topic,
                &sender,
                trusted,
                DeliveryScope::Neighbors,
                content.clone(),
            )
            .await;
        let heard = next(&mut hearer.inbound).await;
        assert_eq!(heard.from, trusted);
        assert_eq!(heard.content, content);
        assert_eq!(
            next(&mut next_hop.inbound).await.content,
            content,
            "and it is passed on"
        );

        // Delivered once more, it is a duplicate.
        hearer
            .layer
            .on_message(&topic, &sender, trusted, DeliveryScope::Neighbors, content)
            .await;
        assert!(hearer.inbound.try_recv().is_err());
    }
}
