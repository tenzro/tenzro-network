//! The node's rules for received gossip.
//!
//! [`GossipGuard`] runs on every message the iroh gossip layer
//! ([`tenzro_iroh::gossip`]) receives, before the message is delivered or
//! passed on to other nodes:
//!
//! 1. the neighbour that delivered it must not be banned, and must stay
//!    within its budget for the topic's traffic class
//!    ([`GossipValidator::admit`]);
//! 2. a message seen before is dropped (the layer's seen-cache);
//! 3. the message must fit the size limit, decode as a [`NetworkMessage`]
//!    and pass [`crate::message::validate_message`]
//!    ([`GossipValidator::check`]).
//!
//! Every neighbour has a score for the session. The score, the ban and the
//! budgets belong to the neighbour's machine identity when a verified
//! endpoint record names its endpoint (see [`PeerIdentities`]), so a banned
//! machine is not readmitted by presenting a new endpoint key; a neighbour no
//! record names is scored by its endpoint id, which is free to make.
//! A neighbour only passes on messages it accepted, so a valid message
//! raises the score of the neighbour that delivered it and an invalid,
//! rejected one lowers it. Topics bootstrap through the
//! best-scored peers first; at the ban threshold the neighbour's messages
//! are refused and its gossip connections closed and refused for the ban
//! period.
//!
//! Each neighbour has two message budgets per window, set by
//! [`GossipLimits`]: one for the topics consensus and sync depend on
//! ([`CONSENSUS_TOPICS`]) and one for every other topic, transactions
//! included. A message over its class budget is dropped without blame: a
//! busy but honest relay loses its excess transactions, never its standing
//! or its certificates. Only invalid messages cost reputation.
//!
//! With a [`PeerIdentities`] source installed, a neighbour that no verified,
//! unexpired endpoint record names may not deliver on [`CONSENSUS_TOPICS`]:
//! its messages there are dropped without blame and not passed on. It may
//! still deliver on every other topic, within the general budget.
//!
//! Peers the node joined its topics through (see
//! [`crate::gossip::NetworkGossip::add_peers`]) are protected: never rate
//! limited, penalised or banned.
//!
//! A topic whose messages only the node can judge (a block, whose
//! certificate needs the validator set) is subscribed with
//! [`crate::gossip::NetworkGossip::subscribe_validated`]. Each message then
//! arrives with a [`ValidationTicket`] and is passed on only if the node
//! accepts it; a ticket dropped without a verdict ignores the message.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::{Mutex, RwLock};
use tenzro_iroh::EndpointId;
use tenzro_iroh::gossip::{GossipValidator, MAX_GOSSIP_MESSAGE, Verdict};
use tenzro_onboarding_types::onboarding::Standing as RegistryStanding;

use crate::message::NetworkMessage;
use crate::metrics::NetworkMetrics;

pub use tenzro_iroh::gossip::ValidationTicket;

/// Reputation at or below which a neighbour is banned.
const BAN_THRESHOLD: i32 = -50;
/// Reputation lost per invalid message.
const PENALTY: i32 = 5;
/// Reputation bounds.
const REPUTATION_MIN: i32 = -100;
const REPUTATION_MAX: i32 = 100;
/// Neighbours tracked at once; idle, unbanned entries make room first.
const MAX_TRACKED: usize = 4096;

/// Topics consensus and sync depend on: checkpoint certificates, blocks,
/// validator endpoint announcements and peer status. Their messages are
/// budgeted apart from every other topic.
pub const CONSENSUS_TOPICS: &[&str] = &[
    "tenzro/certificates",
    "tenzro/blocks",
    "tenzro/validators",
    "tenzro/status",
];

/// The topic validators' signed endpoint announcements travel on. It is the
/// one consensus topic a neighbour no record names may deliver on, because
/// the announcements are how the records that name neighbours come to exist.
pub const VALIDATORS_TOPIC: &str = "tenzro/validators";

/// Per-neighbour budgets for received gossip. The node sets them from the
/// network's governed parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GossipLimits {
    /// The budget window.
    pub window: Duration,
    /// Messages per window on [`CONSENSUS_TOPICS`].
    pub consensus_messages: u64,
    /// Messages per window on every other topic.
    pub general_messages: u64,
    /// How long a ban lasts.
    pub ban: Duration,
}

/// The machine identities behind gossip neighbours.
pub trait PeerIdentities: Send + Sync + 'static {
    /// The machine identity (DID) of the verified, unexpired endpoint record
    /// that names `endpoint`, if one is held.
    fn machine_did(&self, endpoint: EndpointId) -> Option<String>;

    /// Whether `announcement` (the bytes of a validator's endpoint
    /// announcement) verifies under the key of a validator this node knows.
    /// A neighbour no record names may deliver on [`VALIDATORS_TOPIC`] only
    /// such announcements: a validator's endpoint is reached through them
    /// before any record can name it.
    fn vouches_for_announcement(&self, _announcement: &[u8]) -> bool {
        false
    }

    /// What the identity registry says about the machine identity `did`.
    /// Read only when the guard is set to deliver from registered
    /// neighbours only ([`GossipGuard::set_registered_only`]); the default
    /// is for sources that predate the identity gate.
    fn registry_standing(&self, _did: &str) -> RegistryStanding {
        RegistryStanding::Registered
    }
}

/// Whom a neighbour's standing belongs to.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum Subject {
    /// A machine identity named by a verified endpoint record.
    Machine(String),
    /// An endpoint key no record names.
    Endpoint(EndpointId),
}

/// A topic's traffic class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Class {
    Consensus,
    General,
}

impl Class {
    fn of(topic: &str) -> Self {
        if CONSENSUS_TOPICS.contains(&topic) {
            Self::Consensus
        } else {
            Self::General
        }
    }
}

/// Messages counted in the current window.
#[derive(Debug, Default)]
struct Budget {
    started: Option<Instant>,
    used: u64,
}

impl Budget {
    /// Takes one message from the budget; false when it is spent.
    fn take(&mut self, now: Instant, window: Duration, allowance: u64) -> bool {
        if self.started.is_none_or(|t| now.duration_since(t) >= window) {
            self.started = Some(now);
            self.used = 0;
        }
        if self.used >= allowance {
            return false;
        }
        self.used += 1;
        true
    }
}

/// A gossip message held pending the node's verdict.
#[derive(Debug)]
pub struct ValidatedMessage {
    /// The decoded message.
    pub message: NetworkMessage,
    /// Report the verdict here.
    pub ticket: ValidationTicket,
}

/// Checks the framing of one message: non-empty, within the size limit,
/// decodable, and valid by [`crate::message::validate_message`].
pub fn validate_gossip_message(data: &[u8]) -> Verdict {
    if data.is_empty() || data.len() > MAX_GOSSIP_MESSAGE {
        return Verdict::Reject;
    }
    match NetworkMessage::from_bytes(data) {
        Ok(msg) => match crate::message::validate_message(&msg) {
            Ok(()) => Verdict::Accept,
            Err(e) => {
                tracing::warn!("Message validation failed: {}", e);
                Verdict::Reject
            }
        },
        Err(e) => {
            tracing::warn!("Failed to parse network message: {}", e);
            Verdict::Reject
        }
    }
}

#[derive(Debug, Default)]
struct Standing {
    reputation: i32,
    banned_until: Option<Instant>,
    consensus: Budget,
    general: Budget,
    last_seen: Option<Instant>,
}

impl Standing {
    fn banned(&self, now: Instant) -> bool {
        self.banned_until.is_some_and(|until| now < until)
    }

    fn penalise(&mut self, now: Instant, ban: Duration) {
        self.reputation = (self.reputation - PENALTY).max(REPUTATION_MIN);
        if self.reputation <= BAN_THRESHOLD {
            self.banned_until = Some(now + ban);
        }
    }
}

/// Per-neighbour bans, budgets and reputation for received gossip.
pub struct GossipGuard {
    standing: Mutex<HashMap<Subject, Standing>>,
    identities: RwLock<Option<Arc<dyn PeerIdentities>>>,
    /// Announcements taken from neighbours no record names, across all of
    /// them, so a flood of fresh endpoint keys cannot make this node verify
    /// more than the consensus budget of one neighbour.
    unidentified: Mutex<Budget>,
    limits: RwLock<GossipLimits>,
    protected: Mutex<HashSet<EndpointId>>,
    /// Whether a neighbour must have a registered identity to deliver
    /// anything but a verified validator announcement.
    registered_only: std::sync::atomic::AtomicBool,
    metrics: Arc<NetworkMetrics>,
}

impl std::fmt::Debug for GossipGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GossipGuard")
            .field("tracked", &self.standing.lock().len())
            .field("protected", &self.protected.lock().len())
            .finish()
    }
}

impl GossipGuard {
    /// A guard with `limits`, counting its verdicts in `metrics`.
    pub fn new(metrics: Arc<NetworkMetrics>, limits: GossipLimits) -> Self {
        Self {
            standing: Mutex::new(HashMap::new()),
            identities: RwLock::new(None),
            unidentified: Mutex::new(Budget::default()),
            limits: RwLock::new(limits),
            protected: Mutex::new(HashSet::new()),
            registered_only: std::sync::atomic::AtomicBool::new(false),
            metrics,
        }
    }

    /// Whether a neighbour must have a registered identity (the registry the
    /// installed [`PeerIdentities`] reads) to deliver anything on any topic.
    /// A neighbour that has none may still deliver a validator's verified
    /// endpoint announcement, from the budget all such neighbours share:
    /// that is how a node learns the records that name the others. Node-local
    /// policy; off until the node turns it on.
    pub fn set_registered_only(&self, on: bool) {
        self.registered_only
            .store(on, std::sync::atomic::Ordering::Relaxed);
    }

    fn registered_only(&self) -> bool {
        self.registered_only
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Whether `peer`'s messages are held to the unvetted rules: a source of
    /// identities is installed, the peer is not protected, and either no
    /// record names it or (with [`Self::set_registered_only`]) the registry
    /// does not list the machine its record names as registered.
    fn is_unvetted(&self, peer: EndpointId) -> bool {
        let identities = self.identities.read();
        let Some(source) = identities.as_ref() else {
            return false;
        };
        if self.is_protected(&peer) {
            return false;
        }
        match source.machine_did(peer) {
            None => true,
            Some(did) => self.registered_only() && !source.registry_standing(&did).is_registered(),
        }
    }

    /// Installs the source of machine identities. Until one is, standings
    /// are by endpoint id and every neighbour may deliver on every topic.
    pub fn set_identities(&self, identities: Arc<dyn PeerIdentities>) {
        *self.identities.write() = Some(identities);
    }

    fn machine_did(&self, peer: EndpointId) -> Option<String> {
        self.identities
            .read()
            .as_ref()
            .and_then(|i| i.machine_did(peer))
    }

    /// The standing `peer` is held to: its machine's when a record names it,
    /// its endpoint id's otherwise.
    fn subject(&self, peer: EndpointId) -> Subject {
        match self.machine_did(peer) {
            Some(did) => Subject::Machine(did),
            None => Subject::Endpoint(peer),
        }
    }

    /// Whether `peer` is banned: by its machine's standing, or by the
    /// standing its endpoint id earned before a record named it.
    fn is_banned(&self, peer: EndpointId, now: Instant) -> bool {
        let subject = self.subject(peer);
        let table = self.standing.lock();
        let banned = |k: &Subject| table.get(k).is_some_and(|s| s.banned(now));
        banned(&subject) || banned(&Subject::Endpoint(peer))
    }

    /// Replaces the budgets; counts already taken in the current window
    /// stand.
    pub fn set_limits(&self, limits: GossipLimits) {
        *self.limits.write() = limits;
    }

    /// The budgets in force.
    pub fn limits(&self) -> GossipLimits {
        *self.limits.read()
    }

    /// Exempts `peers` from budgets, penalties and bans.
    pub fn protect(&self, peers: &[EndpointId]) {
        self.protected.lock().extend(peers.iter().copied());
    }

    fn is_protected(&self, peer: &EndpointId) -> bool {
        self.protected.lock().contains(peer)
    }

    /// Runs `f` on the standing of `peer`, making room for it if needed.
    fn with_standing<T>(&self, peer: EndpointId, f: impl FnOnce(&mut Standing, Instant) -> T) -> T {
        let subject = self.subject(peer);
        let now = Instant::now();
        let window = self.limits.read().window;
        let mut table = self.standing.lock();
        if table.len() >= MAX_TRACKED && !table.contains_key(&subject) {
            // Penalised and banned neighbours are never forgotten, so their
            // standing lasts for the session.
            table.retain(|_, s| {
                s.reputation < 0
                    || s.banned(now)
                    || s.last_seen.is_some_and(|t| now.duration_since(t) < window)
            });
        }
        f(table.entry(subject).or_default(), now)
    }

    fn penalise(&self, peer: EndpointId) {
        if self.is_protected(&peer) {
            return;
        }
        let ban = self.limits.read().ban;
        self.with_standing(peer, |s, now| s.penalise(now, ban));
    }
}

impl GossipValidator for GossipGuard {
    fn admit(&self, topic: &str, from: EndpointId) -> Verdict {
        if self.is_protected(&from) {
            return Verdict::Accept;
        }
        let limits = self.limits();
        let class = Class::of(topic);
        if self.is_banned(from, Instant::now()) {
            tracing::warn!(peer = %from, "Ignoring gossip from banned peer");
            self.metrics.gossip_rejected_invalid.inc();
            return Verdict::Reject;
        }
        if self.is_unvetted(from) && (class == Class::Consensus || self.registered_only()) {
            // Endpoint announcements are what lets a record name a
            // neighbour, so they are heard from one no record names yet,
            // from a budget shared by all such neighbours and passed on only
            // once the announcement itself verifies (see `check`).
            let heard = topic == VALIDATORS_TOPIC
                && self.unidentified.lock().take(
                    Instant::now(),
                    limits.window,
                    limits.consensus_messages,
                );
            if !heard {
                tracing::debug!(
                    peer = %from,
                    topic,
                    reason = "no registered identity",
                    "Gossip from a neighbour no record names, or whose machine is not registered, shed"
                );
                if self.machine_did(from).is_some() || class == Class::General {
                    self.metrics.gossip_shed_unregistered.inc();
                } else {
                    self.metrics.gossip_shed_unidentified.inc();
                }
                return Verdict::Ignore;
            }
            return Verdict::Accept;
        }
        let verdict = self.with_standing(from, |s, now| {
            s.last_seen = Some(now);
            let within = match class {
                Class::Consensus => s
                    .consensus
                    .take(now, limits.window, limits.consensus_messages),
                Class::General => s.general.take(now, limits.window, limits.general_messages),
            };
            if within {
                Verdict::Accept
            } else {
                Verdict::Ignore
            }
        });
        match verdict {
            Verdict::Accept => {}
            Verdict::Reject => {
                tracing::warn!(peer = %from, "Ignoring gossip from banned peer");
                self.metrics.gossip_rejected_invalid.inc();
            }
            Verdict::Ignore => {
                tracing::debug!(peer = %from, topic, "Gossip over the neighbour's budget shed");
                self.metrics.gossip_shed_over_budget.inc();
            }
        }
        verdict
    }

    fn duplicate(&self, _from: EndpointId) {
        self.metrics.gossip_rejected_duplicate.inc();
    }

    fn check(&self, topic: &str, from: EndpointId, content: &[u8]) -> Verdict {
        let mut verdict = validate_gossip_message(content);
        if verdict == Verdict::Accept && topic == VALIDATORS_TOPIC && self.is_unvetted(from) {
            // Nothing a neighbour no record names sends is passed on unless
            // it is a validator's signed announcement.
            let vouched = NetworkMessage::from_bytes(content)
                .ok()
                .and_then(|m| match m.payload {
                    crate::message::MessagePayload::ValidatorEndpoint(bytes) => Some(bytes),
                    _ => None,
                })
                .is_some_and(|bytes| {
                    self.identities
                        .read()
                        .as_ref()
                        .is_some_and(|i| i.vouches_for_announcement(&bytes))
                });
            if !vouched {
                verdict = Verdict::Reject;
            }
        }
        match verdict {
            Verdict::Accept => {
                if !self.is_protected(&from) {
                    self.with_standing(from, |s, _| {
                        s.reputation = (s.reputation + 1).min(REPUTATION_MAX)
                    });
                }
                self.metrics.gossip_accepted.inc();
            }
            Verdict::Reject | Verdict::Ignore => {
                tracing::warn!(peer = %from, topic, "Gossip message rejected");
                if verdict == Verdict::Reject {
                    self.penalise(from);
                }
                self.metrics.gossip_rejected_invalid.inc();
            }
        }
        verdict
    }

    fn allows(&self, peer: EndpointId) -> bool {
        self.is_protected(&peer) || !self.is_banned(peer, Instant::now())
    }

    fn score(&self, peer: EndpointId) -> i32 {
        if self.is_protected(&peer) {
            return REPUTATION_MAX;
        }
        let subject = self.subject(peer);
        self.standing
            .lock()
            .get(&subject)
            .map_or(0, |s| s.reputation)
    }

    fn verdict(&self, from: EndpointId, verdict: Verdict) {
        if verdict == Verdict::Reject {
            self.penalise(from);
            self.metrics.gossip_rejected_invalid.inc();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::MessagePayload;

    fn peer(n: u8) -> EndpointId {
        iroh::SecretKey::from_bytes(&[n; 32]).public()
    }

    const LIMITS: GossipLimits = GossipLimits {
        window: Duration::from_secs(10),
        consensus_messages: 50,
        general_messages: 100,
        ban: Duration::from_secs(300),
    };

    fn guard() -> GossipGuard {
        GossipGuard::new(NetworkMetrics::unregistered(), LIMITS)
    }

    const TXS: &str = "tenzro/transactions";
    const CERTS: &str = "tenzro/certificates";

    fn tx(n: u64) -> bytes::Bytes {
        NetworkMessage::new(MessagePayload::Custom {
            topic: TXS.to_string(),
            data: n.to_le_bytes().to_vec(),
        })
        .to_bytes()
        .unwrap()
    }

    /// Endpoint records by endpoint id, as a node's discovery store holds them.
    #[derive(Default)]
    struct Records(Mutex<HashMap<EndpointId, String>>);

    impl Records {
        fn name(&self, endpoint: EndpointId, did: &str) {
            self.0.lock().insert(endpoint, did.to_string());
        }
    }

    impl PeerIdentities for Records {
        fn machine_did(&self, endpoint: EndpointId) -> Option<String> {
            self.0.lock().get(&endpoint).cloned()
        }
    }

    /// A source that vouches for the announcements whose first byte is 1.
    struct Vouching;

    impl PeerIdentities for Vouching {
        fn machine_did(&self, _: EndpointId) -> Option<String> {
            None
        }

        fn vouches_for_announcement(&self, announcement: &[u8]) -> bool {
            announcement.first() == Some(&1)
        }
    }

    fn announcement(first: u8) -> bytes::Bytes {
        NetworkMessage::new(MessagePayload::ValidatorEndpoint(vec![first, 2, 3]))
            .to_bytes()
            .unwrap()
    }

    #[test]
    fn a_neighbour_no_record_names_is_heard_for_a_verified_announcement_and_nothing_else() {
        let g = guard();
        g.set_identities(Arc::new(Vouching));
        let stranger = peer(50);
        assert_eq!(g.admit(VALIDATORS_TOPIC, stranger), Verdict::Accept);
        assert_eq!(
            g.check(VALIDATORS_TOPIC, stranger, &announcement(1)),
            Verdict::Accept,
            "a verified announcement"
        );
        assert_eq!(
            g.check(VALIDATORS_TOPIC, stranger, &announcement(0)),
            Verdict::Reject,
            "an announcement no validator signed"
        );
        let other = NetworkMessage::new(MessagePayload::Custom {
            topic: VALIDATORS_TOPIC.to_string(),
            data: vec![1],
        })
        .to_bytes()
        .unwrap();
        assert_eq!(
            g.check(VALIDATORS_TOPIC, stranger, &other),
            Verdict::Reject,
            "anything else on the announcements topic"
        );
        for topic in CONSENSUS_TOPICS.iter().filter(|t| **t != VALIDATORS_TOPIC) {
            assert_eq!(g.admit(topic, stranger), Verdict::Ignore, "{topic}");
        }
    }

    #[test]
    fn announcements_from_neighbours_no_record_names_share_one_budget() {
        let g = guard();
        g.set_identities(Arc::new(Vouching));
        let mut heard = 0;
        for n in 0..(LIMITS.consensus_messages * 3) {
            let mut key = [60u8; 32];
            key[..8].copy_from_slice(&n.to_be_bytes());
            let fresh = iroh::SecretKey::from_bytes(&key).public();
            if g.admit(VALIDATORS_TOPIC, fresh) == Verdict::Accept {
                heard += 1;
            }
        }
        assert_eq!(
            heard, LIMITS.consensus_messages,
            "fresh keys do not multiply the budget"
        );
    }

    fn ban(g: &GossipGuard, p: EndpointId) {
        for _ in 0..(-BAN_THRESHOLD / PENALTY) {
            g.verdict(p, Verdict::Reject);
        }
    }

    #[test]
    fn a_neighbour_no_record_names_may_not_deliver_consensus_gossip() {
        let g = guard();
        let records = Arc::new(Records::default());
        g.set_identities(records.clone());
        let (named, stranger) = (peer(20), peer(21));
        records.name(named, "did:tenzro:machine:aa");
        assert_eq!(g.admit(CERTS, named), Verdict::Accept);
        assert_eq!(g.admit(CERTS, stranger), Verdict::Ignore, "no record");
        assert_eq!(g.score(stranger), 0, "dropped without blame");
        assert_eq!(
            g.admit(TXS, stranger),
            Verdict::Accept,
            "other topics stay open"
        );
    }

    #[test]
    fn a_flood_of_fresh_keys_delivers_no_consensus_gossip_and_costs_the_named_peer_nothing() {
        let g = guard();
        let records = Arc::new(Records::default());
        g.set_identities(records.clone());
        let validator = peer(40);
        records.name(validator, "did:tenzro:machine:ee");
        let mut admitted = 0;
        for n in 0..2_000u32 {
            let mut key = [41u8; 32];
            key[..4].copy_from_slice(&n.to_be_bytes());
            let fresh = iroh::SecretKey::from_bytes(&key).public();
            for topic in CONSENSUS_TOPICS.iter().filter(|t| **t != VALIDATORS_TOPIC) {
                if g.admit(topic, fresh) == Verdict::Accept {
                    admitted += 1;
                }
            }
        }
        assert_eq!(
            admitted, 0,
            "no fresh key delivers on a consensus topic but the announcements"
        );
        assert!(
            g.standing.lock().is_empty(),
            "the flood leaves no standing behind"
        );
        for _ in 0..LIMITS.consensus_messages {
            assert_eq!(g.admit(CERTS, validator), Verdict::Accept);
        }
    }

    #[test]
    fn a_protected_peer_needs_no_record_and_no_source_means_no_requirement() {
        let g = guard();
        assert_eq!(g.admit(CERTS, peer(22)), Verdict::Accept, "no source");
        g.set_identities(Arc::new(Records::default()));
        g.protect(&[peer(23)]);
        assert_eq!(g.admit(CERTS, peer(23)), Verdict::Accept);
        assert_eq!(g.admit(CERTS, peer(22)), Verdict::Ignore);
    }

    #[test]
    fn a_banned_machine_is_not_readmitted_under_a_new_endpoint_key() {
        let g = guard();
        let records = Arc::new(Records::default());
        g.set_identities(records.clone());
        let (first, second) = (peer(30), peer(31));
        records.name(first, "did:tenzro:machine:bb");
        ban(&g, first);
        assert!(!g.allows(first));
        assert_eq!(g.admit(TXS, first), Verdict::Reject);
        // The same machine returns on a fresh key, which its record names.
        records.name(second, "did:tenzro:machine:bb");
        assert!(!g.allows(second), "the ban follows the machine");
        assert_eq!(g.admit(TXS, second), Verdict::Reject);
        assert_eq!(g.admit(CERTS, second), Verdict::Reject);
        // Another machine is unaffected.
        records.name(peer(32), "did:tenzro:machine:cc");
        assert!(g.allows(peer(32)));
    }

    #[test]
    fn a_ban_earned_before_a_record_named_the_key_stands() {
        let g = guard();
        let records = Arc::new(Records::default());
        g.set_identities(records.clone());
        let p = peer(33);
        ban(&g, p);
        assert!(!g.allows(p));
        records.name(p, "did:tenzro:machine:dd");
        assert!(!g.allows(p), "naming the key does not lift its ban");
    }

    #[test]
    fn well_formed_messages_pass_and_malformed_ones_are_rejected() {
        let good = NetworkMessage::new(MessagePayload::Ping)
            .to_bytes()
            .unwrap();
        assert_eq!(validate_gossip_message(&good), Verdict::Accept);
        assert_eq!(validate_gossip_message(&[]), Verdict::Reject);
        assert_eq!(validate_gossip_message(b"not a message"), Verdict::Reject);
        let mut stale = NetworkMessage::new(MessagePayload::Ping);
        stale.timestamp -= 2 * 3_600_000;
        assert_eq!(
            validate_gossip_message(&stale.to_bytes().unwrap()),
            Verdict::Reject
        );
        assert_eq!(
            validate_gossip_message(&vec![0u8; MAX_GOSSIP_MESSAGE + 1]),
            Verdict::Reject
        );
    }

    #[test]
    fn repeated_invalid_messages_ban_the_neighbour_but_never_a_protected_one() {
        let g = guard();
        let (bad, trusted) = (peer(1), peer(2));
        g.protect(&[trusted]);
        for _ in 0..(-BAN_THRESHOLD / PENALTY) {
            assert_eq!(g.admit("t", bad), Verdict::Accept);
            assert_eq!(g.check("t", bad, b"junk"), Verdict::Reject);
            assert_eq!(g.check("t", trusted, b"junk"), Verdict::Reject);
        }
        assert_eq!(g.admit("t", bad), Verdict::Reject, "banned");
        assert_eq!(
            g.admit("t", trusted),
            Verdict::Accept,
            "protected peers are never banned"
        );
    }

    #[test]
    fn traffic_over_a_class_budget_is_shed_without_blame() {
        let g = guard();
        let p = peer(3);
        for _ in 0..LIMITS.general_messages {
            assert_eq!(g.admit(TXS, p), Verdict::Accept);
        }
        assert_eq!(g.admit(TXS, p), Verdict::Ignore);
        assert_eq!(g.score(p), 0, "shedding costs no reputation");
        for _ in 0..LIMITS.consensus_messages {
            assert_eq!(g.admit(CERTS, p), Verdict::Accept, "own budget");
        }
        assert_eq!(g.admit(CERTS, p), Verdict::Ignore);
    }

    /// An honest relay forwarding far more transactions than its budget,
    /// as an RPC node under load does, keeps its standing and its
    /// certificates; this walks the receive path (admit, then check) for
    /// every message.
    #[test]
    fn a_busy_transaction_relay_is_never_banned_and_keeps_its_certificates() {
        let g = guard();
        let relay = peer(10);
        let mut delivered = 0;
        for n in 0..20 * LIMITS.general_messages {
            if g.admit(TXS, relay) == Verdict::Accept {
                assert_eq!(g.check(TXS, relay, &tx(n)), Verdict::Accept);
                delivered += 1;
            }
        }
        assert_eq!(delivered, LIMITS.general_messages, "excess shed");
        assert!(g.allows(relay), "not banned");
        assert!(g.score(relay) > 0, "valid deliveries still count");
        let cert = NetworkMessage::new(MessagePayload::Certificate(vec![1, 2, 3]))
            .to_bytes()
            .unwrap();
        assert_eq!(g.admit(CERTS, relay), Verdict::Accept);
        assert_eq!(g.check(CERTS, relay, &cert), Verdict::Accept);
    }

    #[test]
    fn a_budget_refills_each_window_and_follows_new_limits() {
        let g = guard();
        let p = peer(11);
        g.set_limits(GossipLimits {
            window: Duration::from_millis(50),
            general_messages: 2,
            ..LIMITS
        });
        assert_eq!(g.admit(TXS, p), Verdict::Accept);
        assert_eq!(g.admit(TXS, p), Verdict::Accept);
        assert_eq!(g.admit(TXS, p), Verdict::Ignore);
        std::thread::sleep(Duration::from_millis(60));
        assert_eq!(g.admit(TXS, p), Verdict::Accept, "a new window");
    }

    #[test]
    fn every_consensus_topic_is_budgeted_apart() {
        for topic in CONSENSUS_TOPICS {
            assert_eq!(Class::of(topic), Class::Consensus);
        }
        for topic in [TXS, "tenzro/models", "tenzro/providers", "tenzro/sla"] {
            assert_eq!(Class::of(topic), Class::General);
        }
    }

    #[test]
    fn a_rejected_judged_message_costs_reputation() {
        let g = guard();
        let p = peer(4);
        for _ in 0..(-BAN_THRESHOLD / PENALTY) {
            g.verdict(p, Verdict::Reject);
        }
        assert_eq!(g.admit(TXS, p), Verdict::Reject);
        assert!(!g.allows(p));
    }

    #[test]
    fn scores_follow_what_a_neighbour_delivers() {
        let g = guard();
        let (good, bad, trusted) = (peer(5), peer(6), peer(7));
        g.protect(&[trusted]);
        let valid = NetworkMessage::new(MessagePayload::Ping)
            .to_bytes()
            .unwrap();
        for _ in 0..3 {
            g.check("t", good, &valid);
            g.check("t", bad, b"junk");
        }
        assert_eq!(g.score(good), 3);
        assert_eq!(g.score(bad), -3 * PENALTY);
        assert_eq!(g.score(trusted), REPUTATION_MAX);
        assert!(
            g.allows(good) && g.allows(bad),
            "not yet at the ban threshold"
        );
        g.verdict(good, Verdict::Accept);
        g.verdict(good, Verdict::Ignore);
        assert_eq!(
            g.score(good),
            3,
            "only rejections move a score outside check"
        );
    }

    #[test]
    fn a_penalised_neighbour_is_remembered_when_the_table_is_full() {
        let g = guard();
        let bad = peer(8);
        g.check("t", bad, b"junk");
        for n in 0..MAX_TRACKED as u32 {
            let mut key = [9u8; 32];
            key[..4].copy_from_slice(&n.to_be_bytes());
            g.with_standing(iroh::SecretKey::from_bytes(&key).public(), |_, _| ());
        }
        assert_eq!(g.score(bad), -PENALTY);
    }

    /// A transaction whose token operation is an approval of an approval of
    /// an approval, nested as deep as the message size allows, encoded as
    /// gossip. Each extra level costs four bytes on the wire.
    fn nested_approval_gossip(depth: usize) -> Vec<u8> {
        use tenzro_types::account_signature::{ClassicalProof, CompositeSignature};
        use tenzro_types::primitives::{Address, ChainId, Nonce};
        use tenzro_types::token_op::TokenOp;
        use tenzro_types::transaction::{SignedTransaction, Transaction, TransactionType};

        let burn = TokenOp::Burn {
            token_id: [0xA7; 32],
            amount: 1,
        };
        let leaf = bincode::serialize(&burn).unwrap();
        let once = bincode::serialize(&TokenOp::Approve {
            op: Box::new(burn.clone()),
        })
        .unwrap();
        let tag = &once[..once.len() - leaf.len()];
        let tx = Transaction::new(
            ChainId::from(1337u64),
            Address::new([1; 32]),
            Address::new([2; 32]),
            Nonce::from(0u64),
            TransactionType::Token { op: burn },
            21_000,
            1,
        );
        let signed = SignedTransaction::new(
            tx,
            vec![4; 64],
            CompositeSignature::classical(ClassicalProof::Raw {
                signature: vec![5; 64],
            }),
        );
        let flat = NetworkMessage::new(MessagePayload::Transaction(signed))
            .to_bytes()
            .unwrap();
        let at = flat
            .windows(leaf.len())
            .position(|w| w == leaf.as_slice())
            .unwrap();
        let mut out = flat[..at].to_vec();
        for _ in 0..depth {
            out.extend_from_slice(tag);
        }
        out.extend_from_slice(&flat[at..]);
        out
    }

    #[test]
    fn a_deeply_nested_approval_is_rejected_without_exhausting_the_stack() {
        let bytes = nested_approval_gossip((MAX_GOSSIP_MESSAGE - 4_096) / 4);
        assert!(bytes.len() <= MAX_GOSSIP_MESSAGE);
        // Received gossip is decoded on a runtime worker thread; give the
        // check the same 2 MiB stack a tokio worker has.
        let verdict = std::thread::Builder::new()
            .stack_size(2 << 20)
            .spawn(move || validate_gossip_message(&bytes))
            .unwrap()
            .join()
            .unwrap();
        assert_eq!(verdict, Verdict::Reject);
    }

    #[test]
    fn a_single_approval_still_decodes() {
        let bytes = nested_approval_gossip(1);
        assert!(NetworkMessage::from_bytes(&bytes).is_ok());
        assert!(NetworkMessage::from_bytes(&nested_approval_gossip(2)).is_err());
    }

    /// Records plus a registry: which named machines are registered/revoked.
    #[derive(Default)]
    struct Registered {
        names: Mutex<HashMap<EndpointId, String>>,
        standing: Mutex<HashMap<String, RegistryStanding>>,
    }

    impl PeerIdentities for Registered {
        fn machine_did(&self, endpoint: EndpointId) -> Option<String> {
            self.names.lock().get(&endpoint).cloned()
        }
        fn vouches_for_announcement(&self, announcement: &[u8]) -> bool {
            announcement.first() == Some(&1)
        }
        fn registry_standing(&self, did: &str) -> RegistryStanding {
            self.standing
                .lock()
                .get(did)
                .copied()
                .unwrap_or(RegistryStanding::Unregistered)
        }
    }

    #[test]
    fn registered_only_gossip_sheds_every_neighbour_without_a_registered_identity() {
        let g = guard();
        let r = Arc::new(Registered::default());
        g.set_identities(r.clone());
        let (registered, unregistered, revoked, stranger, boot) =
            (peer(60), peer(61), peer(62), peer(63), peer(64));
        for (p, did, st) in [
            (
                registered,
                "did:tenzro:machine:r",
                RegistryStanding::Registered,
            ),
            (
                unregistered,
                "did:tenzro:machine:u",
                RegistryStanding::Unregistered,
            ),
            (revoked, "did:tenzro:machine:x", RegistryStanding::Revoked),
        ] {
            r.names.lock().insert(p, did.to_string());
            r.standing.lock().insert(did.to_string(), st);
        }
        g.protect(&[boot]);

        // Off (today): the unregistered and the stranger deliver transactions.
        assert_eq!(g.admit(TXS, unregistered), Verdict::Accept);
        assert_eq!(g.admit(TXS, stranger), Verdict::Accept);

        g.set_registered_only(true);
        assert_eq!(g.admit(TXS, registered), Verdict::Accept);
        assert_eq!(g.admit(CERTS, registered), Verdict::Accept);
        assert_eq!(
            g.admit(TXS, boot),
            Verdict::Accept,
            "protected peers need no entry"
        );
        for (who, why) in [
            (unregistered, "named but not registered"),
            (revoked, "revoked"),
            (stranger, "no record"),
        ] {
            assert_eq!(g.admit(TXS, who), Verdict::Ignore, "{why}: transactions");
            assert_eq!(g.admit(CERTS, who), Verdict::Ignore, "{why}: consensus");
            assert_eq!(g.score(who), 0, "{why}: shed without blame");
        }
        assert!(g.metrics.gossip_shed_unregistered.get() >= 3);
    }

    #[test]
    fn registered_only_gossip_still_hears_a_verified_validator_announcement_from_anyone() {
        let g = guard();
        let r = Arc::new(Registered::default());
        g.set_identities(r.clone());
        g.set_registered_only(true);
        let stranger = peer(70);
        // Announcements are how records that name neighbours come to exist.
        assert_eq!(g.admit(VALIDATORS_TOPIC, stranger), Verdict::Accept);
        assert_eq!(
            g.check(VALIDATORS_TOPIC, stranger, &announcement(1)),
            Verdict::Accept
        );
        // Anything else on that topic from the same neighbour is rejected.
        assert_eq!(
            g.check(VALIDATORS_TOPIC, stranger, &announcement(9)),
            Verdict::Reject
        );
        assert_eq!(g.check(VALIDATORS_TOPIC, stranger, &tx(1)), Verdict::Reject);
    }
}
