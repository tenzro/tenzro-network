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
//! Where only registered neighbours are heard
//! ([`GossipGuard::set_registered_only`]), a neighbour whose record names a
//! machine that is not registered yet is still heard for the two
//! transactions that get it registered, on [`TRANSACTIONS_TOPIC`]: the
//! enrolment of an account's ML-DSA-65 key, and the registration of that
//! very machine paid by the account that sends it. Its messages there are
//! counted against its own general budget like a registered neighbour's;
//! of those, [`REGISTRATIONS_PER_MACHINE`] per window are looked at further,
//! and one is passed on only when its sender can pay its largest fee
//! ([`PeerIdentities::can_pay`]), the key it carries names its sender and
//! its P-256 signature verifies. A record names a machine by a key alone, so
//! such machines cost nothing to make: the signatures verified for all of
//! them together are held to one general budget per window, and what passes
//! to one more, so many unregistered machines put no more into the network
//! than one registered neighbour may. The guard tracks no more neighbours
//! for them than it has room for. Everything else from such a neighbour is
//! dropped without blame.
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
use tenzro_crypto::composite::{SignatureContext, verify_classical_component};
use tenzro_iroh::EndpointId;
use tenzro_iroh::gossip::{GossipValidator, MAX_GOSSIP_MESSAGE, Verdict};
use tenzro_onboarding_types::onboarding::Standing as RegistryStanding;
use tenzro_types::account_signature::AccountKeysOp;
use tenzro_types::constants::BASE_TRANSACTION_GAS;
use tenzro_types::transaction::{SignedTransaction, Transaction, TransactionType};

use crate::message::{MessagePayload, NetworkMessage};
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
///
/// Not a governed parameter: it bounds the memory of this node's own table
/// of neighbour standings, and no other node, block or vote depends on its
/// value. A node that tracked more or fewer would judge the same messages
/// the same way; it would only forget an idle neighbour's standing sooner
/// or later.
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

/// The topic transactions travel on.
pub const TRANSACTIONS_TOPIC: &str = "tenzro/transactions";

/// Transactions of its own registration a machine that is not registered
/// yet has looked at per window: the key enrolment, the identity
/// registration, and a retry of each.
///
/// Node-local, not a governed parameter: it bounds this node's own work, how
/// many of one such machine's transactions it decodes as a registration and
/// checks a signature for in a window. No other node, block or vote depends
/// on its value; a node looking at more or fewer passes on the same
/// registrations, only sooner or later. What the network forwards from all
/// such machines is bounded by the governed general budget (the shared
/// acceptance and signature budgets draw on it).
pub const REGISTRATIONS_PER_MACHINE: u64 = 4;

/// Whether `tx` is what the machine `machine` sends to get registered: the
/// enrolment of an account's ML-DSA-65 key, or the registration of `machine`
/// itself with the sending account as its wallet. Nothing in a key enrolment
/// names a machine.
fn registers(tx: &Transaction, machine: &str) -> bool {
    match &tx.tx_type {
        TransactionType::AccountKeys {
            op: AccountKeysOp::EnrollPqKey { .. },
        } => true,
        TransactionType::RegisterIdentity {
            did,
            wallet_address,
            ..
        } => did == machine && *wallet_address == tx.from,
        _ => false,
    }
}

/// Whether the P-256 key `tx` carries names its sender and its P-256
/// signature over the transaction verifies. The ML-DSA-65 leg is checked
/// against chain state by the pool.
fn signed_by_sender(tx: &SignedTransaction) -> bool {
    tenzro_crypto::controls_account(&tx.public_key, tx.transaction.from.as_bytes())
        && tx.signature.has_classical_leg()
        && verify_classical_component(
            &tx.public_key,
            SignatureContext::Transaction,
            tx.transaction.hash().as_bytes(),
            &tx.signature.classical,
        )
        .is_ok()
}

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

    /// Whether `endpoint` may be a gossip neighbour of this node at all,
    /// whichever side dialled. An isolated validator keeps only its boot
    /// list and the validators' machines; the default keeps every peer.
    fn may_neighbour(&self, _endpoint: EndpointId) -> bool {
        true
    }

    /// Whether the sender of `tx` pays for it as the pool would require
    /// ([`covers_fee`], with the least gas price the pool admits `tx` at and
    /// the sender's balance). Asked for the registration transactions of a
    /// machine that is not registered yet, which are passed on only when
    /// paid for. The default knows no balance and no price, so no such
    /// transaction is passed on.
    fn can_pay(&self, _tx: &SignedTransaction) -> bool {
        false
    }
}

/// Whether a sender holding `balance` pays for `tx` where the pool admits
/// no gas price under `floor`: `tx` is priced at `floor` or above, allows at
/// least the base gas of a transaction, and `balance` covers its gas limit
/// at its gas price. A pool with no floor cannot price a transaction yet
/// (it has not read the base fee), so nothing is paid for there.
pub fn covers_fee(tx: &Transaction, floor: u64, balance: u128) -> bool {
    floor > 0
        && tx.gas_limit >= BASE_TRANSACTION_GAS
        && tx.gas_price >= floor
        && balance >= u128::from(tx.gas_limit).saturating_mul(u128::from(tx.gas_price))
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
    /// Transactions of its own registration, while its machine is not
    /// registered.
    registrations: Budget,
    /// The standing was last used for a machine that is not registered. It
    /// is cleared by every use for a registered one.
    unregistered: bool,
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
    /// Registration transactions taken from neighbours whose machine is not
    /// registered yet, across all of them.
    registrations: Mutex<Budget>,
    /// Signatures verified for neighbours whose machine is not registered
    /// yet, across all of them.
    verifications: Mutex<Budget>,
    limits: RwLock<GossipLimits>,
    protected: Mutex<HashSet<EndpointId>>,
    /// Whether a neighbour must have a registered identity to deliver
    /// anything but a verified validator announcement.
    registered_only: std::sync::atomic::AtomicBool,
    /// How far a test has moved the guard's clock on, in place of sleeping.
    #[cfg(test)]
    clock_skew: Mutex<Duration>,
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
            registrations: Mutex::new(Budget::default()),
            verifications: Mutex::new(Budget::default()),
            limits: RwLock::new(limits),
            protected: Mutex::new(HashSet::new()),
            registered_only: std::sync::atomic::AtomicBool::new(false),
            #[cfg(test)]
            clock_skew: Mutex::new(Duration::ZERO),
            metrics,
        }
    }

    /// The time the guard judges windows and bans by: the real clock, which a
    /// test moves forward with [`Self::advance`] instead of sleeping.
    fn now(&self) -> Instant {
        #[cfg(test)]
        {
            Instant::now() + *self.clock_skew.lock()
        }
        #[cfg(not(test))]
        {
            Instant::now()
        }
    }

    /// Moves the guard's clock on by `by`.
    #[cfg(test)]
    fn advance(&self, by: Duration) {
        *self.clock_skew.lock() += by;
    }

    /// Whether a neighbour must have a registered identity (the registry the
    /// installed [`PeerIdentities`] reads) to deliver anything on any topic.
    /// A neighbour that has none may still deliver a validator's verified
    /// endpoint announcement, from the budget all such neighbours share:
    /// that is how a node learns the records that name the others. A
    /// neighbour whose record names a machine that is not registered yet may
    /// also deliver the two transactions that get it registered (see the
    /// module documentation). Node-local policy; off until the node turns it
    /// on.
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

    /// The machine `peer` is heard for the registration of, where only
    /// registered neighbours are heard: the machine its record names, when
    /// the registry holds that machine as not registered yet. Never a
    /// machine the registry revoked, and never a neighbour no record names.
    fn registering_machine(&self, peer: EndpointId) -> Option<String> {
        if !self.registered_only() || self.is_protected(&peer) {
            return None;
        }
        let identities = self.identities.read();
        let source = identities.as_ref()?;
        source
            .machine_did(peer)
            .filter(|did| source.registry_standing(did) == RegistryStanding::Unregistered)
    }

    /// Whether `content`, delivered on the transactions topic by `from`
    /// whose machine `machine` is not registered yet, is passed on: a
    /// transaction of that machine's registration ([`registers`]), within
    /// the machine's [`REGISTRATIONS_PER_MACHINE`], from an account that can
    /// pay its largest fee, signed by its sender ([`signed_by_sender`]), and
    /// within the budget all such machines share. A signature is checked
    /// only inside the machine's number and inside the number of signatures
    /// verified for all such machines in the window.
    fn hears_registration(&self, from: EndpointId, machine: &str, content: &[u8]) -> bool {
        let shed = |why: &str| {
            tracing::debug!(
                peer = %from,
                why,
                "Transaction from a neighbour whose machine is not registered shed"
            );
            false
        };
        let Ok(MessagePayload::Transaction(tx)) =
            NetworkMessage::from_bytes(content).map(|m| m.payload)
        else {
            return shed("not a transaction");
        };
        if !registers(&tx.transaction, machine) {
            return shed("not a key enrolment or this machine's registration");
        }
        let limits = self.limits();
        let within = self.with_standing_if_room(from, |s, now| {
            s.last_seen = Some(now);
            s.registrations
                .take(now, limits.window, REGISTRATIONS_PER_MACHINE)
        });
        match within {
            Some(true) => {}
            Some(false) => return shed("over the machine's registrations for the window"),
            None => return shed("no room to track another neighbour"),
        }
        // The source reads the pool and chain state: asked with no lock of
        // the guard held.
        let source = self.identities.read().clone();
        if !source.is_some_and(|i| i.can_pay(&tx)) {
            return shed("its sender cannot pay its fee");
        }
        if !self
            .verifications
            .lock()
            .take(self.now(), limits.window, limits.general_messages)
        {
            return shed("over the signatures verified for all unregistered machines");
        }
        if !signed_by_sender(&tx) {
            return shed("not signed by its sender");
        }
        if !self
            .registrations
            .lock()
            .take(self.now(), limits.window, limits.general_messages)
        {
            return shed("over the registrations all unregistered machines share");
        }
        true
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
        let now = self.now();
        let mut table = self.standing.lock();
        let subject = self.make_room(&mut table, peer, now);
        let standing = table.entry(subject).or_default();
        standing.unregistered = false;
        f(standing, now)
    }

    /// Runs `f` on the standing of `peer` by the rule for its machine: one
    /// that is not registered is tracked only while there is room
    /// ([`Self::with_standing_if_room`]), any other always.
    fn on_standing(&self, peer: EndpointId, f: impl FnOnce(&mut Standing, Instant)) {
        if self.registering_machine(peer).is_some() {
            self.with_standing_if_room(peer, f);
        } else {
            self.with_standing(peer, f);
        }
    }

    /// [`Self::with_standing`] for a neighbour whose machine is not
    /// registered yet: `None`, tracking nothing, when the table is full and
    /// holds no standing that can be forgotten.
    fn with_standing_if_room<T>(
        &self,
        peer: EndpointId,
        f: impl FnOnce(&mut Standing, Instant) -> T,
    ) -> Option<T> {
        let now = self.now();
        let mut table = self.standing.lock();
        let subject = self.make_room(&mut table, peer, now);
        if table.len() >= MAX_TRACKED && !table.contains_key(&subject) {
            return None;
        }
        let standing = table.entry(subject).or_default();
        standing.unregistered = true;
        Some(f(standing, now))
    }

    /// Whom `peer`'s standing belongs to, after forgetting the idle
    /// standings of a full table that does not hold it yet.
    fn make_room(
        &self,
        table: &mut HashMap<Subject, Standing>,
        peer: EndpointId,
        now: Instant,
    ) -> Subject {
        let subject = self.subject(peer);
        if table.len() >= MAX_TRACKED && !table.contains_key(&subject) {
            let window = self.limits.read().window;
            // Penalised and banned neighbours are never forgotten, so their
            // standing lasts for the session. A machine that is not
            // registered costs nothing to make again, so its standing,
            // whatever it holds, lasts a window and cannot fill the table
            // for good.
            table.retain(|_, s| {
                let fresh = s.last_seen.is_some_and(|t| now.duration_since(t) < window);
                fresh || (!s.unregistered && (s.reputation < 0 || s.banned(now)))
            });
        }
        subject
    }

    fn penalise(&self, peer: EndpointId) {
        if self.is_protected(&peer) {
            return;
        }
        let ban = self.limits.read().ban;
        self.on_standing(peer, |s, now| {
            // Blame on a machine that is not registered is kept like the
            // rest of its standing: while there is room, and for a window.
            if s.unregistered {
                s.last_seen = Some(now);
            }
            s.penalise(now, ban)
        });
    }
}

impl GossipValidator for GossipGuard {
    fn admit(&self, topic: &str, from: EndpointId) -> Verdict {
        if self.is_protected(&from) {
            return Verdict::Accept;
        }
        let limits = self.limits();
        let class = Class::of(topic);
        if self.is_banned(from, self.now()) {
            tracing::warn!(peer = %from, "Ignoring gossip from banned peer");
            self.metrics.gossip_rejected_invalid.inc();
            return Verdict::Reject;
        }
        // A machine that is not registered yet is heard on the transactions
        // topic within its own budget; `check` keeps only its registration.
        let registering = topic == TRANSACTIONS_TOPIC && self.registering_machine(from).is_some();
        if !registering
            && self.is_unvetted(from)
            && (class == Class::Consensus || self.registered_only())
        {
            // Endpoint announcements are what lets a record name a
            // neighbour, so they are heard from one no record names yet,
            // from a budget shared by all such neighbours and passed on only
            // once the announcement itself verifies (see `check`).
            let heard = topic == VALIDATORS_TOPIC
                && self.unidentified.lock().take(
                    self.now(),
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
        let charge = |s: &mut Standing, now: Instant| {
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
        };
        let verdict = if registering {
            // No standing is tracked for a machine that is not registered
            // yet when there is no room for one.
            let Some(verdict) = self.with_standing_if_room(from, charge) else {
                tracing::debug!(
                    peer = %from,
                    topic,
                    "No room to track a neighbour whose machine is not registered; shed"
                );
                self.metrics.gossip_shed_unregistered.inc();
                return Verdict::Ignore;
            };
            verdict
        } else {
            self.with_standing(from, charge)
        };
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

    fn duplicate(&self, topic: &str, _from: EndpointId, bytes: usize) {
        self.metrics.duplicate(topic, bytes);
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
        if verdict == Verdict::Accept
            && topic == TRANSACTIONS_TOPIC
            && let Some(machine) = self.registering_machine(from)
            && !self.hears_registration(from, &machine, content)
        {
            self.metrics.gossip_shed_unregistered.inc();
            return Verdict::Ignore;
        }
        match verdict {
            Verdict::Accept => {
                if !self.is_protected(&from) {
                    self.on_standing(from, |s, _| {
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
        if self.is_protected(&peer) {
            return true;
        }
        !self.is_banned(peer, self.now())
            && self
                .identities
                .read()
                .as_ref()
                .is_none_or(|i| i.may_neighbour(peer))
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

    /// The source of an isolated node: it keeps as neighbours only the
    /// endpoints it names.
    struct Isolated(Records);

    impl PeerIdentities for Isolated {
        fn machine_did(&self, endpoint: EndpointId) -> Option<String> {
            self.0.machine_did(endpoint)
        }

        fn may_neighbour(&self, endpoint: EndpointId) -> bool {
            self.0.machine_did(endpoint).is_some()
        }
    }

    #[test]
    fn an_isolated_node_keeps_no_gossip_neighbour_outside_its_allowed_peers() {
        let g = guard();
        let (allowed, other, protected) = (peer(70), peer(71), peer(72));
        assert!(g.allows(other), "no source installed: every peer");
        let records = Records::default();
        records.name(allowed, "did:tenzro:machine:boot");
        g.set_identities(Arc::new(Isolated(records)));
        g.protect(&[protected]);
        assert!(g.allows(allowed), "a boot machine or a validator");
        assert!(g.allows(protected), "a protected endpoint");
        assert!(
            !g.allows(other),
            "a peer off the boot list and outside the set"
        );
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
        let window = Duration::from_secs(3600);
        g.set_limits(GossipLimits {
            window,
            general_messages: 2,
            ..LIMITS
        });
        assert_eq!(g.admit(TXS, p), Verdict::Accept);
        assert_eq!(g.admit(TXS, p), Verdict::Accept);
        assert_eq!(g.admit(TXS, p), Verdict::Ignore);
        g.advance(window + Duration::from_secs(1));
        assert_eq!(g.admit(TXS, p), Verdict::Accept, "a new window");
        assert_eq!(g.admit(TXS, p), Verdict::Accept);
        assert_eq!(g.admit(TXS, p), Verdict::Ignore);
        g.set_limits(GossipLimits {
            window,
            general_messages: 3,
            ..LIMITS
        });
        assert_eq!(g.admit(TXS, p), Verdict::Accept, "the new allowance");
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
    /// An account holds what `balances` says, and more than any fee when it
    /// says nothing.
    #[derive(Default)]
    struct Registered {
        names: Mutex<HashMap<EndpointId, String>>,
        standing: Mutex<HashMap<String, RegistryStanding>>,
        balances: Mutex<HashMap<Address, u128>>,
        /// The least gas price the pool admits; 1 when not set.
        floor: Mutex<Option<u64>>,
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
        fn can_pay(&self, tx: &SignedTransaction) -> bool {
            let balance = self
                .balances
                .lock()
                .get(&tx.transaction.from)
                .copied()
                .unwrap_or(u128::MAX);
            covers_fee(&tx.transaction, self.floor.lock().unwrap_or(1), balance)
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
        for (who, why) in [(revoked, "revoked"), (stranger, "no record")] {
            assert_eq!(g.admit(TXS, who), Verdict::Ignore, "{why}: transactions");
            assert_eq!(g.admit(CERTS, who), Verdict::Ignore, "{why}: consensus");
            assert_eq!(g.score(who), 0, "{why}: shed without blame");
        }
        // A named machine that is not registered yet is counted on the
        // transactions topic, and a transaction that is not part of its
        // registration is shed there without blame.
        assert_eq!(g.admit(TXS, unregistered), Verdict::Accept);
        assert_eq!(g.check(TXS, unregistered, &tx(1)), Verdict::Ignore);
        assert_eq!(g.check(TXS, unregistered, &transfer()), Verdict::Ignore);
        assert_eq!(g.admit(CERTS, unregistered), Verdict::Ignore);
        for topic in ["tenzro/providers", "tenzro/status", "tenzro/blocks"] {
            assert_eq!(g.admit(topic, unregistered), Verdict::Ignore, "{topic}");
        }
        assert_eq!(g.score(unregistered), 0, "shed without blame");
        assert!(g.metrics.gossip_shed_unregistered.get() >= 3);
    }

    use tenzro_crypto::HybridSigner;
    use tenzro_crypto::composite::testing::TestHybridSigner;
    use tenzro_types::primitives::Address;

    /// The account of the test key `seed`.
    fn account(seed: u8) -> Address {
        let key = TestHybridSigner::p256_only(seed);
        Address::new(tenzro_crypto::composite::account_slot(
            &key.public_key().p256,
        ))
    }

    /// `tx_type` at `nonce` sent from the account of the test key `seed`
    /// and signed by it.
    fn signed_tx(seed: u8, nonce: u64, tx_type: TransactionType) -> SignedTransaction {
        signed_at(seed, nonce, BASE_TRANSACTION_GAS, 1, tx_type)
    }

    /// [`signed_tx`] with a gas limit and a gas price.
    fn signed_at(
        seed: u8,
        nonce: u64,
        gas_limit: u64,
        gas_price: u64,
        tx_type: TransactionType,
    ) -> SignedTransaction {
        let key = TestHybridSigner::p256_only(seed);
        let transaction = Transaction::new(
            7u64.into(),
            account(seed),
            Address::zero(),
            nonce.into(),
            tx_type,
            gas_limit,
            gas_price,
        );
        let signature = key
            .sign(SignatureContext::Transaction, transaction.hash().as_bytes())
            .unwrap();
        SignedTransaction::new(transaction, key.public_key().p256.clone(), signature)
    }

    fn gossip(tx: SignedTransaction) -> bytes::Bytes {
        NetworkMessage::new(MessagePayload::Transaction(tx))
            .to_bytes()
            .unwrap()
    }

    fn transfer() -> bytes::Bytes {
        gossip(signed_tx(1, 0, TransactionType::Transfer { amount: 1 }))
    }

    fn enrol() -> TransactionType {
        TransactionType::AccountKeys {
            op: AccountKeysOp::EnrollPqKey {
                ml_dsa_public_key: vec![1; 8],
                possession: vec![2; 8],
            },
        }
    }

    /// A key enrolment of the account of the test key `seed`, signed by it.
    fn enrolment(seed: u8, nonce: u64) -> bytes::Bytes {
        gossip(signed_tx(seed, nonce, enrol()))
    }

    /// The registration of `did` with `wallet` as its wallet.
    fn register(did: &str, wallet: Address) -> TransactionType {
        TransactionType::RegisterIdentity {
            did: did.to_string(),
            identity_type: "machine".to_string(),
            display_name: String::new(),
            controller_pubkey: vec![4; 65],
            key_type: "P-256".to_string(),
            wallet_id: String::new(),
            wallet_address: wallet,
            pq_verifying_key: Vec::new(),
            metadata: Default::default(),
            proof: tenzro_types::identity::RegistrationProof::Hardware {
                signature: Default::default(),
            },
        }
    }

    const NEW: &str = "did:tenzro:machine:new";

    /// A guard hearing registered neighbours only, with a source naming
    /// two machines that are not registered yet, a revoked one, a
    /// registered one, and leaving the fifth endpoint unnamed.
    fn registered_only_guard() -> (GossipGuard, [EndpointId; 5]) {
        let g = guard();
        let r = Arc::new(Registered::default());
        let peers = [peer(80), peer(81), peer(82), peer(83), peer(84)];
        for (p, did, st) in [
            (peers[0], NEW, RegistryStanding::Unregistered),
            (
                peers[1],
                "did:tenzro:machine:new2",
                RegistryStanding::Unregistered,
            ),
            (
                peers[2],
                "did:tenzro:machine:gone",
                RegistryStanding::Revoked,
            ),
            (
                peers[3],
                "did:tenzro:machine:old",
                RegistryStanding::Registered,
            ),
        ] {
            r.names.lock().insert(p, did.to_string());
            r.standing.lock().insert(did.to_string(), st);
        }
        g.set_identities(r);
        g.set_registered_only(true);
        (g, peers)
    }

    #[test]
    fn only_a_key_enrolment_and_the_machines_own_registration_register_it() {
        let from = account(1);
        let tx = |tx_type| signed_tx(1, 0, tx_type).transaction;
        assert!(registers(&tx(enrol()), NEW));
        assert!(registers(&tx(register(NEW, from)), NEW));
        assert!(
            !registers(&tx(register("did:tenzro:machine:other", from)), NEW),
            "another machine's registration"
        );
        assert!(
            !registers(&tx(register(NEW, account(2))), NEW),
            "a registration naming a wallet that is not its sender"
        );
        assert!(
            !registers(
                &tx(TransactionType::AccountKeys {
                    op: AccountKeysOp::RequirePqLeg {},
                }),
                NEW
            ),
            "an account key operation that is not the enrolment"
        );
        assert!(!registers(
            &tx(TransactionType::Transfer { amount: 1 }),
            NEW
        ));
    }

    #[test]
    fn a_machine_not_yet_registered_is_heard_for_its_registration_only() {
        let (g, [new, _, revoked, _, stranger]) = registered_only_guard();
        assert_eq!(g.admit(TXS, new), Verdict::Accept);
        assert_eq!(
            g.check(TXS, new, &enrolment(1, 0)),
            Verdict::Accept,
            "a key enrolment its sender signed"
        );
        assert_eq!(
            g.check(
                TXS,
                new,
                &gossip(signed_tx(1, 1, register(NEW, account(1))))
            ),
            Verdict::Accept,
            "its own registration"
        );
        assert_eq!(g.check(TXS, new, &transfer()), Verdict::Ignore);
        // A revoked machine and a neighbour no record names stay unheard.
        for who in [revoked, stranger] {
            assert_eq!(g.admit(TXS, who), Verdict::Ignore);
        }
        // With the rule off the check does not single registrations out.
        g.set_registered_only(false);
        assert_eq!(g.check(TXS, new, &transfer()), Verdict::Accept);
    }

    #[test]
    fn someone_elses_registration_from_a_registering_neighbour_is_ignored() {
        let (g, [new, ..]) = registered_only_guard();
        let other = gossip(signed_tx(
            1,
            0,
            register("did:tenzro:machine:new2", account(1)),
        ));
        assert_eq!(g.check(TXS, new, &other), Verdict::Ignore);
        assert_eq!(g.score(new), 0, "without blame");
        assert_eq!(g.metrics.gossip_accepted.get(), 0);
    }

    #[test]
    fn a_registration_its_sender_did_not_sign_is_ignored() {
        let (g, [new, ..]) = registered_only_guard();
        // Signed by a key that does not name the sender.
        let mut wrong_key = signed_tx(1, 0, enrol());
        wrong_key.public_key = TestHybridSigner::p256_only(2).public_key().p256.clone();
        assert_eq!(g.check(TXS, new, &gossip(wrong_key)), Verdict::Ignore);
        // The sender's key, over another transaction.
        let mut altered = signed_tx(1, 0, enrol());
        altered.transaction.gas_limit += 1;
        assert_eq!(g.check(TXS, new, &gossip(altered)), Verdict::Ignore);
        // No signature at all.
        let unsigned = SignedTransaction::new(
            signed_tx(1, 0, enrol()).transaction,
            TestHybridSigner::p256_only(1).public_key().p256.clone(),
            Default::default(),
        );
        assert_eq!(g.check(TXS, new, &gossip(unsigned)), Verdict::Ignore);
        assert_eq!(g.metrics.gossip_accepted.get(), 0, "none is passed on");
        assert_eq!(g.score(new), 0);
    }

    #[test]
    fn what_is_not_a_transaction_from_a_registering_neighbour_is_ignored() {
        let (g, [new, ..]) = registered_only_guard();
        for payload in [
            MessagePayload::Custom {
                topic: TXS.to_string(),
                data: vec![1, 2, 3],
            },
            MessagePayload::TransactionResponse(Some(signed_tx(1, 0, enrol()))),
            MessagePayload::TransactionResponse(None),
            MessagePayload::TransactionRequest(tenzro_types::primitives::Hash::zero()),
            MessagePayload::Ping,
        ] {
            let bytes = NetworkMessage::new(payload).to_bytes().unwrap();
            assert_eq!(g.check(TXS, new, &bytes), Verdict::Ignore);
        }
        assert_eq!(g.metrics.gossip_accepted.get(), 0);
    }

    /// Content the guard ignores is not recorded as seen by the gossip
    /// layer, so another neighbour's copy is still heard; a neighbour
    /// replaying it gets it judged again only while its budget lasts, since
    /// the layer charges every delivery in `admit` before `check` runs.
    #[test]
    fn replays_of_ignored_content_are_judged_only_within_the_neighbours_budget() {
        let (g, [new, ..]) = registered_only_guard();
        let ignored = NetworkMessage::new(MessagePayload::Ping)
            .to_bytes()
            .unwrap();
        let mut judged = 0;
        for _ in 0..LIMITS.general_messages * 4 {
            // The layer's order: admit, then check (gossip.rs on_message).
            if g.admit(TXS, new) == Verdict::Accept {
                assert_eq!(g.check(TXS, new, &ignored), Verdict::Ignore);
                judged += 1;
            }
        }
        assert_eq!(
            judged, LIMITS.general_messages,
            "replays judged past the budget"
        );
    }

    #[test]
    fn a_machine_not_yet_registered_stays_within_a_neighbours_budget() {
        let (g, [new, ..]) = registered_only_guard();
        for _ in 0..LIMITS.general_messages {
            assert_eq!(g.admit(TXS, new), Verdict::Accept);
        }
        assert_eq!(g.admit(TXS, new), Verdict::Ignore, "over its own budget");
    }

    #[test]
    fn a_machine_has_a_few_registration_transactions_looked_at_per_window() {
        let (g, [new, other, ..]) = registered_only_guard();
        for nonce in 0..REGISTRATIONS_PER_MACHINE {
            assert_eq!(g.check(TXS, new, &enrolment(1, nonce)), Verdict::Accept);
        }
        assert_eq!(
            g.check(TXS, new, &enrolment(1, REGISTRATIONS_PER_MACHINE)),
            Verdict::Ignore,
            "over the machine's number"
        );
        // Unsigned ones count against the number as well, so no more
        // signatures are checked than it allows.
        let mut unsigned = signed_tx(2, 0, enrol());
        unsigned.signature = Default::default();
        let unsigned = gossip(unsigned);
        for _ in 0..REGISTRATIONS_PER_MACHINE {
            assert_eq!(g.check(TXS, other, &unsigned), Verdict::Ignore);
        }
        assert_eq!(
            g.check(TXS, other, &enrolment(2, 1)),
            Verdict::Ignore,
            "the number is spent"
        );
        // What is not a registration does not count against it.
        let (g, [new, ..]) = registered_only_guard();
        for _ in 0..10 {
            assert_eq!(g.check(TXS, new, &transfer()), Verdict::Ignore);
        }
        assert_eq!(g.check(TXS, new, &enrolment(1, 0)), Verdict::Accept);
    }

    #[test]
    fn the_registration_budgets_start_again_with_the_window() {
        let window = Duration::from_secs(3600);
        let g = GossipGuard::new(
            NetworkMetrics::unregistered(),
            GossipLimits {
                window,
                general_messages: REGISTRATIONS_PER_MACHINE,
                ..LIMITS
            },
        );
        let r = Arc::new(Registered::default());
        let (new, other) = (peer(90), peer(91));
        r.names.lock().insert(new, NEW.to_string());
        r.names
            .lock()
            .insert(other, "did:tenzro:machine:new2".to_string());
        g.set_identities(r);
        g.set_registered_only(true);

        for nonce in 0..REGISTRATIONS_PER_MACHINE {
            assert_eq!(g.check(TXS, new, &enrolment(1, nonce)), Verdict::Accept);
        }
        assert_eq!(g.check(TXS, new, &enrolment(1, 9)), Verdict::Ignore);
        assert_eq!(
            g.check(TXS, other, &enrolment(2, 0)),
            Verdict::Ignore,
            "the shared budget is spent too"
        );
        g.advance(window + Duration::from_secs(1));
        assert_eq!(g.check(TXS, new, &enrolment(1, 10)), Verdict::Accept);
        assert_eq!(g.check(TXS, other, &enrolment(2, 1)), Verdict::Accept);
    }

    /// A source naming `count` machines that are not registered yet.
    fn unregistered_machines(g: &GossipGuard, count: u8) -> Vec<EndpointId> {
        let r = Arc::new(Registered::default());
        let machines: Vec<EndpointId> = (100..100 + count).map(peer).collect();
        for (n, p) in machines.iter().enumerate() {
            r.names
                .lock()
                .insert(*p, format!("did:tenzro:machine:m{n}"));
        }
        g.set_identities(r);
        g.set_registered_only(true);
        machines
    }

    /// Many unregistered machines, each inside its own number, get no more
    /// registration transactions passed on in a window than one registered
    /// neighbour may send.
    #[test]
    fn many_unregistered_machines_together_pass_on_one_budget_in_a_window() {
        let g = guard();
        let machines = unregistered_machines(&g, 40);
        let mut passed_on = 0u64;
        for nonce in 0..REGISTRATIONS_PER_MACHINE {
            for (n, from) in machines.iter().enumerate() {
                assert_eq!(g.admit(TXS, *from), Verdict::Accept);
                if g.check(TXS, *from, &enrolment(n as u8, nonce)) == Verdict::Accept {
                    passed_on += 1;
                }
            }
        }
        assert_eq!(passed_on, LIMITS.general_messages);
        assert_eq!(g.metrics.gossip_accepted.get(), LIMITS.general_messages);
        assert!(machines.iter().all(|m| g.score(*m) >= 0), "none is blamed");
    }

    /// Machines that are not registered yet cost nothing to make. However
    /// many deliver, the signatures verified for them in a window stop at
    /// one general budget.
    #[test]
    fn signatures_verified_for_unregistered_machines_stop_at_one_budget() {
        let g = guard();
        let machines = unregistered_machines(&g, 60);
        // Every machine sends its full number of enrolments whose signature
        // does not verify.
        for nonce in 0..REGISTRATIONS_PER_MACHINE {
            for (n, from) in machines.iter().enumerate() {
                let mut forged = signed_tx(n as u8, nonce, enrol());
                forged.transaction.gas_limit += 1;
                assert_eq!(g.check(TXS, *from, &gossip(forged)), Verdict::Ignore);
            }
        }
        assert_eq!(g.verifications.lock().used, LIMITS.general_messages);
        assert_eq!(g.registrations.lock().used, 0, "none reached the budget");
        assert_eq!(g.metrics.gossip_accepted.get(), 0);
    }

    #[test]
    fn a_registration_from_an_account_that_cannot_pay_is_ignored() {
        let g = guard();
        let r = Arc::new(Registered::default());
        let new = peer(95);
        r.names.lock().insert(new, NEW.to_string());
        g.set_identities(r.clone());
        g.set_registered_only(true);
        let fee = 21_000u128;

        r.balances.lock().insert(account(1), fee - 1);
        assert_eq!(g.check(TXS, new, &enrolment(1, 0)), Verdict::Ignore);
        assert_eq!(g.metrics.gossip_accepted.get(), 0, "not passed on");
        assert_eq!(g.verifications.lock().used, 0, "no signature verified");
        assert_eq!(g.score(new), 0);

        r.balances.lock().insert(account(1), fee);
        assert_eq!(g.check(TXS, new, &enrolment(1, 1)), Verdict::Accept);
    }

    #[test]
    fn a_fee_is_covered_only_at_the_pools_price_with_gas_and_the_balance() {
        let tx = |limit, price| signed_at(1, 0, limit, price, enrol()).transaction;
        let base = BASE_TRANSACTION_GAS;
        assert!(covers_fee(&tx(base, 5), 5, u128::from(base) * 5));
        assert!(
            !covers_fee(&tx(base, 5), 5, u128::from(base) * 5 - 1),
            "balance"
        );
        assert!(!covers_fee(&tx(base, 4), 5, u128::MAX), "under the floor");
        assert!(!covers_fee(&tx(base, 0), 5, u128::MAX), "no price");
        assert!(!covers_fee(&tx(0, 5), 5, u128::MAX), "no gas");
        assert!(
            !covers_fee(&tx(base - 1, 5), 5, u128::MAX),
            "too little gas"
        );
        assert!(covers_fee(&tx(u64::MAX, u64::MAX), 5, u128::MAX));
        assert!(
            !covers_fee(&tx(base, 5), 0, u128::MAX),
            "a pool with no floor"
        );
        assert!(!covers_fee(&tx(base, 0), 0, u128::MAX));
    }

    /// A registration that costs nothing as sent, or less than the pool
    /// asks, is ignored before any signature is verified, even from an
    /// account that holds funds.
    #[test]
    fn a_registration_priced_or_limited_under_the_pools_terms_is_ignored() {
        let g = guard();
        let r = Arc::new(Registered::default());
        let new = peer(97);
        r.names.lock().insert(new, NEW.to_string());
        *r.floor.lock() = Some(5);
        g.set_identities(r.clone());
        g.set_registered_only(true);
        let base = BASE_TRANSACTION_GAS;
        for (limit, price, why) in [
            (base, 0, "no gas price"),
            (0, 5, "no gas limit"),
            (base, 4, "a price under the floor"),
        ] {
            let tx = gossip(signed_at(1, 0, limit, price, enrol()));
            assert_eq!(g.check(TXS, new, &tx), Verdict::Ignore, "{why}");
        }
        // An empty account pays for none of them either.
        r.balances.lock().insert(account(2), 0);
        let tx = gossip(signed_at(2, 0, base, 0, enrol()));
        assert_eq!(g.check(TXS, new, &tx), Verdict::Ignore);
        assert_eq!(g.verifications.lock().used, 0, "no signature verified");
        assert_eq!(g.metrics.gossip_accepted.get(), 0);

        // Priced at the floor, the same transaction is heard (from another
        // machine: this one's number for the window is spent).
        let other = peer(96);
        r.names
            .lock()
            .insert(other, "did:tenzro:machine:new2".to_string());
        let tx = gossip(signed_at(1, 0, base, 5, enrol()));
        assert_eq!(g.check(TXS, other, &tx), Verdict::Accept, "at the floor");
    }

    /// A node whose pool has no price floor yet (it has not read the base
    /// fee) passes on no registration, priced or not.
    #[test]
    fn where_the_pool_has_no_floor_no_registration_is_passed_on() {
        let g = guard();
        let r = Arc::new(Registered::default());
        let new = peer(94);
        r.names.lock().insert(new, NEW.to_string());
        *r.floor.lock() = Some(0);
        r.balances.lock().insert(account(2), 0);
        g.set_identities(r);
        g.set_registered_only(true);
        let base = BASE_TRANSACTION_GAS;
        let free = gossip(signed_at(2, 0, base, 0, enrol()));
        assert_eq!(
            g.check(TXS, new, &free),
            Verdict::Ignore,
            "an empty account"
        );
        assert_eq!(
            g.check(TXS, new, &enrolment(1, 0)),
            Verdict::Ignore,
            "a funded one"
        );
        assert_eq!(g.verifications.lock().used, 0);
        assert_eq!(g.metrics.gossip_accepted.get(), 0);
    }

    /// Blame set on a machine after it registered is blame on a registered
    /// neighbour: it is not forgotten with the standings of machines that
    /// are not registered.
    #[test]
    fn blame_after_registering_is_kept_as_a_registered_neighbours() {
        let window = Duration::from_secs(3600);
        let g = GossipGuard::new(
            NetworkMetrics::unregistered(),
            GossipLimits { window, ..LIMITS },
        );
        let r = Arc::new(Registered::default());
        let (machine, later) = (peer(92), peer(93));
        r.names.lock().insert(machine, NEW.to_string());
        r.names
            .lock()
            .insert(later, "did:tenzro:machine:new2".to_string());
        g.set_identities(r.clone());
        g.set_registered_only(true);

        // Heard for its registration while it is not registered.
        assert_eq!(g.admit(TXS, machine), Verdict::Accept);
        assert_eq!(g.check(TXS, machine, &enrolment(1, 0)), Verdict::Accept);
        let subject = Subject::Machine(NEW.to_string());
        assert!(g.standing.lock()[&subject].unregistered);

        // It registers, and is blamed before it sends anything else.
        r.standing
            .lock()
            .insert(NEW.to_string(), RegistryStanding::Registered);
        for _ in 0..3 {
            g.penalise(machine);
        }
        assert!(!g.standing.lock()[&subject].unregistered);

        // A full table, a window later: its blame is still held.
        {
            let now = Instant::now();
            let mut table = g.standing.lock();
            for n in 0..MAX_TRACKED - 1 {
                table.insert(
                    Subject::Machine(format!("did:tenzro:machine:churn{n}")),
                    Standing {
                        unregistered: true,
                        last_seen: Some(now),
                        ..Standing::default()
                    },
                );
            }
        }
        g.advance(window + Duration::from_secs(1));
        assert_eq!(g.admit(TXS, later), Verdict::Accept);
        let table = g.standing.lock();
        assert!(table[&subject].reputation < 0, "the blame is kept");
        assert_eq!(table.len(), 2);
    }

    /// The residual of the rule: transactions that name a funded account as
    /// their sender under a signature that does not verify spend the
    /// signatures verified in a window and are shed without blame; a
    /// machine's real registration is heard in the next window.
    #[test]
    fn forged_registrations_cost_a_window_of_verifications_and_no_more() {
        let window = Duration::from_secs(3600);
        let g = GossipGuard::new(
            NetworkMetrics::unregistered(),
            GossipLimits {
                window,
                general_messages: 2 * REGISTRATIONS_PER_MACHINE,
                ..LIMITS
            },
        );
        let machines = unregistered_machines(&g, 3);
        let (forgers, honest) = (&machines[..2], machines[2]);
        for nonce in 0..REGISTRATIONS_PER_MACHINE {
            for from in forgers {
                // The funded account of key 9, signed by nobody who holds it.
                let mut forged = signed_tx(9, nonce, enrol());
                forged.signature = signed_tx(8, nonce, enrol()).signature;
                assert_eq!(g.check(TXS, *from, &gossip(forged)), Verdict::Ignore);
            }
        }
        assert_eq!(
            g.verifications.lock().used,
            2 * REGISTRATIONS_PER_MACHINE,
            "the window's verifications are spent"
        );
        assert_eq!(
            g.check(TXS, honest, &enrolment(3, 0)),
            Verdict::Ignore,
            "a real registration in the same window is not heard"
        );
        assert!(forgers.iter().all(|f| g.score(*f) == 0), "without blame");
        assert_eq!(g.metrics.gossip_accepted.get(), 0);

        g.advance(window + Duration::from_secs(1));
        assert_eq!(g.check(TXS, honest, &enrolment(3, 1)), Verdict::Accept);
    }

    /// Standings of machines that are not registered, blamed or not, are
    /// forgotten after a window, so they cannot keep the table full.
    #[test]
    fn blamed_unregistered_machines_do_not_keep_the_table_full() {
        let window = Duration::from_secs(3600);
        let g = GossipGuard::new(
            NetworkMetrics::unregistered(),
            GossipLimits { window, ..LIMITS },
        );
        let r = Arc::new(Registered::default());
        let (new, registered) = (peer(98), peer(99));
        r.names.lock().insert(new, NEW.to_string());
        r.names
            .lock()
            .insert(registered, "did:tenzro:machine:old".to_string());
        r.standing.lock().insert(
            "did:tenzro:machine:old".to_string(),
            RegistryStanding::Registered,
        );
        g.set_identities(r);
        g.set_registered_only(true);
        // A registered neighbour that was blamed, and a table otherwise
        // full of blamed machines that are not registered.
        g.penalise(registered);
        {
            let now = Instant::now();
            let mut table = g.standing.lock();
            for n in 0..MAX_TRACKED - 1 {
                table.insert(
                    Subject::Machine(format!("did:tenzro:machine:churn{n}")),
                    Standing {
                        reputation: -PENALTY,
                        unregistered: true,
                        last_seen: Some(now),
                        ..Standing::default()
                    },
                );
            }
        }
        assert_eq!(g.standing.lock().len(), MAX_TRACKED);
        assert_eq!(g.admit(TXS, new), Verdict::Ignore, "full within the window");

        g.advance(window + Duration::from_secs(1));
        assert_eq!(g.admit(TXS, new), Verdict::Accept, "room after the window");
        let table = g.standing.lock();
        assert_eq!(
            table.len(),
            2,
            "the blamed registered neighbour and the new one"
        );
        assert!(table[&Subject::Machine("did:tenzro:machine:old".to_string())].reputation < 0);
    }

    /// Blame on a machine that is not registered marks its standing as one
    /// that lasts a window.
    #[test]
    fn blame_on_an_unregistered_machine_is_kept_like_its_standing() {
        let (g, [new, _, _, registered, _]) = registered_only_guard();
        g.penalise(new);
        g.penalise(registered);
        let table = g.standing.lock();
        assert!(table[&Subject::Machine(NEW.to_string())].unregistered);
        assert!(!table[&Subject::Machine("did:tenzro:machine:old".to_string())].unregistered);
    }

    /// A source that names every endpoint as one machine that is not
    /// registered and knows no balance.
    struct NoBalances;

    impl PeerIdentities for NoBalances {
        fn machine_did(&self, _: EndpointId) -> Option<String> {
            Some(NEW.to_string())
        }
        fn registry_standing(&self, _: &str) -> RegistryStanding {
            RegistryStanding::Unregistered
        }
    }

    #[test]
    fn without_a_source_of_balances_no_registration_is_passed_on() {
        let g = guard();
        g.set_identities(Arc::new(NoBalances));
        g.set_registered_only(true);
        assert_eq!(g.check(TXS, peer(96), &enrolment(1, 0)), Verdict::Ignore);
        assert_eq!(g.metrics.gossip_accepted.get(), 0);
    }

    #[test]
    fn a_full_table_tracks_no_machine_that_is_not_registered() {
        let (g, [new, _, _, registered, _]) = registered_only_guard();
        {
            let now = Instant::now();
            let mut table = g.standing.lock();
            for n in 0..MAX_TRACKED {
                table.insert(
                    Subject::Machine(format!("did:tenzro:machine:busy{n}")),
                    Standing {
                        last_seen: Some(now),
                        ..Standing::default()
                    },
                );
            }
        }
        assert_eq!(g.admit(TXS, new), Verdict::Ignore);
        assert_eq!(g.check(TXS, new, &enrolment(1, 0)), Verdict::Ignore);
        assert_eq!(
            g.standing.lock().len(),
            MAX_TRACKED,
            "the table did not grow"
        );
        assert_eq!(g.metrics.gossip_accepted.get(), 0);
        // A registered neighbour is always tracked: the limit is where
        // idle standings start to be forgotten, not a cap on registered
        // neighbours.
        assert_eq!(g.admit(TXS, registered), Verdict::Accept);
        assert_eq!(g.standing.lock().len(), MAX_TRACKED + 1);
    }

    /// A transaction carries its sender and a registration its wallet as
    /// the same 32-byte account type, so the account of a P-256 key has one
    /// form in both: its 20-byte address followed by twelve zero bytes.
    #[test]
    fn a_registration_names_its_sender_in_the_one_form_an_account_has() {
        let sender = account(1);
        assert_eq!(&sender.as_bytes()[20..], &[0u8; 12]);
        let tx = signed_tx(1, 0, register(NEW, sender));
        assert!(registers(&tx.transaction, NEW));
        assert!(tenzro_crypto::controls_account(
            &tx.public_key,
            &sender.as_bytes()[..20]
        ));
        assert!(signed_by_sender(&tx));
        // A wallet that differs from the sender in those last bytes is
        // another account.
        let mut other = sender.0;
        other[31] = 1;
        let tx = signed_tx(1, 0, register(NEW, Address::new(other)));
        assert!(!registers(&tx.transaction, NEW));
    }

    #[test]
    fn a_registered_neighbour_never_draws_on_the_shared_registration_budget() {
        let (g, [new, _, _, registered, _]) = registered_only_guard();
        // Far more registrations than the shared budget, from a registered
        // neighbour: none is looked at by the registration rule.
        for nonce in 0..3 * LIMITS.general_messages {
            assert_eq!(
                g.check(TXS, registered, &enrolment(3, nonce)),
                Verdict::Accept
            );
        }
        assert_eq!(g.check(TXS, registered, &transfer()), Verdict::Accept);
        assert_eq!(
            g.check(TXS, new, &enrolment(1, 0)),
            Verdict::Accept,
            "the shared budget is untouched"
        );
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
