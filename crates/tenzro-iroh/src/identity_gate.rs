//! Peer admission by registered identity (layer 1).
//!
//! Every connection the endpoint accepts is classified by the protocol (ALPN)
//! it asks for and by who the peer is:
//!
//! - A peer is named by the verified, unexpired endpoint record the
//!   [`DiscoveryStore`] holds for its endpoint id. The record proves the
//!   endpoint belongs to a hardware-rooted machine identity (the DID its key
//!   derives); it does NOT prove the identity is registered. That is what the
//!   [`RegistryView`] says, from the identity registry the node mirrors from
//!   consensus state.
//! - A registered peer, or a member of the validator epoch set, gets
//!   everything the node serves.
//! - An unregistered peer gets an *onboarding session*: only the protocols in
//!   [`alpn_access`] marked [`AlpnAccess::Onboarding`] (discovery, state and
//!   block sync, gossip, hole punching and the registration request). Every
//!   other protocol is closed with [`REFUSED_UNREGISTERED`] and the reason is
//!   logged. The session lasts [`OnboardingPolicy::window`] from first
//!   contact (see [`OnboardingLedger`] for how reconnects and extensions
//!   count); when it ends, the peer's connections are closed with
//!   [`ONBOARDING_ENDED`] and it is backed off.
//! - A revoked identity gets nothing, not even an onboarding session.
//!
//! The gate is node-local policy. It reads the registry and changes nothing
//! in consensus. It is inert until the node installs a [`RegistryView`], so
//! an endpoint built without one (tests, tools) behaves as before.
//!
//! [`IdentityGate::sweep`] is the standing sweep: it ends expired onboarding
//! sessions and closes the connections of identities that were revoked, or
//! never registered, since they were admitted.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use iroh::endpoint::{Connection, WeakConnectionHandle};
use iroh::{EndpointId, TransportAddr};
use parking_lot::{Mutex, RwLock};
use tenzro_onboarding_types::onboarding::{
    GateMode, OnboardingLedger, OnboardingPolicy, SessionId, Standing, Who,
};

use crate::discovery::{ALPN_DISCOVERY, DiscoveryStore};
use crate::relay::now_ms;

/// ALPN of the registration request: ask for a challenge, show an owner
/// approval, submit a signed registration for sponsorship, read the status.
pub const ALPN_ONBOARD: &[u8] = b"tenzro/onboard";

/// Close code: the peer has no registered identity and asked for a protocol
/// an onboarding session does not include.
pub const REFUSED_UNREGISTERED: u32 = 5;
/// Close code: the peer's identity was revoked.
pub const REFUSED_REVOKED: u32 = 6;
/// Close code: the peer's onboarding window ended.
pub const ONBOARDING_ENDED: u32 = 7;
/// Close code: no onboarding session could be opened (back-off, limits).
pub const ONBOARDING_REFUSED: u32 = 8;

/// Most refusals the gate remembers for inspection.
const RECENT_REFUSALS: usize = 256;

/// How often the gate logs the refusals of one peer on one protocol: the
/// first at once, then at most one line per interval, naming how many it
/// left out. A peer that redials what it is refused would otherwise fill
/// the log with one line per attempt.
const REFUSAL_LOG_INTERVAL_MS: u64 = 60_000;

/// Most peer and protocol pairs whose refusal lines are paced at once; past
/// it, the pair logged longest ago is forgotten.
const PACED_REFUSALS: usize = 1_024;

/// When the gate last logged a refusal of each peer on each protocol, and
/// how many refusals of it it has left out since.
#[derive(Default)]
struct RefusalPacing {
    last: HashMap<(String, String), (u64, u64)>,
}

impl RefusalPacing {
    /// Whether a refusal of `peer` on `alpn` at `at_ms` is logged, with how
    /// many refusals of that pair were left out since the last line.
    fn admit(&mut self, peer: &str, alpn: &str, at_ms: u64) -> Option<u64> {
        let key = (peer.to_string(), alpn.to_string());
        if let Some((logged, left_out)) = self.last.get_mut(&key) {
            if at_ms.saturating_sub(*logged) < REFUSAL_LOG_INTERVAL_MS {
                *left_out += 1;
                return None;
            }
            let skipped = *left_out;
            (*logged, *left_out) = (at_ms, 0);
            return Some(skipped);
        }
        if self.last.len() >= PACED_REFUSALS
            && let Some(oldest) = self
                .last
                .iter()
                .min_by_key(|(_, (logged, _))| *logged)
                .map(|(k, _)| k.clone())
        {
            self.last.remove(&oldest);
        }
        self.last.insert(key, (at_ms, 0));
        Some(0)
    }
}

/// What a protocol is open to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlpnAccess {
    /// Open to an onboarding session: sync enough to learn the registry, the
    /// files of a retained state snapshot, and the registration request.
    Onboarding,
    /// Only to a registered identity.
    Registered,
}

/// What the protocol `alpn` is open to. Anything not named is
/// [`AlpnAccess::Registered`]: a protocol added later is closed until
/// someone decides it is safe to open.
pub fn alpn_access(alpn: &[u8]) -> AlpnAccess {
    if alpn == ALPN_DISCOVERY
        || alpn == crate::state_sync::ALPN_STATE_SYNC
        || alpn == crate::state_sync::ALPN_STATE_SYNC_ANCHOR
        || alpn == crate::zk_proof::ALPN_ZK_PROOF
        || alpn == crate::block_sync::ALPN_BLOCK_SYNC
        || alpn == crate::gossip::ALPN_GOSSIP
        || alpn == crate::paths::ALPN_PUNCH
        || alpn == ALPN_ONBOARD
        // Using this node's relay: a joining machine needs it to be reached.
        || alpn == crate::relay::RELAY_CLIENT
        // Blobs: the blob provider serves an onboarding peer nothing but the
        // files of a retained state snapshot (see `licence_gate`).
        || alpn == iroh_blobs::ALPN
    {
        AlpnAccess::Onboarding
    } else {
        AlpnAccess::Registered
    }
}

/// The identity registry as the gate reads it.
pub trait RegistryView: Send + Sync + 'static {
    /// What the registry says about the machine identity `did`.
    fn standing(&self, did: &str) -> Standing;

    /// Whether the registry is complete enough to be believed: a node still
    /// syncing from empty cannot tell an unregistered peer from a registered
    /// one it has not yet heard of. While it is not ready, only the
    /// validator epoch set and the protected identities count as registered.
    fn ready(&self) -> bool {
        true
    }
}

/// What the gate decided about a connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Admit {
    /// Serve it in full.
    Allow,
    /// Serve it inside an onboarding session.
    Onboarding {
        /// The session.
        session: SessionId,
        /// Milliseconds the window has left.
        remaining_ms: u64,
    },
    /// Close it.
    Refuse {
        /// The application close code.
        code: u32,
        /// Why, as logged.
        reason: String,
    },
}

/// A refusal the gate remembers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefusalRecord {
    /// When (ms since the epoch).
    pub at_ms: u64,
    /// The peer's endpoint id.
    pub peer: String,
    /// The machine identity its record names, if any.
    pub did: Option<String>,
    /// The protocol asked for.
    pub alpn: String,
    /// Why it was refused.
    pub reason: String,
    /// What the gate did: `refused`, or `audit` when it only logged.
    pub action: &'static str,
}

/// What a sweep did.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SweepReport {
    /// Peers whose onboarding window ended: (peer, did, retry at).
    pub expired: Vec<(String, Option<String>, u64)>,
    /// Peers closed because their identity is revoked.
    pub revoked: Vec<(String, Option<String>)>,
    /// Peers closed because they hold full access with no registered identity.
    pub quarantined: Vec<(String, Option<String>)>,
    /// Peers whose onboarding session ended because they registered.
    pub promoted: Vec<(String, Option<String>)>,
    /// Connections closed in all.
    pub closed: usize,
}

struct Live {
    conn: WeakConnectionHandle,
    endpoint: EndpointId,
    session: Option<SessionId>,
    alpn: String,
    source: Option<String>,
}

struct Inner {
    policy: RwLock<OnboardingPolicy>,
    registry: RwLock<Option<Arc<dyn RegistryView>>>,
    discovery: Option<Arc<DiscoveryStore>>,
    ledger: Mutex<OnboardingLedger>,
    protected: RwLock<HashSet<String>>,
    isolated: AtomicBool,
    live: Mutex<HashMap<usize, Live>>,
    refusals: Mutex<VecDeque<RefusalRecord>>,
    refusal_log: Mutex<RefusalPacing>,
}

/// The identity gate of one endpoint.
#[derive(Clone)]
pub struct IdentityGate {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for IdentityGate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdentityGate")
            .field("active", &self.is_active())
            .finish_non_exhaustive()
    }
}

/// An address prefix for the per-source limits: /24 for IPv4, /48 for IPv6.
/// A peer reached only through a relay has none; the total and per-root
/// limits still bound it.
fn source_of(conn: &Connection) -> Option<String> {
    let paths = conn.paths();
    let addr = paths.iter().find_map(|p| match p.remote_addr() {
        TransportAddr::Ip(a) => Some(a.ip()),
        _ => None,
    })?;
    Some(match addr {
        std::net::IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{}.{}.{}", o[0], o[1], o[2])
        }
        std::net::IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => {
                let o = v4.octets();
                format!("{}.{}.{}", o[0], o[1], o[2])
            }
            None => {
                let s = v6.segments();
                format!("{:x}:{:x}:{:x}", s[0], s[1], s[2])
            }
        },
    })
}

impl IdentityGate {
    /// A gate naming peers from `discovery`. With no discovery store it can
    /// name nobody and stays inert.
    pub fn new(policy: OnboardingPolicy, discovery: Option<Arc<DiscoveryStore>>) -> Self {
        Self {
            inner: Arc::new(Inner {
                ledger: Mutex::new(OnboardingLedger::new(policy)),
                policy: RwLock::new(policy),
                registry: RwLock::new(None),
                discovery,
                protected: RwLock::new(HashSet::new()),
                isolated: AtomicBool::new(false),
                live: Mutex::new(HashMap::new()),
                refusals: Mutex::new(VecDeque::new()),
                refusal_log: Mutex::new(RefusalPacing::default()),
            }),
        }
    }

    /// Installs the registry the gate reads. From here the gate acts, in the
    /// policy's mode.
    pub fn install_registry(&self, registry: Arc<dyn RegistryView>) {
        *self.inner.registry.write() = Some(registry);
    }

    /// Replaces the policy (mode, window, limits). Sessions already open keep
    /// the window they were given.
    pub fn set_policy(&self, policy: OnboardingPolicy) {
        *self.inner.policy.write() = policy;
        let mut ledger = self.inner.ledger.lock();
        let sessions_carry_over = ledger.open_sessions() > 0;
        if !sessions_carry_over {
            *ledger = OnboardingLedger::new(policy);
        }
    }

    /// Machine identities that are admitted in full whatever the registry
    /// says: the boot list and the validators, without whom a node cannot
    /// sync the registry in the first place. Replaces the previous set.
    pub fn protect(&self, dids: impl IntoIterator<Item = String>) {
        *self.inner.protected.write() = dids.into_iter().collect();
    }

    /// Whether `did` is admitted in full whatever the registry says: an
    /// identity set by [`Self::protect`], or a member of the epoch set.
    pub fn protects(&self, did: &str) -> bool {
        self.inner.protected.read().contains(did)
            || self
                .inner
                .discovery
                .as_ref()
                .is_some_and(|d| d.in_epoch_set(did))
    }

    /// Holds this node to the identities it protects for every peer it
    /// reaches out to: with `on`, discovery sync, relay forwarders and gossip
    /// neighbours are limited to the boot list and the validators' machines
    /// ([`Self::may_dial`]). A validator in enforce mode is isolated so.
    pub fn isolate(&self, on: bool) {
        self.inner.isolated.store(on, Ordering::Relaxed);
    }

    /// Whether this node may dial, sync with or keep as a gossip neighbour
    /// the peer whose record names the machine `did` (`None`: no record
    /// names the peer). Always true unless the node is isolated
    /// ([`Self::isolate`]); then only for an identity it protects.
    pub fn may_dial(&self, did: Option<&str>) -> bool {
        !self.inner.isolated.load(Ordering::Relaxed) || did.is_some_and(|d| self.protects(d))
    }

    /// The address prefix `endpoint` is currently connected from, when it
    /// holds a connection to this node.
    pub fn source_for(&self, endpoint: EndpointId) -> Option<String> {
        self.inner
            .live
            .lock()
            .values()
            .find(|l| l.endpoint == endpoint)
            .and_then(|l| l.source.clone())
    }

    /// Whether the gate acts at all (a registry is installed and the mode is
    /// not off).
    pub fn is_active(&self) -> bool {
        self.inner.registry.read().is_some() && self.inner.policy.read().mode != GateMode::Off
    }

    /// The policy in force.
    pub fn policy(&self) -> OnboardingPolicy {
        *self.inner.policy.read()
    }

    /// Records that an owner approval for the peer named by `did` is in
    /// progress until `until_ms`, so its window can be extended once.
    pub fn approval_in_progress(&self, endpoint: &str, did: Option<&str>, until_ms: u64) {
        let who = Who {
            endpoint: endpoint.to_string(),
            root: did.map(str::to_string),
            source: None,
        };
        self.inner
            .ledger
            .lock()
            .approval_in_progress(&who, until_ms);
    }

    /// The recent refusals, oldest first.
    pub fn recent_refusals(&self) -> Vec<RefusalRecord> {
        self.inner.refusals.lock().iter().cloned().collect()
    }

    /// Onboarding sessions open now.
    pub fn open_sessions(&self) -> usize {
        self.inner.ledger.lock().open_sessions()
    }

    fn name_of(&self, endpoint: EndpointId) -> Option<String> {
        self.inner
            .discovery
            .as_ref()
            .and_then(|d| d.naming(endpoint))
            .map(|r| r.machine_did())
    }

    /// What the registry says about the peer named `did` (`None`: no record
    /// names it).
    fn standing_of(&self, did: Option<&str>) -> Standing {
        let Some(did) = did else {
            return Standing::Unregistered;
        };
        if self.protects(did) {
            return Standing::Registered;
        }
        match self.inner.registry.read().as_ref() {
            Some(r) if r.ready() => r.standing(did),
            Some(_) => Standing::Unregistered,
            None => Standing::Registered,
        }
    }

    /// Whether `endpoint` is a registered identity, or the gate refuses
    /// nothing (off, or only auditing). A peer for which this is false holds
    /// an onboarding session at most.
    pub fn holds_full_access(&self, endpoint: Option<EndpointId>) -> bool {
        if !self.is_active() || self.policy().mode == GateMode::Audit {
            return true;
        }
        let did = endpoint.and_then(|e| self.name_of(e));
        self.standing_of(did.as_deref()) == Standing::Registered
    }

    fn remember(&self, record: RefusalRecord) {
        let logged = self
            .inner
            .refusal_log
            .lock()
            .admit(&record.peer, &record.alpn, record.at_ms);
        if let Some(left_out) = logged {
            tracing::warn!(
                target: "tenzro_iroh::identity_gate",
                peer = %record.peer,
                did = ?record.did,
                alpn = %record.alpn,
                action = record.action,
                reason = %record.reason,
                left_out,
                "identity gate"
            );
        }
        let mut q = self.inner.refusals.lock();
        if q.len() >= RECENT_REFUSALS {
            q.pop_front();
        }
        q.push_back(record);
    }

    /// The decision for a peer: pure of any connection, so it is tested with
    /// plain values. `source` is the peer's address prefix, if known.
    pub fn evaluate(
        &self,
        now_ms: u64,
        endpoint: EndpointId,
        did: Option<&str>,
        source: Option<&str>,
        alpn: &[u8],
    ) -> Admit {
        let policy = self.policy();
        if !self.is_active() {
            return Admit::Allow;
        }
        let standing = self.standing_of(did);
        let access = alpn_access(alpn);
        let verdict = match (standing, access) {
            (Standing::Registered, _) => {
                if did.is_some() {
                    let who = Who {
                        endpoint: endpoint.to_string(),
                        root: did.map(str::to_string),
                        source: None,
                    };
                    self.inner.ledger.lock().registered(&who);
                }
                return Admit::Allow;
            }
            (Standing::Revoked, _) => Admit::Refuse {
                code: REFUSED_REVOKED,
                reason: Standing::Revoked.refusal().to_string(),
            },
            (Standing::Unregistered, AlpnAccess::Registered) => Admit::Refuse {
                code: REFUSED_UNREGISTERED,
                reason: format!(
                    "{}: an onboarding session allows only sync, discovery, gossip and the registration request",
                    Standing::Unregistered.refusal()
                ),
            },
            (Standing::Unregistered, AlpnAccess::Onboarding) => {
                let who = Who {
                    endpoint: endpoint.to_string(),
                    root: did.map(str::to_string),
                    source: source.map(str::to_string),
                };
                match self.inner.ledger.lock().contact(now_ms, &who) {
                    Ok((session, remaining_ms)) => {
                        tracing::info!(
                            target: "tenzro_iroh::identity_gate",
                            peer = %endpoint,
                            did = ?did,
                            remaining_secs = remaining_ms / 1000,
                            "onboarding session: {} left to register",
                            humanise(remaining_ms)
                        );
                        return Admit::Onboarding {
                            session,
                            remaining_ms,
                        };
                    }
                    Err(refusal) => Admit::Refuse {
                        code: ONBOARDING_REFUSED,
                        reason: refusal.reason(),
                    },
                }
            }
        };
        if let Admit::Refuse { reason, .. } = &verdict {
            let audit = policy.mode == GateMode::Audit;
            self.remember(RefusalRecord {
                at_ms: now_ms,
                peer: endpoint.to_string(),
                did: did.map(str::to_string),
                alpn: String::from_utf8_lossy(alpn).into_owned(),
                reason: reason.clone(),
                action: if audit { "audit" } else { "refused" },
            });
            if audit {
                return Admit::Allow;
            }
        }
        verdict
    }

    /// Decides for a live connection, waiting up to the handshake timeout for
    /// a peer that no record names yet to publish one when the protocol it
    /// asks for is not part of an onboarding session.
    pub async fn admit(&self, conn: &Connection) -> Admit {
        if !self.is_active() {
            return Admit::Allow;
        }
        let endpoint = conn.remote_id();
        let alpn = conn.alpn().to_vec();
        let mut did = self.name_of(endpoint);
        if did.is_none() && alpn_access(&alpn) == AlpnAccess::Registered {
            let deadline = tokio::time::Instant::now() + self.policy().handshake_timeout;
            while did.is_none() && tokio::time::Instant::now() < deadline {
                tokio::time::sleep(Duration::from_millis(200)).await;
                did = self.name_of(endpoint);
            }
        }
        let source = source_of(conn);
        let verdict = self.evaluate(now_ms(), endpoint, did.as_deref(), source.as_deref(), &alpn);
        match &verdict {
            Admit::Allow => self.track(conn, None),
            Admit::Onboarding { session, .. } => self.track(conn, Some(*session)),
            Admit::Refuse { .. } => {}
        }
        verdict
    }

    /// Remembers `conn` so the sweep can close it, and forgets it when it
    /// closes.
    fn track(&self, conn: &Connection, session: Option<SessionId>) {
        let id = conn.stable_id();
        self.inner.live.lock().insert(
            id,
            Live {
                conn: conn.weak_handle(),
                endpoint: conn.remote_id(),
                session,
                alpn: String::from_utf8_lossy(conn.alpn()).into_owned(),
                source: source_of(conn),
            },
        );
        let inner = self.inner.clone();
        let held = conn.clone();
        tokio::spawn(async move {
            held.closed().await;
            let gone = inner.live.lock().remove(&id);
            // The ledger counts the connections that hold a session and
            // ends it with the last one.
            if let Some(Live {
                session: Some(s), ..
            }) = gone
            {
                inner.ledger.lock().close(s);
            }
        });
    }

    /// Ends the onboarding windows that are over, and re-reads the registry
    /// for every live connection: a revoked identity, or one that holds full
    /// access without being registered, is closed; an onboarding peer that
    /// has registered since is promoted. Logs the reason for each.
    pub fn sweep(&self, now_ms: u64) -> SweepReport {
        let mut report = SweepReport::default();
        if !self.is_active() {
            return report;
        }
        let audit = self.policy().mode == GateMode::Audit;

        // 1. Windows that are over.
        let ended = self.inner.ledger.lock().sweep(now_ms);
        let ended_sessions: HashMap<SessionId, u64> =
            ended.iter().map(|e| (e.session, e.retry_at_ms)).collect();
        for e in &ended {
            report
                .expired
                .push((e.who.endpoint.clone(), e.who.root.clone(), e.retry_at_ms));
            tracing::warn!(
                target: "tenzro_iroh::identity_gate",
                peer = %e.who.endpoint,
                did = ?e.who.root,
                retry_at_ms = e.retry_at_ms,
                "onboarding window ended without a registered identity: dropped, backed off"
            );
        }

        // 2. Every live connection against the registry as it is now. A
        // registry that is not ready (the node is syncing) cannot say who is
        // unregistered, so it removes nobody.
        if !self
            .inner
            .registry
            .read()
            .as_ref()
            .is_some_and(|r| r.ready())
        {
            return report;
        }
        let mut live = self.inner.live.lock();
        let ids: Vec<usize> = live.keys().copied().collect();
        for id in ids {
            let Some(l) = live.get(&id) else { continue };
            let Some(conn) = l.conn.upgrade() else {
                self.forget(&mut live, id);
                continue;
            };
            let did = self.name_of(l.endpoint);
            let standing = self.standing_of(did.as_deref());
            let peer = l.endpoint.to_string();
            // A session the ledger no longer holds is over as well: its
            // window ended at a sweep that could judge nobody (the registry
            // was not ready), or at a later contact.
            let session_over = l.session.is_some_and(|s| {
                ended_sessions.contains_key(&s) || (!audit && !self.inner.ledger.lock().is_open(s))
            });
            let close = match (standing, l.session, session_over) {
                (Standing::Revoked, _, _) => {
                    report.revoked.push((peer.clone(), did.clone()));
                    Some((REFUSED_REVOKED, "identity revoked: connection removed"))
                }
                (Standing::Unregistered, None, _) => {
                    report.quarantined.push((peer.clone(), did.clone()));
                    Some((
                        REFUSED_UNREGISTERED,
                        "no registered identity: quarantined from full access",
                    ))
                }
                (Standing::Unregistered, Some(_), true) => {
                    Some((ONBOARDING_ENDED, "onboarding window ended"))
                }
                (Standing::Registered, Some(s), _) => {
                    // Registered since it connected: its session is done and
                    // the connection keeps serving as a registered peer.
                    report.promoted.push((peer.clone(), did.clone()));
                    self.inner.ledger.lock().close(s);
                    if let Some(l) = live.get_mut(&id) {
                        l.session = None;
                    }
                    None
                }
                _ => None,
            };
            if let Some((code, reason)) = close {
                self.remember(RefusalRecord {
                    at_ms: now_ms,
                    peer: peer.clone(),
                    did: did.clone(),
                    alpn: live.get(&id).map(|l| l.alpn.clone()).unwrap_or_default(),
                    reason: reason.to_string(),
                    action: if audit { "audit" } else { "closed" },
                });
                if !audit {
                    conn.close(code.into(), reason.as_bytes());
                    self.forget(&mut live, id);
                    report.closed += 1;
                }
            }
        }
        report
    }

    /// Drops a live connection the sweep is done with, and with it the
    /// connection's hold on its session.
    fn forget(&self, live: &mut HashMap<usize, Live>, id: usize) {
        if let Some(Live {
            session: Some(s), ..
        }) = live.remove(&id)
        {
            self.inner.ledger.lock().close(s);
        }
    }

    /// Runs [`Self::sweep`] every `every` until the gate is dropped.
    pub fn spawn_sweeper(&self, every: Duration) -> tokio::task::JoinHandle<()> {
        let weak = Arc::downgrade(&self.inner);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(every);
            loop {
                tick.tick().await;
                let Some(inner) = weak.upgrade() else { return };
                let gate = IdentityGate { inner };
                gate.sweep(now_ms());
            }
        })
    }
}

fn humanise(ms: u64) -> String {
    let secs = ms / 1000;
    format!("{}m{:02}s", secs / 60, secs % 60)
}

#[cfg(test)]
#[expect(
    clippy::disallowed_methods,
    reason = "the test runner bounds every wait in a test"
)]
mod tests {
    use super::*;
    use crate::connection_limits::{ConnectionGate, ConnectionLimits, GatedRouter};
    use crate::identity_record::tests::TestMachineKey;
    use crate::identity_record::{EndpointRecord, RecordScope};
    use crate::identity_transport::iroh_endpoint_key;
    use iroh::Endpoint;
    use iroh::endpoint::ConnectionError;
    use iroh::protocol::{AcceptError, ProtocolHandler, Router};
    use std::sync::atomic::{AtomicBool, Ordering};

    const MIN: u64 = 60_000;

    /// A registry the test edits.
    #[derive(Default)]
    struct Registry {
        registered: Mutex<HashSet<String>>,
        revoked: Mutex<HashSet<String>>,
        not_ready: AtomicBool,
    }

    impl Registry {
        fn register(&self, did: &str) {
            self.registered.lock().insert(did.to_string());
        }
        fn revoke(&self, did: &str) {
            self.revoked.lock().insert(did.to_string());
        }
    }

    impl RegistryView for Registry {
        fn standing(&self, did: &str) -> Standing {
            if self.revoked.lock().contains(did) {
                Standing::Revoked
            } else if self.registered.lock().contains(did) {
                Standing::Registered
            } else {
                Standing::Unregistered
            }
        }
        fn ready(&self) -> bool {
            !self.not_ready.load(Ordering::SeqCst)
        }
    }

    fn peer(n: u8) -> EndpointId {
        iroh::SecretKey::from_bytes(&[n; 32]).public()
    }

    fn gate_with(registry: Arc<Registry>, mode: GateMode) -> IdentityGate {
        let policy = OnboardingPolicy {
            mode,
            ..OnboardingPolicy::default()
        };
        let gate = IdentityGate::new(policy, Some(Arc::new(DiscoveryStore::new())));
        gate.install_registry(registry);
        gate
    }

    const DID_A: &str = "did:tenzro:machine:aaaa";

    #[test]
    fn the_protocol_table_opens_only_sync_and_registration_to_an_unregistered_peer() {
        for open in [
            ALPN_DISCOVERY,
            crate::state_sync::ALPN_STATE_SYNC,
            crate::state_sync::ALPN_STATE_SYNC_ANCHOR,
            crate::zk_proof::ALPN_ZK_PROOF,
            crate::block_sync::ALPN_BLOCK_SYNC,
            crate::gossip::ALPN_GOSSIP,
            crate::paths::ALPN_PUNCH,
            ALPN_ONBOARD,
            iroh_blobs::ALPN,
            crate::relay::RELAY_CLIENT,
        ] {
            assert_eq!(alpn_access(open), AlpnAccess::Onboarding, "{open:?}");
        }
        // Everything that transacts, serves, stakes or speaks for an agent.
        for closed in [
            crate::app_stream::ALPN_APP_STREAM,
            crate::consensus::ALPN_CONSENSUS,
            crate::request::ALPN_DA_COMMITTEE,
            crate::request::ALPN_AGENT_KEY,
            crate::request::ALPN_AGENT_TOKEN,
            crate::request::ALPN_KV_CHECKPOINT,
            crate::request::ALPN_SLA,
            crate::request::ALPN_INFER,
            crate::jsonrpc::ALPN_A2A,
            crate::jsonrpc::ALPN_A2A_PQ,
            crate::jsonrpc::ALPN_MCP,
            crate::jsonrpc::ALPN_MCP_PQ,
            crate::jsonrpc::ALPN_MOE,
            crate::jsonrpc::ALPN_MOE_PQ,
            crate::paths::ALPN_PEER_RELAY,
            b"tenzro/some-protocol-added-later",
        ] {
            assert_eq!(alpn_access(closed), AlpnAccess::Registered, "{closed:?}");
        }
    }

    #[test]
    fn a_gate_with_no_registry_changes_nothing() {
        let gate = IdentityGate::new(
            OnboardingPolicy::default(),
            Some(Arc::new(DiscoveryStore::new())),
        );
        assert!(!gate.is_active());
        assert_eq!(
            gate.evaluate(0, peer(1), None, None, crate::consensus::ALPN_CONSENSUS),
            Admit::Allow
        );
        assert!(gate.holds_full_access(Some(peer(1))));
    }

    #[test]
    fn an_unregistered_peer_is_refused_every_gated_protocol_with_its_reason_logged() {
        let gate = gate_with(Arc::new(Registry::default()), GateMode::Enforce);
        assert!(!gate.holds_full_access(Some(peer(1))));
        assert!(!gate.holds_full_access(None));
        // A gate that only audits refuses nothing, here as everywhere.
        assert!(
            gate_with(Arc::new(Registry::default()), GateMode::Audit)
                .holds_full_access(Some(peer(1)))
        );
        for alpn in [
            crate::request::ALPN_INFER,
            crate::jsonrpc::ALPN_MCP_PQ,
            crate::jsonrpc::ALPN_A2A_PQ,
            crate::request::ALPN_DA_COMMITTEE,
        ] {
            let v = gate.evaluate(0, peer(1), Some(DID_A), None, alpn);
            let Admit::Refuse { code, reason } = v else {
                panic!("{alpn:?} was not refused")
            };
            assert_eq!(code, REFUSED_UNREGISTERED);
            assert!(reason.contains("no registered identity"), "{reason}");
        }
        let log = gate.recent_refusals();
        assert_eq!(log.len(), 4);
        assert!(
            log.iter()
                .all(|r| r.action == "refused" && r.did.as_deref() == Some(DID_A))
        );
    }

    #[test]
    fn a_peer_no_record_names_is_unregistered_and_waits_nowhere_in_the_pure_decision() {
        let gate = gate_with(Arc::new(Registry::default()), GateMode::Enforce);
        assert!(matches!(
            gate.evaluate(0, peer(1), None, None, crate::request::ALPN_INFER),
            Admit::Refuse {
                code: REFUSED_UNREGISTERED,
                ..
            }
        ));
    }

    #[test]
    fn an_unregistered_peer_gets_an_onboarding_session_on_sync_and_registration() {
        let gate = gate_with(Arc::new(Registry::default()), GateMode::Enforce);
        for alpn in [
            crate::state_sync::ALPN_STATE_SYNC,
            crate::block_sync::ALPN_BLOCK_SYNC,
            ALPN_ONBOARD,
        ] {
            let v = gate.evaluate(0, peer(1), Some(DID_A), Some("1.2.3"), alpn);
            assert!(
                matches!(v, Admit::Onboarding { remaining_ms, .. } if remaining_ms == 30 * MIN),
                "{alpn:?}: {v:?}"
            );
        }
        // One peer, one session, however many protocols it speaks.
        assert_eq!(gate.open_sessions(), 1);
    }

    #[test]
    fn protects_names_the_protected_identities_and_the_epoch_set() {
        let store = Arc::new(DiscoveryStore::new());
        let gate = IdentityGate::new(OnboardingPolicy::default(), Some(store.clone()));
        assert!(!gate.protects(DID_A));
        gate.protect([DID_A.to_string()]);
        assert!(gate.protects(DID_A));
        let member = "did:tenzro:machine:member";
        assert!(!gate.protects(member));
        store.set_epoch_set([member.to_string()].into_iter().collect());
        assert!(gate.protects(member));
    }

    #[test]
    fn a_registered_peer_and_a_validator_are_served_in_full() {
        let reg = Arc::new(Registry::default());
        reg.register(DID_A);
        let gate = gate_with(reg, GateMode::Enforce);
        assert_eq!(
            gate.evaluate(0, peer(1), Some(DID_A), None, crate::request::ALPN_INFER),
            Admit::Allow
        );
        // A genesis validator needs no registry entry (a node syncing from
        // empty must reach them to learn the registry at all).
        gate.protect(["did:tenzro:machine:boot".to_string()]);
        assert_eq!(
            gate.evaluate(
                0,
                peer(2),
                Some("did:tenzro:machine:boot"),
                None,
                crate::request::ALPN_INFER
            ),
            Admit::Allow
        );
    }

    #[test]
    fn a_revoked_identity_gets_nothing_not_even_an_onboarding_session() {
        let reg = Arc::new(Registry::default());
        reg.register(DID_A);
        reg.revoke(DID_A);
        let gate = gate_with(reg, GateMode::Enforce);
        for alpn in [
            ALPN_ONBOARD,
            crate::state_sync::ALPN_STATE_SYNC,
            crate::request::ALPN_INFER,
        ] {
            assert!(
                matches!(
                    gate.evaluate(0, peer(1), Some(DID_A), None, alpn),
                    Admit::Refuse {
                        code: REFUSED_REVOKED,
                        ..
                    }
                ),
                "{alpn:?}"
            );
        }
    }

    #[test]
    fn a_node_that_has_not_finished_syncing_does_not_believe_its_empty_registry() {
        let reg = Arc::new(Registry::default());
        reg.register(DID_A);
        reg.not_ready.store(true, Ordering::SeqCst);
        let gate = gate_with(reg, GateMode::Enforce);
        // Registered on paper, but this node cannot tell yet: onboarding only.
        assert!(matches!(
            gate.evaluate(0, peer(1), Some(DID_A), None, crate::request::ALPN_INFER),
            Admit::Refuse { .. }
        ));
    }

    #[test]
    fn audit_mode_logs_the_refusal_and_refuses_nothing() {
        let gate = gate_with(Arc::new(Registry::default()), GateMode::Audit);
        assert_eq!(
            gate.evaluate(0, peer(1), Some(DID_A), None, crate::request::ALPN_INFER),
            Admit::Allow
        );
        let log = gate.recent_refusals();
        assert_eq!(log.len(), 1);
        assert_eq!(log[0].action, "audit");
    }

    #[test]
    fn the_window_survives_a_new_endpoint_key_and_ends_at_thirty_minutes() {
        let gate = gate_with(Arc::new(Registry::default()), GateMode::Enforce);
        let alpn = crate::state_sync::ALPN_STATE_SYNC;
        gate.evaluate(0, peer(1), Some(DID_A), None, alpn);
        // 20 minutes on, the machine returns under a new endpoint key.
        let Admit::Onboarding { remaining_ms, .. } =
            gate.evaluate(20 * MIN, peer(2), Some(DID_A), None, alpn)
        else {
            panic!()
        };
        assert_eq!(remaining_ms, 10 * MIN);
    }

    #[test]
    fn registering_ends_the_session_and_opens_everything() {
        let reg = Arc::new(Registry::default());
        let gate = gate_with(reg.clone(), GateMode::Enforce);
        gate.evaluate(0, peer(1), Some(DID_A), None, ALPN_ONBOARD);
        assert_eq!(gate.open_sessions(), 1);
        reg.register(DID_A);
        assert_eq!(
            gate.evaluate(MIN, peer(1), Some(DID_A), None, crate::request::ALPN_INFER),
            Admit::Allow
        );
        assert_eq!(gate.open_sessions(), 0);
    }

    // -- over real connections ---------------------------------------------

    const OPEN_ALPN: &[u8] = b"tenzro/discovery";

    #[derive(Debug, Clone)]
    struct Hold;

    impl ProtocolHandler for Hold {
        async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
            while let Ok((mut send, mut recv)) = conn.accept_bi().await {
                let msg = recv
                    .read_to_end(1024)
                    .await
                    .map_err(AcceptError::from_err)?;
                send.write_all(&msg).await.map_err(AcceptError::from_err)?;
                send.finish().map_err(AcceptError::from_err)?;
            }
            conn.closed().await;
            Ok(())
        }
    }

    struct Rig {
        server: Endpoint,
        _router: Router,
        store: Arc<DiscoveryStore>,
        gate: IdentityGate,
        registry: Arc<Registry>,
    }

    async fn rig(mode: GateMode, policy: impl FnOnce(&mut OnboardingPolicy)) -> Rig {
        let limits = ConnectionLimits::default();
        let server = crate::identity_transport::on_loopback(
            crate::identity_transport::base_builder_with(&limits, false),
        )
        .bind()
        .await
        .unwrap();
        let store = Arc::new(DiscoveryStore::new());
        let registry = Arc::new(Registry::default());
        let mut p = OnboardingPolicy {
            mode,
            handshake_timeout: Duration::from_millis(600),
            ..OnboardingPolicy::default()
        };
        policy(&mut p);
        let gate = IdentityGate::new(p, Some(store.clone()));
        gate.install_registry(registry.clone());
        let router = GatedRouter::new(Router::builder(server.clone()), ConnectionGate::new(limits))
            .with_identity_gate(gate.clone())
            .accept(OPEN_ALPN, Hold)
            .accept(crate::request::ALPN_INFER, Hold)
            .accept(crate::consensus::ALPN_CONSENSUS, Hold)
            .spawn();
        Rig {
            server,
            _router: router,
            store,
            gate,
            registry,
        }
    }

    async fn dial(rig: &Rig, alpn: &[u8]) -> (Endpoint, Connection) {
        let client =
            crate::identity_transport::on_loopback(crate::identity_transport::base_builder())
                .bind()
                .await
                .unwrap();
        let conn = client.connect(rig.server.addr(), alpn).await.unwrap();
        (client, conn)
    }

    fn name(rig: &Rig, client: &Endpoint, key: &TestMachineKey, seq: u64) -> String {
        let record = EndpointRecord::sign(
            key,
            iroh_endpoint_key(client.id()),
            vec![],
            Vec::new(),
            None,
            RecordScope::Network,
            Vec::new(),
            seq,
            now_ms(),
        )
        .unwrap();
        let did = record.machine_did();
        rig.store.offer(record).unwrap();
        did
    }

    async fn echoes(conn: &Connection) -> bool {
        let Ok((mut send, mut recv)) = conn.open_bi().await else {
            return false;
        };
        if send.write_all(b"ping").await.is_err() || send.finish().is_err() {
            return false;
        }
        matches!(
            tokio::time::timeout(Duration::from_secs(5), recv.read_to_end(16)).await,
            Ok(Ok(reply)) if reply == b"ping"
        )
    }

    /// Whether the gate comes to hold `n` sessions within ten seconds: a
    /// closed connection reaches the gate's ledger only once the server has
    /// seen the close.
    async fn sessions_reach(gate: &IdentityGate, n: usize) -> bool {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while gate.open_sessions() != n {
            if tokio::time::Instant::now() >= deadline {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        true
    }

    async fn closed_with(conn: &Connection) -> Option<u32> {
        match tokio::time::timeout(Duration::from_secs(3), conn.closed()).await {
            Ok(ConnectionError::ApplicationClosed(c)) => {
                Some(u32::try_from(u64::from(c.error_code)).unwrap())
            }
            _ => None,
        }
    }

    #[tokio::test]
    async fn over_real_connections_an_unregistered_peer_syncs_but_cannot_use_the_node() {
        let rig = rig(GateMode::Enforce, |_| {}).await;
        let key = TestMachineKey::from_seed(31);

        // Onboarding protocol: served inside a session.
        let (client, conn) = dial(&rig, OPEN_ALPN).await;
        name(&rig, &client, &key, 1);
        assert!(echoes(&conn).await, "an onboarding protocol is served");
        assert_eq!(rig.gate.open_sessions(), 1);

        // Gated protocols: closed with the reason code, at once.
        for alpn in [crate::request::ALPN_INFER, crate::consensus::ALPN_CONSENSUS] {
            let conn = client.connect(rig.server.addr(), alpn).await.unwrap();
            assert_eq!(
                closed_with(&conn).await,
                Some(REFUSED_UNREGISTERED),
                "{alpn:?}"
            );
        }
        let log = rig.gate.recent_refusals();
        assert!(
            log.iter()
                .any(|r| r.alpn == "tenzro/infer" && r.reason.contains("no registered identity"))
        );
        assert!(log.iter().any(|r| r.alpn == "tenzro/consensus"));
    }

    #[tokio::test]
    async fn over_real_connections_a_registered_peer_is_served_everything() {
        let rig = rig(GateMode::Enforce, |_| {}).await;
        let key = TestMachineKey::from_seed(32);
        let (client, conn) = dial(&rig, OPEN_ALPN).await;
        let did = name(&rig, &client, &key, 1);
        drop(conn);
        rig.registry.register(&did);
        let conn = client
            .connect(rig.server.addr(), crate::request::ALPN_INFER)
            .await
            .unwrap();
        assert!(echoes(&conn).await);
    }

    #[tokio::test]
    async fn the_sweep_removes_a_revoked_identity_that_stayed_connected() {
        let rig = rig(GateMode::Enforce, |_| {}).await;
        let key = TestMachineKey::from_seed(33);
        let (client, conn) = dial(&rig, crate::request::ALPN_INFER).await;
        // No record names it yet and the protocol is gated: the gate waits the
        // handshake timeout for one, then refuses.
        assert_eq!(closed_with(&conn).await, Some(REFUSED_UNREGISTERED));

        // Now it is named and registered, and connects.
        let did = name(&rig, &client, &key, 1);
        rig.registry.register(&did);
        let conn = client
            .connect(rig.server.addr(), crate::request::ALPN_INFER)
            .await
            .unwrap();
        assert!(echoes(&conn).await);

        // Governance revokes it. Nothing has closed the connection yet.
        rig.registry.revoke(&did);
        assert!(echoes(&conn).await, "still connected before the sweep");
        let report = rig.gate.sweep(now_ms());
        assert_eq!(report.revoked.len(), 1);
        assert_eq!(report.closed, 1);
        assert_eq!(closed_with(&conn).await, Some(REFUSED_REVOKED));
        assert!(
            rig.gate
                .recent_refusals()
                .iter()
                .any(|r| r.reason.contains("identity revoked") && r.action == "closed")
        );
    }

    #[tokio::test]
    async fn the_sweep_ends_an_onboarding_window_and_closes_its_connection() {
        let rig = rig(GateMode::Enforce, |_| {}).await;
        let key = TestMachineKey::from_seed(34);
        let (client, conn) = dial(&rig, OPEN_ALPN).await;
        name(&rig, &client, &key, 1);
        assert!(echoes(&conn).await);
        // 31 minutes later.
        let report = rig.gate.sweep(now_ms() + 31 * MIN);
        assert_eq!(report.expired.len(), 1);
        assert_eq!(report.closed, 1);
        assert_eq!(closed_with(&conn).await, Some(ONBOARDING_ENDED));
        // A repeat attempt inside the back-off is refused.
        let again = client.connect(rig.server.addr(), OPEN_ALPN).await.unwrap();
        assert_eq!(closed_with(&again).await, Some(ONBOARDING_REFUSED));
    }

    #[tokio::test]
    async fn the_sweep_quarantines_a_participant_that_was_connected_before_the_gate_knew_better() {
        // The gate starts in audit (the live network before enforcement): the
        // peer holds full access. Enforcement turns on; the sweep removes it.
        let rig = rig(GateMode::Audit, |_| {}).await;
        let key = TestMachineKey::from_seed(35);
        let (client, conn) = dial(&rig, crate::request::ALPN_INFER).await;
        name(&rig, &client, &key, 1);
        assert!(echoes(&conn).await, "audit mode serves it");
        let mut p = rig.gate.policy();
        p.mode = GateMode::Enforce;
        rig.gate.set_policy(p);
        let report = rig.gate.sweep(now_ms());
        assert_eq!(report.quarantined.len(), 1, "{report:?}");
        assert_eq!(closed_with(&conn).await, Some(REFUSED_UNREGISTERED));
    }

    #[tokio::test]
    async fn a_window_that_ended_while_the_registry_was_not_ready_closes_at_the_next_sweep() {
        let rig = rig(GateMode::Enforce, |_| {}).await;
        let key = TestMachineKey::from_seed(36);
        let (client, conn) = dial(&rig, OPEN_ALPN).await;
        name(&rig, &client, &key, 1);
        assert!(echoes(&conn).await);
        // The node is syncing when the window ends: nobody can be judged.
        rig.registry.not_ready.store(true, Ordering::SeqCst);
        let report = rig.gate.sweep(now_ms() + 31 * MIN);
        assert_eq!((report.expired.len(), report.closed), (1, 0), "{report:?}");
        assert!(
            echoes(&conn).await,
            "left alone while the registry cannot say"
        );
        // Once it can, the connection of the ended session goes.
        rig.registry.not_ready.store(false, Ordering::SeqCst);
        let report = rig.gate.sweep(now_ms() + 31 * MIN);
        assert_eq!(report.closed, 1, "{report:?}");
        assert_eq!(closed_with(&conn).await, Some(ONBOARDING_ENDED));
    }

    #[tokio::test]
    async fn one_peer_on_several_connections_holds_one_session_until_its_last_connection_closes() {
        let rig = rig(GateMode::Enforce, |p| {
            p.max_sessions = 1;
            p.max_sessions_per_source = 100;
        })
        .await;
        let (client, a) = dial(&rig, OPEN_ALPN).await;
        let b = client.connect(rig.server.addr(), OPEN_ALPN).await.unwrap();
        assert!(
            echoes(&a).await && echoes(&b).await,
            "both connections are served"
        );
        assert_eq!(rig.gate.open_sessions(), 1);
        // The one place is taken, and stays taken while either is open.
        let (_c2, other) = dial(&rig, OPEN_ALPN).await;
        assert_eq!(closed_with(&other).await, Some(ONBOARDING_REFUSED));
        a.close(0u32.into(), b"done");
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(rig.gate.open_sessions(), 1);
        assert!(echoes(&b).await, "the second connection is still served");
        b.close(0u32.into(), b"done");
        assert!(
            sessions_reach(&rig.gate, 0).await,
            "the session ends with its last connection"
        );
        let (_c3, next) = dial(&rig, OPEN_ALPN).await;
        assert!(echoes(&next).await);
    }

    #[tokio::test]
    async fn too_many_onboarding_sessions_are_refused_and_the_place_returns_when_one_closes() {
        let rig = rig(GateMode::Enforce, |p| {
            p.max_sessions = 2;
            p.max_sessions_per_source = 100;
        })
        .await;
        let (_c1, a) = dial(&rig, OPEN_ALPN).await;
        let (_c2, b) = dial(&rig, OPEN_ALPN).await;
        assert!(echoes(&a).await && echoes(&b).await);
        let (_c3, c) = dial(&rig, OPEN_ALPN).await;
        assert_eq!(closed_with(&c).await, Some(ONBOARDING_REFUSED));
        a.close(0u32.into(), b"done");
        assert!(
            sessions_reach(&rig.gate, 1).await,
            "a closed session gives its place back"
        );
        let (_c4, d) = dial(&rig, OPEN_ALPN).await;
        assert!(echoes(&d).await);
    }

    /// A peer redialling what it is refused gets one log line per interval
    /// on each protocol, the next naming how many were left out; another
    /// peer or protocol is logged at once, and the pacing holds a bounded
    /// number of pairs.
    #[test]
    fn refusals_of_one_peer_are_logged_once_per_interval() {
        let mut pacing = RefusalPacing::default();
        assert_eq!(pacing.admit("a", "tenzro/consensus", 0), Some(0));
        for t in 1..=5 {
            assert_eq!(pacing.admit("a", "tenzro/consensus", t * 1_000), None);
        }
        assert_eq!(pacing.admit("a", "tenzro/mcp/3", 6_000), Some(0));
        assert_eq!(pacing.admit("b", "tenzro/consensus", 6_000), Some(0));
        assert_eq!(
            pacing.admit("a", "tenzro/consensus", REFUSAL_LOG_INTERVAL_MS),
            Some(5)
        );
        assert_eq!(
            pacing.admit("a", "tenzro/consensus", REFUSAL_LOG_INTERVAL_MS + 1),
            None
        );
        for p in 0..(2 * PACED_REFUSALS) {
            pacing.admit(&p.to_string(), "tenzro/consensus", 0);
        }
        assert_eq!(pacing.last.len(), PACED_REFUSALS);
    }
}
