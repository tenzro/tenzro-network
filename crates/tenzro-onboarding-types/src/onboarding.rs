//! The identity gate: what a node lets in without a registered identity, and
//! for how long.
//!
//! Tenzro has no participants without an identity and a wallet. A node that
//! meets a peer or a caller whose machine identity is not in the identity
//! registry (mirrored from consensus state) gives it an *onboarding session*
//! and nothing else: enough to sync and learn the registry, and to make a
//! registration request. This module holds the pure rules of that session,
//! with every clock reading passed in, so the rules are tested without
//! sleeping:
//!
//! - [`OnboardingPolicy`]: the node settings (window, extension, back-off,
//!   session limits). Node-local; none of it is consensus.
//! - [`OnboardingLedger`]: first contact per peer identity AND per hardware
//!   root, so a reconnect or a new endpoint key does not restart the window;
//!   one extension while an owner approval is in progress; exponential
//!   back-off after expiry; concurrent-session limits in total, per source
//!   and per root; a bound on what the ledger itself remembers.
//! - [`SponsorLedger`]: the quota behind a sponsored first registration, per
//!   hardware root, per owner approval, per source and in total per day.
//! - [`ApprovalBook`]: the single-use, expiring challenge an owner approval
//!   answers, bound to the machine identity, the endpoint and the label.
//!
//! The values below are the default guidance: 60 s to
//! present an identity, 30 minutes to get in order, 5 minutes per approval
//! challenge. They are settings, not protocol constants.

use std::collections::{HashMap, VecDeque};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// What the identity registry says about an identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Standing {
    /// Registered and not revoked.
    Registered,
    /// Registered and then revoked, by its root or by governance.
    Revoked,
    /// Not in the registry (or no identity could be named at all).
    Unregistered,
}

impl Standing {
    /// Whether the identity may act as a participant.
    pub fn is_registered(self) -> bool {
        self == Standing::Registered
    }

    /// The reason logged when this standing is refused.
    pub fn refusal(self) -> &'static str {
        match self {
            Standing::Registered => "registered",
            Standing::Revoked => "identity revoked",
            Standing::Unregistered => "no registered identity",
        }
    }
}

/// How hard the gate acts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GateMode {
    /// No gate: today's behaviour.
    Off,
    /// The gate decides and logs the decision, and refuses nothing. For
    /// observing a live network before enforcing on it.
    Audit,
    /// The gate refuses.
    Enforce,
}

/// Node settings of the identity gate. All node-local.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct OnboardingPolicy {
    /// How hard the gate acts.
    pub mode: GateMode,
    /// How long a connection may take to name an identity before it is
    /// dropped (Bitcoin Core's version handshake timeout is 60 s).
    #[serde(with = "secs")]
    pub handshake_timeout: Duration,
    /// The onboarding window from first contact.
    #[serde(with = "secs")]
    pub window: Duration,
    /// How much one extension adds while an owner approval is in progress.
    #[serde(with = "secs")]
    pub extension: Duration,
    /// Extensions a subject may use in total (not per session).
    pub max_extensions: u32,
    /// How long an approval challenge is valid (WebAuthn guidance is 5 to
    /// 10 minutes).
    #[serde(with = "secs")]
    pub challenge_ttl: Duration,
    /// The first back-off after an expired window; it doubles per strike.
    #[serde(with = "secs")]
    pub backoff_base: Duration,
    /// The longest back-off.
    #[serde(with = "secs")]
    pub backoff_cap: Duration,
    /// Onboarding sessions open at once, all sources together.
    pub max_sessions: usize,
    /// Onboarding sessions open at once from one source.
    pub max_sessions_per_source: usize,
    /// Onboarding sessions open at once for one hardware root.
    pub max_sessions_per_root: usize,
    /// Subjects first seen from one source in an hour.
    pub max_new_subjects_per_source_hour: usize,
    /// Subjects the ledger remembers; past it a new unknown subject is
    /// refused rather than the table grown.
    pub max_tracked: usize,
}

impl Default for OnboardingPolicy {
    fn default() -> Self {
        Self {
            // The rule is "no participants without an identity"; a node
            // enforces it with `mode = "enforce"`. It starts in audit (decide
            // and log, refuse nothing) until the from-empty smoke run has
            // shown that enforcing it leaves a live network able to sync and
            // order blocks.
            mode: GateMode::Audit,
            handshake_timeout: Duration::from_secs(60),
            window: Duration::from_secs(30 * 60),
            extension: Duration::from_secs(10 * 60),
            max_extensions: 1,
            challenge_ttl: Duration::from_secs(5 * 60),
            backoff_base: Duration::from_secs(60),
            backoff_cap: Duration::from_secs(6 * 3600),
            max_sessions: 64,
            max_sessions_per_source: 4,
            max_sessions_per_root: 2,
            max_new_subjects_per_source_hour: 16,
            max_tracked: 16_384,
        }
    }
}

mod secs {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::time::Duration;

    pub fn serialize<S: Serializer>(d: &Duration, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u64(d.as_secs())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
        u64::deserialize(d).map(Duration::from_secs)
    }
}

fn ms(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

/// Who is asking for an onboarding session.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Who {
    /// The peer's transport identity (an iroh endpoint id). It changes at
    /// every bind, so on its own it proves little.
    pub endpoint: String,
    /// The hardware root it is tied to: the machine DID a verified endpoint
    /// record names. `None` when no record names the endpoint.
    pub root: Option<String>,
    /// Where it came from (an address prefix, a relay): the unit of the
    /// per-source limits. `None` when unknown.
    pub source: Option<String>,
}

/// Why a session was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// A previous window expired; the next attempt is allowed at `until_ms`.
    BackedOff {
        /// When the subject may try again (ms since the epoch).
        until_ms: u64,
        /// The strike that set this back-off.
        strikes: u32,
    },
    /// Too many onboarding sessions are open.
    TooManySessions(&'static str),
    /// This source has introduced too many new subjects this hour.
    TooManyNewSubjects,
    /// The ledger is full of live subjects.
    LedgerFull,
}

impl Refusal {
    /// The reason logged with the refusal.
    pub fn reason(&self) -> String {
        match self {
            Refusal::BackedOff { until_ms, strikes } => {
                format!(
                    "onboarding window expired earlier (strike {strikes}); backed off until {until_ms}"
                )
            }
            Refusal::TooManySessions(scope) => {
                format!("too many onboarding sessions open ({scope})")
            }
            Refusal::TooManyNewSubjects => {
                "this source introduced too many new unregistered peers this hour".into()
            }
            Refusal::LedgerFull => "the onboarding ledger is full".into(),
        }
    }
}

/// An open onboarding session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SessionId(pub u64);

/// A session's standing at a check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    /// Still inside its window.
    Active {
        /// Milliseconds left.
        remaining_ms: u64,
    },
    /// The window ended; the session is closed and the subject backed off.
    Expired {
        /// When the subject may try again.
        retry_at_ms: u64,
    },
    /// No such session (closed, or registered since).
    Gone,
}

/// A session the sweep ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Expired {
    /// The session.
    pub session: SessionId,
    /// Who held it.
    pub who: Who,
    /// When the subject may try again.
    pub retry_at_ms: u64,
}

#[derive(Debug, Default, Clone)]
struct Entry {
    first_contact_ms: u64,
    expires_ms: u64,
    extensions_used: u32,
    approval_until_ms: Option<u64>,
    strikes: u32,
    backoff_until_ms: u64,
    last_seen_ms: u64,
    /// A window is running (as opposed to a back-off being served).
    open: bool,
}

#[derive(Debug, Clone)]
struct Session {
    who: Who,
    /// The ledger keys the session's window is counted under.
    keys: Vec<Key>,
    /// The connections that hold the session; it ends with the last one.
    holders: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum Key {
    Root(String),
    Endpoint(String),
}

/// First contact, windows, back-off and session limits of unregistered
/// peers. Not thread-safe by itself; wrap it in a mutex.
#[derive(Debug)]
pub struct OnboardingLedger {
    policy: OnboardingPolicy,
    entries: HashMap<Key, Entry>,
    sessions: HashMap<SessionId, Session>,
    next_session: u64,
    per_source: HashMap<String, usize>,
    per_root: HashMap<String, usize>,
    /// First sightings per source, oldest first.
    source_sightings: HashMap<String, VecDeque<u64>>,
    /// Sessions a contact found ended, kept for the next sweep to report.
    ended: Vec<Expired>,
}

impl OnboardingLedger {
    /// A ledger under `policy`.
    pub fn new(policy: OnboardingPolicy) -> Self {
        Self {
            policy,
            entries: HashMap::new(),
            sessions: HashMap::new(),
            next_session: 1,
            per_source: HashMap::new(),
            per_root: HashMap::new(),
            source_sightings: HashMap::new(),
            ended: Vec::new(),
        }
    }

    /// The policy in force.
    pub fn policy(&self) -> &OnboardingPolicy {
        &self.policy
    }

    /// Whether `session` is open.
    pub fn is_open(&self, session: SessionId) -> bool {
        self.sessions.contains_key(&session)
    }

    /// Sessions open now.
    pub fn open_sessions(&self) -> usize {
        self.sessions.len()
    }

    fn keys(who: &Who) -> Vec<Key> {
        let mut keys = Vec::with_capacity(2);
        if let Some(root) = &who.root {
            keys.push(Key::Root(root.clone()));
        }
        keys.push(Key::Endpoint(who.endpoint.clone()));
        keys
    }

    /// Opens (or refuses) an onboarding session for `who` at `now_ms`, or
    /// joins the one its endpoint key holds already.
    ///
    /// A session belongs to a subject, not to a connection. A joining node
    /// holds several connections to one member at a time (discovery, state
    /// sync, block sync, gossip, the registration request), and each of them
    /// is the same subject inside the same window: a contact from an endpoint
    /// key that holds a session returns that session and counts one more
    /// holder, and the session limits, which count subjects, are not asked
    /// again. [`Self::close`] gives a holder back.
    ///
    /// The window is counted from the earliest first contact under any key
    /// the subject presents: a reconnect, or a new endpoint key on the same
    /// hardware root, finds its window already running (or already spent).
    pub fn contact(&mut self, now_ms: u64, who: &Who) -> Result<(SessionId, u64), Refusal> {
        let mut keys = Self::keys(who);

        // A window that ended before the sweep came by is not renewed by one
        // more connection: the session ends here, with its strike, and the
        // next sweep reports it.
        let mut sharing: Vec<SessionId> = self
            .sessions
            .iter()
            .filter(|(_, s)| s.keys.iter().any(|k| keys.contains(k)))
            .map(|(id, _)| *id)
            .collect();
        sharing.sort();
        for id in sharing {
            let held_by = self.sessions.get(&id).map(|s| s.who.clone());
            if let (SessionState::Expired { retry_at_ms }, Some(held_by)) =
                (self.check(now_ms, id), held_by)
            {
                if self.ended.len() >= self.policy.max_sessions.max(1) {
                    self.ended.remove(0);
                }
                self.ended.push(Expired {
                    session: id,
                    who: held_by,
                    retry_at_ms,
                });
            }
        }

        // The session this endpoint key holds already, if any. A key that
        // named no hardware root at first may name one later; a key that
        // names another root is another subject.
        let held = self
            .sessions
            .iter()
            .filter(|(_, s)| {
                s.who.endpoint == who.endpoint
                    && (s.who.root.is_none() || who.root.is_none() || s.who.root == who.root)
            })
            .map(|(id, _)| *id)
            .min();
        if let Some(s) = held.and_then(|id| self.sessions.get(&id)) {
            for k in &s.keys {
                if !keys.contains(k) {
                    keys.push(k.clone());
                }
            }
        }

        let known: Vec<Entry> = keys
            .iter()
            .filter_map(|k| self.entries.get(k).cloned())
            .collect();

        // Back-off under any key binds the subject.
        if let Some(until) = known
            .iter()
            .filter(|e| e.backoff_until_ms > now_ms)
            .map(|e| (e.backoff_until_ms, e.strikes))
            .max()
        {
            return Err(Refusal::BackedOff {
                until_ms: until.0,
                strikes: until.1,
            });
        }

        match held {
            None => self.place_for(now_ms, who, known.is_empty())?,
            Some(id) => {
                // The session takes the hardware root its key names now,
                // if that root has a place left.
                let unnamed = self.sessions.get(&id).is_some_and(|s| s.who.root.is_none());
                if unnamed
                    && let Some(root) = &who.root
                    && self.per_root.get(root).copied().unwrap_or(0)
                        >= self.policy.max_sessions_per_root
                {
                    return Err(Refusal::TooManySessions("this hardware root"));
                }
            }
        }

        // The merged entry. A window already running under any key keeps
        // running: the earliest first contact and the latest expiry granted
        // (an extension under one key stands for the others) carry over, and
        // a reconnect does not renew it.
        let mut merged = Entry {
            first_contact_ms: now_ms,
            expires_ms: now_ms.saturating_add(ms(self.policy.window)),
            last_seen_ms: now_ms,
            open: true,
            ..Entry::default()
        };
        let running: Vec<&Entry> = known
            .iter()
            .filter(|e| e.open && e.expires_ms > now_ms)
            .collect();
        if !running.is_empty() {
            merged.first_contact_ms = running
                .iter()
                .map(|e| e.first_contact_ms)
                .min()
                .unwrap_or(now_ms);
            merged.expires_ms = running
                .iter()
                .map(|e| e.expires_ms)
                .max()
                .unwrap_or(merged.expires_ms);
            merged.extensions_used = running.iter().map(|e| e.extensions_used).max().unwrap_or(0);
            merged.approval_until_ms = running.iter().map(|e| e.approval_until_ms).max().flatten();
        }
        merged.strikes = known.iter().map(|e| e.strikes).max().unwrap_or(0);
        let expires = merged.expires_ms;
        for k in &keys {
            self.entries.insert(k.clone(), merged.clone());
        }

        if let Some(id) = held {
            if let Some(s) = self.sessions.get_mut(&id) {
                s.holders += 1;
                if s.who.root.is_none()
                    && let Some(root) = &who.root
                {
                    s.who.root = Some(root.clone());
                    *self.per_root.entry(root.clone()).or_default() += 1;
                }
                s.keys = keys;
            }
            return Ok((id, expires.saturating_sub(now_ms)));
        }
        let id = SessionId(self.next_session);
        self.next_session += 1;
        if let Some(source) = &who.source {
            *self.per_source.entry(source.clone()).or_default() += 1;
        }
        if let Some(root) = &who.root {
            *self.per_root.entry(root.clone()).or_default() += 1;
        }
        self.sessions.insert(
            id,
            Session {
                who: who.clone(),
                keys,
                holders: 1,
            },
        );
        Ok((id, expires.saturating_sub(now_ms)))
    }

    /// Whether a subject that holds no session may open one at `now_ms`: the
    /// session limits and, for a subject with no record (`is_new`), the room
    /// left in the ledger and its source's hourly allowance of new subjects.
    fn place_for(&mut self, now_ms: u64, who: &Who, is_new: bool) -> Result<(), Refusal> {
        // Session limits.
        if self.sessions.len() >= self.policy.max_sessions {
            return Err(Refusal::TooManySessions("all sources"));
        }
        if let Some(source) = &who.source
            && self.per_source.get(source).copied().unwrap_or(0)
                >= self.policy.max_sessions_per_source
        {
            return Err(Refusal::TooManySessions("this source"));
        }
        if let Some(root) = &who.root
            && self.per_root.get(root).copied().unwrap_or(0) >= self.policy.max_sessions_per_root
        {
            return Err(Refusal::TooManySessions("this hardware root"));
        }

        if is_new {
            if self.entries.len() >= self.policy.max_tracked {
                self.forget_idle(now_ms);
                if self.entries.len() >= self.policy.max_tracked {
                    return Err(Refusal::LedgerFull);
                }
            }
            if let Some(source) = &who.source {
                let hour = 3_600_000u64;
                let q = self.source_sightings.entry(source.clone()).or_default();
                while q.front().is_some_and(|t| now_ms.saturating_sub(*t) >= hour) {
                    q.pop_front();
                }
                if q.len() >= self.policy.max_new_subjects_per_source_hour {
                    return Err(Refusal::TooManyNewSubjects);
                }
                q.push_back(now_ms);
            }
        }
        Ok(())
    }

    /// Records that an owner approval for `who` is visibly in progress until
    /// `until_ms`: when the window ends before that, it is extended once.
    pub fn approval_in_progress(&mut self, who: &Who, until_ms: u64) {
        for k in Self::keys(who) {
            if let Some(e) = self.entries.get_mut(&k) {
                e.approval_until_ms = Some(until_ms);
            }
        }
    }

    /// The state of `session` at `now_ms`; an ended window closes the
    /// session and starts the subject's back-off.
    pub fn check(&mut self, now_ms: u64, session: SessionId) -> SessionState {
        let Some(s) = self.sessions.get(&session) else {
            return SessionState::Gone;
        };
        let keys = s.keys.clone();
        let Some(expires) = keys
            .iter()
            .filter_map(|k| self.entries.get(k))
            .map(|e| e.expires_ms)
            .max()
        else {
            return SessionState::Gone;
        };
        if now_ms < expires {
            return SessionState::Active {
                remaining_ms: expires - now_ms,
            };
        }
        // The window ended. One extension while an approval is in progress.
        let extend = keys.iter().filter_map(|k| self.entries.get(k)).any(|e| {
            e.approval_until_ms.is_some_and(|t| t > now_ms)
                && e.extensions_used < self.policy.max_extensions
        });
        if extend {
            let new_expiry = now_ms.saturating_add(ms(self.policy.extension));
            for k in &keys {
                if let Some(e) = self.entries.get_mut(k) {
                    e.extensions_used += 1;
                    e.expires_ms = new_expiry;
                }
            }
            return SessionState::Active {
                remaining_ms: new_expiry - now_ms,
            };
        }
        let retry = self.expire(now_ms, &keys);
        self.end(session);
        SessionState::Expired { retry_at_ms: retry }
    }

    fn expire(&mut self, now_ms: u64, keys: &[Key]) -> u64 {
        // One window, one strike: two endpoint keys on one hardware root
        // share a window, and when it ends the second session takes the
        // strike and the back-off the first one set.
        let served = keys
            .iter()
            .filter_map(|k| self.entries.get(k))
            .filter(|e| !e.open && e.backoff_until_ms > now_ms)
            .map(|e| (e.backoff_until_ms, e.strikes))
            .max();
        let strikes = keys
            .iter()
            .filter_map(|k| self.entries.get(k))
            .map(|e| e.strikes)
            .max()
            .unwrap_or(0)
            + 1;
        let shift = (strikes - 1).min(32);
        let wait = ms(self.policy.backoff_base)
            .saturating_mul(1u64 << shift)
            .min(ms(self.policy.backoff_cap));
        let until = now_ms.saturating_add(wait);
        let (until, strikes) = served.unwrap_or((until, strikes));
        for k in keys {
            if let Some(e) = self.entries.get_mut(k) {
                e.strikes = strikes;
                e.backoff_until_ms = until;
                e.open = false;
            }
        }
        until
    }

    /// Ends every session whose window is over at `now_ms` (extending those
    /// with an approval in progress) and returns the ones ended, with those
    /// a contact found ended since the last sweep.
    pub fn sweep(&mut self, now_ms: u64) -> Vec<Expired> {
        let ids: Vec<SessionId> = self.sessions.keys().copied().collect();
        let mut out = std::mem::take(&mut self.ended);
        for id in ids {
            let who = self.sessions.get(&id).map(|s| s.who.clone());
            if let (SessionState::Expired { retry_at_ms }, Some(who)) =
                (self.check(now_ms, id), who)
            {
                out.push(Expired {
                    session: id,
                    who,
                    retry_at_ms,
                });
            }
        }
        out.sort_by_key(|e| e.session);
        out
    }

    /// One connection that held `session` ended. The session ends, without
    /// a strike, when its last connection does.
    pub fn close(&mut self, session: SessionId) {
        let Some(s) = self.sessions.get_mut(&session) else {
            return;
        };
        s.holders = s.holders.saturating_sub(1);
        if s.holders == 0 {
            self.end(session);
        }
    }

    /// Ends `session` whatever holds it, and gives its places back.
    fn end(&mut self, session: SessionId) {
        if let Some(s) = self.sessions.remove(&session) {
            if let Some(source) = &s.who.source
                && let Some(n) = self.per_source.get_mut(source)
            {
                *n = n.saturating_sub(1);
                if *n == 0 {
                    self.per_source.remove(source);
                }
            }
            if let Some(root) = &s.who.root
                && let Some(n) = self.per_root.get_mut(root)
            {
                *n = n.saturating_sub(1);
                if *n == 0 {
                    self.per_root.remove(root);
                }
            }
        }
    }

    /// `who` is registered now: its window, strikes and back-off go, and its
    /// sessions are returned (the gate re-classifies them as full).
    pub fn registered(&mut self, who: &Who) -> Vec<SessionId> {
        let keys = Self::keys(who);
        let ids: Vec<SessionId> = self
            .sessions
            .iter()
            .filter(|(_, s)| s.keys.iter().any(|k| keys.contains(k)))
            .map(|(id, _)| *id)
            .collect();
        for k in &keys {
            self.entries.remove(k);
        }
        for id in &ids {
            self.end(*id);
        }
        ids
    }

    /// Drops entries with no session, no back-off to serve and no recent
    /// sighting, so the table does not grow without bound.
    fn forget_idle(&mut self, now_ms: u64) {
        let live: std::collections::HashSet<&Key> =
            self.sessions.values().flat_map(|s| s.keys.iter()).collect();
        let hour = 3_600_000u64;
        let live: std::collections::HashSet<Key> = live.into_iter().cloned().collect();
        self.entries.retain(|k, e| {
            live.contains(k)
                || e.backoff_until_ms > now_ms
                || now_ms.saturating_sub(e.last_seen_ms) < hour
        });
    }
}

// ---------------------------------------------------------------------------
// Sponsored first registration
// ---------------------------------------------------------------------------

/// The quota of sponsored first registrations. A sponsor is a node that pays
/// the registration fee from its own funded account (node-local; nothing in
/// consensus changes: the registration statement is not bound to the paying
/// account).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SponsorPolicy {
    /// Whether this node sponsors at all.
    pub enabled: bool,
    /// Identities one hardware root may have sponsored, ever. A delegated
    /// root counts against its provider.
    pub max_per_root: u32,
    /// Identities one owner approval may sponsor.
    pub max_per_owner: u32,
    /// Sponsored registrations per source per day.
    pub max_per_source_day: u32,
    /// Sponsored registrations in total per day.
    pub max_per_day: u32,
    /// Most fee (smallest unit) one sponsored registration may cost. Written
    /// as an integer, or as a string when it exceeds a TOML integer.
    #[serde(with = "fee_amount")]
    pub max_fee: u128,
    /// Whether an owner approval is required before the sponsor pays.
    pub require_owner_approval: bool,
}

impl Default for SponsorPolicy {
    fn default() -> Self {
        Self {
            enabled: false,
            max_per_root: 1,
            max_per_owner: 8,
            max_per_source_day: 4,
            max_per_day: 200,
            // 0.0016 TNZO at 18 decimals is the registration fee today; the
            // cap leaves room for the gas price to move, not for abuse.
            max_fee: 5_000_000_000_000_000,
            require_owner_approval: true,
        }
    }
}

/// A fee amount in a configuration file. TOML has no 128-bit integer, so an
/// amount is written as an integer when it fits a signed 64-bit one and as a
/// decimal string otherwise; either form reads back.
mod fee_amount {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(value: &u128, serializer: S) -> Result<S::Ok, S::Error> {
        match i64::try_from(*value) {
            Ok(v) => serializer.serialize_i64(v),
            Err(_) => serializer.serialize_str(&value.to_string()),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u128, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Amount {
            Int(u64),
            Text(String),
        }
        match Amount::deserialize(deserializer)? {
            Amount::Int(v) => Ok(u128::from(v)),
            Amount::Text(s) => s.trim().parse().map_err(serde::de::Error::custom),
        }
    }
}

/// A request for a sponsored first registration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SponsorAsk {
    /// The hardware root (machine DID) to register.
    pub root: String,
    /// The provider holding a delegated root, when it is delegated.
    pub provider: Option<String>,
    /// The owner identity whose approval backs it, when one was shown.
    pub owner: Option<String>,
    /// Where the request came from.
    pub source: Option<String>,
    /// The fee the registration will cost.
    pub fee: u128,
}

/// Why a sponsored registration was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SponsorRefusal {
    /// This node does not sponsor.
    Disabled,
    /// No owner approval was shown.
    NoOwnerApproval,
    /// The root already had its sponsored registration.
    RootExhausted,
    /// The root's provider has sponsored its share.
    ProviderExhausted,
    /// The owner approval has sponsored its share.
    OwnerExhausted,
    /// The source has used its day.
    SourceExhausted,
    /// The node has sponsored its day.
    DayExhausted,
    /// The fee is above the cap.
    FeeAboveCap,
}

impl SponsorRefusal {
    /// The reason logged with the refusal.
    pub fn reason(&self) -> &'static str {
        match self {
            Self::Disabled => "this node does not sponsor registrations",
            Self::NoOwnerApproval => "a sponsored registration needs an owner approval",
            Self::RootExhausted => "this hardware root already had its sponsored registration",
            Self::ProviderExhausted => "this root's provider has sponsored its share of roots",
            Self::OwnerExhausted => "this owner approval has sponsored its share of identities",
            Self::SourceExhausted => "this source used its sponsored registrations for the day",
            Self::DayExhausted => "this node used its sponsored registrations for the day",
            Self::FeeAboveCap => "the registration fee is above the sponsor's cap",
        }
    }
}

/// A reserved sponsored registration. Release it if the transaction was not
/// admitted; keep it once it was.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SponsorGrant {
    root: String,
    provider: Option<String>,
    owner: Option<String>,
    source: Option<String>,
    day: u64,
}

/// Counts of sponsored registrations.
#[derive(Debug, Default)]
pub struct SponsorLedger {
    policy: SponsorPolicy,
    by_root: HashMap<String, u32>,
    by_provider: HashMap<String, u32>,
    by_owner: HashMap<String, u32>,
    by_source_day: HashMap<(String, u64), u32>,
    by_day: HashMap<u64, u32>,
}

const DAY_MS: u64 = 86_400_000;

impl SponsorLedger {
    /// A ledger under `policy`.
    pub fn new(policy: SponsorPolicy) -> Self {
        Self {
            policy,
            ..Self::default()
        }
    }

    /// Reserves one sponsored registration for `ask` at `now_ms`, or says why
    /// not. Nothing is reserved on a refusal.
    pub fn authorise(
        &mut self,
        now_ms: u64,
        ask: &SponsorAsk,
    ) -> Result<SponsorGrant, SponsorRefusal> {
        let p = self.policy;
        if !p.enabled {
            return Err(SponsorRefusal::Disabled);
        }
        if ask.fee > p.max_fee {
            return Err(SponsorRefusal::FeeAboveCap);
        }
        if p.require_owner_approval && ask.owner.is_none() {
            return Err(SponsorRefusal::NoOwnerApproval);
        }
        let day = now_ms / DAY_MS;
        if self.by_root.get(&ask.root).copied().unwrap_or(0) >= p.max_per_root {
            return Err(SponsorRefusal::RootExhausted);
        }
        if let Some(provider) = &ask.provider
            && self.by_provider.get(provider).copied().unwrap_or(0) >= p.max_per_owner
        {
            return Err(SponsorRefusal::ProviderExhausted);
        }
        if let Some(owner) = &ask.owner
            && self.by_owner.get(owner).copied().unwrap_or(0) >= p.max_per_owner
        {
            return Err(SponsorRefusal::OwnerExhausted);
        }
        if let Some(source) = &ask.source
            && self
                .by_source_day
                .get(&(source.clone(), day))
                .copied()
                .unwrap_or(0)
                >= p.max_per_source_day
        {
            return Err(SponsorRefusal::SourceExhausted);
        }
        if self.by_day.get(&day).copied().unwrap_or(0) >= p.max_per_day {
            return Err(SponsorRefusal::DayExhausted);
        }
        *self.by_root.entry(ask.root.clone()).or_default() += 1;
        if let Some(provider) = &ask.provider {
            *self.by_provider.entry(provider.clone()).or_default() += 1;
        }
        if let Some(owner) = &ask.owner {
            *self.by_owner.entry(owner.clone()).or_default() += 1;
        }
        if let Some(source) = &ask.source {
            *self.by_source_day.entry((source.clone(), day)).or_default() += 1;
        }
        *self.by_day.entry(day).or_default() += 1;
        // Days before yesterday are forgotten.
        self.by_day.retain(|d, _| *d + 1 >= day);
        self.by_source_day.retain(|(_, d), _| *d + 1 >= day);
        Ok(SponsorGrant {
            root: ask.root.clone(),
            provider: ask.provider.clone(),
            owner: ask.owner.clone(),
            source: ask.source.clone(),
            day,
        })
    }

    /// Gives a reservation back: the transaction was not admitted.
    pub fn release(&mut self, grant: SponsorGrant) {
        fn dec<K: std::hash::Hash + Eq>(m: &mut HashMap<K, u32>, k: &K) {
            if let Some(n) = m.get_mut(k) {
                *n = n.saturating_sub(1);
                if *n == 0 {
                    m.remove(k);
                }
            }
        }
        dec(&mut self.by_root, &grant.root);
        if let Some(p) = &grant.provider {
            dec(&mut self.by_provider, p);
        }
        if let Some(o) = &grant.owner {
            dec(&mut self.by_owner, o);
        }
        if let Some(s) = &grant.source {
            dec(&mut self.by_source_day, &(s.clone(), grant.day));
        }
        dec(&mut self.by_day, &grant.day);
    }
}

// ---------------------------------------------------------------------------
// Owner approval challenge
// ---------------------------------------------------------------------------

/// A challenge an owner approval answers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalChallenge {
    /// Single-use nonce.
    pub nonce: [u8; 16],
    /// The machine identity the approval is for.
    pub machine_did: String,
    /// The transport endpoint it was requested from.
    pub endpoint: String,
    /// The label the machine will carry.
    pub label: String,
    /// When it was issued (ms since the epoch).
    pub issued_ms: u64,
    /// When it stops being valid.
    pub expires_ms: u64,
}

impl ApprovalChallenge {
    /// The 32 bytes the owner's passkey signs: every binding is in it.
    pub fn statement(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"tenzro/onboarding/approval/v1");
        for field in [
            &self.nonce[..],
            self.machine_did.as_bytes(),
            self.endpoint.as_bytes(),
            self.label.as_bytes(),
        ] {
            h.update((field.len() as u64).to_le_bytes());
            h.update(field);
        }
        h.update(self.issued_ms.to_le_bytes());
        h.update(self.expires_ms.to_le_bytes());
        h.finalize().into()
    }
}

/// Why an approval was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalError {
    /// No such challenge, or it was already used.
    Unknown,
    /// The challenge has expired.
    Expired,
    /// The approval names another machine, endpoint or label than the
    /// challenge was issued for.
    Mismatch,
}

impl ApprovalError {
    /// The reason logged with the refusal.
    pub fn reason(self) -> &'static str {
        match self {
            Self::Unknown => "unknown or already used approval challenge",
            Self::Expired => "approval challenge expired",
            Self::Mismatch => "approval is for another machine, endpoint or label",
        }
    }
}

/// Issued, unspent challenges.
#[derive(Debug)]
pub struct ApprovalBook {
    ttl: Duration,
    cap: usize,
    open: HashMap<[u8; 16], ApprovalChallenge>,
}

impl ApprovalBook {
    /// A book issuing challenges valid for `ttl`, holding at most `cap`.
    pub fn new(ttl: Duration, cap: usize) -> Self {
        Self {
            ttl,
            cap: cap.max(1),
            open: HashMap::new(),
        }
    }

    /// Issues a challenge with `nonce` (the caller supplies randomness).
    pub fn issue(
        &mut self,
        now_ms: u64,
        nonce: [u8; 16],
        machine_did: &str,
        endpoint: &str,
        label: &str,
    ) -> ApprovalChallenge {
        self.open.retain(|_, c| c.expires_ms > now_ms);
        while self.open.len() >= self.cap {
            // Oldest first.
            let Some(oldest) = self
                .open
                .iter()
                .min_by_key(|(_, c)| c.issued_ms)
                .map(|(k, _)| *k)
            else {
                break;
            };
            self.open.remove(&oldest);
        }
        let challenge = ApprovalChallenge {
            nonce,
            machine_did: machine_did.to_string(),
            endpoint: endpoint.to_string(),
            label: label.to_string(),
            issued_ms: now_ms,
            expires_ms: now_ms.saturating_add(ms(self.ttl)),
        };
        self.open.insert(nonce, challenge.clone());
        challenge
    }

    /// Spends the challenge `nonce` for an approval naming `machine_did`,
    /// `endpoint` and `label`. A challenge is spent by the first attempt
    /// that reaches it, right or wrong, so a stale approval cannot be tried
    /// again.
    pub fn redeem(
        &mut self,
        now_ms: u64,
        nonce: &[u8; 16],
        machine_did: &str,
        endpoint: &str,
        label: &str,
    ) -> Result<ApprovalChallenge, ApprovalError> {
        let c = self.open.remove(nonce).ok_or(ApprovalError::Unknown)?;
        if now_ms >= c.expires_ms {
            return Err(ApprovalError::Expired);
        }
        if c.machine_did != machine_did || c.endpoint != endpoint || c.label != label {
            return Err(ApprovalError::Mismatch);
        }
        Ok(c)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_sponsor_fee_cap_reads_as_an_integer_or_a_string_and_writes_back() {
        let default = super::SponsorPolicy::default();
        let text = serde_json::to_string(&default).unwrap();
        assert!(text.contains("\"max_fee\":5000000000000000"), "{text}");
        let back: super::SponsorPolicy = serde_json::from_str(&text).unwrap();
        assert_eq!(back, default);
        let big = super::SponsorPolicy {
            max_fee: u128::from(u64::MAX) * 4,
            ..default
        };
        let text = serde_json::to_string(&big).unwrap();
        assert!(
            text.contains(&format!("\"max_fee\":\"{}\"", big.max_fee)),
            "{text}"
        );
        assert_eq!(
            serde_json::from_str::<super::SponsorPolicy>(&text).unwrap(),
            big
        );
        let quoted: super::SponsorPolicy = serde_json::from_str(r#"{"max_fee":"7"}"#).unwrap();
        assert_eq!(quoted.max_fee, 7);
    }

    use super::*;

    const MIN: u64 = 60_000;

    fn who(endpoint: &str, root: Option<&str>, source: Option<&str>) -> Who {
        Who {
            endpoint: endpoint.into(),
            root: root.map(Into::into),
            source: source.map(Into::into),
        }
    }

    fn ledger() -> OnboardingLedger {
        OnboardingLedger::new(OnboardingPolicy::default())
    }

    #[test]
    fn the_defaults_are_the_plans_values() {
        let p = OnboardingPolicy::default();
        assert_eq!(p.handshake_timeout, Duration::from_secs(60));
        assert_eq!(p.window, Duration::from_secs(1800));
        assert_eq!(p.challenge_ttl, Duration::from_secs(300));
        assert_eq!(p.max_extensions, 1);
    }

    #[test]
    fn a_window_runs_thirty_minutes_then_closes_and_backs_off() {
        let mut l = ledger();
        let w = who("e1", Some("did:tenzro:machine:a"), Some("1.2.3"));
        let (s, left) = l.contact(0, &w).unwrap();
        assert_eq!(left, 30 * MIN);
        assert_eq!(
            l.check(29 * MIN, s),
            SessionState::Active { remaining_ms: MIN }
        );
        let SessionState::Expired { retry_at_ms } = l.check(30 * MIN, s) else {
            panic!("window should have ended")
        };
        assert_eq!(retry_at_ms, 30 * MIN + MIN, "first back-off is one minute");
        assert_eq!(l.open_sessions(), 0);
        // Inside the back-off the same root is refused.
        assert!(matches!(
            l.contact(30 * MIN + 1, &w),
            Err(Refusal::BackedOff { strikes: 1, .. })
        ));
    }

    #[test]
    fn reconnecting_or_rebinding_does_not_reset_the_window() {
        let mut l = ledger();
        let root = Some("did:tenzro:machine:a");
        let (s1, _) = l.contact(0, &who("e1", root, Some("src"))).unwrap();
        l.close(s1);
        // Same endpoint, 20 minutes later: 10 minutes left, not 30.
        let (_, left) = l.contact(20 * MIN, &who("e1", root, Some("src"))).unwrap();
        assert_eq!(left, 10 * MIN);
        // A fresh endpoint key on the same hardware root: still 10 left.
        let (_, left) = l.contact(20 * MIN, &who("e2", root, Some("src"))).unwrap();
        assert_eq!(left, 10 * MIN);
    }

    #[test]
    fn a_new_endpoint_key_with_no_record_is_a_new_subject_but_limited_by_source() {
        let mut p = OnboardingPolicy::default();
        p.max_new_subjects_per_source_hour = 3;
        p.max_sessions_per_source = 100;
        let mut l = OnboardingLedger::new(p);
        for i in 0..3 {
            l.contact(i, &who(&format!("k{i}"), None, Some("src")))
                .unwrap();
        }
        assert_eq!(
            l.contact(10, &who("k99", None, Some("src"))),
            Err(Refusal::TooManyNewSubjects)
        );
        // Another source is unaffected; an hour later the first is too.
        l.contact(10, &who("k99", None, Some("other"))).unwrap();
        l.contact(3_600_001 + 2, &who("k100", None, Some("src")))
            .unwrap();
    }

    #[test]
    fn one_extension_while_an_approval_is_in_progress_and_no_more() {
        let mut l = ledger();
        let w = who("e1", Some("did:tenzro:machine:a"), None);
        let (s, _) = l.contact(0, &w).unwrap();
        l.approval_in_progress(&w, 100 * MIN);
        // The window ends at 30; the approval is in progress: extended 10.
        assert_eq!(
            l.check(30 * MIN, s),
            SessionState::Active {
                remaining_ms: 10 * MIN
            }
        );
        // Ends again at 40; the approval is still "in progress" but the one
        // extension is spent.
        assert!(matches!(l.check(40 * MIN, s), SessionState::Expired { .. }));
    }

    #[test]
    fn an_approval_that_is_not_in_progress_extends_nothing() {
        let mut l = ledger();
        let w = who("e1", Some("did:tenzro:machine:a"), None);
        let (s, _) = l.contact(0, &w).unwrap();
        l.approval_in_progress(&w, 5 * MIN); // lapsed before the window ends
        assert!(matches!(l.check(30 * MIN, s), SessionState::Expired { .. }));
    }

    #[test]
    fn backoff_doubles_to_its_cap() {
        let mut l = ledger();
        let w = who("e1", Some("did:tenzro:machine:a"), None);
        let mut now = 0u64;
        let mut waits = Vec::new();
        for _ in 0..12 {
            let (s, left) = l.contact(now, &w).unwrap();
            now += left;
            let SessionState::Expired { retry_at_ms } = l.check(now, s) else {
                panic!()
            };
            waits.push((retry_at_ms - now) / 1000);
            now = retry_at_ms;
        }
        assert_eq!(&waits[..5], &[60, 120, 240, 480, 960]);
        assert_eq!(*waits.last().unwrap(), 6 * 3600, "capped");
    }

    #[test]
    fn sessions_are_bounded_in_total_per_source_and_per_root() {
        let mut p = OnboardingPolicy::default();
        p.max_sessions = 5;
        p.max_sessions_per_source = 2;
        p.max_sessions_per_root = 1;
        let mut l = OnboardingLedger::new(p);
        let (a, _) = l.contact(0, &who("a", Some("r1"), Some("s1"))).unwrap();
        assert_eq!(
            l.contact(0, &who("a2", Some("r1"), Some("s9"))),
            Err(Refusal::TooManySessions("this hardware root"))
        );
        l.contact(0, &who("b", Some("r2"), Some("s1"))).unwrap();
        assert_eq!(
            l.contact(0, &who("c", Some("r3"), Some("s1"))),
            Err(Refusal::TooManySessions("this source"))
        );
        l.contact(0, &who("d", Some("r4"), Some("s2"))).unwrap();
        l.contact(0, &who("e", Some("r5"), Some("s3"))).unwrap();
        l.contact(0, &who("f", Some("r6"), Some("s4"))).unwrap();
        assert_eq!(
            l.contact(0, &who("g", Some("r7"), Some("s5"))),
            Err(Refusal::TooManySessions("all sources"))
        );
        // Closing frees the place.
        l.close(a);
        l.contact(0, &who("g", Some("r7"), Some("s5"))).unwrap();
    }

    #[test]
    fn registering_clears_the_window_and_the_strikes() {
        let mut l = ledger();
        let w = who("e1", Some("did:tenzro:machine:a"), None);
        let (s, left) = l.contact(0, &w).unwrap();
        l.check(left, s);
        assert!(l.contact(left + 1, &w).is_err());
        l.registered(&w);
        let (_, left) = l.contact(left + 1, &w).unwrap();
        assert_eq!(left, 30 * MIN, "no memory of the earlier window");
    }

    #[test]
    fn the_sweep_ends_exactly_the_expired_sessions() {
        let mut l = ledger();
        let (_, _) = l.contact(0, &who("old", Some("r1"), None)).unwrap();
        let (young, _) = l
            .contact(20 * MIN, &who("young", Some("r2"), None))
            .unwrap();
        let ended = l.sweep(31 * MIN);
        assert_eq!(ended.len(), 1);
        assert_eq!(ended[0].who.endpoint, "old");
        assert_eq!(
            l.check(31 * MIN, young),
            SessionState::Active {
                remaining_ms: 19 * MIN
            }
        );
    }

    #[test]
    fn one_subject_on_several_connections_holds_one_session_until_the_last_closes() {
        let mut p = OnboardingPolicy::default();
        p.max_sessions_per_root = 1;
        let mut l = OnboardingLedger::new(p);
        let w = who("e1", Some("r1"), Some("src"));
        let (s, left) = l.contact(0, &w).unwrap();
        // Two more connections of the same endpoint key: the same session,
        // the same window, no further place taken.
        assert_eq!(l.contact(MIN, &w).unwrap(), (s, left - MIN));
        assert_eq!(l.contact(2 * MIN, &w).unwrap(), (s, left - 2 * MIN));
        assert_eq!(l.open_sessions(), 1);
        let other = who("e2", Some("r1"), Some("src"));
        assert_eq!(
            l.contact(2 * MIN, &other),
            Err(Refusal::TooManySessions("this hardware root"))
        );
        // The session ends with its last connection, not its first.
        l.close(s);
        l.close(s);
        assert!(l.is_open(s));
        assert!(l.contact(2 * MIN, &other).is_err());
        l.close(s);
        assert!(!l.is_open(s));
        l.contact(2 * MIN, &other).unwrap();
    }

    #[test]
    fn a_connection_after_the_window_ended_does_not_renew_it() {
        let mut l = ledger();
        let w = who("e1", Some("did:tenzro:machine:a"), None);
        let (s, _) = l.contact(0, &w).unwrap();
        // No sweep came by; the subject connects again after its window.
        assert!(matches!(
            l.contact(31 * MIN, &w),
            Err(Refusal::BackedOff { strikes: 1, .. })
        ));
        assert!(!l.is_open(s));
        // The sweep still reports the session, once.
        let ended = l.sweep(31 * MIN);
        assert_eq!(ended.len(), 1);
        assert_eq!((ended[0].session, ended[0].retry_at_ms), (s, 32 * MIN));
        assert!(l.sweep(31 * MIN).is_empty());
    }

    #[test]
    fn a_session_takes_the_hardware_root_its_key_names_later() {
        let mut p = OnboardingPolicy::default();
        p.max_sessions_per_root = 1;
        let mut l = OnboardingLedger::new(p);
        // Connected before any record named it, then named.
        let (s, _) = l.contact(0, &who("e1", None, None)).unwrap();
        assert_eq!(l.contact(MIN, &who("e1", Some("r1"), None)).unwrap().0, s);
        // The root's place is taken now.
        assert_eq!(
            l.contact(MIN, &who("e2", Some("r1"), None)),
            Err(Refusal::TooManySessions("this hardware root"))
        );
        // A key that names a root with no place left is refused, and the
        // session it holds stays as it was.
        let (t, _) = l.contact(MIN, &who("e3", None, None)).unwrap();
        assert_eq!(
            l.contact(MIN, &who("e3", Some("r1"), None)),
            Err(Refusal::TooManySessions("this hardware root"))
        );
        assert!(l.is_open(t));
        // Both connections of the first key close: the root's place returns.
        l.close(s);
        l.close(s);
        assert!(!l.is_open(s));
        l.contact(MIN, &who("e2", Some("r1"), None)).unwrap();
    }

    #[test]
    fn two_endpoint_keys_on_one_root_share_one_window_and_one_strike() {
        let mut l = ledger();
        let root = Some("did:tenzro:machine:a");
        l.contact(0, &who("e1", root, None)).unwrap();
        l.contact(0, &who("e2", root, None)).unwrap();
        let ended = l.sweep(30 * MIN);
        assert_eq!(ended.len(), 2);
        assert!(
            ended.iter().all(|e| e.retry_at_ms == 31 * MIN),
            "one window, one strike: {ended:?}"
        );
        assert!(matches!(
            l.contact(30 * MIN + 1, &who("e1", root, None)),
            Err(Refusal::BackedOff { strikes: 1, .. })
        ));
    }

    #[test]
    fn the_ledger_is_bounded_and_fails_closed() {
        let mut p = OnboardingPolicy::default();
        p.max_tracked = 4;
        p.max_sessions = 100;
        p.max_sessions_per_source = 100;
        p.max_new_subjects_per_source_hour = 100;
        let mut l = OnboardingLedger::new(p);
        // Each unrecorded subject takes one endpoint key.
        for i in 0..4 {
            l.contact(0, &who(&format!("k{i}"), None, None)).unwrap();
        }
        assert_eq!(
            l.contact(1, &who("k4", None, None)),
            Err(Refusal::LedgerFull)
        );
    }

    fn ask(root: &str, owner: Option<&str>, source: &str) -> SponsorAsk {
        SponsorAsk {
            root: root.into(),
            provider: None,
            owner: owner.map(Into::into),
            source: Some(source.into()),
            fee: 1_600_000_000_000_000,
        }
    }

    fn sponsor() -> SponsorLedger {
        SponsorLedger::new(SponsorPolicy {
            enabled: true,
            ..SponsorPolicy::default()
        })
    }

    #[test]
    fn a_node_that_does_not_sponsor_refuses() {
        let mut s = SponsorLedger::new(SponsorPolicy::default());
        assert_eq!(
            s.authorise(0, &ask("r", Some("o"), "s")),
            Err(SponsorRefusal::Disabled)
        );
    }

    #[test]
    fn a_sponsored_registration_needs_an_owner_approval() {
        let mut s = sponsor();
        assert_eq!(
            s.authorise(0, &ask("r", None, "s")),
            Err(SponsorRefusal::NoOwnerApproval)
        );
    }

    #[test]
    fn a_root_is_sponsored_once_and_a_refusal_reserves_nothing() {
        let mut s = sponsor();
        let g = s.authorise(0, &ask("r", Some("o"), "s")).unwrap();
        assert_eq!(
            s.authorise(0, &ask("r", Some("o"), "s")),
            Err(SponsorRefusal::RootExhausted)
        );
        // The first transaction was not admitted: the root has its turn back.
        s.release(g);
        s.authorise(0, &ask("r", Some("o"), "s")).unwrap();
    }

    #[test]
    fn one_owner_approval_sponsors_a_bounded_number_of_identities() {
        let mut s = sponsor();
        for i in 0..8 {
            s.authorise(0, &ask(&format!("r{i}"), Some("o"), &format!("s{i}")))
                .unwrap();
        }
        assert_eq!(
            s.authorise(0, &ask("r9", Some("o"), "s9")),
            Err(SponsorRefusal::OwnerExhausted)
        );
    }

    #[test]
    fn a_source_and_the_node_have_a_daily_budget_that_renews() {
        let mut s = SponsorLedger::new(SponsorPolicy {
            enabled: true,
            max_per_source_day: 2,
            max_per_day: 3,
            max_per_owner: 100,
            ..SponsorPolicy::default()
        });
        s.authorise(0, &ask("r1", Some("o1"), "s")).unwrap();
        s.authorise(0, &ask("r2", Some("o2"), "s")).unwrap();
        assert_eq!(
            s.authorise(0, &ask("r3", Some("o3"), "s")),
            Err(SponsorRefusal::SourceExhausted)
        );
        s.authorise(0, &ask("r3", Some("o3"), "t")).unwrap();
        assert_eq!(
            s.authorise(0, &ask("r4", Some("o4"), "u")),
            Err(SponsorRefusal::DayExhausted)
        );
        s.authorise(DAY_MS, &ask("r4", Some("o4"), "u")).unwrap();
    }

    #[test]
    fn a_fee_above_the_cap_is_not_sponsored() {
        let mut s = sponsor();
        let mut a = ask("r", Some("o"), "s");
        a.fee = u128::MAX;
        assert_eq!(s.authorise(0, &a), Err(SponsorRefusal::FeeAboveCap));
    }

    #[test]
    fn delegated_roots_count_against_their_provider() {
        let mut s = SponsorLedger::new(SponsorPolicy {
            enabled: true,
            max_per_owner: 2,
            max_per_source_day: 100,
            ..SponsorPolicy::default()
        });
        let mut a = ask("r1", Some("o1"), "s");
        a.provider = Some("p".into());
        s.authorise(0, &a).unwrap();
        let mut b = ask("r2", Some("o2"), "s");
        b.provider = Some("p".into());
        s.authorise(0, &b).unwrap();
        let mut c = ask("r3", Some("o3"), "s");
        c.provider = Some("p".into());
        assert_eq!(s.authorise(0, &c), Err(SponsorRefusal::ProviderExhausted));
    }

    #[test]
    fn an_approval_is_single_use_expiring_and_bound() {
        let mut b = ApprovalBook::new(Duration::from_secs(300), 8);
        let c = b.issue(0, [1; 16], "did:tenzro:machine:a", "ep1", "pi");
        // Replay of a spent challenge.
        b.redeem(10, &c.nonce, "did:tenzro:machine:a", "ep1", "pi")
            .unwrap();
        assert_eq!(
            b.redeem(11, &c.nonce, "did:tenzro:machine:a", "ep1", "pi"),
            Err(ApprovalError::Unknown)
        );
        // Stale.
        let c = b.issue(0, [2; 16], "did:tenzro:machine:a", "ep1", "pi");
        assert_eq!(
            b.redeem(5 * MIN, &c.nonce, "did:tenzro:machine:a", "ep1", "pi"),
            Err(ApprovalError::Expired)
        );
        // Bound to machine, endpoint and label; a wrong try spends it.
        for (did, ep, label) in [
            ("did:tenzro:machine:b", "ep1", "pi"),
            ("did:tenzro:machine:a", "ep2", "pi"),
            ("did:tenzro:machine:a", "ep1", "other"),
        ] {
            let c = b.issue(0, [3; 16], "did:tenzro:machine:a", "ep1", "pi");
            assert_eq!(
                b.redeem(1, &c.nonce, did, ep, label),
                Err(ApprovalError::Mismatch)
            );
            assert_eq!(
                b.redeem(2, &c.nonce, "did:tenzro:machine:a", "ep1", "pi"),
                Err(ApprovalError::Unknown)
            );
        }
    }

    #[test]
    fn the_approval_statement_commits_to_every_binding() {
        let base = ApprovalChallenge {
            nonce: [7; 16],
            machine_did: "did:tenzro:machine:a".into(),
            endpoint: "ep".into(),
            label: "pi".into(),
            issued_ms: 1,
            expires_ms: 2,
        };
        let s = base.statement();
        let mut v = base.clone();
        v.machine_did = "did:tenzro:machine:b".into();
        assert_ne!(v.statement(), s);
        let mut v = base.clone();
        v.endpoint = "ep2".into();
        assert_ne!(v.statement(), s);
        let mut v = base.clone();
        v.label = "x".into();
        assert_ne!(v.statement(), s);
        let mut v = base.clone();
        v.expires_ms = 3;
        assert_ne!(v.statement(), s);
        let mut v = base.clone();
        v.nonce = [8; 16];
        assert_ne!(v.statement(), s);
        // Field boundaries are length-prefixed: moving a byte between
        // fields changes the statement.
        let mut v = base.clone();
        v.endpoint = "e".into();
        v.label = "ppi".into();
        assert_ne!(v.statement(), s);
    }

    #[test]
    fn the_approval_book_is_bounded() {
        let mut b = ApprovalBook::new(Duration::from_secs(300), 2);
        let c1 = b.issue(0, [1; 16], "d", "e", "l");
        b.issue(1, [2; 16], "d", "e", "l");
        b.issue(2, [3; 16], "d", "e", "l");
        assert_eq!(
            b.redeem(3, &c1.nonce, "d", "e", "l"),
            Err(ApprovalError::Unknown),
            "the oldest was dropped to make room"
        );
    }
}
