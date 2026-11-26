//! What on this node is open and needs its operator's attention.
//!
//! A condition is something the node itself observes: it is stopping, it is
//! catching up with or not following the network, a subsystem is degraded or
//! not working, stopping this validator would cost its committee its quorum,
//! a newer release is ready, a role's stake is below what the role requires,
//! a configured role is not served or a served role has lost its bond,
//! `tenzro-node doctor` would name a fix (load, TPM, relays, reachability), the
//! data disk is filling, or the key holder that signs for this machine
//! has no grant in force. [`judge`] is the whole rule: it takes what was seen
//! and names the conditions that hold. Nothing here watches on a timer. The
//! list is worked out when it is read, and [`ConditionBook`] compares each
//! reading with the one before, so a condition that began or ended in
//! between is published once on the node's event stream and kept in a short
//! history for a reader that was not subscribed.
//!
//! A condition the node can act on by itself asks for a passkey bound to its
//! operator: it carries a challenge, and [`submit_approval`] checks the
//! passkey's answer and then does what the condition names. The operator may
//! acknowledge any open condition with a reason ([`acknowledge_condition`]);
//! the node keeps the acknowledgement in its store for as long as that
//! opening of the condition holds at no graver severity. Every answer is
//! published on the event stream too.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::Arc;

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tenzro_events::{EventBus, TenzroEvent};
use tenzro_storage::resources::Level;
use tenzro_storage::{CF_METADATA, KvStore};

use crate::consensus_driver::QuorumStanding;
use crate::doctor::Finding;
use crate::follow_state::{FollowState, Following, GAP_SAMPLE_AGE, Reason};
use crate::health::SubsystemStatus;
use crate::node::{NodeState, TenzroNode};
use crate::rpc::JsonRpcError;

/// How many condition changes the history keeps.
const HISTORY: usize = 64;

/// How long a reading answers the next reader, so a stream of reads costs one
/// look at the chain state and the key holder.
const READING_HOLDS_MS: u64 = 5_000;

/// The longest reason an acknowledgement takes, in characters.
const MAX_REASON_CHARS: usize = 500;

/// How many acknowledgements are read back from the store. The node keeps
/// one only for an open condition, so the store never holds more than the
/// open conditions.
const MAX_ACKS: usize = 64;

/// Key prefix of an acknowledgement in the node's metadata, by condition id.
const ACK_PREFIX: &str = "condition_ack:";

/// How much a condition matters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// Worth knowing; nothing is failing.
    Info,
    /// The node works and will stop doing something if this is left.
    Warning,
    /// The node is not doing its work.
    Critical,
}

impl Severity {
    /// The name a client reads.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Critical => "critical",
        }
    }
}

/// A newer release the node holds a verified notice for.
#[derive(Debug, Clone)]
pub struct Update {
    pub version: String,
    pub severity: tenzro_update_notice::Severity,
    pub released_ms: u64,
}

/// One role's stake held by this node's operator account.
#[derive(Debug, Clone)]
pub struct Stake {
    pub role: &'static str,
    pub bonded: u128,
    pub required: u128,
}

/// A role this node's configuration and its standing disagree on.
#[derive(Debug, Clone)]
pub struct RoleGap {
    pub role: &'static str,
    pub gap: Gap,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Gap {
    /// Dropped at startup: this machine cannot back it, and why.
    Unsupported(String),
    /// Not served until its bond lands: none at startup, or the bond went.
    AwaitingBond,
}

/// Where the node is in its own run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lifecycle {
    Starting,
    Running,
    Stopping,
}

/// What was seen on one reading.
#[derive(Debug, Clone)]
pub struct Seen {
    pub lifecycle: Lifecycle,
    pub follow: FollowState,
    /// The health monitor's subsystems, by name.
    pub health: Vec<(String, SubsystemStatus)>,
    /// What stopping this validator would leave of its committee's quorum,
    /// on a node that runs a consensus engine.
    pub quorum: Option<QuorumStanding>,
    pub update: Option<Update>,
    pub stakes: Vec<Stake>,
    pub roles: Vec<RoleGap>,
    /// What `tenzro-node doctor` would find from the running node alone,
    /// each with its fix.
    pub doctor: Vec<(Finding, String)>,
    pub disk_level: Level,
    pub disk_used_pct: u8,
    /// The key holder's answer when this machine signs through one: the end
    /// of its grant (`None` when no grant is installed), or why it gave no
    /// answer. `None` on a machine that holds its own key.
    pub key_grant: Option<Result<Option<u64>, String>>,
    /// The relying party of the operator's passkeys, when a device bound to
    /// this node's operator can approve what the node would then do itself.
    pub approver: Option<String>,
}

/// What the node does itself once its operator approves a condition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Act {
    /// Start the install of this release.
    InstallUpdate { version: String },
}

/// An approval a condition waits for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ask {
    pub act: Act,
    pub rp_id: String,
}

/// A condition that holds on one reading.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Found {
    pub id: String,
    pub kind: &'static str,
    pub code: &'static str,
    pub severity: Severity,
    pub title: String,
    pub detail: String,
    /// When it began, where what was seen says so.
    pub began_ms: Option<u64>,
    /// The approval it waits for, when the node can act on it by itself.
    pub ask: Option<Ask>,
}

/// The conditions that hold, given what was seen.
pub fn judge(seen: &Seen, now_ms: u64) -> Vec<Found> {
    let mut found = Vec::new();

    let run = match seen.lifecycle {
        Lifecycle::Running => None,
        Lifecycle::Starting => Some((
            "starting",
            "The node is starting",
            "It answers while its subsystems start and does no work for the network yet.",
        )),
        Lifecycle::Stopping => Some((
            "stopping",
            "The node is stopping",
            "It was asked to stop and exits once its drain ends.",
        )),
    };
    if let Some((code, title, detail)) = run {
        found.push(Found {
            id: "node".into(),
            kind: "node",
            code,
            severity: Severity::Warning,
            title: title.into(),
            detail: detail.into(),
            began_ms: None,
            ask: None,
        });
    }

    if seen.follow.state == Following::CatchingUp {
        let behind = seen.follow.behind.unwrap_or(0);
        let detail = match seen.follow.behind_before {
            Some(before) if before > behind => format!(
                "{behind} blocks behind the network's head, {} fewer than {} seconds ago.",
                before - behind,
                GAP_SAMPLE_AGE.as_secs()
            ),
            _ => format!("{behind} blocks behind the network's head, and importing."),
        };
        found.push(Found {
            id: "follow".into(),
            kind: "follow",
            code: "catching_up",
            severity: Severity::Info,
            title: "Catching up with the network".into(),
            detail,
            began_ms: None,
            ask: None,
        });
    }

    if seen.follow.state == Following::Stalled {
        found.push(Found {
            id: "follow".into(),
            kind: "follow",
            code: match seen.follow.reason {
                Some(Reason::NoPeerHeard) => "no_peer_heard",
                Some(Reason::NoProgress) => "no_progress",
                Some(Reason::RangeBroughtNothing) => "range_brought_nothing",
                None => "stalled",
            },
            severity: Severity::Critical,
            title: "Not following the network".into(),
            detail: seen
                .follow
                .detail
                .unwrap_or("This node stopped importing blocks.")
                .into(),
            began_ms: seen
                .follow
                .last_import_ms
                .map(|elapsed| now_ms.saturating_sub(elapsed)),
            ask: None,
        });
    }

    if let Some(update) = &seen.update {
        let (code, severity, detail) = match update.severity {
            tenzro_update_notice::Severity::Normal => (
                "update_ready",
                Severity::Info,
                format!("Release {} can be installed.", update.version),
            ),
            tenzro_update_notice::Severity::Security => (
                "security_update",
                Severity::Warning,
                format!("Release {} fixes a security issue.", update.version),
            ),
            tenzro_update_notice::Severity::RequiredByEpoch { epoch } => (
                "required_update",
                Severity::Critical,
                format!(
                    "The network requires release {} from epoch {epoch}.",
                    update.version
                ),
            ),
        };
        found.push(Found {
            id: format!("update:{}", update.version),
            kind: "update",
            code,
            severity,
            title: format!("Update {} is ready", update.version),
            detail,
            began_ms: Some(update.released_ms),
            ask: seen.approver.clone().map(|rp_id| Ask {
                act: Act::InstallUpdate {
                    version: update.version.clone(),
                },
                rp_id,
            }),
        });
    }

    for stake in &seen.stakes {
        if stake.bonded > 0 && stake.bonded < stake.required {
            found.push(Found {
                id: format!("stake:{}", stake.role),
                kind: "stake",
                code: "stake_short",
                severity: Severity::Warning,
                title: format!("The {} stake is short", stake.role),
                detail: format!(
                    "{} TNZO is bonded and the role requires {} TNZO.",
                    tnzo(stake.bonded),
                    tnzo(stake.required)
                ),
                began_ms: None,
                ask: None,
            });
        }
    }

    for RoleGap { role, gap } in &seen.roles {
        let (code, severity, title, detail) = match gap {
            Gap::Unsupported(reason) => (
                "role_unsupported",
                Severity::Warning,
                format!("The {role} role is not served"),
                format!("This machine cannot back it: {reason}."),
            ),
            Gap::AwaitingBond => (
                "role_unbonded",
                Severity::Warning,
                format!("The {role} role is not served"),
                "It takes a bond the operator account does not hold. Bond it with a signed \
                 Stake transaction from the operator account and the node takes it up when \
                 the bond lands, or drop it from --roles."
                    .to_string(),
            ),
        };
        found.push(Found {
            id: format!("role:{role}"),
            kind: "role",
            code,
            severity,
            title,
            detail,
            began_ms: None,
            ask: None,
        });
    }

    for (finding, fix) in &seen.doctor {
        let (code, severity, title) = match finding {
            Finding::Load { critical } => (
                "load_shedding",
                if *critical {
                    Severity::Critical
                } else {
                    Severity::Warning
                },
                "The node is shedding work",
            ),
            Finding::TpmStalled => (
                "tpm_stalled",
                Severity::Critical,
                "The TPM stopped answering",
            ),
            Finding::NoRelay => ("no_relay", Severity::Warning, "No relay is connected"),
            Finding::Unreachable => (
                "unreachable",
                Severity::Warning,
                "Peers cannot reach this node",
            ),
            Finding::SymmetricNat => (
                "symmetric_nat",
                Severity::Info,
                "Most peers reach this node through a relay",
            ),
            Finding::NoUdp => (
                "no_udp",
                Severity::Info,
                "No peer has reached this node over UDP",
            ),
            Finding::ValidatorNotDirect => (
                "validator_not_direct",
                Severity::Warning,
                "This validator has no direct address",
            ),
        };
        found.push(Found {
            id: format!("doctor:{code}"),
            kind: "doctor",
            code,
            severity,
            title: title.to_string(),
            detail: fix.clone(),
            began_ms: None,
            ask: None,
        });
    }

    let disk = match seen.disk_level {
        Level::Ok => None,
        Level::Warn | Level::Prune => Some((
            "disk_filling",
            Severity::Warning,
            "The data disk is filling",
            "The node prunes harder to stay within it.",
        )),
        Level::Refuse => Some((
            "disk_refusing",
            Severity::Critical,
            "The data disk is nearly full",
            "The node refuses data it can run without; consensus continues.",
        )),
        Level::Reserve => Some((
            "disk_reserve",
            Severity::Critical,
            "The data disk is full",
            "The node released its reserve and stopped taking snapshots.",
        )),
    };
    if let Some((code, severity, title, what)) = disk {
        found.push(Found {
            id: "requirement:disk".into(),
            kind: "requirement",
            code,
            severity,
            title: title.into(),
            detail: format!("{}% of the data disk is used. {what}", seen.disk_used_pct),
            began_ms: None,
            ask: None,
        });
    }

    // The disk's own subsystem is the disk condition above.
    for (name, status) in &seen.health {
        let (code, severity, title, reason) = match status {
            SubsystemStatus::Healthy => continue,
            _ if name == crate::storage_maintenance::DISK_SUBSYSTEM => continue,
            SubsystemStatus::Degraded { reason } => (
                "degraded",
                Severity::Warning,
                format!("The {name} subsystem is degraded"),
                reason,
            ),
            SubsystemStatus::Unhealthy { reason } => (
                "unhealthy",
                Severity::Critical,
                format!("The {name} subsystem is not working"),
                reason,
            ),
        };
        found.push(Found {
            id: format!("health:{name}"),
            kind: "health",
            code,
            severity,
            title,
            detail: format!("{reason}."),
            began_ms: None,
            ask: None,
        });
    }

    if let Some(q) = seen.quorum {
        let others = q.total_seats.saturating_sub(q.seats);
        let quorum = if others < q.quorum {
            Some((
                "committee_needs_this_validator",
                Severity::Info,
                "Stopping this validator stops its committee",
                format!(
                    "Without this validator's {} of {} seats the committee of epoch {} holds {others}, \
                     and a certificate needs {}: nothing is certified while it is stopped.",
                    q.seats, q.total_seats, q.epoch, q.quorum
                ),
            ))
        } else if q.reached_seats < q.quorum {
            Some((
                "quorum_rests_on_this_validator",
                Severity::Warning,
                "Stopping this validator now would stop certification",
                format!(
                    "This validator has open consensus channels to members holding {} of the other \
                     {others} seats, and a certificate needs {}. Members it has no channel to may \
                     still be running and reach each other.",
                    q.reached_seats, q.quorum
                ),
            ))
        } else {
            None
        };
        if let Some((code, severity, title, detail)) = quorum {
            found.push(Found {
                id: "quorum".into(),
                kind: "quorum",
                code,
                severity,
                title: title.into(),
                detail,
                began_ms: None,
                ask: None,
            });
        }
    }

    let grant = match &seen.key_grant {
        Some(Err(why)) => Some((
            "key_holder_unreachable",
            format!("The key holder gave no answer: {why}."),
            None,
        )),
        Some(Ok(None)) => Some((
            "key_grant_missing",
            "The key holder has no grant for this machine.".to_string(),
            None,
        )),
        Some(Ok(Some(end))) if *end <= now_ms => Some((
            "key_grant_expired",
            "The key holder's grant for this machine ended.".to_string(),
            Some(*end),
        )),
        Some(Ok(Some(_))) | None => None,
    };
    if let Some((code, detail, began_ms)) = grant {
        found.push(Found {
            id: "key_grant".into(),
            kind: "key_grant",
            code,
            severity: Severity::Critical,
            title: "This machine cannot use its key".into(),
            detail,
            began_ms,
            ask: None,
        });
    }

    found
}

/// An amount in the smallest unit as whole TNZO, without trailing zeros.
fn tnzo(amount: u128) -> String {
    const UNIT: u128 = 1_000_000_000_000_000_000;
    let whole = amount / UNIT;
    let part = amount % UNIT;
    if part == 0 {
        return whole.to_string();
    }
    let digits = format!("{part:018}");
    format!("{whole}.{}", digits.trim_end_matches('0'))
}

/// A time in milliseconds since the epoch as RFC 3339 in UTC.
fn rfc3339(ms: u64) -> String {
    i64::try_from(ms)
        .ok()
        .and_then(chrono::DateTime::<chrono::Utc>::from_timestamp_millis)
        .unwrap_or_default()
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// An open condition, as a client reads it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Condition {
    /// The same for as long as the condition stays open.
    pub id: String,
    pub kind: &'static str,
    pub code: &'static str,
    pub severity: Severity,
    pub title: String,
    pub detail: String,
    /// When it began, RFC 3339 in UTC.
    pub since: String,
    /// Set while the node waits for its operator's answer.
    #[serde(flatten)]
    pub asking: Option<Asking>,
    /// The operator's acknowledgement of this opening, or `null`.
    pub ack: Option<Ack>,
    #[serde(skip)]
    since_ms: u64,
}

/// The operator's acknowledgement of an open condition, as a client reads it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ack {
    /// The DID of the caller that acknowledged it, when it signed in.
    pub by: Option<String>,
    pub reason: String,
    /// When, RFC 3339 in UTC.
    pub at: String,
}

/// An acknowledgement as the node stores it: it holds for the opening it
/// was given for, at the severity it was given at.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Acknowledged {
    pub since_ms: u64,
    pub severity: Severity,
    #[serde(flatten)]
    pub ack: Ack,
}

/// Why an acknowledgement was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AckRefusal {
    /// No open condition has the id.
    NotOpen,
    /// The condition is open, since this time and not the one given.
    OpenedAgain(String),
    /// The store did not take it.
    Store(String),
}

/// What an open condition asks of a passkey bound to the node's operator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Asking {
    /// What an approval needs: `passkey`.
    pub needs: &'static str,
    /// What the passkey signs, base64url. A challenge answers once.
    #[serde(serialize_with = "base64url")]
    pub challenge: [u8; 32],
    /// The relying party the passkey is asked under.
    pub rp_id: String,
    #[serde(skip)]
    act: Act,
}

fn base64url<S: serde::Serializer>(bytes: &[u8; 32], to: S) -> Result<S::Ok, S::Error> {
    use base64::Engine;
    to.serialize_str(&base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
}

/// A condition opening or clearing, as the history keeps it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Change {
    /// The event's sequence on the node's event stream.
    pub sequence: u64,
    /// `condition_opened`, `condition_cleared` or `condition_answered`.
    pub kind: &'static str,
    pub summary: String,
    /// When the node saw it, RFC 3339 in UTC.
    pub at: String,
    /// The node's height when it saw it.
    pub block: u64,
    /// The condition's id.
    pub condition: String,
    pub severity: Severity,
}

#[derive(Default)]
struct Inner {
    open: BTreeMap<String, Condition>,
    /// The open conditions the operator answered: they ask no more.
    answered: BTreeSet<String>,
    /// The acknowledgements of open conditions, by id.
    acks: BTreeMap<String, Acknowledged>,
    /// Acknowledgements read back from the store, applied on the next
    /// reading only.
    restoring: Option<BTreeMap<String, Acknowledged>>,
    restored: bool,
    /// Acknowledgements that no longer hold, still to be removed from the
    /// store.
    stale: Vec<String>,
    recent: VecDeque<Change>,
    read_ms: Option<u64>,
    /// The node's height at the last reading.
    height: u64,
}

impl Change {
    /// A change seen at `now_ms`, before it is published.
    fn seen(
        kind: &'static str,
        summary: String,
        condition: String,
        severity: Severity,
        now_ms: u64,
    ) -> Self {
        Self {
            sequence: 0,
            kind,
            summary,
            at: rfc3339(now_ms),
            block: 0,
            condition,
            severity,
        }
    }
}

impl Inner {
    /// Publish `event` on `bus` and keep `change` in the history, with the
    /// event's sequence and the height of the last reading.
    fn record(&mut self, bus: &EventBus, event: TenzroEvent, mut change: Change) {
        change.sequence = bus.publish(event, Some(self.height), None);
        change.block = self.height;
        if self.recent.len() == HISTORY {
            self.recent.pop_back();
        }
        self.recent.push_front(change);
    }
}

/// The open conditions and the changes between readings.
#[derive(Default)]
pub struct ConditionBook {
    inner: Mutex<Inner>,
}

impl ConditionBook {
    /// The open conditions, when a reading was settled recently enough to
    /// answer this reader too.
    pub fn held(&self, now_ms: u64) -> Option<Vec<Condition>> {
        let inner = self.inner.lock();
        inner
            .read_ms
            .filter(|read| now_ms.saturating_sub(*read) < READING_HOLDS_MS)
            .map(|_| listed(&inner.open))
    }

    /// Take one reading: a condition found for the first time opens, one no
    /// longer found clears, and each of those is published on `bus` and
    /// recorded. A condition that stays open keeps the time it began, the
    /// challenge it asks with and its acknowledgement, and takes the
    /// reading's wording; an acknowledgement ends when its condition clears
    /// or grows graver. Returns the open conditions, the most severe first.
    pub fn settle(
        &self,
        found: Vec<Found>,
        now_ms: u64,
        height: u64,
        bus: &EventBus,
    ) -> Vec<Condition> {
        let mut inner = self.inner.lock();
        let inner = &mut *inner;
        inner.height = height;
        let mut restoring = inner.restoring.take().unwrap_or_default();
        let mut open = BTreeMap::new();
        let mut acks = BTreeMap::new();
        for f in found {
            let (since_ms, asked, acked) = match inner.open.remove(&f.id) {
                Some(before) => (before.since_ms, before.asking, inner.acks.remove(&f.id)),
                None => {
                    inner.record(
                        bus,
                        TenzroEvent::ConditionOpened {
                            id: f.id.clone(),
                            kind: f.kind.into(),
                            code: f.code.into(),
                            severity: f.severity.as_str().into(),
                            summary: f.title.clone(),
                        },
                        Change::seen(
                            "condition_opened",
                            f.title.clone(),
                            f.id.clone(),
                            f.severity,
                            now_ms,
                        ),
                    );
                    // An acknowledgement the store kept across a restart
                    // keeps the opening it was given for.
                    let restored = restoring.remove(&f.id);
                    let since_ms = restored.as_ref().map_or_else(
                        || f.began_ms.unwrap_or(now_ms).min(now_ms),
                        |kept| kept.since_ms,
                    );
                    (since_ms, None, restored)
                }
            };
            let ack = match acked {
                Some(kept) if kept.severity >= f.severity => {
                    let ack = kept.ack.clone();
                    acks.insert(f.id.clone(), kept);
                    Some(ack)
                }
                Some(_) => {
                    inner.stale.push(f.id.clone());
                    None
                }
                None => None,
            };
            let asking = f
                .ask
                .filter(|_| !inner.answered.contains(&f.id))
                .map(|ask| Asking {
                    needs: "passkey",
                    challenge: asked.map_or_else(rand::random, |asked| asked.challenge),
                    rp_id: ask.rp_id,
                    act: ask.act,
                });
            open.insert(
                f.id.clone(),
                Condition {
                    id: f.id,
                    kind: f.kind,
                    code: f.code,
                    severity: f.severity,
                    title: f.title,
                    detail: f.detail,
                    since: rfc3339(since_ms),
                    asking,
                    ack,
                    since_ms,
                },
            );
        }
        inner.answered.retain(|id| open.contains_key(id));
        let ended = std::mem::replace(&mut inner.acks, acks);
        inner
            .stale
            .extend(ended.into_keys().chain(restoring.into_keys()));
        for gone in std::mem::replace(&mut inner.open, open).into_values() {
            let summary = format!("Cleared: {}", gone.title);
            inner.record(
                bus,
                TenzroEvent::ConditionCleared {
                    id: gone.id.clone(),
                    kind: gone.kind.into(),
                    code: gone.code.into(),
                    severity: gone.severity.as_str().into(),
                    summary: summary.clone(),
                },
                Change::seen("condition_cleared", summary, gone.id, gone.severity, now_ms),
            );
        }
        inner.read_ms = Some(now_ms);
        listed(&inner.open)
    }

    /// The condition changes the history holds, newest first.
    pub fn recent(&self) -> Vec<Change> {
        self.inner.lock().recent.iter().cloned().collect()
    }

    /// The challenge an open condition asks with, and what the node does once
    /// it is approved. `None` when no open condition with this id is asking.
    pub fn challenge(&self, id: &str) -> Option<([u8; 32], Act)> {
        let inner = self.inner.lock();
        let asking = inner.open.get(id)?.asking.as_ref()?;
        Some((asking.challenge, asking.act.clone()))
    }

    /// Spend `used`, a challenge an assertion verified against: the condition
    /// asks with a fresh one from here on, so a challenge answers once.
    /// `false` when the condition no longer asks with `used`, because another
    /// answer spent it first.
    pub fn spend_challenge(&self, id: &str, used: &[u8; 32]) -> bool {
        let mut inner = self.inner.lock();
        let Some(asking) = inner
            .open
            .get_mut(id)
            .and_then(|condition| condition.asking.as_mut())
        else {
            return false;
        };
        if asking.challenge != *used {
            return false;
        }
        asking.challenge = rand::random();
        true
    }

    /// Record the operator's answer to a condition that asks, by `by`, and
    /// publish it: the condition stays listed for as long as it holds and
    /// asks no more. `false` when no open condition with this id is asking.
    pub fn answer(
        &self,
        id: &str,
        approved: bool,
        by: Option<String>,
        now_ms: u64,
        bus: &EventBus,
    ) -> bool {
        let mut inner = self.inner.lock();
        let inner = &mut *inner;
        let Some(condition) = inner.open.get_mut(id) else {
            return false;
        };
        if condition.asking.take().is_none() {
            return false;
        }
        let (answer, said) = if approved {
            ("approved", "Approved")
        } else {
            ("declined", "Declined")
        };
        let summary = format!("{said}: {}", condition.title);
        let (kind, severity) = (condition.kind, condition.severity);
        inner.answered.insert(id.to_string());
        inner.record(
            bus,
            TenzroEvent::ConditionAnswered {
                id: id.into(),
                kind: kind.into(),
                answer: answer.into(),
                by,
                summary: summary.clone(),
            },
            Change::seen("condition_answered", summary, id.into(), severity, now_ms),
        );
        true
    }

    /// Acknowledge the opening of condition `id` that began at `since` (as
    /// the list gives it): the condition stays listed with `ack` until it
    /// clears or grows graver. `keep` stores the acknowledgement; it is taken
    /// only once that succeeded, and published.
    pub fn acknowledge(
        &self,
        id: &str,
        since: &str,
        ack: Ack,
        now_ms: u64,
        bus: &EventBus,
        keep: impl FnOnce(&Acknowledged) -> Result<(), String>,
    ) -> Result<Ack, AckRefusal> {
        let mut inner = self.inner.lock();
        let inner = &mut *inner;
        let condition = inner.open.get_mut(id).ok_or(AckRefusal::NotOpen)?;
        if condition.since != since {
            return Err(AckRefusal::OpenedAgain(condition.since.clone()));
        }
        let by = ack.by.clone();
        let kept = Acknowledged {
            since_ms: condition.since_ms,
            severity: condition.severity,
            ack,
        };
        keep(&kept).map_err(AckRefusal::Store)?;
        condition.ack = Some(kept.ack.clone());
        let summary = format!("Acknowledged: {}", condition.title);
        let (kind, severity) = (condition.kind, condition.severity);
        let ack = kept.ack.clone();
        inner.acks.insert(id.to_string(), kept);
        inner.record(
            bus,
            TenzroEvent::ConditionAnswered {
                id: id.into(),
                kind: kind.into(),
                answer: "acknowledged".into(),
                by,
                summary: summary.clone(),
            },
            Change::seen("condition_answered", summary, id.into(), severity, now_ms),
        );
        Ok(ack)
    }

    /// Hand the book the acknowledgements its store kept, once: the next
    /// reading keeps each whose condition is open again, and the rest end.
    pub fn restore_once(&self, load: impl FnOnce() -> Vec<(String, Acknowledged)>) {
        let mut inner = self.inner.lock();
        if !inner.restored {
            inner.restored = true;
            inner.restoring = Some(load().into_iter().collect());
        }
    }

    /// The ids whose acknowledgement ended since this was last asked, to be
    /// removed from the store.
    pub fn take_stale_acks(&self) -> Vec<String> {
        std::mem::take(&mut self.inner.lock().stale)
    }
}

/// The key of condition `id`'s acknowledgement in the node's metadata.
fn ack_key(id: &str) -> Vec<u8> {
    format!("{ACK_PREFIX}{id}").into_bytes()
}

/// The acknowledgements `store` holds, at most [`MAX_ACKS`]; a record that
/// does not read is left out.
fn stored_acks(store: &dyn KvStore) -> Vec<(String, Acknowledged)> {
    store
        .scan_prefix(CF_METADATA, ACK_PREFIX.as_bytes())
        .unwrap_or_default()
        .into_iter()
        .filter_map(|(key, value)| {
            let id = std::str::from_utf8(key.get(ACK_PREFIX.len()..)?).ok()?;
            let ack = serde_json::from_slice::<Acknowledged>(&value).ok()?;
            Some((id.to_string(), ack))
        })
        .take(MAX_ACKS)
        .collect()
}

/// The open conditions in the order a client shows them: the most severe
/// first, then the longest open.
fn listed(open: &BTreeMap<String, Condition>) -> Vec<Condition> {
    let mut list: Vec<Condition> = open.values().cloned().collect();
    list.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then(a.since_ms.cmp(&b.since_ms))
            .then_with(|| a.id.cmp(&b.id))
    });
    list
}

/// Read this node's conditions now: what `tenzro_listConditions` answers.
pub(crate) async fn observe(node: &Arc<TenzroNode>) -> Vec<Condition> {
    let now_ms = chrono::Utc::now().timestamp_millis().max(0) as u64;
    if let Some(open) = node.conditions.held(now_ms) {
        return open;
    }
    let store = node.storage().map(|s| s.clone() as Arc<dyn KvStore>);
    if let Some(store) = &store {
        node.conditions.restore_once(|| stored_acks(store.as_ref()));
    }
    let lifecycle = match *node.state.read() {
        NodeState::Running => Lifecycle::Running,
        NodeState::Created | NodeState::Starting => Lifecycle::Starting,
        NodeState::Stopping | NodeState::Stopped => Lifecycle::Stopping,
    };
    let follow = node.follow_state().await;
    let height = follow.local_height;
    let update = crate::update_notice::hub(&node.config().data_dir)
        .newer(now_ms)
        .map(|notice| Update {
            version: notice.version.clone(),
            severity: notice.severity,
            released_ms: notice.released_ms,
        });
    let disk = node.disk_guard().status();
    let health = node
        .health_monitor()
        .list_subsystems()
        .into_iter()
        .map(|(name, status, _)| (name, status))
        .collect();
    let seen = Seen {
        lifecycle,
        follow,
        health,
        quorum: node.consensus().and_then(|c| c.quorum_standing()),
        approver: update.as_ref().and_then(|_| approver(node)),
        update,
        stakes: operator_stakes(node),
        roles: role_gaps(node),
        doctor: doctor_findings(node),
        disk_level: disk.level,
        disk_used_pct: disk.used_pct,
        key_grant: key_grant().await,
    };
    let open = node
        .conditions
        .settle(judge(&seen, now_ms), now_ms, height, &node.event_bus);
    if let Some(store) = &store {
        for id in node.conditions.take_stale_acks() {
            if let Err(e) = store.delete(CF_METADATA, &ack_key(&id)) {
                tracing::warn!(condition = %id, error = %e, "an ended acknowledgement stays in the store");
            }
        }
    }
    open
}

/// The relying party of the operator's passkeys, when this node has an
/// operator with a bound device.
fn approver(node: &Arc<TenzroNode>) -> Option<String> {
    let operator = node.operator_did()?;
    let bound = crate::device_rpc::list_devices(node, &operator).ok()?;
    (!bound.is_empty()).then(|| node.http_surface().webauthn_rp_id().to_string())
}

/// A passkey's answer to a challenge, as a browser or phone returns it. Every
/// field is base64url.
#[derive(Debug, Deserialize)]
pub struct Assertion {
    pub credential_id: String,
    pub authenticator_data: String,
    pub client_data_json: String,
    pub signature: String,
}

#[derive(Debug, Deserialize)]
struct Approval {
    condition_id: String,
    approve: bool,
    assertion: Option<Assertion>,
}

fn refusal(code: i32, message: impl Into<String>) -> JsonRpcError {
    JsonRpcError {
        code,
        message: message.into(),
        data: None,
    }
}

/// `tenzro_submitApproval`: the operator's answer to a condition that asks.
///
/// An approval carries a passkey's assertion over the condition's challenge,
/// made by a device bound to the operator; the node then does what the
/// condition names, and the condition asks no more once that started. A
/// decline needs no assertion: the condition stays listed while it holds and
/// asks no more.
pub(crate) async fn submit_approval(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let approval: Approval = crate::passkey_rpc::parse_params(params)?;
    let id = approval.condition_id.as_str();
    let open = observe(node).await;
    let condition = open
        .iter()
        .find(|condition| condition.id == id)
        .ok_or_else(|| refusal(-32602, format!("No open condition has the id {id}.")))?;
    let unasked = || {
        refusal(
            -32003,
            format!(
                "\"{}\" is not waiting for an answer: the node does not act on it by itself, \
                 or it was answered already.",
                condition.title
            ),
        )
    };
    let by = crate::rpc::current_caller_did();
    if !approval.approve {
        let now_ms = chrono::Utc::now().timestamp_millis().max(0) as u64;
        return if node
            .conditions
            .answer(id, false, by, now_ms, &node.event_bus)
        {
            Ok(serde_json::json!({ "ok": true, "condition_id": id, "approved": false }))
        } else {
            Err(unasked())
        };
    }
    let assertion = approval
        .assertion
        .ok_or_else(|| refusal(-32602, "An approval needs a passkey's assertion."))?;
    let operator = node.operator_did().ok_or_else(|| {
        refusal(
            -32003,
            "This node has no operator whose passkey could approve.",
        )
    })?;
    // The challenge is spent only once an assertion verified against it, so a
    // caller with a bad assertion cannot burn the one the operator is answering.
    let (challenge, act) = node.conditions.challenge(id).ok_or_else(unasked)?;
    crate::device_rpc::require_operator_assertion(node, &operator, &challenge, &assertion)?;
    if !node.conditions.spend_challenge(id, &challenge) {
        return Err(unasked());
    }
    let done = match act {
        Act::InstallUpdate { version } => {
            let hub = crate::update_notice::hub(&node.config().data_dir);
            let now_ms = chrono::Utc::now().timestamp_millis().max(0) as u64;
            crate::update_notice::install(
                &hub,
                now_ms,
                Some(&version),
                crate::update_notice::updater_beside_node(),
            )
            .map_err(|message| refusal(-32603, message))?;
            serde_json::json!({ "installing": version })
        }
    };
    let now_ms = chrono::Utc::now().timestamp_millis().max(0) as u64;
    node.conditions
        .answer(id, true, by, now_ms, &node.event_bus);
    Ok(serde_json::json!({ "ok": true, "condition_id": id, "approved": true, "done": done }))
}

#[derive(Debug, Deserialize)]
struct Acknowledgement {
    id: String,
    since: String,
    reason: String,
}

/// `tenzro_acknowledgeCondition`: the operator saw an open condition and says
/// why it may stay. Params `{id, since, reason}`: `since` as the list gives it,
/// so an acknowledgement never lands on a later opening; `reason` is 1 to
/// [`MAX_REASON_CHARS`] characters once trimmed. The node stores it and lists
/// it with the condition until the condition clears or grows graver.
pub(crate) async fn acknowledge_condition(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let request: Acknowledgement = crate::passkey_rpc::parse_params(params)?;
    let reason = request.reason.trim();
    if reason.is_empty() || reason.chars().count() > MAX_REASON_CHARS {
        return Err(refusal(
            -32602,
            format!("A reason is 1 to {MAX_REASON_CHARS} characters."),
        ));
    }
    let store = node
        .storage()
        .map(|s| s.clone() as Arc<dyn KvStore>)
        .ok_or_else(|| refusal(-32000, "Storage not initialized"))?;
    observe(node).await;
    let now_ms = chrono::Utc::now().timestamp_millis().max(0) as u64;
    let ack = node
        .conditions
        .acknowledge(
            &request.id,
            &request.since,
            Ack {
                by: crate::rpc::current_caller_did(),
                reason: reason.to_string(),
                at: rfc3339(now_ms),
            },
            now_ms,
            &node.event_bus,
            |kept| keep_ack(store.as_ref(), &request.id, kept),
        )
        .map_err(|refused| ack_refusal(&request.id, refused))?;
    Ok(serde_json::json!({ "ok": true, "id": request.id, "ack": ack }))
}

/// Store condition `id`'s acknowledgement.
fn keep_ack(store: &dyn KvStore, id: &str, kept: &Acknowledged) -> Result<(), String> {
    let bytes = serde_json::to_vec(kept).map_err(|e| e.to_string())?;
    store
        .put(CF_METADATA, &ack_key(id), &bytes)
        .map_err(|e| e.to_string())
}

fn ack_refusal(id: &str, refused: AckRefusal) -> JsonRpcError {
    match refused {
        AckRefusal::NotOpen => refusal(-32602, format!("No open condition has the id {id}.")),
        AckRefusal::OpenedAgain(since) => refusal(
            -32003,
            format!("That condition opened again, at {since}: read the list again."),
        ),
        AckRefusal::Store(why) => {
            refusal(-32603, format!("The acknowledgement was not stored: {why}"))
        }
    }
}

/// The role stakes this node's operator account holds, with what each role
/// requires of it.
fn operator_stakes(node: &TenzroNode) -> Vec<Stake> {
    let (Some(chain), Some(operator)) = (crate::rpc::chain_state_of(node), node.operator_payee())
    else {
        return Vec::new();
    };
    let ladder = tenzro_vm::native::stake_ladder(&chain);
    tenzro_vm::native::role_stakes_of(&chain, operator.as_bytes())
        .into_iter()
        .map(|(role, stake)| Stake {
            role: role.as_str(),
            bonded: stake.bonded,
            required: role.required_stake(&stake.capacity, &ladder),
        })
        .collect()
}

/// The roles this machine cannot back, and the roles waiting for a bond.
fn role_gaps(node: &TenzroNode) -> Vec<RoleGap> {
    let awaiting = node.roles_awaiting_bond.lock().clone();
    node.roles_unsupported
        .iter()
        .map(|(role, reason)| RoleGap {
            role: role.as_str(),
            gap: Gap::Unsupported(reason.clone()),
        })
        .chain(awaiting.into_iter().map(|role| RoleGap {
            role: role.as_str(),
            gap: Gap::AwaitingBond,
        }))
        .collect()
}

/// What `tenzro-node doctor` would find from this node alone: its load, its
/// TPM, its relays and how peers reach it.
fn doctor_findings(node: &TenzroNode) -> Vec<(Finding, String)> {
    let level = crate::load_monitor::current_level();
    let load = crate::doctor::LoadStatus {
        level: level.name().to_string(),
        shedding: crate::load_monitor::shed_classes(level)
            .into_iter()
            .map(|class| class.name().to_string())
            .collect(),
    };
    let tpm = tenzro_device_key::tpm_health()
        .and_then(|health| health.get("summary")?.as_str().map(str::to_string));
    let reach = match (node.identity_transport.as_ref(), node.iroh_resolver()) {
        (Some(transport), Some(resolver)) => Some(transport.connectivity(resolver.endpoint())),
        _ => None,
    };
    let config = node.config();
    crate::doctor::findings(
        Some(&load),
        tpm.as_deref(),
        reach.as_ref(),
        config.iroh.relay_only,
        node.runtime_roles.read().is_validator(),
        config.iroh.bind_addr.port(),
    )
}

/// The key holder's answer about its grant, on a machine that signs through
/// one.
#[cfg(unix)]
async fn key_grant() -> Option<Result<Option<u64>, String>> {
    let socket = crate::identity_bootstrap::key_holder_socket()?;
    Some(
        tokio::task::spawn_blocking(move || crate::tpm_key_holder::holder_id(&socket))
            .await
            .map_err(|e| e.to_string())
            .and_then(|answer| answer)
            .map(|(_, grant_end)| grant_end),
    )
}

/// A key holder is reached over a local socket, which this platform's node
/// does not use.
#[cfg(not(unix))]
async fn key_grant() -> Option<Result<Option<u64>, String>> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_events::EventBusConfig;

    const NOW: u64 = 1_800_000_000_000;
    const TNZO: u128 = 1_000_000_000_000_000_000;

    fn following() -> FollowState {
        FollowState {
            state: Following::Following,
            reason: None,
            detail: None,
            local_height: 900,
            network_head: Some(900),
            head_heard_ms: Some(200),
            behind: Some(0),
            behind_before: Some(0),
            last_import_ms: Some(400),
        }
    }

    fn healthy() -> Seen {
        Seen {
            lifecycle: Lifecycle::Running,
            follow: following(),
            health: vec![("consensus".into(), SubsystemStatus::Healthy)],
            quorum: Some(QuorumStanding {
                epoch: 4,
                seats: 1,
                total_seats: 4,
                quorum: 3,
                reached_seats: 3,
            }),
            update: None,
            stakes: vec![Stake {
                role: "validator",
                bonded: 1_000 * TNZO,
                required: 1_000 * TNZO,
            }],
            roles: Vec::new(),
            doctor: Vec::new(),
            disk_level: Level::Ok,
            disk_used_pct: 41,
            key_grant: Some(Ok(Some(NOW + 3_600_000))),
            approver: None,
        }
    }

    /// A node that knows of a newer release and has an operator whose bound
    /// device can approve its install.
    fn awaiting_approval() -> Seen {
        Seen {
            update: Some(Update {
                version: "0.2.9".into(),
                severity: tenzro_update_notice::Severity::Normal,
                released_ms: NOW - 5_000,
            }),
            approver: Some("node.example".into()),
            ..healthy()
        }
    }

    fn stalled(reason: Reason) -> FollowState {
        FollowState {
            state: Following::Stalled,
            reason: Some(reason),
            detail: Some("No block arrived for a while."),
            last_import_ms: Some(90_000),
            ..following()
        }
    }

    fn bus() -> EventBus {
        EventBus::new(EventBusConfig::default())
    }

    fn one(seen: &Seen) -> Found {
        let mut found = judge(seen, NOW);
        assert_eq!(found.len(), 1, "{found:?}");
        found.remove(0)
    }

    #[test]
    fn a_healthy_node_has_no_conditions() {
        assert_eq!(judge(&healthy(), NOW), Vec::new());
    }

    #[test]
    fn a_node_that_has_heard_nothing_yet_has_no_follow_condition() {
        let seen = Seen {
            follow: FollowState {
                state: Following::Starting,
                behind: None,
                ..following()
            },
            ..healthy()
        };
        assert_eq!(judge(&seen, NOW), Vec::new());
    }

    #[test]
    fn a_node_that_is_catching_up_says_how_far_behind_it_is() {
        let catching_up = |behind_before| Seen {
            follow: FollowState {
                state: Following::CatchingUp,
                behind: Some(40),
                behind_before,
                ..following()
            },
            ..healthy()
        };
        let found = one(&catching_up(Some(100)));
        assert_eq!(found.id, "follow");
        assert_eq!(found.kind, "follow");
        assert_eq!(found.code, "catching_up");
        assert_eq!(found.severity, Severity::Info);
        assert_eq!(found.title, "Catching up with the network");
        assert_eq!(
            found.detail,
            "40 blocks behind the network's head, 60 fewer than 30 seconds ago."
        );
        assert_eq!(
            one(&catching_up(None)).detail,
            "40 blocks behind the network's head, and importing."
        );
    }

    #[test]
    fn a_node_that_is_not_running_says_so() {
        for (lifecycle, code, title) in [
            (Lifecycle::Starting, "starting", "The node is starting"),
            (Lifecycle::Stopping, "stopping", "The node is stopping"),
        ] {
            let found = one(&Seen {
                lifecycle,
                ..healthy()
            });
            assert_eq!(found.id, "node");
            assert_eq!(found.kind, "node");
            assert_eq!(found.code, code);
            assert_eq!(found.severity, Severity::Warning);
            assert_eq!(found.title, title);
        }
    }

    #[test]
    fn each_subsystem_that_is_not_healthy_is_a_condition_but_the_disk_has_its_own() {
        let found = judge(
            &Seen {
                health: vec![
                    (
                        "bridge".into(),
                        SubsystemStatus::Unhealthy {
                            reason: "no route answered".into(),
                        },
                    ),
                    ("consensus".into(), SubsystemStatus::Healthy),
                    (
                        "disk".into(),
                        SubsystemStatus::Degraded {
                            reason: "data volume low".into(),
                        },
                    ),
                    (
                        "tee".into(),
                        SubsystemStatus::Degraded {
                            reason: "attestation is stale".into(),
                        },
                    ),
                ],
                ..healthy()
            },
            NOW,
        );
        let rows: Vec<(&str, &str, Severity, &str, &str)> = found
            .iter()
            .map(|f| {
                (
                    f.id.as_str(),
                    f.code,
                    f.severity,
                    f.title.as_str(),
                    f.detail.as_str(),
                )
            })
            .collect();
        assert_eq!(
            rows,
            [
                (
                    "health:bridge",
                    "unhealthy",
                    Severity::Critical,
                    "The bridge subsystem is not working",
                    "no route answered."
                ),
                (
                    "health:tee",
                    "degraded",
                    Severity::Warning,
                    "The tee subsystem is degraded",
                    "attestation is stale."
                ),
            ]
        );
        assert!(found.iter().all(|f| f.kind == "health"));
    }

    #[test]
    fn a_validator_its_committee_cannot_certify_without_is_told_so() {
        let standing = |seats, total_seats, quorum, reached_seats| Seen {
            quorum: Some(QuorumStanding {
                epoch: 4,
                seats,
                total_seats,
                quorum,
                reached_seats,
            }),
            ..healthy()
        };
        // Four members of one seat each: a certificate needs three.
        assert_eq!(judge(&standing(1, 4, 3, 3), NOW), Vec::new());
        let thin = one(&standing(1, 4, 3, 2));
        assert_eq!(thin.id, "quorum");
        assert_eq!(thin.kind, "quorum");
        assert_eq!(thin.code, "quorum_rests_on_this_validator");
        assert_eq!(thin.severity, Severity::Warning);
        assert!(
            thin.detail.starts_with(
                "This validator has open consensus channels to members holding 2 of the other 3 seats, and a certificate needs 3."
            ),
            "{}",
            thin.detail
        );

        let alone = one(&standing(1, 1, 1, 0));
        assert_eq!(alone.code, "committee_needs_this_validator");
        assert_eq!(alone.severity, Severity::Info);
        assert_eq!(
            alone.detail,
            "Without this validator's 1 of 1 seats the committee of epoch 4 holds 0, and a certificate needs 1: nothing is certified while it is stopped."
        );
        let heavy = one(&standing(2, 3, 2, 1));
        assert_eq!(heavy.code, "committee_needs_this_validator");

        let follower = Seen {
            quorum: None,
            ..healthy()
        };
        assert_eq!(judge(&follower, NOW), Vec::new());
    }

    #[test]
    fn a_stalled_node_names_its_reason_and_when_it_last_imported() {
        for (reason, code) in [
            (Reason::NoPeerHeard, "no_peer_heard"),
            (Reason::NoProgress, "no_progress"),
            (Reason::RangeBroughtNothing, "range_brought_nothing"),
        ] {
            let found = one(&Seen {
                follow: stalled(reason),
                ..healthy()
            });
            assert_eq!(found.id, "follow");
            assert_eq!(found.kind, "follow");
            assert_eq!(found.code, code);
            assert_eq!(found.severity, Severity::Critical);
            assert_eq!(found.detail, "No block arrived for a while.");
            assert_eq!(found.began_ms, Some(NOW - 90_000));
        }
    }

    #[test]
    fn a_newer_release_is_a_condition_as_grave_as_its_notice() {
        for (severity, code, grave) in [
            (
                tenzro_update_notice::Severity::Normal,
                "update_ready",
                Severity::Info,
            ),
            (
                tenzro_update_notice::Severity::Security,
                "security_update",
                Severity::Warning,
            ),
            (
                tenzro_update_notice::Severity::RequiredByEpoch { epoch: 77 },
                "required_update",
                Severity::Critical,
            ),
        ] {
            let found = one(&Seen {
                update: Some(Update {
                    version: "0.2.9".into(),
                    severity,
                    released_ms: NOW - 5_000,
                }),
                ..healthy()
            });
            assert_eq!(found.id, "update:0.2.9");
            assert_eq!(found.kind, "update");
            assert_eq!(found.code, code);
            assert_eq!(found.severity, grave);
            assert_eq!(found.title, "Update 0.2.9 is ready");
            assert_eq!(found.began_ms, Some(NOW - 5_000));
        }
        let required = one(&Seen {
            update: Some(Update {
                version: "0.2.9".into(),
                severity: tenzro_update_notice::Severity::RequiredByEpoch { epoch: 77 },
                released_ms: NOW,
            }),
            ..healthy()
        });
        assert_eq!(
            required.detail,
            "The network requires release 0.2.9 from epoch 77."
        );
    }

    #[test]
    fn a_stake_is_short_only_when_some_is_bonded_and_less_than_required() {
        let with = |bonded: u128| Seen {
            stakes: vec![Stake {
                role: "model_provider",
                bonded,
                required: 500 * TNZO,
            }],
            ..healthy()
        };
        assert_eq!(judge(&with(0), NOW), Vec::new());
        assert_eq!(judge(&with(500 * TNZO), NOW), Vec::new());
        assert_eq!(judge(&with(900 * TNZO), NOW), Vec::new());
        let found = one(&with(499 * TNZO + TNZO / 2));
        assert_eq!(found.id, "stake:model_provider");
        assert_eq!(found.kind, "stake");
        assert_eq!(found.code, "stake_short");
        assert_eq!(found.severity, Severity::Warning);
        assert_eq!(
            found.detail,
            "499.5 TNZO is bonded and the role requires 500 TNZO."
        );
    }

    #[test]
    fn a_role_the_node_does_not_stand_behind_says_why() {
        let gap = |role, gap| RoleGap { role, gap };
        let seen = Seen {
            roles: vec![
                gap(
                    "tee_provider",
                    Gap::Unsupported("no TEE was detected".into()),
                ),
                gap("rpc", Gap::AwaitingBond),
            ],
            ..healthy()
        };
        let found: Vec<_> = judge(&seen, NOW)
            .into_iter()
            .map(|f| (f.id, f.kind, f.code, f.severity, f.title))
            .collect();
        assert_eq!(
            found,
            [
                (
                    "role:tee_provider".to_string(),
                    "role",
                    "role_unsupported",
                    Severity::Warning,
                    "The tee_provider role is not served".to_string(),
                ),
                (
                    "role:rpc".into(),
                    "role",
                    "role_unbonded",
                    Severity::Warning,
                    "The rpc role is not served".into(),
                ),
            ]
        );
        assert!(
            judge(&seen, NOW)[0]
                .detail
                .ends_with("cannot back it: no TEE was detected.")
        );
    }

    #[test]
    fn what_the_doctor_finds_is_a_condition_with_its_fix() {
        let seen = Seen {
            doctor: vec![
                (Finding::Load { critical: false }, "shed less".into()),
                (Finding::Load { critical: true }, "shed less".into()),
                (Finding::TpmStalled, "wait for the chip".into()),
                (Finding::NoUdp, "allow UDP".into()),
                (Finding::ValidatorNotDirect, "give it an address".into()),
            ],
            ..healthy()
        };
        let found: Vec<_> = judge(&seen, NOW)
            .into_iter()
            .map(|f| (f.id, f.kind, f.severity, f.detail))
            .collect();
        assert_eq!(
            found,
            [
                (
                    "doctor:load_shedding".to_string(),
                    "doctor",
                    Severity::Warning,
                    "shed less".to_string(),
                ),
                (
                    "doctor:load_shedding".into(),
                    "doctor",
                    Severity::Critical,
                    "shed less".into(),
                ),
                (
                    "doctor:tpm_stalled".into(),
                    "doctor",
                    Severity::Critical,
                    "wait for the chip".into(),
                ),
                (
                    "doctor:no_udp".into(),
                    "doctor",
                    Severity::Info,
                    "allow UDP".into(),
                ),
                (
                    "doctor:validator_not_direct".into(),
                    "doctor",
                    Severity::Warning,
                    "give it an address".into(),
                ),
            ]
        );
    }

    #[test]
    fn the_disk_condition_follows_the_disk_level() {
        for (level, expected) in [
            (Level::Ok, None),
            (Level::Warn, Some(("disk_filling", Severity::Warning))),
            (Level::Prune, Some(("disk_filling", Severity::Warning))),
            (Level::Refuse, Some(("disk_refusing", Severity::Critical))),
            (Level::Reserve, Some(("disk_reserve", Severity::Critical))),
        ] {
            let found = judge(
                &Seen {
                    disk_level: level,
                    disk_used_pct: 93,
                    ..healthy()
                },
                NOW,
            );
            match expected {
                None => assert_eq!(found, Vec::new()),
                Some((code, severity)) => {
                    assert_eq!(found.len(), 1);
                    assert_eq!(found[0].id, "requirement:disk");
                    assert_eq!(found[0].kind, "requirement");
                    assert_eq!(found[0].code, code);
                    assert_eq!(found[0].severity, severity);
                    assert!(found[0].detail.starts_with("93% of the data disk is used."));
                }
            }
        }
    }

    #[test]
    fn a_key_holder_without_a_grant_in_force_is_a_condition() {
        let with = |key_grant| Seen {
            key_grant,
            ..healthy()
        };
        assert_eq!(judge(&with(None), NOW), Vec::new());
        assert_eq!(judge(&with(Some(Ok(Some(NOW + 1)))), NOW), Vec::new());

        let silent = one(&with(Some(Err("connection refused".into()))));
        assert_eq!(silent.id, "key_grant");
        assert_eq!(silent.kind, "key_grant");
        assert_eq!(silent.code, "key_holder_unreachable");
        assert_eq!(silent.severity, Severity::Critical);
        assert_eq!(
            silent.detail,
            "The key holder gave no answer: connection refused."
        );

        let none = one(&with(Some(Ok(None))));
        assert_eq!(none.code, "key_grant_missing");
        assert_eq!(none.began_ms, None);

        let ended = one(&with(Some(Ok(Some(NOW - 30_000)))));
        assert_eq!(ended.code, "key_grant_expired");
        assert_eq!(ended.began_ms, Some(NOW - 30_000));
        assert_eq!(one(&with(Some(Ok(Some(NOW))))).code, "key_grant_expired");
    }

    #[test]
    fn amounts_read_as_whole_tnzo() {
        assert_eq!(tnzo(0), "0");
        assert_eq!(tnzo(TNZO), "1");
        assert_eq!(tnzo(1_250 * TNZO + TNZO / 4), "1250.25");
        assert_eq!(tnzo(1), "0.000000000000000001");
    }

    #[tokio::test]
    async fn opening_and_clearing_are_each_published_once() {
        let bus = bus();
        let mut listener = bus.subscribe();
        let book = ConditionBook::default();
        let stalled_node = Seen {
            follow: stalled(Reason::NoProgress),
            ..healthy()
        };

        let open = book.settle(judge(&stalled_node, NOW), NOW, 900, &bus);
        assert_eq!(open.len(), 1);
        assert_eq!(open[0].id, "follow");
        assert_eq!(open[0].since, "2027-01-15T07:58:30Z");
        let opened = listener.recv().await.unwrap();
        assert_eq!(opened.block_height, Some(900));
        assert_eq!(
            opened.event,
            TenzroEvent::ConditionOpened {
                id: "follow".into(),
                kind: "follow".into(),
                code: "no_progress".into(),
                severity: "critical".into(),
                summary: "Not following the network".into(),
            }
        );

        // Still stalled a minute later, for another reason: the same
        // condition, open since the same time, and nothing is published.
        let later = NOW + 60_000;
        let still = book.settle(
            judge(
                &Seen {
                    follow: stalled(Reason::RangeBroughtNothing),
                    ..healthy()
                },
                later,
            ),
            later,
            900,
            &bus,
        );
        assert_eq!(still.len(), 1);
        assert_eq!(still[0].code, "range_brought_nothing");
        assert_eq!(still[0].since, open[0].since);
        assert_eq!(book.recent().len(), 1);

        let after = later + 60_000;
        assert_eq!(
            book.settle(judge(&healthy(), after), after, 950, &bus),
            Vec::new()
        );
        let cleared = listener.recv().await.unwrap();
        assert_eq!(cleared.sequence, opened.sequence + 1);
        assert_eq!(cleared.block_height, Some(950));
        assert_eq!(
            cleared.event,
            TenzroEvent::ConditionCleared {
                id: "follow".into(),
                kind: "follow".into(),
                code: "range_brought_nothing".into(),
                severity: "critical".into(),
                summary: "Cleared: Not following the network".into(),
            }
        );

        let recent = book.recent();
        assert_eq!(recent.len(), 2);
        assert_eq!(recent[0].kind, "condition_cleared");
        assert_eq!(recent[0].sequence, cleared.sequence);
        assert_eq!(recent[0].summary, "Cleared: Not following the network");
        assert_eq!(recent[0].block, 950);
        assert_eq!(recent[0].condition, "follow");
        assert_eq!(recent[1].kind, "condition_opened");
        assert_eq!(recent[1].sequence, opened.sequence);
        assert_eq!(recent[1].at, "2027-01-15T08:00:00Z");
    }

    #[test]
    fn a_condition_never_began_after_it_was_seen() {
        let bus = bus();
        let book = ConditionBook::default();
        let open = book.settle(
            judge(
                &Seen {
                    update: Some(Update {
                        version: "0.2.9".into(),
                        severity: tenzro_update_notice::Severity::Normal,
                        released_ms: NOW + 3_600_000,
                    }),
                    ..healthy()
                },
                NOW,
            ),
            NOW,
            1,
            &bus,
        );
        assert_eq!(open[0].since, "2027-01-15T08:00:00Z");
    }

    #[test]
    fn the_list_puts_the_most_severe_first_then_the_longest_open() {
        let bus = bus();
        let book = ConditionBook::default();
        let seen = Seen {
            follow: stalled(Reason::NoPeerHeard),
            update: Some(Update {
                version: "0.2.9".into(),
                severity: tenzro_update_notice::Severity::Normal,
                released_ms: NOW - 1_000,
            }),
            stakes: vec![Stake {
                role: "validator",
                bonded: TNZO,
                required: 2 * TNZO,
            }],
            disk_level: Level::Refuse,
            disk_used_pct: 97,
            key_grant: None,
            approver: None,
            ..healthy()
        };
        let ids: Vec<String> = book
            .settle(judge(&seen, NOW), NOW, 5, &bus)
            .into_iter()
            .map(|c| c.id)
            .collect();
        assert_eq!(
            ids,
            [
                "follow",
                "requirement:disk",
                "stake:validator",
                "update:0.2.9"
            ]
        );
    }

    #[test]
    fn a_reading_answers_the_next_reader_for_a_short_while() {
        let bus = bus();
        let book = ConditionBook::default();
        assert_eq!(book.held(NOW), None);
        let open = book.settle(
            judge(
                &Seen {
                    disk_level: Level::Warn,
                    ..healthy()
                },
                NOW,
            ),
            NOW,
            5,
            &bus,
        );
        assert_eq!(book.held(NOW + READING_HOLDS_MS - 1), Some(open));
        assert_eq!(book.held(NOW + READING_HOLDS_MS), None);
    }

    #[test]
    fn the_history_keeps_the_newest_changes() {
        let bus = bus();
        let book = ConditionBook::default();
        let filling = Seen {
            disk_level: Level::Warn,
            ..healthy()
        };
        for round in 0..HISTORY as u64 {
            let at = NOW + round * 2;
            book.settle(judge(&filling, at), at, round, &bus);
            book.settle(judge(&healthy(), at + 1), at + 1, round, &bus);
        }
        let recent = book.recent();
        assert_eq!(recent.len(), HISTORY);
        assert_eq!(recent[0].kind, "condition_cleared");
        assert_eq!(recent[0].block, HISTORY as u64 - 1);
        assert!(recent.windows(2).all(|w| w[0].sequence > w[1].sequence));
    }

    #[test]
    fn only_an_update_an_operator_device_can_approve_asks_for_a_passkey() {
        let asked = one(&awaiting_approval());
        assert_eq!(
            asked.ask,
            Some(Ask {
                act: Act::InstallUpdate {
                    version: "0.2.9".into()
                },
                rp_id: "node.example".into(),
            })
        );
        let nobody = one(&Seen {
            approver: None,
            ..awaiting_approval()
        });
        assert_eq!(nobody.ask, None);
        let other = one(&Seen {
            disk_level: Level::Refuse,
            update: None,
            ..awaiting_approval()
        });
        assert_eq!(other.ask, None);
    }

    #[test]
    fn a_condition_asks_with_one_challenge_until_it_is_taken() {
        let bus = bus();
        let book = ConditionBook::default();
        let first = book.settle(judge(&awaiting_approval(), NOW), NOW, 5, &bus);
        let asking = first[0].asking.clone().expect("the update asks");
        assert_eq!(asking.needs, "passkey");
        assert_eq!(asking.rp_id, "node.example");

        let later = NOW + 60_000;
        let again = book.settle(judge(&awaiting_approval(), later), later, 6, &bus);
        assert_eq!(again[0].asking, Some(asking.clone()));

        let (shown, act) = book.challenge("update:0.2.9").expect("it asks");
        assert_eq!(shown, asking.challenge);
        assert_eq!(
            act,
            Act::InstallUpdate {
                version: "0.2.9".into()
            }
        );
        // Reading it spends nothing; only a verified answer does, once.
        assert_eq!(book.challenge("update:0.2.9").expect("it asks").0, shown);
        assert!(book.spend_challenge("update:0.2.9", &shown));
        assert!(!book.spend_challenge("update:0.2.9", &shown));
        let after = book.held(later).expect("the reading still holds");
        let fresh = after[0].asking.clone().expect("it still asks");
        assert_ne!(fresh.challenge, asking.challenge);
        assert_eq!(
            book.challenge("update:0.2.9").expect("it asks").0,
            fresh.challenge
        );
    }

    #[test]
    fn an_answered_condition_stays_listed_and_asks_no_more() {
        let bus = bus();
        let book = ConditionBook::default();
        book.settle(judge(&awaiting_approval(), NOW), NOW, 5, &bus);
        assert!(book.answer("update:0.2.9", false, None, NOW, &bus));
        assert!(!book.answer("update:0.2.9", false, None, NOW, &bus));
        assert_eq!(book.challenge("update:0.2.9"), None);

        let later = NOW + 60_000;
        let open = book.settle(judge(&awaiting_approval(), later), later, 6, &bus);
        assert_eq!(open.len(), 1);
        assert_eq!(open[0].id, "update:0.2.9");
        assert_eq!(open[0].asking, None);

        // The answer is to that release: a condition that cleared and opens
        // again asks again.
        let cleared = later + 60_000;
        assert!(
            book.settle(judge(&healthy(), cleared), cleared, 7, &bus)
                .is_empty()
        );
        let back = cleared + 60_000;
        let open = book.settle(judge(&awaiting_approval(), back), back, 8, &bus);
        assert!(open[0].asking.is_some());
    }

    #[test]
    fn a_condition_nothing_asks_about_takes_no_answer() {
        let bus = bus();
        let book = ConditionBook::default();
        let filling = Seen {
            disk_level: Level::Refuse,
            disk_used_pct: 96,
            ..healthy()
        };
        book.settle(judge(&filling, NOW), NOW, 5, &bus);
        assert!(!book.answer("requirement:disk", true, None, NOW, &bus));
        assert_eq!(book.challenge("requirement:disk"), None);
        assert!(!book.answer("update:0.2.9", true, None, NOW, &bus));
    }

    #[test]
    fn a_condition_that_asks_serializes_what_the_passkey_signs() {
        use base64::Engine;
        let bus = bus();
        let book = ConditionBook::default();
        let open = book.settle(judge(&awaiting_approval(), NOW), NOW, 5, &bus);
        let challenge = open[0].asking.as_ref().expect("the update asks").challenge;
        assert_eq!(
            serde_json::to_value(&open).unwrap(),
            serde_json::json!([{
                "id": "update:0.2.9",
                "kind": "update",
                "code": "update_ready",
                "severity": "info",
                "title": "Update 0.2.9 is ready",
                "detail": "Release 0.2.9 can be installed.",
                "since": "2027-01-15T07:59:55Z",
                "needs": "passkey",
                "challenge": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(challenge),
                "rp_id": "node.example",
                "ack": null,
            }])
        );
    }

    #[test]
    fn a_condition_serializes_the_fields_a_client_reads() {
        let bus = bus();
        let book = ConditionBook::default();
        let open = book.settle(
            judge(
                &Seen {
                    disk_level: Level::Refuse,
                    disk_used_pct: 96,
                    ..healthy()
                },
                NOW,
            ),
            NOW,
            5,
            &bus,
        );
        assert_eq!(
            serde_json::to_value(&open).unwrap(),
            serde_json::json!([{
                "id": "requirement:disk",
                "kind": "requirement",
                "code": "disk_refusing",
                "severity": "critical",
                "title": "The data disk is nearly full",
                "detail": "96% of the data disk is used. The node refuses data it can run without; consensus continues.",
                "since": "2027-01-15T08:00:00Z",
                "ack": null,
            }])
        );
    }

    fn filling() -> Seen {
        Seen {
            disk_level: Level::Warn,
            disk_used_pct: 88,
            ..healthy()
        }
    }

    fn ack(reason: &str, at_ms: u64) -> Ack {
        Ack {
            by: Some("did:tenzro:human:operator".into()),
            reason: reason.into(),
            at: rfc3339(at_ms),
        }
    }

    #[tokio::test]
    async fn an_answer_is_published_with_who_gave_it() {
        let bus = bus();
        let book = ConditionBook::default();
        book.settle(judge(&awaiting_approval(), NOW), NOW, 5, &bus);
        let mut listener = bus.subscribe();
        assert!(book.answer(
            "update:0.2.9",
            true,
            Some("did:tenzro:human:operator".into()),
            NOW + 1_000,
            &bus
        ));
        let answered = listener.recv().await.unwrap();
        assert_eq!(answered.block_height, Some(5));
        assert_eq!(
            answered.event,
            TenzroEvent::ConditionAnswered {
                id: "update:0.2.9".into(),
                kind: "update".into(),
                answer: "approved".into(),
                by: Some("did:tenzro:human:operator".into()),
                summary: "Approved: Update 0.2.9 is ready".into(),
            }
        );
        let recent = book.recent();
        assert_eq!(recent[0].kind, "condition_answered");
        assert_eq!(recent[0].sequence, answered.sequence);
        assert_eq!(recent[0].summary, "Approved: Update 0.2.9 is ready");
    }

    #[tokio::test]
    async fn an_acknowledged_condition_lists_the_acknowledgement_and_publishes_it() {
        let bus = bus();
        let book = ConditionBook::default();
        let open = book.settle(judge(&filling(), NOW), NOW, 5, &bus);
        let mut listener = bus.subscribe();
        let mut stored = None;
        let given = book
            .acknowledge(
                "requirement:disk",
                &open[0].since,
                ack("a larger disk arrives on Monday", NOW + 1_000),
                NOW + 1_000,
                &bus,
                |kept| {
                    stored = Some(kept.clone());
                    Ok(())
                },
            )
            .expect("an open condition takes an acknowledgement");
        assert_eq!(given, ack("a larger disk arrives on Monday", NOW + 1_000));
        assert_eq!(
            stored,
            Some(Acknowledged {
                since_ms: NOW,
                severity: Severity::Warning,
                ack: given.clone(),
            })
        );
        assert_eq!(
            listener.recv().await.unwrap().event,
            TenzroEvent::ConditionAnswered {
                id: "requirement:disk".into(),
                kind: "requirement".into(),
                answer: "acknowledged".into(),
                by: Some("did:tenzro:human:operator".into()),
                summary: "Acknowledged: The data disk is filling".into(),
            }
        );
        let listed = book.held(NOW + 1_000).expect("the reading holds");
        assert_eq!(listed[0].ack, Some(given.clone()));
        assert_eq!(
            serde_json::to_value(&listed[0]).unwrap()["ack"],
            serde_json::json!({
                "by": "did:tenzro:human:operator",
                "reason": "a larger disk arrives on Monday",
                "at": "2027-01-15T08:00:01Z",
            })
        );

        // A later reading at the same severity keeps it.
        let later = NOW + 60_000;
        let again = book.settle(judge(&filling(), later), later, 6, &bus);
        assert_eq!(again[0].ack, Some(given));
        assert!(book.take_stale_acks().is_empty());
    }

    #[test]
    fn an_acknowledgement_is_refused_for_a_condition_not_open_or_a_later_opening() {
        let bus = bus();
        let book = ConditionBook::default();
        let open = book.settle(judge(&filling(), NOW), NOW, 5, &bus);
        let never = |_: &Acknowledged| -> Result<(), String> { panic!("nothing is stored") };
        assert_eq!(
            book.acknowledge(
                "update:0.2.9",
                &open[0].since,
                ack("x", NOW),
                NOW,
                &bus,
                never
            ),
            Err(AckRefusal::NotOpen)
        );
        assert_eq!(
            book.acknowledge(
                "requirement:disk",
                "2027-01-15T07:00:00Z",
                ack("x", NOW),
                NOW,
                &bus,
                never
            ),
            Err(AckRefusal::OpenedAgain(open[0].since.clone()))
        );
        assert_eq!(
            book.acknowledge(
                "requirement:disk",
                &open[0].since,
                ack("x", NOW),
                NOW,
                &bus,
                |_| Err("disk full".into())
            ),
            Err(AckRefusal::Store("disk full".into()))
        );
        assert_eq!(book.held(NOW).unwrap()[0].ack, None);
    }

    #[test]
    fn an_acknowledgement_ends_when_its_condition_grows_graver_or_clears() {
        let bus = bus();
        let book = ConditionBook::default();
        let acknowledged = |book: &ConditionBook, at: u64| {
            let open = book.settle(judge(&filling(), at), at, 5, &bus);
            book.acknowledge(
                "requirement:disk",
                &open[0].since,
                ack("known", at),
                at,
                &bus,
                |_| Ok(()),
            )
            .unwrap();
        };
        acknowledged(&book, NOW);
        let graver = Seen {
            disk_level: Level::Refuse,
            ..filling()
        };
        let later = NOW + 60_000;
        let open = book.settle(judge(&graver, later), later, 6, &bus);
        assert_eq!(open[0].ack, None);
        assert_eq!(book.take_stale_acks(), ["requirement:disk"]);
        // Back down to a warning: the ended acknowledgement does not return.
        let open = book.settle(judge(&filling(), later + 1), later + 1, 6, &bus);
        assert_eq!(open[0].ack, None);

        let book = ConditionBook::default();
        acknowledged(&book, NOW);
        book.settle(judge(&healthy(), later), later, 6, &bus);
        assert_eq!(book.take_stale_acks(), ["requirement:disk"]);
        let open = book.settle(judge(&filling(), later + 1), later + 1, 6, &bus);
        assert_eq!(open[0].ack, None);
    }

    #[test]
    fn a_stored_acknowledgement_holds_across_a_restart_for_its_opening() {
        let store = tenzro_storage::MemoryStore::new();
        let bus = bus();
        let before = ConditionBook::default();
        let open = before.settle(judge(&filling(), NOW), NOW, 5, &bus);
        let given = before
            .acknowledge(
                "requirement:disk",
                &open[0].since,
                ack("known", NOW),
                NOW,
                &bus,
                |kept| keep_ack(&store, "requirement:disk", kept),
            )
            .unwrap();
        keep_ack(
            &store,
            "follow",
            &Acknowledged {
                since_ms: NOW,
                severity: Severity::Critical,
                ack: ack("old", NOW),
            },
        )
        .unwrap();
        store
            .put(CF_METADATA, &ack_key("garbled"), b"not json")
            .unwrap();

        // The node restarted: the disk is still filling, the follow
        // condition is gone.
        let after = ConditionBook::default();
        after.restore_once(|| stored_acks(&store));
        after.restore_once(|| panic!("the store is read once"));
        let restart = NOW + 600_000;
        let open = after.settle(judge(&filling(), restart), restart, 9, &bus);
        assert_eq!(open[0].since, rfc3339(NOW));
        assert_eq!(open[0].ack, Some(given));
        assert_eq!(after.take_stale_acks(), ["follow"]);
    }

    #[test]
    fn the_store_gives_back_at_most_the_bound_of_acknowledgements() {
        let store = tenzro_storage::MemoryStore::new();
        for n in 0..MAX_ACKS + 3 {
            keep_ack(
                &store,
                &format!("health:s{n}"),
                &Acknowledged {
                    since_ms: NOW,
                    severity: Severity::Warning,
                    ack: ack("known", NOW),
                },
            )
            .unwrap();
        }
        assert_eq!(stored_acks(&store).len(), MAX_ACKS);
    }
}
