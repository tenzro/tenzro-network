//! Whether this node follows the network, as a client can rely on it.
//!
//! A node knows its own height. What it knows of the network's is what it
//! heard: the middle of the tips its peers answered block-sync with. With that and the time of its last import it is in exactly
//! one state: starting, catching up, following or stalled. A node that has
//! heard from nobody is never reported as following.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use serde::Serialize;

/// Blocks a node may be behind the heard head and still count as following:
/// a block in flight is not a node that fell behind.
pub const BEHIND_TOLERANCE: u64 = 2;

/// How long after its start a node with no word of the network is starting
/// rather than stalled.
pub const STARTING_GRACE: Duration = Duration::from_secs(60);

/// How long a heard head stands. Older than this, the node no longer knows
/// where the network is.
pub const HEAD_FRESH: Duration = Duration::from_secs(120);

/// How long a node that is behind may go without importing a block before it
/// is stalled rather than catching up.
pub const STALL_AFTER: Duration = Duration::from_secs(120);

/// How far back the earlier sample of the gap is taken.
pub const GAP_SAMPLE_AGE: Duration = Duration::from_secs(30);

/// The one state a node is in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Following {
    /// Just started; nothing heard of the network yet.
    Starting,
    /// Behind the heard head and importing.
    CatchingUp,
    /// At the heard head, or the only member of its committee.
    Following,
    /// Behind and not importing, or with no word of the network.
    Stalled,
}

/// Why a node is not following.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Reason {
    /// No peer has answered.
    NoPeerHeard,
    /// Behind, and nothing imported for [`STALL_AFTER`].
    NoProgress,
    /// Behind, and the last range a peer served brought nothing new, for
    /// the reason block-sync gave.
    RangeBroughtNothing,
}

/// What a client reads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FollowState {
    /// The one state.
    pub state: Following,
    /// Why, when the state is not `following`.
    pub reason: Option<Reason>,
    /// What block-sync said of the last range that brought nothing new,
    /// with `range_brought_nothing`.
    pub detail: Option<&'static str>,
    /// This node's height.
    pub local_height: u64,
    /// The highest height heard from the network while that word stands.
    pub network_head: Option<u64>,
    /// How long ago that was heard, in milliseconds.
    pub head_heard_ms: Option<u64>,
    /// Blocks behind the heard head now.
    pub behind: Option<u64>,
    /// Blocks behind about [`GAP_SAMPLE_AGE`] ago: lower now means the gap
    /// is closing.
    pub behind_before: Option<u64>,
    /// How long ago this node last imported a block, in milliseconds.
    pub last_import_ms: Option<u64>,
}

/// What the node has seen, as plain values: the judgement is a function of
/// these alone.
#[derive(Debug, Clone, Copy)]
pub struct Seen {
    /// This node's height.
    pub local_height: u64,
    /// Whether this node is the only member of its committee.
    pub alone: bool,
    /// Time since the node started.
    pub up: Duration,
    /// The highest height heard and how long ago.
    pub head: Option<(u64, Duration)>,
    /// How long ago a block was last imported.
    pub last_import: Option<Duration>,
    /// The gap at the earlier sample.
    pub behind_before: Option<u64>,
    /// What block-sync said of the last range that brought nothing new.
    pub fruitless: Option<&'static str>,
}

/// The state that follows from what was seen.
pub fn judge(seen: Seen) -> FollowState {
    let head = seen.head.filter(|(_, age)| *age <= HEAD_FRESH);
    let behind = head.map(|(h, _)| h.saturating_sub(seen.local_height));
    let (state, reason, detail) = if seen.alone {
        (Following::Following, None, None)
    } else {
        match behind {
            None if seen.up < STARTING_GRACE => (Following::Starting, None, None),
            None => (Following::Stalled, Some(Reason::NoPeerHeard), None),
            Some(gap) if gap <= BEHIND_TOLERANCE => (Following::Following, None, None),
            Some(_) if seen.last_import.is_some_and(|age| age < STALL_AFTER) => {
                (Following::CatchingUp, None, None)
            }
            Some(_) if seen.up < STARTING_GRACE => (Following::CatchingUp, None, None),
            Some(_) => match seen.fruitless {
                Some(why) => (
                    Following::Stalled,
                    Some(Reason::RangeBroughtNothing),
                    Some(why),
                ),
                None => (Following::Stalled, Some(Reason::NoProgress), None),
            },
        }
    };
    let ms = |d: Duration| u64::try_from(d.as_millis()).unwrap_or(u64::MAX);
    FollowState {
        state,
        reason,
        detail,
        local_height: seen.local_height,
        network_head: head.map(|(h, _)| h),
        head_heard_ms: head.map(|(_, age)| ms(age)),
        behind,
        behind_before: seen.behind_before,
        last_import_ms: seen.last_import.map(ms),
    }
}

/// The health subsystem a node's place behind the network is reported
/// under: a node that is behind is not reported healthy.
pub const HEALTH_SUBSYSTEM: &str = "sync";

/// How often the node's health takes up its follow state.
pub const HEALTH_EVERY: Duration = Duration::from_secs(15);

/// Why a node in `s` is not healthy, in plain words: `None` while it follows
/// or is starting. A node catching up says how far behind it is and whether
/// the gap is closing; a stalled one says why.
pub fn unhealthy_reason(s: &FollowState) -> Option<String> {
    match s.state {
        Following::Following | Following::Starting => None,
        Following::CatchingUp => Some(match (s.behind, s.behind_before) {
            (Some(b), Some(before)) if b < before => format!(
                "{b} blocks behind the network and closing the gap ({before} about 30 s ago)"
            ),
            (Some(b), Some(before)) => format!(
                "{b} blocks behind the network and not closing the gap ({before} about 30 s ago)"
            ),
            (Some(b), None) => format!("{b} blocks behind the network and catching up"),
            (None, _) => "catching up with the network".to_string(),
        }),
        Following::Stalled => Some(match (s.reason, s.behind) {
            (Some(Reason::NoPeerHeard), _) | (_, None) => {
                "no peer has answered, so the node does not know where the network is".to_string()
            }
            (_, Some(b)) => format!(
                "{b} blocks behind the network and importing nothing{}; if it stays so, \
                 rejoin from a snapshot (docs/operations/node-joining.md)",
                s.detail.map(|d| format!(": {d}")).unwrap_or_default()
            ),
        }),
    }
}

#[derive(Debug)]
struct Inner {
    head: Option<(u64, Instant)>,
    local: Option<u64>,
    last_import: Option<Instant>,
    gaps: VecDeque<(Instant, u64)>,
    fruitless: Option<&'static str>,
}

/// Collects what the node hears and imports.
#[derive(Debug)]
pub struct FollowTracker {
    started: Instant,
    inner: Mutex<Inner>,
}

impl Default for FollowTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl FollowTracker {
    /// A tracker for a node starting now.
    pub fn new() -> Self {
        Self {
            started: Instant::now(),
            inner: Mutex::new(Inner {
                head: None,
                local: None,
                last_import: None,
                gaps: VecDeque::new(),
                fruitless: None,
            }),
        }
    }

    /// A height the network was heard at: the middle of the tips the peers
    /// answered. The highest heard stands, and a fresh word at the same
    /// height renews it.
    pub fn heard(&self, height: u64) {
        let now = Instant::now();
        let mut inner = self.inner.lock();
        let stale = inner
            .head
            .is_none_or(|(h, at)| height >= h || now.duration_since(at) > HEAD_FRESH);
        if stale {
            inner.head = Some((height, now));
        }
    }

    /// The local height as block-sync last read it. A rise is an import;
    /// it also clears what the last fruitless range said.
    pub fn local(&self, height: u64) {
        let now = Instant::now();
        let mut inner = self.inner.lock();
        if inner.local.is_some_and(|h| height > h) {
            inner.last_import = Some(now);
            inner.fruitless = None;
        }
        inner.local = Some(height);
        if let Some((head, _)) = inner.head {
            inner.gaps.push_back((now, head.saturating_sub(height)));
            while inner
                .gaps
                .front()
                .is_some_and(|(at, _)| now.duration_since(*at) > GAP_SAMPLE_AGE * 4)
            {
                inner.gaps.pop_front();
            }
        }
    }

    /// A served range brought nothing new, for `reason`.
    pub fn fruitless(&self, reason: &'static str) {
        self.inner.lock().fruitless = Some(reason);
    }

    /// The state now, for a node at `local_height`.
    pub fn state(&self, local_height: u64, alone: bool) -> FollowState {
        let now = Instant::now();
        let inner = self.inner.lock();
        let behind_before = inner
            .gaps
            .iter()
            .rev()
            .find(|(at, _)| now.duration_since(*at) >= GAP_SAMPLE_AGE)
            .map(|(_, gap)| *gap);
        judge(Seen {
            local_height,
            alone,
            up: now.duration_since(self.started),
            head: inner.head.map(|(h, at)| (h, now.duration_since(at))),
            last_import: inner.last_import.map(|at| now.duration_since(at)),
            behind_before,
            fruitless: inner.fruitless,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const S: Duration = Duration::from_secs(1);

    fn seen() -> Seen {
        Seen {
            local_height: 1741,
            alone: false,
            up: 600 * S,
            head: None,
            last_import: None,
            behind_before: None,
            fruitless: None,
        }
    }

    #[test]
    fn a_node_that_heard_from_nobody_is_starting_then_stalled_never_following() {
        let fresh = judge(Seen {
            up: 5 * S,
            ..seen()
        });
        assert_eq!((fresh.state, fresh.reason), (Following::Starting, None));
        let later = judge(seen());
        assert_eq!(
            (later.state, later.reason),
            (Following::Stalled, Some(Reason::NoPeerHeard))
        );
        assert_eq!(later.network_head, None);
    }

    #[test]
    fn word_of_the_network_that_is_too_old_is_no_word() {
        let state = judge(Seen {
            head: Some((1741, HEAD_FRESH + S)),
            ..seen()
        });
        assert_eq!(state.reason, Some(Reason::NoPeerHeard));
        assert_eq!(state.behind, None);
    }

    /// Only a following or starting node is healthy; one behind says by how
    /// much and whether the gap closes, one stalled says why.
    #[test]
    fn a_node_behind_the_network_is_not_healthy_and_says_how_far() {
        let following = judge(Seen {
            head: Some((1741, 3 * S)),
            ..seen()
        });
        assert_eq!(unhealthy_reason(&following), None);
        let closing = judge(Seen {
            head: Some((3141, 3 * S)),
            last_import: Some(S),
            behind_before: Some(1500),
            ..seen()
        });
        let why = unhealthy_reason(&closing).unwrap();
        assert!(
            why.contains("1400 blocks behind") && why.contains("closing the gap"),
            "{why}"
        );
        let stuck = judge(Seen {
            head: Some((3141, 3 * S)),
            last_import: Some(S),
            behind_before: Some(1400),
            ..seen()
        });
        assert!(
            unhealthy_reason(&stuck)
                .unwrap()
                .contains("not closing the gap")
        );
        let stalled = judge(Seen {
            head: Some((3141, 3 * S)),
            last_import: Some(STALL_AFTER + S),
            ..seen()
        });
        assert!(
            unhealthy_reason(&stalled)
                .unwrap()
                .contains("importing nothing")
        );
        assert!(
            unhealthy_reason(&judge(seen()))
                .unwrap()
                .contains("no peer has answered")
        );
    }

    #[test]
    fn a_node_at_the_heard_head_follows() {
        let state = judge(Seen {
            head: Some((1741 + BEHIND_TOLERANCE, 3 * S)),
            ..seen()
        });
        assert_eq!((state.state, state.reason), (Following::Following, None));
        assert_eq!(state.behind, Some(BEHIND_TOLERANCE));
    }

    #[test]
    fn a_node_behind_and_importing_is_catching_up() {
        let state = judge(Seen {
            head: Some((3266, 3 * S)),
            last_import: Some(4 * S),
            behind_before: Some(1600),
            ..seen()
        });
        assert_eq!(state.state, Following::CatchingUp);
        assert_eq!(
            (state.behind, state.behind_before),
            (Some(1525), Some(1600))
        );
    }

    /// A node a day behind whose only peer serves ranges that bring nothing
    /// is stalled, with what block-sync said.
    #[test]
    fn a_node_behind_and_importing_nothing_is_stalled_with_the_reason() {
        let quiet = judge(Seen {
            head: Some((3266, 3 * S)),
            last_import: Some(STALL_AFTER + S),
            ..seen()
        });
        assert_eq!(
            (quiet.state, quiet.reason),
            (Following::Stalled, Some(Reason::NoProgress))
        );
        let told = judge(Seen {
            head: Some((3266, 3 * S)),
            fruitless: Some("no certificate"),
            ..seen()
        });
        assert_eq!(told.reason, Some(Reason::RangeBroughtNothing));
        assert_eq!(told.detail, Some("no certificate"));
    }

    #[test]
    fn the_only_member_of_a_committee_follows_with_no_word_of_a_network() {
        let state = judge(Seen {
            alone: true,
            ..seen()
        });
        assert_eq!(state.state, Following::Following);
    }

    #[test]
    fn the_tracker_keeps_the_highest_head_and_times_an_import() {
        let tracker = FollowTracker::new();
        tracker.local(10);
        tracker.heard(40);
        tracker.heard(30);
        let behind = tracker.state(10, false);
        assert_eq!(behind.network_head, Some(40));
        assert_eq!(behind.last_import_ms, None);
        tracker.fruitless("no certificate");
        tracker.local(12);
        let moved = tracker.state(12, false);
        assert_eq!(moved.state, Following::CatchingUp);
        assert!(moved.last_import_ms.is_some());
        assert_eq!(moved.detail, None);
    }

    #[test]
    fn the_state_reads_as_plain_names() {
        let json = serde_json::to_value(judge(seen())).unwrap();
        assert_eq!(json["state"], "stalled");
        assert_eq!(json["reason"], "no_peer_heard");
    }
}
