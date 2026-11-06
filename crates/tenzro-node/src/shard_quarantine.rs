//! Containment for shard replication.
//!
//! A shard a node was asked to pin can fail to fetch or to store: the origin
//! is gone, the blob store reports a poisoned entry, the disk is full, or a
//! hostile origin keeps announcing an object that never completes. None of
//! that may cost the node anything beyond that one object, and none of it may
//! touch block application or consensus, which never wait on the storage role.
//!
//! [`ShardQuarantine`] bounds what a failing object costs:
//!
//! - an object that failed is not tried again until a backoff that doubles
//!   with each failure has passed;
//! - after [`ShardQuarantinePolicy::max_attempts`] failures it is quarantined
//!   for [`ShardQuarantinePolicy::quarantine_for`], during which every
//!   announcement of it is ignored without touching the blob store, then gets
//!   one fresh round of attempts;
//! - the table holds at most [`ShardQuarantinePolicy::capacity`] objects, so a
//!   flood of distinct bad objects cannot grow it; when full, the entry
//!   closest to being retried is dropped.
//!
//! The limits are local operating limits of the storage role, not consensus
//! parameters: they decide only which announcements this node acts on.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use parking_lot::Mutex;

/// Local limits of the quarantine.
#[derive(Debug, Clone)]
pub struct ShardQuarantinePolicy {
    /// Failures after which an object is quarantined.
    pub max_attempts: u32,
    /// Wait after the first failure; doubles with each further one.
    pub base_backoff: Duration,
    /// The longest backoff between attempts.
    pub max_backoff: Duration,
    /// How long a quarantined object is ignored.
    pub quarantine_for: Duration,
    /// Most objects the table remembers.
    pub capacity: usize,
}

impl Default for ShardQuarantinePolicy {
    fn default() -> Self {
        Self {
            max_attempts: 5,
            base_backoff: Duration::from_secs(30),
            max_backoff: Duration::from_secs(15 * 60),
            quarantine_for: Duration::from_secs(6 * 60 * 60),
            capacity: 4096,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct Entry {
    failures: u32,
    retry_at: Instant,
}

/// Remembers which shard objects failed and when each may be tried again.
#[derive(Debug)]
pub struct ShardQuarantine {
    policy: ShardQuarantinePolicy,
    entries: Mutex<HashMap<String, Entry>>,
}

impl Default for ShardQuarantine {
    fn default() -> Self {
        Self::new(ShardQuarantinePolicy::default())
    }
}

impl ShardQuarantine {
    /// A quarantine under `policy`.
    pub fn new(policy: ShardQuarantinePolicy) -> Self {
        Self {
            policy,
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// Whether `key` (a blob hash) may be fetched at `now`.
    pub fn admit(&self, key: &str, now: Instant) -> bool {
        let mut entries = self.entries.lock();
        match entries.get(key) {
            None => true,
            Some(e) if now >= e.retry_at => {
                // A quarantined object that has served its time starts over.
                if e.failures >= self.policy.max_attempts {
                    entries.remove(key);
                }
                true
            }
            Some(_) => false,
        }
    }

    /// Records a failed fetch or store of `key` at `now`.
    pub fn record_failure(&self, key: &str, now: Instant) {
        let mut entries = self.entries.lock();
        if !entries.contains_key(key)
            && entries.len() >= self.policy.capacity.max(1)
            && let Some(oldest) = entries
                .iter()
                .min_by_key(|(_, e)| e.retry_at)
                .map(|(k, _)| k.clone())
        {
            entries.remove(&oldest);
        }
        let failures = entries.get(key).map_or(0, |e| e.failures).saturating_add(1);
        let wait = if failures >= self.policy.max_attempts {
            self.policy.quarantine_for
        } else {
            let doubled = self
                .policy
                .base_backoff
                .saturating_mul(1u32 << (failures - 1).min(20));
            doubled.min(self.policy.max_backoff)
        };
        entries.insert(
            key.to_string(),
            Entry {
                failures,
                retry_at: now + wait,
            },
        );
    }

    /// Forgets `key` after it was pinned.
    pub fn record_success(&self, key: &str) {
        self.entries.lock().remove(key);
    }

    /// Whether `key` is quarantined (past its attempts) at `now`.
    #[cfg(test)]
    pub fn is_quarantined(&self, key: &str, now: Instant) -> bool {
        self.entries
            .lock()
            .get(key)
            .is_some_and(|e| e.failures >= self.policy.max_attempts && now < e.retry_at)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn q() -> ShardQuarantine {
        ShardQuarantine::new(ShardQuarantinePolicy {
            max_attempts: 3,
            base_backoff: Duration::from_secs(10),
            max_backoff: Duration::from_secs(60),
            quarantine_for: Duration::from_secs(1000),
            capacity: 4,
        })
    }

    #[test]
    fn an_unknown_object_is_admitted() {
        assert!(q().admit("a", Instant::now()));
    }

    #[test]
    fn retries_back_off_then_the_object_is_quarantined() {
        let q = q();
        let t0 = Instant::now();
        q.record_failure("a", t0);
        assert!(!q.admit("a", t0 + Duration::from_secs(9)));
        assert!(q.admit("a", t0 + Duration::from_secs(10)));
        q.record_failure("a", t0 + Duration::from_secs(10));
        // second failure doubles the wait to 20 s
        assert!(!q.admit("a", t0 + Duration::from_secs(29)));
        assert!(q.admit("a", t0 + Duration::from_secs(30)));
        q.record_failure("a", t0 + Duration::from_secs(30));
        // third failure: quarantined for the long period
        assert!(q.is_quarantined("a", t0 + Duration::from_secs(31)));
        assert!(!q.admit("a", t0 + Duration::from_secs(900)));
        // served its time: one fresh round
        assert!(q.admit("a", t0 + Duration::from_secs(1031)));
        assert!(!q.is_quarantined("a", t0 + Duration::from_secs(1031)));
        q.record_failure("a", t0 + Duration::from_secs(1031));
        assert!(!q.admit("a", t0 + Duration::from_secs(1032)));
    }

    #[test]
    fn backoff_is_capped() {
        let q = ShardQuarantine::new(ShardQuarantinePolicy {
            max_attempts: 100,
            base_backoff: Duration::from_secs(10),
            max_backoff: Duration::from_secs(60),
            quarantine_for: Duration::from_secs(1000),
            capacity: 4,
        });
        let t0 = Instant::now();
        for _ in 0..30 {
            q.record_failure("a", t0);
        }
        assert!(!q.admit("a", t0 + Duration::from_secs(59)));
        assert!(q.admit("a", t0 + Duration::from_secs(60)));
    }

    #[test]
    fn success_clears_the_object() {
        let q = q();
        let t0 = Instant::now();
        q.record_failure("a", t0);
        q.record_success("a");
        assert!(q.admit("a", t0));
    }

    #[test]
    fn the_table_never_outgrows_its_capacity() {
        let q = q();
        let t0 = Instant::now();
        for i in 0..100 {
            q.record_failure(&format!("obj{i}"), t0 + Duration::from_secs(i));
        }
        assert!(q.entries.lock().len() <= 4);
        // the newest failures are the ones still held back
        assert!(!q.admit("obj99", t0 + Duration::from_secs(99)));
    }
}
