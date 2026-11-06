//! Admission and limits for surfaces anyone can reach.
//!
//! A request that arrives before its sender is known costs the node whatever
//! the sender chooses to make it cost: a task, a buffer the size the sender
//! declares, a row in a table. Every such surface takes its bounds from here,
//! so they are bounded the same way:
//!
//! - [`Admission`]: how many requests are served at once, overall and from
//!   one peer. A request over either bound is refused at once rather than
//!   queued.
//! - [`AdmissionLimits::read_timeout`] and [`AdmissionLimits::write_timeout`]:
//!   how long a peer may take to send its request, or to take the next part
//!   of a reply, before it is cut off.
//! - [`BoundedBuffer`]: a request body read as it arrives, never allocated up
//!   front from the length the sender declared.
//! - [`ExpiringMap`]: state a request leaves behind (a pending sign-in, an
//!   issued challenge), dropped when it expires and, at its capacity, oldest
//!   first. Expiry is swept as entries are added, at amortised constant cost.

use std::collections::{HashMap, VecDeque};
use std::hash::Hash;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

/// Bounds for one surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AdmissionLimits {
    /// Requests served at once on the surface, from all peers together.
    pub max_in_flight: usize,
    /// Requests served at once on the surface from one peer.
    pub max_in_flight_per_peer: usize,
    /// How long a peer may take to send a whole request.
    #[serde(with = "duration_secs")]
    pub read_timeout: Duration,
    /// How long one part of a reply may wait for the peer to take it.
    #[serde(with = "duration_secs")]
    pub write_timeout: Duration,
}

impl Default for AdmissionLimits {
    fn default() -> Self {
        Self {
            max_in_flight: 1024,
            max_in_flight_per_peer: 32,
            read_timeout: Duration::from_secs(30),
            write_timeout: Duration::from_secs(30),
        }
    }
}

mod duration_secs {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::time::Duration;

    pub fn serialize<S: Serializer>(d: &Duration, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u64(d.as_secs())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
        u64::deserialize(d).map(Duration::from_secs)
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    // A panic while holding one of these locks leaves only counters behind,
    // which stay consistent; keep serving.
    m.lock().unwrap_or_else(|p| p.into_inner())
}

#[derive(Debug)]
struct Counts<K> {
    total: usize,
    per_peer: HashMap<K, usize>,
}

/// Concurrency bounds for one surface, overall and per peer.
#[derive(Debug)]
pub struct Admission<K: Eq + Hash + Clone> {
    limits: AdmissionLimits,
    counts: Arc<Mutex<Counts<K>>>,
}

impl<K: Eq + Hash + Clone> Clone for Admission<K> {
    fn clone(&self) -> Self {
        Self {
            limits: self.limits,
            counts: self.counts.clone(),
        }
    }
}

impl<K: Eq + Hash + Clone> Admission<K> {
    /// A surface admitting up to `limits`.
    pub fn new(limits: AdmissionLimits) -> Self {
        Self {
            limits,
            counts: Arc::new(Mutex::new(Counts {
                total: 0,
                per_peer: HashMap::new(),
            })),
        }
    }

    /// The bounds in force.
    pub fn limits(&self) -> &AdmissionLimits {
        &self.limits
    }

    /// Admit one request from `peer`, or `None` when the surface or the
    /// peer is at its bound. The request counts until the permit is dropped.
    pub fn try_admit(&self, peer: K) -> Option<Permit<K>> {
        let mut counts = lock(&self.counts);
        if counts.total >= self.limits.max_in_flight {
            return None;
        }
        let held = counts.per_peer.get(&peer).copied().unwrap_or(0);
        if held >= self.limits.max_in_flight_per_peer {
            return None;
        }
        counts.total += 1;
        counts.per_peer.insert(peer.clone(), held + 1);
        Some(Permit {
            counts: self.counts.clone(),
            peer,
        })
    }

    /// Requests being served now.
    pub fn in_flight(&self) -> usize {
        lock(&self.counts).total
    }
}

/// One admitted request. Dropping it frees its place.
#[derive(Debug)]
pub struct Permit<K: Eq + Hash + Clone> {
    counts: Arc<Mutex<Counts<K>>>,
    peer: K,
}

impl<K: Eq + Hash + Clone> Drop for Permit<K> {
    fn drop(&mut self) {
        let mut counts = lock(&self.counts);
        counts.total = counts.total.saturating_sub(1);
        if let Some(n) = counts.per_peer.get_mut(&self.peer) {
            *n -= 1;
            if *n == 0 {
                counts.per_peer.remove(&self.peer);
            }
        }
    }
}

/// Why a body could not be read whole.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyError {
    /// The declared or received length exceeds what the surface accepts.
    TooLarge {
        /// Bytes declared or received so far.
        len: usize,
        /// Most the surface accepts.
        max: usize,
    },
    /// More bytes arrived than were declared.
    Overrun,
}

impl std::fmt::Display for BodyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooLarge { len, max } => write!(f, "body of {len} bytes exceeds {max}"),
            Self::Overrun => f.write_str("more bytes arrived than were declared"),
        }
    }
}

impl std::error::Error for BodyError {}

/// A body of a declared length, filled as its bytes arrive. Memory grows with
/// what was received, never with what was declared.
#[derive(Debug)]
pub struct BoundedBuffer {
    want: usize,
    buf: Vec<u8>,
}

impl BoundedBuffer {
    /// Bytes reserved before anything has arrived.
    const INITIAL: usize = 64 * 1024;

    /// A buffer for a body declared as `declared` bytes, refused when that
    /// exceeds `max`.
    pub fn new(declared: usize, max: usize) -> Result<Self, BodyError> {
        if declared > max {
            return Err(BodyError::TooLarge { len: declared, max });
        }
        Ok(Self {
            want: declared,
            buf: Vec::with_capacity(declared.min(Self::INITIAL)),
        })
    }

    /// Bytes still to come.
    pub fn remaining(&self) -> usize {
        self.want - self.buf.len()
    }

    /// Whether the whole body has arrived.
    pub fn is_complete(&self) -> bool {
        self.buf.len() == self.want
    }

    /// Append the next bytes received.
    pub fn push(&mut self, chunk: &[u8]) -> Result<(), BodyError> {
        if chunk.len() > self.remaining() {
            return Err(BodyError::Overrun);
        }
        self.buf.extend_from_slice(chunk);
        Ok(())
    }

    /// The body received.
    pub fn into_vec(self) -> Vec<u8> {
        self.buf
    }
}

/// A map whose entries expire a fixed time after they were last inserted,
/// holding at most `capacity` of them.
///
/// Entries are kept in insertion order, which is also expiry order, so each
/// insert drops the expired entries at the front and, when the map is full,
/// the oldest live one. Nothing ever walks the whole map.
#[derive(Debug)]
pub struct ExpiringMap<K, V> {
    ttl: Duration,
    capacity: usize,
    entries: HashMap<K, (V, Instant, u64)>,
    order: VecDeque<(K, Instant, u64)>,
    next_seq: u64,
}

impl<K: Eq + Hash + Clone, V> ExpiringMap<K, V> {
    /// An empty map whose entries live for `ttl`, holding at most `capacity`.
    pub fn new(ttl: Duration, capacity: usize) -> Self {
        Self {
            ttl,
            capacity: capacity.max(1),
            entries: HashMap::new(),
            order: VecDeque::new(),
            next_seq: 0,
        }
    }

    /// How long an entry lives.
    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    /// Most entries held.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Insert `value` under `key`, replacing any entry there and restarting
    /// its lifetime. Returns the entries this dropped: the replaced one, the
    /// expired ones and, at capacity, the oldest.
    pub fn insert(&mut self, key: K, value: V) -> Vec<(K, V)> {
        self.insert_at(key, value, Instant::now())
    }

    fn insert_at(&mut self, key: K, value: V, now: Instant) -> Vec<(K, V)> {
        let mut dropped = self.sweep_at(now);
        if let Some((old, _, _)) = self.entries.remove(&key) {
            dropped.push((key.clone(), old));
        }
        while self.entries.len() >= self.capacity {
            match self.pop_front_live() {
                Some(evicted) => dropped.push(evicted),
                None => break,
            }
        }
        let seq = self.next_seq;
        self.next_seq += 1;
        self.order.push_back((key.clone(), now, seq));
        self.entries.insert(key, (value, now, seq));
        self.compact();
        dropped
    }

    /// Drop every expired entry, returning them.
    pub fn sweep(&mut self) -> Vec<(K, V)> {
        self.sweep_at(Instant::now())
    }

    fn sweep_at(&mut self, now: Instant) -> Vec<(K, V)> {
        let mut dropped = Vec::new();
        while let Some((_, at, _)) = self.order.front() {
            if now.saturating_duration_since(*at) < self.ttl {
                break;
            }
            let (key, _, seq) = self.order.pop_front().expect("front exists");
            if self.entries.get(&key).is_some_and(|(_, _, s)| *s == seq)
                && let Some((v, _, _)) = self.entries.remove(&key)
            {
                dropped.push((key, v));
            }
        }
        dropped
    }

    fn pop_front_live(&mut self) -> Option<(K, V)> {
        while let Some((key, _, seq)) = self.order.pop_front() {
            if self.entries.get(&key).is_some_and(|(_, _, s)| *s == seq) {
                return self.entries.remove(&key).map(|(v, _, _)| (key, v));
            }
        }
        None
    }

    /// Keep the order queue proportional to the live entries: removals leave
    /// stale slots behind, cleared once they outnumber the live ones.
    fn compact(&mut self) {
        if self.order.len() > 2 * self.entries.len() + 16 {
            let entries = &self.entries;
            self.order
                .retain(|(k, _, seq)| entries.get(k).is_some_and(|(_, _, s)| s == seq));
        }
    }

    fn live(&self, at: Instant, now: Instant) -> bool {
        now.saturating_duration_since(at) < self.ttl
    }

    /// The live entry under `key`.
    pub fn get(&self, key: &K) -> Option<&V> {
        let now = Instant::now();
        self.entries
            .get(key)
            .filter(|(_, at, _)| self.live(*at, now))
            .map(|(v, _, _)| v)
    }

    /// The live entry under `key`, mutably. Its lifetime is not restarted.
    pub fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        let now = Instant::now();
        let ttl = self.ttl;
        self.entries
            .get_mut(key)
            .filter(|(_, at, _)| now.saturating_duration_since(*at) < ttl)
            .map(|(v, _, _)| v)
    }

    /// Remove and return the entry under `key`, if it is live.
    pub fn take(&mut self, key: &K) -> Option<V> {
        let now = Instant::now();
        let (v, at, _) = self.entries.remove(key)?;
        self.compact();
        self.live(at, now).then_some(v)
    }

    /// Live and not yet swept entries held.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether nothing is held.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Every live entry, oldest first.
    pub fn iter(&self) -> impl Iterator<Item = (&K, &V)> {
        let now = Instant::now();
        self.order.iter().filter_map(move |(k, at, seq)| {
            let (v, _, s) = self.entries.get(k)?;
            (s == seq && self.live(*at, now)).then_some((k, v))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admission_bounds_the_surface_and_each_peer() {
        let a = Admission::new(AdmissionLimits {
            max_in_flight: 3,
            max_in_flight_per_peer: 2,
            ..AdmissionLimits::default()
        });
        let p1 = a.try_admit("x").unwrap();
        let _p2 = a.try_admit("x").unwrap();
        assert!(a.try_admit("x").is_none(), "per-peer bound");
        let _p3 = a.try_admit("y").unwrap();
        assert!(a.try_admit("z").is_none(), "surface bound");
        drop(p1);
        let _p4 = a.try_admit("z").unwrap();
        assert_eq!(a.in_flight(), 3);
    }

    #[test]
    fn a_bounded_buffer_grows_with_what_arrives() {
        assert!(BoundedBuffer::new(10, 9).is_err());
        let mut b = BoundedBuffer::new(1 << 30, 1 << 30).unwrap();
        assert!(b.buf.capacity() <= BoundedBuffer::INITIAL);
        b.push(b"abc").unwrap();
        assert_eq!(b.remaining(), (1 << 30) - 3);
        let mut b = BoundedBuffer::new(3, 3).unwrap();
        b.push(b"ab").unwrap();
        assert_eq!(b.push(b"cd"), Err(BodyError::Overrun));
        b.push(b"c").unwrap();
        assert!(b.is_complete());
        assert_eq!(b.into_vec(), b"abc");
    }

    #[test]
    fn an_expiring_map_drops_the_oldest_at_capacity_and_expired_on_insert() {
        let mut m = ExpiringMap::new(Duration::from_secs(10), 3);
        let t0 = Instant::now();
        for i in 0..3 {
            assert!(m.insert_at(i, i, t0).is_empty());
        }
        let dropped = m.insert_at(3, 3, t0);
        assert_eq!(dropped, vec![(0, 0)]);
        assert_eq!(m.len(), 3);
        let later = t0 + Duration::from_secs(11);
        let dropped = m.insert_at(9, 9, later);
        assert_eq!(dropped.len(), 3);
        assert_eq!(m.len(), 1);
        assert_eq!(m.take(&9), Some(9));
        assert!(m.is_empty());
    }

    #[test]
    fn removals_do_not_grow_the_order_queue() {
        let mut m = ExpiringMap::new(Duration::from_secs(600), 1_000_000);
        for i in 0..100_000u32 {
            m.insert(i, ());
            m.take(&i);
        }
        assert!(m.order.len() <= 32, "{} stale slots", m.order.len());
    }

    #[test]
    fn reinserting_a_key_restarts_it() {
        let mut m = ExpiringMap::new(Duration::from_secs(10), 2);
        let t0 = Instant::now();
        m.insert_at("a", 1, t0);
        m.insert_at("b", 2, t0);
        let dropped = m.insert_at("a", 3, t0 + Duration::from_secs(5));
        assert_eq!(dropped, vec![("a", 1)]);
        let dropped = m.insert_at("c", 4, t0 + Duration::from_secs(6));
        assert_eq!(dropped, vec![("b", 2)]);
        assert_eq!(
            m.iter().map(|(k, _)| *k).collect::<Vec<_>>(),
            vec!["a", "c"]
        );
    }
}
