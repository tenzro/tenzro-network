//! Replays a recorded population of actors against the simulated network.
//!
//! A trace is one JSON object per line, `{"t_ms":..,"buyer":..,"provider":..,"amount_milli":..}`
//! (`from` and `to` are accepted for `buyer` and `provider`; other fields are
//! ignored): at simulated millisecond `t_ms`, actor `buyer` pays actor
//! `provider` `amount_milli` thousandths of a TNZO. The trace comes from a
//! population simulation run outside this repository. Lines starting with `#` and blank lines are skipped.
//! Actors are numbered from zero; actor `a` is the simulated user account
//! `a % users`, so a population larger than the user accounts shares them
//! (several actors behind one account), and a payment from an account to itself
//! after that mapping is dropped and counted.
//!
//! Times are taken from the trace's first payment, which is sent at the start
//! of the run, so a trace stamped with wall-clock times replays the same way.
//!
//! The same trace always sends the same transactions at the same simulated
//! times; what the network does with them is the simulation's.

use std::io::BufRead;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use rand::rngs::StdRng;
use serde::Deserialize;

use crate::ledger::{Ledger, SimTx, TNZO, TxResult, USER_BASE};
use crate::world::ClientDriver;

/// The most payments handed to the network in one simulated second, so a
/// trace with a very large burst cannot flood a run.
const MAX_PER_STEP: usize = 5_000;

/// One recorded payment.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
pub struct TraceEvent {
    /// Simulated millisecond it is sent.
    pub t_ms: u64,
    /// Paying actor.
    #[serde(alias = "buyer")]
    pub from: u32,
    /// Paid actor.
    #[serde(alias = "provider")]
    pub to: u32,
    /// Amount, thousandths of a TNZO.
    pub amount_milli: u64,
}

/// What a replay did, readable while and after it runs.
#[derive(Debug, Default)]
pub struct TraceStats {
    /// Payments handed to the network.
    pub sent: AtomicU64,
    /// Payments the chain executed.
    pub applied: AtomicU64,
    /// Payments the chain refused or reverted.
    pub refused: AtomicU64,
    /// Payments dropped because both ends mapped to one account.
    pub self_paid: AtomicU64,
    /// Payments held back to keep a second's burst within the cap.
    pub deferred: AtomicU64,
}

impl TraceStats {
    /// A one-line summary.
    pub fn line(&self) -> String {
        format!(
            "trace sent={} applied={} refused={} self_paid={} deferred={}",
            self.sent.load(Ordering::Relaxed),
            self.applied.load(Ordering::Relaxed),
            self.refused.load(Ordering::Relaxed),
            self.self_paid.load(Ordering::Relaxed),
            self.deferred.load(Ordering::Relaxed)
        )
    }
}

/// Reads a trace, sorted by time. Malformed lines are an error with their number.
pub fn read_trace(reader: impl BufRead) -> Result<Vec<TraceEvent>, String> {
    let mut events = Vec::new();
    for (n, line) in reader.lines().enumerate() {
        let line = line.map_err(|e| format!("line {}: {e}", n + 1))?;
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let e: TraceEvent =
            serde_json::from_str(line).map_err(|e| format!("line {}: {e}", n + 1))?;
        events.push(e);
    }
    events.sort_by_key(|e| e.t_ms);
    if let Some(first) = events.first().map(|e| e.t_ms) {
        for e in &mut events {
            e.t_ms -= first;
        }
    }
    Ok(events)
}

/// The driver that sends a trace's payments.
pub struct TraceDriver {
    events: Vec<TraceEvent>,
    next: usize,
    users: u32,
    stats: Arc<TraceStats>,
}

impl TraceDriver {
    /// A driver over `events` (sorted) for a network with `users` user
    /// accounts, with the counters it fills.
    pub fn new(events: Vec<TraceEvent>, users: u32) -> (Self, Arc<TraceStats>) {
        let stats = Arc::new(TraceStats::default());
        (
            Self {
                events,
                next: 0,
                users: users.max(2),
                stats: stats.clone(),
            },
            stats,
        )
    }

    fn account(&self, actor: u32) -> u32 {
        USER_BASE + actor % self.users
    }
}

impl TraceDriver {
    /// The payments due by simulated microsecond `now_us`.
    fn due(&mut self, now_us: u64) -> Vec<SimTx> {
        let mut out = Vec::new();
        while let Some(e) = self.events.get(self.next) {
            if e.t_ms.saturating_mul(1_000) > now_us {
                break;
            }
            if out.len() >= MAX_PER_STEP {
                self.stats.deferred.fetch_add(1, Ordering::Relaxed);
                break;
            }
            self.next += 1;
            let (from, to) = (self.account(e.from), self.account(e.to));
            if from == to {
                self.stats.self_paid.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            out.push(SimTx::Transfer {
                from,
                to,
                amount: u128::from(e.amount_milli) * TNZO / 1_000,
                nonce: 0,
            });
        }
        self.stats
            .sent
            .fetch_add(out.len() as u64, Ordering::Relaxed);
        out
    }
}

impl ClientDriver for TraceDriver {
    fn step(&mut self, now_us: u64, _ledger: &Ledger, _rng: &mut StdRng) -> Vec<SimTx> {
        self.due(now_us)
    }

    fn results(&mut self, results: &[TxResult]) {
        for r in results {
            if r.applied {
                self.stats.applied.fetch_add(1, Ordering::Relaxed);
            } else {
                self.stats.refused.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(t_ms: u64, from: u32, to: u32) -> TraceEvent {
        TraceEvent {
            t_ms,
            from,
            to,
            amount_milli: 1_500,
        }
    }

    #[test]
    fn a_trace_is_read_sorted_and_malformed_lines_name_their_number() {
        let text = "# header\n{\"t_ms\":30,\"from\":1,\"to\":2,\"amount_milli\":5}\n\n{\"t_ms\":10,\"from\":3,\"to\":4,\"amount_milli\":7}\n";
        let events = read_trace(text.as_bytes()).unwrap();
        assert_eq!(
            events.iter().map(|e| e.t_ms).collect::<Vec<_>>(),
            vec![0, 20]
        );
        let err = read_trace("{\"t_ms\":1}\n".as_bytes()).unwrap_err();
        assert!(err.starts_with("line 1:"), "{err}");
    }

    #[test]
    fn a_trace_naming_buyers_and_providers_is_read_and_extra_fields_ignored() {
        let text = "{\"t_ms\":5,\"buyer\":7,\"provider\":2,\"service\":\"inference\",\"amount_milli\":40,\"delivered\":true}\n";
        let events = read_trace(text.as_bytes()).unwrap();
        assert_eq!(
            events,
            vec![TraceEvent {
                t_ms: 0,
                from: 7,
                to: 2,
                amount_milli: 40
            }]
        );
    }

    #[test]
    fn payments_are_sent_at_their_times_with_the_amount_in_tnzo() {
        let (mut d, stats) = TraceDriver::new(vec![event(500, 0, 1), event(2_500, 1, 2)], 10);
        assert!(d.due(100_000).is_empty());
        let first = d.due(1_000_000);
        assert_eq!(first.len(), 1);
        match first[0] {
            SimTx::Transfer {
                from, to, amount, ..
            } => {
                assert_eq!((from, to), (USER_BASE, USER_BASE + 1));
                assert_eq!(amount, TNZO * 3 / 2);
            }
            _ => panic!("a transfer"),
        }
        assert!(d.due(2_000_000).is_empty());
        assert_eq!(d.due(3_000_000).len(), 1);
        assert_eq!(stats.sent.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn a_population_larger_than_the_accounts_shares_them_and_self_payments_are_dropped() {
        let (mut d, stats) = TraceDriver::new(vec![event(0, 0, 10), event(0, 0, 3)], 10);
        let sent = d.due(1_000);
        assert_eq!(sent.len(), 1, "0 and 10 are one account");
        assert_eq!(stats.self_paid.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn a_burst_beyond_the_cap_is_held_for_the_next_second() {
        let events: Vec<_> = (0..MAX_PER_STEP as u32 + 3)
            .map(|i| event(0, i % 7, 7 + i % 5))
            .collect();
        let (mut d, stats) = TraceDriver::new(events, 100);
        let first = d.due(1_000).len();
        assert_eq!(first, MAX_PER_STEP);
        assert_eq!(stats.deferred.load(Ordering::Relaxed), 1);
        assert_eq!(d.due(2_000).len(), 3);
    }
}
