//! A command queue in front of a TPM that takes one command at a time.
//!
//! A TPM command can take seconds, and a burst of requests that all reach the
//! chip at once either wait on its lock past every time limit or are cut off.
//! [`TpmQueue`] lets one command run at a time, in arrival order, and makes
//! the rest wait a bounded time in a bounded line. When the line is full, or a
//! request would wait longer than the limit, it is refused at once with a
//! reason that says how long to wait before asking again. A command that
//! fails with an error the chip reports as temporary is retried with a growing
//! pause, inside the same turn, so the next request does not start against a
//! chip that has just said it is busy.

use std::collections::VecDeque;
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

/// How the queue behaves. Governed, not constant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueueParams {
    /// Requests allowed to wait behind the one running.
    pub max_waiting: usize,
    /// The longest a request waits for its turn.
    pub max_wait_ms: u64,
    /// Retries of a command the chip reported as temporarily unable.
    pub retries: u32,
    /// The pause before the first retry; it doubles each retry.
    pub backoff_base_ms: u64,
    /// The longest pause between retries.
    pub backoff_cap_ms: u64,
}

impl Default for QueueParams {
    fn default() -> Self {
        Self {
            max_waiting: 64,
            max_wait_ms: 120_000,
            retries: 3,
            backoff_base_ms: 200,
            backoff_cap_ms: 5_000,
        }
    }
}

/// Why a request was not run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Busy {
    /// The line is full.
    Full { waiting: usize, retry_after_ms: u64 },
    /// The request waited its limit without getting a turn.
    TimedOut { retry_after_ms: u64 },
}

impl std::fmt::Display for Busy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Busy::Full {
                waiting,
                retry_after_ms,
            } => write!(
                f,
                "tpm busy: the queue is full ({waiting} waiting); retry in {retry_after_ms} ms"
            ),
            Busy::TimedOut { retry_after_ms } => write!(
                f,
                "tpm busy: no turn within the wait limit; retry in {retry_after_ms} ms"
            ),
        }
    }
}

/// The prefix of a refusal that means "ask again later".
pub const BUSY_PREFIX: &str = "tpm busy:";

struct State {
    next: u64,
    line: VecDeque<u64>,
    running: bool,
    /// How long the last command took, to estimate the wait for the next.
    last_cost_ms: u64,
}

pub struct TpmQueue {
    params: QueueParams,
    state: Mutex<State>,
    turn: Condvar,
}

impl TpmQueue {
    pub fn new(params: QueueParams) -> Self {
        Self {
            params,
            state: Mutex::new(State {
                next: 0,
                line: VecDeque::new(),
                running: false,
                last_cost_ms: 1_000,
            }),
            turn: Condvar::new(),
        }
    }

    pub fn params(&self) -> QueueParams {
        self.params
    }

    /// Requests waiting for a turn (not counting the one running).
    pub fn waiting(&self) -> usize {
        self.state.lock().expect("queue").line.len()
    }

    /// Runs `command` when it is this request's turn. `transient` says
    /// whether an error from the command is one to retry.
    pub fn run<T, E>(
        &self,
        mut command: impl FnMut() -> Result<T, E>,
        transient: impl Fn(&E) -> bool,
    ) -> Result<Result<T, E>, Busy> {
        let ticket = self.enter()?;
        let started = Instant::now();
        let mut attempt = 0u32;
        let out = loop {
            match command() {
                Err(e) if attempt < self.params.retries && transient(&e) => {
                    let pause = self
                        .params
                        .backoff_base_ms
                        .saturating_mul(1u64 << attempt.min(20))
                        .min(self.params.backoff_cap_ms);
                    std::thread::sleep(Duration::from_millis(pause));
                    attempt += 1;
                }
                other => break other,
            }
        };
        self.leave(ticket, started.elapsed());
        Ok(out)
    }

    fn enter(&self) -> Result<u64, Busy> {
        let mut st = self.state.lock().expect("queue");
        let estimate =
            |st: &State, ahead: usize| st.last_cost_ms.saturating_mul(ahead as u64 + 1).max(1);
        if st.line.len() >= self.params.max_waiting {
            return Err(Busy::Full {
                waiting: st.line.len(),
                retry_after_ms: estimate(&st, st.line.len()),
            });
        }
        let ticket = st.next;
        st.next += 1;
        st.line.push_back(ticket);
        let deadline = Instant::now() + Duration::from_millis(self.params.max_wait_ms);
        loop {
            if !st.running && st.line.front() == Some(&ticket) {
                st.line.pop_front();
                st.running = true;
                return Ok(ticket);
            }
            let now = Instant::now();
            if now >= deadline {
                st.line.retain(|t| *t != ticket);
                let retry_after_ms = estimate(&st, st.line.len());
                self.turn.notify_all();
                return Err(Busy::TimedOut { retry_after_ms });
            }
            let (guard, _) = self.turn.wait_timeout(st, deadline - now).expect("queue");
            st = guard;
        }
    }

    fn leave(&self, _ticket: u64, took: Duration) {
        let mut st = self.state.lock().expect("queue");
        st.running = false;
        st.last_cost_ms = (took.as_millis() as u64).max(1);
        self.turn.notify_all();
    }
}

/// Whether a TPM error is the chip being temporarily unable (response codes
/// retry, yielded, testing, and the like), not a refusal of the command.
pub fn is_transient(message: &str) -> bool {
    let m = message.to_ascii_lowercase();
    [
        "tpm_rc_retry",
        "tpm_rc_yielded",
        "tpm_rc_testing",
        "0x922",
        "0x908",
        "0x90a",
        "busy",
        "try again",
    ]
    .iter()
    .any(|s| m.contains(s))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn commands_run_one_at_a_time_in_arrival_order() {
        let q = Arc::new(TpmQueue::new(QueueParams::default()));
        let running = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let done = Arc::new(AtomicUsize::new(0));
        let threads: Vec<_> = (0..20)
            .map(|_| {
                let (q, running, peak, done) =
                    (q.clone(), running.clone(), peak.clone(), done.clone());
                std::thread::spawn(move || {
                    q.run(
                        || -> Result<(), ()> {
                            let now = running.fetch_add(1, Ordering::SeqCst) + 1;
                            peak.fetch_max(now, Ordering::SeqCst);
                            std::thread::sleep(Duration::from_millis(5));
                            running.fetch_sub(1, Ordering::SeqCst);
                            done.fetch_add(1, Ordering::SeqCst);
                            Ok(())
                        },
                        |_| false,
                    )
                    .unwrap()
                    .unwrap();
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
        assert_eq!(done.load(Ordering::SeqCst), 20);
        assert_eq!(peak.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn a_full_line_is_refused_at_once_with_a_retry_hint() {
        let q = Arc::new(TpmQueue::new(QueueParams {
            max_waiting: 1,
            ..QueueParams::default()
        }));
        let gate = Arc::new(std::sync::Barrier::new(2));
        let q1 = q.clone();
        let g = gate.clone();
        let holder = std::thread::spawn(move || {
            q1.run(
                || -> Result<(), ()> {
                    g.wait();
                    std::thread::sleep(Duration::from_millis(300));
                    Ok(())
                },
                |_| false,
            )
        });
        gate.wait(); // the first is running
        let q2 = q.clone();
        let waiter = std::thread::spawn(move || q2.run(|| -> Result<(), ()> { Ok(()) }, |_| false));
        while q.waiting() < 1 {
            std::thread::sleep(Duration::from_millis(2));
        }
        let t = Instant::now();
        let refused = q.run(|| -> Result<(), ()> { Ok(()) }, |_| false);
        assert!(matches!(refused, Err(Busy::Full { .. })));
        assert!(
            t.elapsed() < Duration::from_millis(100),
            "refused without waiting"
        );
        assert!(refused.unwrap_err().to_string().starts_with(BUSY_PREFIX));
        holder.join().unwrap().unwrap().unwrap();
        waiter.join().unwrap().unwrap().unwrap();
    }

    #[test]
    fn a_request_that_waits_its_limit_is_refused() {
        let q = Arc::new(TpmQueue::new(QueueParams {
            max_wait_ms: 50,
            ..QueueParams::default()
        }));
        let gate = Arc::new(std::sync::Barrier::new(2));
        let (q1, g) = (q.clone(), gate.clone());
        let holder = std::thread::spawn(move || {
            q1.run(
                || -> Result<(), ()> {
                    g.wait();
                    std::thread::sleep(Duration::from_millis(300));
                    Ok(())
                },
                |_| false,
            )
        });
        gate.wait();
        let r = q.run(|| -> Result<(), ()> { Ok(()) }, |_| false);
        assert!(matches!(r, Err(Busy::TimedOut { .. })));
        assert_eq!(q.waiting(), 0, "the abandoned place is gone");
        holder.join().unwrap().unwrap().unwrap();
    }

    #[test]
    fn a_temporary_error_is_retried_with_a_pause_and_a_hard_error_is_not() {
        let q = TpmQueue::new(QueueParams {
            backoff_base_ms: 20,
            ..QueueParams::default()
        });
        let calls = AtomicUsize::new(0);
        let t = Instant::now();
        let r = q
            .run(
                || {
                    if calls.fetch_add(1, Ordering::SeqCst) < 2 {
                        Err("TPM_RC_RETRY")
                    } else {
                        Ok(7)
                    }
                },
                |e: &&str| is_transient(e),
            )
            .unwrap();
        assert_eq!(r, Ok(7));
        assert_eq!(calls.load(Ordering::SeqCst), 3);
        assert!(t.elapsed() >= Duration::from_millis(20 + 40));
        let hard = AtomicUsize::new(0);
        let r = q
            .run(
                || {
                    hard.fetch_add(1, Ordering::SeqCst);
                    Err::<(), _>("TPM_RC_AUTH_FAIL")
                },
                |e: &&str| is_transient(e),
            )
            .unwrap();
        assert!(r.is_err());
        assert_eq!(hard.load(Ordering::SeqCst), 1);
    }
}
