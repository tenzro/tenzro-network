//! Pacing for retries of something that keeps failing: a pause that doubles
//! with each failure, spread by jitter so that callers that failed together
//! do not retry together, and a gate that refuses attempts inside the pause.

use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

/// The pause before probe number `attempt` (1 for the first): `base`
/// doubled each attempt, capped at `cap`, then moved by up to a quarter either
/// way by `unit` (0.0 to 1.0) so nodes and threads that stalled together do not
/// probe together.
pub fn backoff(base: Duration, cap: Duration, attempt: u32, unit: f64) -> Duration {
    let doubled = base.saturating_mul(1u32 << attempt.saturating_sub(1).min(20));
    let capped = doubled.min(cap);
    let spread = 0.75 + 0.5 * unit.clamp(0.0, 1.0);
    capped.mul_f64(spread).min(cap.mul_f64(1.25))
}

/// A number in `[0, 1)` that differs between calls, from the clock and a
/// counter. Not for secrets: it only spreads retries.
pub fn jitter_unit() -> f64 {
    use std::sync::atomic::AtomicU64;
    static N: AtomicU64 = AtomicU64::new(0x9E37_79B9_7F4A_7C15);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos() as u64);
    let mut x = N.fetch_add(0x9E37_79B9_7F4A_7C15, Ordering::Relaxed) ^ nanos;
    x ^= x >> 33;
    x = x.wrapping_mul(0xFF51_AFD7_ED55_8CCD);
    x ^= x >> 33;
    (x >> 11) as f64 / (1u64 << 53) as f64
}

/// Paces retries of an operation that keeps failing, such as loading a key
/// into a TPM that is not answering: after each failure the next attempt
/// waits twice as long (with jitter, up to a cap), and one success starts
/// over. Attempts inside the pause are refused without touching the chip.
#[derive(Debug, Clone)]
pub struct RetryGate {
    base: Duration,
    cap: Duration,
    failures: u32,
    not_before: Option<Instant>,
}

impl RetryGate {
    /// A gate whose first pause is `base` and whose longest is `cap`.
    pub fn new(base: Duration, cap: Duration) -> Self {
        Self {
            base,
            cap,
            failures: 0,
            not_before: None,
        }
    }

    /// `Err` with the time left to wait when an attempt now is too early.
    pub fn check(&self, now: Instant) -> std::result::Result<(), Duration> {
        match self.not_before {
            Some(at) if now < at => Err(at - now),
            _ => Ok(()),
        }
    }

    /// Records a failed attempt and returns the pause before the next.
    pub fn failed(&mut self, now: Instant) -> Duration {
        self.failures = self.failures.saturating_add(1);
        let pause = backoff(self.base, self.cap, self.failures, jitter_unit());
        self.not_before = Some(now + pause);
        pause
    }

    /// Records a successful attempt.
    pub fn succeeded(&mut self) {
        self.failures = 0;
        self.not_before = None;
    }

    /// Failed attempts since the last success.
    pub fn failures(&self) -> u32 {
        self.failures
    }
}
