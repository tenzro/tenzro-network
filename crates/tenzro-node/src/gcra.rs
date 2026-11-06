//! Generic Cell Rate Algorithm rate limiting, one theoretical arrival time
//! per key.

use std::time::{Duration, Instant};

/// Generic Cell Rate Algorithm (GCRA) rate limiter. One TAT
/// (Theoretical Arrival Time) value per key; one atomic write per
/// request; no background refill task.
///
/// `period` is the inverse rate: time-between-cells when traffic is
/// perfectly paced. `burst` is the max number of "borrowed" future cells
/// the key can consume in one go before being throttled to the steady
/// rate. Default config (1 cell per 100ms, burst 100) admits ~10 req/sec
/// sustained with bursts of 100 — appropriate for a per-tenant
/// Chainlink-quote rate limit.
#[derive(Debug, Clone, Copy)]
pub struct GcraConfig {
    pub period: Duration,
    pub burst: u32,
}

impl GcraConfig {
    /// Default: ~10 req/sec sustained, bursts of 100.
    pub const fn default_chainlink() -> Self {
        Self {
            period: Duration::from_millis(100),
            burst: 100,
        }
    }
}

impl Default for GcraConfig {
    fn default() -> Self {
        Self::default_chainlink()
    }
}

/// One per-key GCRA gate decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GcraDecision {
    /// Request admitted. `remaining_burst` is the current burst budget
    /// after this admission.
    Admit { remaining_burst: u32 },
    /// Request denied. `retry_after` is the minimum wait before the next
    /// attempt should be retried.
    Deny { retry_after: Duration },
}

/// In-memory GCRA limiter keyed on `String` (the client address).
pub struct GcraLimiter {
    cfg: GcraConfig,
    /// `tat` per key — the Theoretical Arrival Time of the next cell
    /// such that the bucket is full.
    tat: dashmap::DashMap<String, Instant>,
}

impl GcraLimiter {
    pub fn new(cfg: GcraConfig) -> Self {
        Self {
            cfg,
            tat: dashmap::DashMap::new(),
        }
    }

    /// Returns the current gate decision for `key_id`. On admit, updates
    /// the TAT in-place (no extra round trip).
    ///
    /// Canonical GCRA: a cell is admitted when `tat - burst_window <=
    /// now`, equivalently `tat <= now + burst_window`. On admit, TAT
    /// advances by one `period`. We initialize `tat = now - burst_window`
    /// so a fresh key has a full burst of credit.
    pub fn check(&self, key_id: &str) -> GcraDecision {
        self.check_at(key_id, Instant::now())
    }

    /// [`check`](Self::check) at a given instant, so the decision depends
    /// only on the arrival times it is given.
    fn check_at(&self, key_id: &str, now: Instant) -> GcraDecision {
        let burst_window = self.cfg.period.saturating_mul(self.cfg.burst);

        let mut entry = self
            .tat
            .entry(key_id.to_string())
            .or_insert_with(|| now.checked_sub(burst_window).unwrap_or(now));
        let tat = *entry.value();

        // The "increment" — by how much would this cell advance TAT?
        let new_tat_if_admitted = tat.max(now) + self.cfg.period;
        // The deny threshold — TAT after this admit would be too far in
        // the future (more than burst_window past now).
        let allowed_after = now + burst_window;
        if new_tat_if_admitted > allowed_after {
            let retry_after = new_tat_if_admitted.saturating_duration_since(allowed_after);
            return GcraDecision::Deny { retry_after };
        }

        // Admit and persist.
        *entry.value_mut() = new_tat_if_admitted;
        let remaining_burst = allowed_after
            .saturating_duration_since(new_tat_if_admitted)
            .as_millis()
            / self.cfg.period.as_millis().max(1);
        GcraDecision::Admit {
            remaining_burst: remaining_burst as u32,
        }
    }

    /// Drop entries whose burst budget has fully replenished. A key whose
    /// TAT is at least one full burst window in the past is
    /// indistinguishable from a fresh key, so keeping it only wastes
    /// memory. Called opportunistically by the per-IP gate to bound map
    /// growth when a scanner sprays requests from many source addresses.
    pub fn evict_replenished(&self) {
        let now = Instant::now();
        let burst_window = self.cfg.period.saturating_mul(self.cfg.burst);
        if let Some(threshold) = now.checked_sub(burst_window) {
            self.tat.retain(|_, tat| *tat > threshold);
        }
    }

    /// Number of keys currently tracked.
    pub fn active_keys(&self) -> usize {
        self.tat.len()
    }

    /// Returns the current configured limit (cells per second).
    pub fn rate_per_second(&self) -> f64 {
        1000.0 / self.cfg.period.as_millis() as f64
    }

    pub fn burst(&self) -> u32 {
        self.cfg.burst
    }
}

impl Default for GcraLimiter {
    fn default() -> Self {
        Self::new(GcraConfig::default())
    }
}

impl std::fmt::Debug for GcraLimiter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GcraLimiter")
            .field("cfg", &self.cfg)
            .field("active_keys", &self.tat.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gcra_admits_within_burst() {
        let limiter = GcraLimiter::new(GcraConfig {
            period: Duration::from_millis(100),
            burst: 5,
        });
        // First 5 calls at the same instant should admit.
        let now = Instant::now();
        for i in 0..5 {
            match limiter.check_at("burst-test", now) {
                GcraDecision::Admit { .. } => {}
                GcraDecision::Deny { .. } => panic!("denied at i={}", i),
            }
        }
    }

    #[test]
    fn gcra_denies_after_burst_exhausted() {
        let limiter = GcraLimiter::new(GcraConfig {
            period: Duration::from_millis(100),
            burst: 3,
        });
        // First 3 admit, 4th denies.
        let now = Instant::now();
        for _ in 0..3 {
            assert!(matches!(
                limiter.check_at("k", now),
                GcraDecision::Admit { .. }
            ));
        }
        assert!(matches!(
            limiter.check_at("k", now),
            GcraDecision::Deny { .. }
        ));
        // One period later exactly one more cell is admitted.
        let later = now + Duration::from_millis(100);
        assert!(matches!(
            limiter.check_at("k", later),
            GcraDecision::Admit { .. }
        ));
        assert!(matches!(
            limiter.check_at("k", later),
            GcraDecision::Deny { .. }
        ));
    }

    #[test]
    fn gcra_keys_are_isolated() {
        let limiter = GcraLimiter::new(GcraConfig {
            period: Duration::from_millis(100),
            burst: 2,
        });
        // Exhaust k1.
        let now = Instant::now();
        limiter.check_at("k1", now);
        limiter.check_at("k1", now);
        assert!(matches!(
            limiter.check_at("k1", now),
            GcraDecision::Deny { .. }
        ));
        // k2 still has full budget.
        assert!(matches!(
            limiter.check_at("k2", now),
            GcraDecision::Admit { .. }
        ));
    }
}
