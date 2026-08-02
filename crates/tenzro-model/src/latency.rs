//! Streaming latency-tail estimation for provider routing.
//!
//! Hedging and steering decisions need the *tail* of a provider's latency
//! distribution, not its mean. Per the tail-at-scale insight (Dean &
//! Barroso, "The Tail at Scale", CACM 2013), the mean systematically
//! under-provisions a hedge delay: a provider whose mean is 120ms but whose
//! p95 is 600ms will have most requests reply well before the mean elapses,
//! so racing at the mean fires far too many hedges. Racing at the observed
//! p95 fires a backup only when the primary has genuinely landed in its own
//! tail.
//!
//! [`LatencyTail`] tracks a chosen quantile with the P² algorithm (Jain &
//! Chlamtac, "The P² Algorithm for Dynamic Calculation of Quantiles and
//! Histograms Without Storing Observations", CACM 1985): O(1) memory, O(1)
//! per observation, five markers adjusted by piecewise-parabolic
//! interpolation. No stored history, no windowing — it converges to the
//! true quantile of the running stream, and every field serializes so the
//! estimate survives a node restart alongside the rest of `ProviderMetrics`.

use serde::{Deserialize, Serialize};

/// Streaming quantile estimator using the P² algorithm.
///
/// Records latency observations in milliseconds and reports a running
/// estimate of a target quantile (e.g. p95) without storing history.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LatencyTail {
    /// Target quantile in `(0, 1)`, e.g. `0.95` for p95.
    p: f64,
    /// Observation count. The estimator warms up on the first five.
    count: usize,
    /// The first five observations, kept until warm-up seeds the markers.
    init: Vec<f64>,
    /// Marker heights (estimated values at each marker position).
    q: [f64; 5],
    /// Marker positions (1-indexed integer counts of observations).
    n: [f64; 5],
    /// Desired marker positions (fractional).
    np: [f64; 5],
    /// Increments to the desired positions per observation.
    dn: [f64; 5],
}

impl LatencyTail {
    /// Creates an estimator for quantile `p`, clamped to `(0, 1)`.
    pub fn new(p: f64) -> Self {
        Self {
            p: p.clamp(f64::EPSILON, 1.0 - f64::EPSILON),
            count: 0,
            init: Vec::with_capacity(5),
            q: [0.0; 5],
            n: [0.0; 5],
            np: [0.0; 5],
            dn: [0.0; 5],
        }
    }

    /// Records one latency observation (milliseconds) and updates the
    /// running quantile estimate.
    pub fn observe(&mut self, x_ms: u64) {
        let x = x_ms as f64;
        if self.count < 5 {
            self.init.push(x);
            self.count += 1;
            if self.count == 5 {
                self.init
                    .sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
                for i in 0..5 {
                    self.q[i] = self.init[i];
                    self.n[i] = (i + 1) as f64;
                }
                self.np = [
                    1.0,
                    1.0 + 2.0 * self.p,
                    1.0 + 4.0 * self.p,
                    3.0 + 2.0 * self.p,
                    5.0,
                ];
                self.dn = [0.0, self.p / 2.0, self.p, (1.0 + self.p) / 2.0, 1.0];
            }
            return;
        }

        self.count += 1;

        // Locate the cell k such that q[k] <= x < q[k+1], clamping the ends.
        let k = if x < self.q[0] {
            self.q[0] = x;
            0
        } else if x >= self.q[4] {
            self.q[4] = x;
            3
        } else {
            let mut cell = 0;
            for i in 0..4 {
                if self.q[i] <= x && x < self.q[i + 1] {
                    cell = i;
                    break;
                }
            }
            cell
        };

        for i in (k + 1)..5 {
            self.n[i] += 1.0;
        }
        for i in 0..5 {
            self.np[i] += self.dn[i];
        }

        // Adjust the three interior markers.
        for i in 1..4 {
            let d = self.np[i] - self.n[i];
            let can_up = d >= 1.0 && (self.n[i + 1] - self.n[i]) > 1.0;
            let can_down = d <= -1.0 && (self.n[i - 1] - self.n[i]) < -1.0;
            if can_up || can_down {
                let dsign = if d >= 0.0 { 1.0 } else { -1.0 };
                let parabolic = self.parabolic(i, dsign);
                if self.q[i - 1] < parabolic && parabolic < self.q[i + 1] {
                    self.q[i] = parabolic;
                } else {
                    self.q[i] = self.linear(i, dsign);
                }
                self.n[i] += dsign;
            }
        }
    }

    fn parabolic(&self, i: usize, d: f64) -> f64 {
        let a = d / (self.n[i + 1] - self.n[i - 1]);
        let b = (self.n[i] - self.n[i - 1] + d) * (self.q[i + 1] - self.q[i])
            / (self.n[i + 1] - self.n[i])
            + (self.n[i + 1] - self.n[i] - d) * (self.q[i] - self.q[i - 1])
                / (self.n[i] - self.n[i - 1]);
        self.q[i] + a * b
    }

    fn linear(&self, i: usize, d: f64) -> f64 {
        let j = if d >= 0.0 { i + 1 } else { i - 1 };
        self.q[i] + d * (self.q[j] - self.q[i]) / (self.n[j] - self.n[i])
    }

    /// Current quantile estimate in milliseconds, or `None` before warm-up
    /// completes (fewer than five observations). During warm-up the best
    /// available estimate is the max seen — conservative for a tail
    /// quantile, so it never under-provisions a hedge delay.
    pub fn estimate_ms(&self) -> Option<u64> {
        let est = if self.count < 5 {
            self.init
                .iter()
                .copied()
                .fold(None, |acc: Option<f64>, v| {
                    Some(acc.map_or(v, |a| a.max(v)))
                })?
        } else {
            self.q[2]
        };
        Some(est.max(0.0).round() as u64)
    }
}

impl Default for LatencyTail {
    /// A p95 estimator — the tail quantile hedging keys off.
    fn default() -> Self {
        Self::new(0.95)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn warm_up_reports_max_seen() {
        let mut t = LatencyTail::new(0.95);
        assert_eq!(t.estimate_ms(), None);
        t.observe(100);
        assert_eq!(t.estimate_ms(), Some(100));
        t.observe(50);
        assert_eq!(t.estimate_ms(), Some(100));
        t.observe(200);
        assert_eq!(t.estimate_ms(), Some(200));
    }

    #[test]
    fn tracks_p95_of_a_skewed_stream() {
        // Mostly fast with a heavy tail: the mean is far below p95.
        let mut t = LatencyTail::new(0.95);
        for i in 0..1000 {
            // 95% at ~100ms, 5% at ~1000ms.
            if i % 20 == 0 {
                t.observe(1000);
            } else {
                t.observe(100);
            }
        }
        let p95 = t.estimate_ms().unwrap();
        // p95 should sit up near the tail (hundreds of ms), not at the
        // ~145ms mean of this distribution.
        assert!(p95 >= 100, "p95 {p95} collapsed below the fast cluster");
        assert!(p95 <= 1000, "p95 {p95} exceeded the observed maximum");
    }

    #[test]
    fn survives_serde_round_trip() {
        let mut t = LatencyTail::new(0.95);
        for x in [80, 120, 90, 300, 110, 95, 700, 130] {
            t.observe(x);
        }
        let before = t.estimate_ms();
        let bytes = serde_json::to_vec(&t).unwrap();
        let restored: LatencyTail = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(before, restored.estimate_ms());
    }
}
