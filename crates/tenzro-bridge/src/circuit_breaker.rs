//! Circuit breaker for bridge adapter HTTP calls.
//!
//! Prevents cascading failures when an external service (LayerZero endpoint,
//! CCIP router RPC, deBridge API, LI.FI API, etc.) becomes degraded. The
//! breaker tracks consecutive failures per endpoint and transitions between
//! three states:
//!
//! - **Closed** — normal operation, requests pass through.
//! - **Open** — failure threshold exceeded, requests short-circuit with
//!   `BridgeError::NetworkError("circuit open")` until the cooldown elapses.
//! - **HalfOpen** — cooldown elapsed, one probe request is allowed. Success
//!   closes the breaker; failure reopens it with fresh cooldown.
//!
//! ## Example
//!
//! ```rust,ignore
//! use std::time::Duration;
//! use tenzro_bridge::circuit_breaker::CircuitBreaker;
//!
//! let breaker = CircuitBreaker::new(5, Duration::from_secs(30));
//!
//! let result = breaker.call("dln-api", async {
//!     // make HTTP request
//!     Ok::<_, tenzro_bridge::BridgeError>(42)
//! }).await;
//! ```

use crate::error::{BridgeError, Result};
use dashmap::DashMap;
use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, warn};

/// Per-endpoint circuit breaker state.
#[derive(Debug, Clone)]
struct BreakerState {
    /// Number of consecutive failures observed.
    failures: u32,
    /// When the breaker transitioned to Open (if currently open).
    opened_at: Option<Instant>,
}

impl BreakerState {
    fn new() -> Self {
        Self {
            failures: 0,
            opened_at: None,
        }
    }
}

/// Circuit breaker that short-circuits calls to a failing external service.
///
/// Shared across all bridge adapters via `Arc<CircuitBreaker>`. Keyed by
/// endpoint name (e.g. `"ccip-router-eth"`, `"dln-api"`, `"layerzero-scan"`).
pub struct CircuitBreaker {
    /// Per-endpoint state (endpoint_name -> state).
    states: Arc<DashMap<String, BreakerState>>,
    /// Number of consecutive failures before tripping open.
    failure_threshold: u32,
    /// How long to wait in Open state before trying a probe.
    cooldown: Duration,
}

impl CircuitBreaker {
    /// Create a new circuit breaker with the given failure threshold and cooldown.
    ///
    /// Recommended defaults: `failure_threshold=5, cooldown=30s`.
    pub fn new(failure_threshold: u32, cooldown: Duration) -> Self {
        Self {
            states: Arc::new(DashMap::new()),
            failure_threshold,
            cooldown,
        }
    }

    /// Executes `f` under the circuit breaker for the given endpoint.
    ///
    /// If the breaker is currently open and the cooldown has not elapsed,
    /// returns `Err(BridgeError::NetworkError("circuit open for …"))` without
    /// calling `f`. Otherwise runs `f`, records the outcome, and returns.
    pub async fn call<F, Fut, T>(&self, endpoint: &str, f: F) -> Result<T>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<T>>,
    {
        // Check state before calling
        {
            let state = self
                .states
                .entry(endpoint.to_string())
                .or_insert_with(BreakerState::new);

            if let Some(opened_at) = state.opened_at {
                if opened_at.elapsed() < self.cooldown {
                    debug!(
                        "Circuit breaker OPEN for {} (opened {:?} ago, cooldown {:?})",
                        endpoint,
                        opened_at.elapsed(),
                        self.cooldown
                    );
                    return Err(BridgeError::NetworkError(format!(
                        "circuit open for {} (cooldown {}s)",
                        endpoint,
                        self.cooldown.as_secs()
                    )));
                }
                // Cooldown elapsed — enter HalfOpen (probe)
                debug!("Circuit breaker HALF-OPEN for {} (probing)", endpoint);
            }
        } // drop the DashMap ref before the await

        // Execute the call
        let result = f().await;

        // Update state based on outcome
        let mut state = self
            .states
            .entry(endpoint.to_string())
            .or_insert_with(BreakerState::new);

        match &result {
            Ok(_) => {
                if state.failures > 0 || state.opened_at.is_some() {
                    debug!("Circuit breaker CLOSED for {} (recovered)", endpoint);
                }
                state.failures = 0;
                state.opened_at = None;
            }
            Err(_) => {
                state.failures = state.failures.saturating_add(1);
                if state.failures >= self.failure_threshold && state.opened_at.is_none() {
                    warn!(
                        "Circuit breaker TRIPPED for {} after {} consecutive failures",
                        endpoint, state.failures
                    );
                    state.opened_at = Some(Instant::now());
                } else if state.opened_at.is_some() {
                    // Probe failed — reset cooldown timer
                    state.opened_at = Some(Instant::now());
                }
            }
        }

        result
    }

    /// Returns the current failure count for an endpoint (0 if never called).
    pub fn failure_count(&self, endpoint: &str) -> u32 {
        self.states.get(endpoint).map(|s| s.failures).unwrap_or(0)
    }

    /// Returns true if the breaker is currently open for the given endpoint.
    pub fn is_open(&self, endpoint: &str) -> bool {
        self.states
            .get(endpoint)
            .and_then(|s| s.opened_at)
            .map(|opened| opened.elapsed() < self.cooldown)
            .unwrap_or(false)
    }

    /// Manually reset the breaker for an endpoint (useful for admin recovery).
    pub fn reset(&self, endpoint: &str) {
        self.states.remove(endpoint);
    }
}

impl Default for CircuitBreaker {
    fn default() -> Self {
        Self::new(5, Duration::from_secs(30))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_closed_breaker_passes_through() {
        let cb = CircuitBreaker::new(3, Duration::from_millis(100));
        let result = cb
            .call("test", || async { Ok::<i32, BridgeError>(42) })
            .await;
        assert_eq!(result.unwrap(), 42);
        assert_eq!(cb.failure_count("test"), 0);
        assert!(!cb.is_open("test"));
    }

    #[tokio::test]
    async fn test_breaker_trips_after_threshold() {
        let cb = CircuitBreaker::new(3, Duration::from_secs(60));

        for _ in 0..3 {
            let _ = cb
                .call("test", || async {
                    Err::<i32, _>(BridgeError::NetworkError("boom".to_string()))
                })
                .await;
        }

        assert_eq!(cb.failure_count("test"), 3);
        assert!(cb.is_open("test"));

        // Next call should short-circuit
        let result = cb
            .call("test", || async { Ok::<i32, BridgeError>(42) })
            .await;
        assert!(result.is_err());
        assert!(
            matches!(result, Err(BridgeError::NetworkError(ref s)) if s.contains("circuit open"))
        );
    }

    #[tokio::test]
    async fn test_breaker_resets_after_cooldown() {
        let cb = CircuitBreaker::new(2, Duration::from_millis(50));

        for _ in 0..2 {
            let _ = cb
                .call("test", || async {
                    Err::<i32, _>(BridgeError::NetworkError("boom".to_string()))
                })
                .await;
        }
        assert!(cb.is_open("test"));

        // Wait for cooldown
        tokio::time::sleep(Duration::from_millis(80)).await;

        // Probe succeeds — breaker closes
        let result = cb
            .call("test", || async { Ok::<i32, BridgeError>(42) })
            .await;
        assert_eq!(result.unwrap(), 42);
        assert_eq!(cb.failure_count("test"), 0);
        assert!(!cb.is_open("test"));
    }

    #[tokio::test]
    async fn test_manual_reset() {
        let cb = CircuitBreaker::new(2, Duration::from_secs(60));

        for _ in 0..2 {
            let _ = cb
                .call("test", || async {
                    Err::<i32, _>(BridgeError::NetworkError("boom".to_string()))
                })
                .await;
        }
        assert!(cb.is_open("test"));

        cb.reset("test");
        assert!(!cb.is_open("test"));
        assert_eq!(cb.failure_count("test"), 0);
    }

    #[tokio::test]
    async fn test_different_endpoints_are_isolated() {
        let cb = CircuitBreaker::new(2, Duration::from_secs(60));

        for _ in 0..2 {
            let _ = cb
                .call("endpoint-a", || async {
                    Err::<i32, _>(BridgeError::NetworkError("boom".to_string()))
                })
                .await;
        }
        assert!(cb.is_open("endpoint-a"));
        assert!(!cb.is_open("endpoint-b"));

        let result = cb
            .call("endpoint-b", || async { Ok::<i32, BridgeError>(7) })
            .await;
        assert_eq!(result.unwrap(), 7);
    }
}
