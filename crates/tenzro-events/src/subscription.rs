//! Subscription lifecycle management
//!
//! Manages the lifecycle of event subscriptions across transports
//! (WebSocket, gRPC, webhooks). Provides a unified subscription
//! manager that tracks active subscriptions and routes events.

use crate::types::{EventFilter, SubscriptionId};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use thiserror::Error;
use tracing::{debug, warn};

/// Errors raised by [`SubscriptionManager`].
#[derive(Debug, Error)]
pub enum SubscriptionError {
    /// The subscription would exceed `SubscriptionManagerConfig::max_total_subscriptions`.
    #[error("subscription limit reached: {current} active, max {max}")]
    LimitReached { current: usize, max: usize },
}

/// Transport type for a subscription.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SubscriptionTransport {
    /// WebSocket connection.
    WebSocket,
    /// gRPC streaming.
    Grpc,
    /// Webhook HTTP callback.
    Webhook,
}

/// Configuration for the subscription manager.
#[derive(Debug, Clone)]
pub struct SubscriptionManagerConfig {
    /// Maximum total subscriptions across all transports.
    pub max_total_subscriptions: usize,
}

impl Default for SubscriptionManagerConfig {
    fn default() -> Self {
        Self {
            max_total_subscriptions: 10_000,
        }
    }
}

/// Tracks a single active subscription.
#[derive(Debug, Clone)]
struct SubscriptionEntry {
    id: SubscriptionId,
    filter: EventFilter,
    transport: SubscriptionTransport,
}

/// Unified subscription manager across all transports.
pub struct SubscriptionManager {
    config: SubscriptionManagerConfig,
    subscriptions: DashMap<SubscriptionId, SubscriptionEntry>,
    next_id: AtomicU64,
}

impl SubscriptionManager {
    /// Create a new subscription manager.
    pub fn new(config: SubscriptionManagerConfig) -> Self {
        Self {
            config,
            subscriptions: DashMap::new(),
            next_id: AtomicU64::new(1),
        }
    }

    /// Returns the configuration this manager was created with.
    pub fn config(&self) -> &SubscriptionManagerConfig {
        &self.config
    }

    /// Returns the configured maximum total subscriptions.
    pub fn max_subscriptions(&self) -> usize {
        self.config.max_total_subscriptions
    }

    /// Create a new subscription, returning its ID.
    ///
    /// Rejects with [`SubscriptionError::LimitReached`] when the active
    /// subscription count would exceed `config.max_total_subscriptions` —
    /// this is the enforcement point for the configured cap and protects
    /// the bus from runaway subscriber attachment (resource exhaustion).
    pub fn create(
        &self,
        filter: EventFilter,
        transport: SubscriptionTransport,
    ) -> Result<SubscriptionId, SubscriptionError> {
        let current = self.subscriptions.len();
        let max = self.config.max_total_subscriptions;
        if current >= max {
            warn!(
                current,
                max,
                "subscription limit reached — rejecting new subscription"
            );
            return Err(SubscriptionError::LimitReached { current, max });
        }
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        self.subscriptions.insert(
            id,
            SubscriptionEntry {
                id,
                filter,
                transport,
            },
        );
        debug!(subscription_id = id, "subscription created");
        Ok(id)
    }

    /// Remove a subscription by ID.
    pub fn remove(&self, id: SubscriptionId) -> bool {
        self.subscriptions.remove(&id).is_some()
    }

    /// Total active subscriptions.
    pub fn count(&self) -> usize {
        self.subscriptions.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_and_remove() {
        let mgr = SubscriptionManager::new(SubscriptionManagerConfig::default());
        let id = mgr
            .create(EventFilter::all(), SubscriptionTransport::WebSocket)
            .unwrap();
        assert_eq!(mgr.count(), 1);
        assert!(mgr.remove(id));
        assert_eq!(mgr.count(), 0);
    }

    #[test]
    fn test_subscription_limit_enforced() {
        let cfg = SubscriptionManagerConfig {
            max_total_subscriptions: 2,
        };
        let mgr = SubscriptionManager::new(cfg);
        assert!(
            mgr.create(EventFilter::all(), SubscriptionTransport::WebSocket)
                .is_ok()
        );
        assert!(
            mgr.create(EventFilter::all(), SubscriptionTransport::Webhook)
                .is_ok()
        );
        let err = mgr
            .create(EventFilter::all(), SubscriptionTransport::Grpc)
            .unwrap_err();
        match err {
            SubscriptionError::LimitReached { current, max } => {
                assert_eq!(current, 2);
                assert_eq!(max, 2);
            }
        }
        assert_eq!(mgr.count(), 2);
        assert_eq!(mgr.config().max_total_subscriptions, 2);
        assert_eq!(mgr.max_subscriptions(), 2);
    }
}
