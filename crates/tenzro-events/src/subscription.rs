//! Subscription lifecycle management
//!
//! Manages the lifecycle of event subscriptions across transports
//! (WebSocket, gRPC, webhooks). Provides a unified subscription
//! manager that tracks active subscriptions and routes events.

use crate::types::{EventFilter, SubscriptionId};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::debug;

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
    subscriptions: DashMap<SubscriptionId, SubscriptionEntry>,
    next_id: AtomicU64,
    #[allow(dead_code)]
    config: SubscriptionManagerConfig,
}

impl SubscriptionManager {
    /// Create a new subscription manager.
    pub fn new(config: SubscriptionManagerConfig) -> Self {
        Self {
            subscriptions: DashMap::new(),
            next_id: AtomicU64::new(1),
            config,
        }
    }

    /// Create a new subscription, returning its ID.
    pub fn create(
        &self,
        filter: EventFilter,
        transport: SubscriptionTransport,
    ) -> SubscriptionId {
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
        id
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
        let id = mgr.create(EventFilter::all(), SubscriptionTransport::WebSocket);
        assert_eq!(mgr.count(), 1);
        assert!(mgr.remove(id));
        assert_eq!(mgr.count(), 0);
    }
}
