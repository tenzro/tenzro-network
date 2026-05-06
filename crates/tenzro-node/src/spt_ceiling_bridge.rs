//! Bridge from `tenzro_payments::mpp::stripe_spt::SptCeilingResolver` to a
//! cached snapshot of Stripe SharedPaymentToken granted-token state.
//!
//! `tenzro-payments` and `tenzro-identity` are sibling leaves in the
//! dependency graph; the trait that lets the payment gate consult an SPT's
//! `usage_limits` lives in `tenzro-payments::mpp::stripe_spt`, and the
//! Stripe wire client lives there too. This adapter, owned by `tenzro-node`,
//! glues them together — it holds a [`StripeClient`] handle plus an
//! in-memory snapshot cache and exposes itself as
//! `Arc<dyn tenzro_payments::mpp::stripe_spt::SptCeilingResolver>`.
//!
//! # Sync trait, async wire
//!
//! The trait is synchronous (`fn resolve`) so the payment gate can be
//! consulted from any context, including the consensus-driven settlement
//! path that does not assume a tokio runtime. The Stripe API is
//! asynchronous. We resolve this by:
//!
//! 1. **Cache-first reads.** [`SptCeilingResolverAdapter::resolve`] only
//!    reads from the in-memory cache. A cache miss returns `Ok(None)`,
//!    which the binder treats as "no SPT axis enforced — fall back to
//!    DelegationScope + SpendingPolicy only."
//! 2. **Async population.** [`SptCeilingResolverAdapter::refresh`] fetches
//!    a granted-token snapshot from Stripe and writes it through to the
//!    cache. The webhook dispatcher (task #385) and the SPT settlement
//!    path call this after every state-changing event.
//!
//! `Ok(None)` on a cache miss is the same fallback semantics that
//! [`crate::spending_policy_bridge::AgentRuntimeSpendingPolicyResolver`]
//! uses for unbound machine DIDs — the resolver does not synthesize a
//! permissive answer; the binder layers above decide the policy.

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::RwLock;
use tracing::debug;

use tenzro_payments::mpp::stripe::StripeClient;
use tenzro_payments::mpp::stripe_spt::{
    SharedPaymentGrantedToken, SptCeilingResolver, SptCeilingSnapshot,
};
use tenzro_payments::Result;

/// `SptCeilingResolver` impl backed by [`StripeClient`] + an in-memory
/// snapshot cache. See module docs.
pub struct SptCeilingResolverAdapter {
    stripe: Arc<StripeClient>,
    cache: RwLock<HashMap<String, SptCeilingSnapshot>>,
}

impl SptCeilingResolverAdapter {
    /// Wraps an existing [`StripeClient`] handle. Cache starts empty;
    /// populate via [`refresh`](Self::refresh) on webhook events or
    /// explicit settlement-path triggers.
    pub fn new(stripe: Arc<StripeClient>) -> Self {
        Self {
            stripe,
            cache: RwLock::new(HashMap::new()),
        }
    }

    /// Fetches the current granted-token snapshot from Stripe and writes
    /// it through to the cache. Returns the projected
    /// [`SptCeilingSnapshot`] on success.
    ///
    /// Called by:
    /// - The webhook dispatcher on `shared_payment.granted_token.*` events
    ///   (task #385).
    /// - The settlement path immediately before invoking
    ///   [`StripeClient::confirm_intent_with_spt`] when no fresh cache
    ///   entry is available.
    pub async fn refresh(&self, granted_token_id: &str) -> Result<SptCeilingSnapshot> {
        let token = self.stripe.retrieve_granted_token(granted_token_id).await?;
        let snapshot = project(&token);
        debug!(
            "SPT cache: refreshed {} -> status={}",
            snapshot.granted_token_id,
            snapshot.status.as_str()
        );
        self.cache
            .write()
            .insert(snapshot.granted_token_id.clone(), snapshot.clone());
        Ok(snapshot)
    }

    /// Removes a cached snapshot — invoked by the webhook dispatcher on
    /// `granted_token.deactivated` so subsequent gate checks see the
    /// credential as missing rather than stale-active.
    pub fn invalidate(&self, granted_token_id: &str) {
        self.cache.write().remove(granted_token_id);
    }

    /// Direct cache-write entry point. Used by the webhook dispatcher
    /// when the webhook payload itself carries a fresh snapshot — saves
    /// a round-trip to Stripe.
    pub fn put_snapshot(&self, snapshot: SptCeilingSnapshot) {
        self.cache
            .write()
            .insert(snapshot.granted_token_id.clone(), snapshot);
    }
}

impl SptCeilingResolver for SptCeilingResolverAdapter {
    fn resolve(&self, granted_token_id: &str) -> Result<Option<SptCeilingSnapshot>> {
        Ok(self.cache.read().get(granted_token_id).cloned())
    }
}

/// Projects a Stripe-side [`SharedPaymentGrantedToken`] into the
/// gate-side [`SptCeilingSnapshot`]. The granted-token resource does
/// not carry a parent issued-token reference in its public shape, so
/// `issued_token_id` is left `None` here; callers that have the parent
/// (e.g., the create-issued-token path) can fill it before
/// [`SptCeilingResolverAdapter::put_snapshot`].
fn project(token: &SharedPaymentGrantedToken) -> SptCeilingSnapshot {
    SptCeilingSnapshot {
        granted_token_id: token.id.clone(),
        issued_token_id: None,
        status: token.status,
        usage_limits: token.usage_limits.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_payments::mpp::stripe_spt::{SptStatus, UsageLimits};

    fn snap(id: &str, status: SptStatus) -> SptCeilingSnapshot {
        SptCeilingSnapshot {
            granted_token_id: id.to_string(),
            issued_token_id: None,
            status,
            usage_limits: UsageLimits {
                currency: "usd".to_string(),
                max_amount: 5_000,
                expires_at: chrono::Utc::now().timestamp() + 3600,
            },
        }
    }

    #[test]
    fn cache_miss_returns_none() {
        let stripe = Arc::new(StripeClient::new("sk_test_dummy"));
        let adapter = SptCeilingResolverAdapter::new(stripe);
        assert!(adapter.resolve("spt_grant_unknown").unwrap().is_none());
    }

    #[test]
    fn put_then_resolve_returns_cached_snapshot() {
        let stripe = Arc::new(StripeClient::new("sk_test_dummy"));
        let adapter = SptCeilingResolverAdapter::new(stripe);
        adapter.put_snapshot(snap("spt_grant_abc", SptStatus::Active));
        let out = adapter.resolve("spt_grant_abc").unwrap();
        assert!(out.is_some());
        let s = out.unwrap();
        assert_eq!(s.granted_token_id, "spt_grant_abc");
        assert_eq!(s.status, SptStatus::Active);
    }

    #[test]
    fn invalidate_removes_cached_snapshot() {
        let stripe = Arc::new(StripeClient::new("sk_test_dummy"));
        let adapter = SptCeilingResolverAdapter::new(stripe);
        adapter.put_snapshot(snap("spt_grant_xyz", SptStatus::Active));
        assert!(adapter.resolve("spt_grant_xyz").unwrap().is_some());
        adapter.invalidate("spt_grant_xyz");
        assert!(adapter.resolve("spt_grant_xyz").unwrap().is_none());
    }
}
