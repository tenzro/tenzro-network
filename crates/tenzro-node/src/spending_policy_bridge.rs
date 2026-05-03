//! Bridge from `tenzro_payments::SpendingPolicyResolver` to the per-machine
//! [`SpendingPolicy`] registry maintained by [`AgentRuntime`].
//!
//! `tenzro-payments` and `tenzro-agent` are sibling leaves in the dependency
//! graph (neither depends on the other). The trait that lets the payment gate
//! consult an agent's runtime spending policy lives in `tenzro-payments`, and
//! the registry that holds those policies lives on `AgentRuntime`. This
//! adapter, owned by `tenzro-node`, glues the two together — it is the only
//! place that depends on both crates and can therefore implement the trait
//! against the registry.
//!
//! At construction time, [`AgentRuntimeSpendingPolicyResolver`] takes an
//! `Arc<AgentRuntime>` and exposes itself as
//! `Arc<dyn tenzro_payments::SpendingPolicyResolver>`. At payment time the
//! `IdentityPaymentBinder` calls `resolve(payer_did)`, this looks up the
//! per-machine `SpendingPolicy`, and returns a `SpendingPolicySnapshot` that
//! the binder uses to enforce the runtime ceiling.
//!
//! `Ok(None)` is returned when the DID has no policy bound (legacy / hand-
//! registered identities). The binder treats that as "fall back to protocol
//! `DelegationScope` only" — the policy gate is additive over the scope, not
//! a replacement for it.

use std::sync::Arc;

use tenzro_agent::AgentRuntime;
use tenzro_payments::{Result, SpendingPolicyResolver, SpendingPolicySnapshot};

/// `SpendingPolicyResolver` impl backed by [`AgentRuntime`]'s in-memory
/// per-machine spending-policy registry. See module docs.
pub struct AgentRuntimeSpendingPolicyResolver {
    runtime: Arc<AgentRuntime>,
}

impl AgentRuntimeSpendingPolicyResolver {
    /// Wraps an existing [`AgentRuntime`] handle.
    pub fn new(runtime: Arc<AgentRuntime>) -> Self {
        Self { runtime }
    }
}

impl SpendingPolicyResolver for AgentRuntimeSpendingPolicyResolver {
    fn resolve(&self, payer_did: &str) -> Result<Option<SpendingPolicySnapshot>> {
        // u64 → u128 widen so the snapshot's amount-comparison axis matches
        // the u128 payment-amount axis used everywhere else in
        // `tenzro-payments`. No information loss.
        Ok(self.runtime.get_spending_policy(payer_did).map(|p| {
            SpendingPolicySnapshot {
                max_per_transaction: p.max_per_transaction as u128,
                max_daily_spend: p.max_daily_spend as u128,
                current_daily_spend: p.current_daily_spend as u128,
                enabled: p.enabled,
            }
        }))
    }
}
