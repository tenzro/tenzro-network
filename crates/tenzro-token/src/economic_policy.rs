//! The live [`EconomicPolicy`], persisted and governance-settable.
//!
//! Every rate the network charges lives in one block. This manager is what
//! makes it *live*: it holds the policy the node is currently applying, writes
//! each change through to `CF_TOKENS`, and hydrates on boot so a restart does
//! not silently revert to defaults.
//!
//! # Why a manager rather than a constant
//!
//! A rate in a `const` has to be found and changed in a release, and every node
//! that has not upgraded keeps charging the old one — so the network disagrees
//! with itself about what a payment is worth, and the disagreement is invisible
//! until someone reconciles two receipts. Governance sets this instead, and the
//! change takes effect at the next settlement on every node that has applied
//! the proposal.
//!
//! # A rejected policy is not applied
//!
//! [`EconomicPolicyManager::apply`] validates before it stores. A proposal that
//! would strand value, pay out more than came in, or leave the serving operator
//! a minority is refused and the previous policy stays live. Governance can
//! move the numbers; it cannot make them incoherent.

use std::sync::Arc;

use parking_lot::RwLock;
use tenzro_storage::{CF_TOKENS, KvStore};
use tenzro_types::economics::EconomicPolicy;
use tracing::{info, warn};

use crate::error::{Result, TokenError};

/// Where the live policy is persisted in `CF_TOKENS`.
pub const ECONOMIC_POLICY_KEY: &str = "economic_policy:current";

/// Holds the live [`EconomicPolicy`] and persists every change.
pub struct EconomicPolicyManager {
    policy: RwLock<EconomicPolicy>,
    storage: Option<Arc<dyn KvStore>>,
}

impl EconomicPolicyManager {
    /// A manager holding the default policy, with no persistence.
    pub fn new() -> Self {
        Self {
            policy: RwLock::new(EconomicPolicy::default()),
            storage: None,
        }
    }

    /// A manager backed by `storage`, hydrating any previously applied policy.
    ///
    /// A stored policy that no longer validates is refused and the default is
    /// used instead — loudly. Applying an incoherent policy because it happened
    /// to be on disk would let one bad proposal outlive the release that
    /// tightened the rules.
    pub fn with_storage(storage: Arc<dyn KvStore>) -> Self {
        let policy = match storage.get(CF_TOKENS, ECONOMIC_POLICY_KEY.as_bytes()) {
            Ok(Some(bytes)) => match serde_json::from_slice::<EconomicPolicy>(&bytes) {
                Ok(stored) => match stored.validate() {
                    Ok(()) => {
                        info!("Hydrated economic policy from storage");
                        stored
                    }
                    Err(e) => {
                        warn!(
                            "Stored economic policy is invalid ({e}); falling back to the default. \
                             The network will charge default rates until governance sets a valid \
                             policy."
                        );
                        EconomicPolicy::default()
                    }
                },
                Err(e) => {
                    warn!("Stored economic policy could not be decoded ({e}); using the default");
                    EconomicPolicy::default()
                }
            },
            _ => EconomicPolicy::default(),
        };

        Self {
            policy: RwLock::new(policy),
            storage: Some(storage),
        }
    }

    /// The policy currently in force.
    ///
    /// Returned by value: it is `Copy` and small, and handing out a guard would
    /// invite a caller to hold it across a settlement.
    pub fn current(&self) -> EconomicPolicy {
        *self.policy.read()
    }

    /// Apply a governance-set policy.
    ///
    /// # Errors
    ///
    /// Refuses a policy that fails [`EconomicPolicy::validate`], leaving the
    /// previous one live.
    pub fn apply(&self, policy: EconomicPolicy) -> Result<()> {
        policy
            .validate()
            .map_err(|e| TokenError::InvalidAmount(format!("economic policy rejected: {e}")))?;

        *self.policy.write() = policy;

        if let Some(ref storage) = self.storage {
            let bytes = serde_json::to_vec(&policy).map_err(|e| {
                TokenError::InvalidAmount(format!("economic policy could not be encoded: {e}"))
            })?;
            storage
                .put(CF_TOKENS, ECONOMIC_POLICY_KEY.as_bytes(), &bytes)
                .map_err(|e| {
                    TokenError::InvalidAmount(format!("economic policy could not be stored: {e}"))
                })?;
        }

        info!(
            operator_validating_bps = policy.validating.operator_bps,
            operator_delegated_bps = policy.delegated.operator_bps,
            rpc_provider_bps = policy.delegated.rpc_provider_bps,
            "Applied economic policy"
        );
        Ok(())
    }
}

impl Default for EconomicPolicyManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_types::economics::{DelegatedSchedule, ValidatingSchedule};

    #[test]
    fn a_fresh_manager_holds_the_default_policy() {
        let mgr = EconomicPolicyManager::new();
        assert_eq!(mgr.current(), EconomicPolicy::default());
    }

    #[test]
    fn a_valid_policy_becomes_live() {
        let mgr = EconomicPolicyManager::new();
        let mut policy = EconomicPolicy::default();
        policy.delegated = DelegatedSchedule {
            operator_bps: 7_000,
            rpc_provider_bps: 2_000,
            treasury_bps: 1_000,
        };
        mgr.apply(policy).unwrap();
        assert_eq!(mgr.current().delegated.rpc_provider_bps, 2_000);
    }

    /// Governance can move the numbers; it cannot make them incoherent — and a
    /// refused proposal must not disturb what is already live.
    #[test]
    fn an_invalid_policy_is_refused_and_the_previous_one_stays_live() {
        let mgr = EconomicPolicyManager::new();
        let before = mgr.current();

        let mut broken = EconomicPolicy::default();
        broken.validating = ValidatingSchedule {
            operator_bps: 4_000,
            treasury_bps: 6_000,
        };
        assert!(mgr.apply(broken).is_err());
        assert_eq!(mgr.current(), before, "the live policy must be untouched");
    }
}
