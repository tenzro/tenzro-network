//! The live [`EconomicPolicy`], persisted and governance-settable.
//!
//! The economic values governance sets live in one block. This manager is what
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
    /// A stored policy that cannot be decoded is replaced by the default,
    /// with a warning.
    pub fn with_storage(storage: Arc<dyn KvStore>) -> Self {
        let policy = match storage.get(CF_TOKENS, ECONOMIC_POLICY_KEY.as_bytes()) {
            Ok(Some(bytes)) => match serde_json::from_slice::<EconomicPolicy>(&bytes) {
                Ok(stored) => {
                    info!("Hydrated economic policy from storage");
                    stored
                }
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
    /// Fails when the policy cannot be encoded or stored.
    pub fn apply(&self, policy: EconomicPolicy) -> Result<()> {
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
            default_conversion = %policy.default_conversion,
            micro_settlement_floor = %policy.micro_settlement_floor,
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
    use tenzro_types::economics::ConversionPolicy;

    #[test]
    fn a_fresh_manager_holds_the_default_policy() {
        let mgr = EconomicPolicyManager::new();
        assert_eq!(mgr.current(), EconomicPolicy::default());
    }

    #[test]
    fn an_applied_policy_becomes_live() {
        let mgr = EconomicPolicyManager::new();
        let policy = EconomicPolicy {
            default_conversion: ConversionPolicy::KeepInbound,
            micro_settlement_floor: 5,
        };
        mgr.apply(policy).unwrap();
        assert_eq!(mgr.current(), policy);
    }
}
