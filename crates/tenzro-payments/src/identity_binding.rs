//! Identity-payment binding
//!
//! Binds TDIP identities to payment credentials, ensuring every payment
//! is tied to a verifiable identity and respects delegation scopes.
//!
//! In addition to the protocol-facing `DelegationScope` ceiling, machine
//! identities backed by an [`AgentAutonomy`](https://docs.rs/tenzro-agent)
//! `SpendingPolicy` carry a *runtime* per-transaction and per-day spend
//! ceiling. `IdentityPaymentBinder` consults a pluggable
//! [`SpendingPolicyResolver`] to enforce that ceiling at payment time —
//! same way `DelegationScope` is consulted, but on the runtime axis.

use crate::error::{PaymentError, Result};
use crate::types::PaymentCredential;
use std::sync::Arc;
use tenzro_identity::{IdentityRegistry, IdentityVerifier, TenzroIdentity};
use tracing::debug;

/// Snapshot of a machine identity's runtime spending ceiling.
///
/// Mirrors the fields on `tenzro_agent::autonomy::SpendingPolicy` that
/// `tenzro-payments` actually needs at gate time. Avoids a hard
/// dependency on `tenzro-agent` so payments stays a leaf of the
/// dependency graph.
#[derive(Debug, Clone, Copy)]
pub struct SpendingPolicySnapshot {
    /// Maximum amount per single transaction (smallest unit).
    pub max_per_transaction: u128,
    /// Maximum daily spend (smallest unit).
    pub max_daily_spend: u128,
    /// Already-spent amount within the current daily window.
    pub current_daily_spend: u128,
    /// Whether the policy is enforcing (false = bypass).
    pub enabled: bool,
}

impl SpendingPolicySnapshot {
    /// Returns `Ok(())` if a payment of `amount` would be allowed by this
    /// snapshot, `Err` otherwise. Pure check — does not record the spend.
    /// (Recording happens once the credential is issued and settled.)
    pub fn check(&self, amount: u128) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }
        if amount > self.max_per_transaction {
            return Err(PaymentError::IdentityError(format!(
                "amount {amount} exceeds spending policy per-transaction limit {}",
                self.max_per_transaction
            )));
        }
        if self.current_daily_spend.saturating_add(amount) > self.max_daily_spend {
            return Err(PaymentError::IdentityError(format!(
                "amount {amount} would exceed spending policy daily limit (current {}, limit {})",
                self.current_daily_spend, self.max_daily_spend
            )));
        }
        Ok(())
    }
}

/// Resolves the runtime spending policy for a payer DID.
///
/// Implemented by `tenzro-node` to bridge `AgentAutonomy::spending_policy()`
/// into the payment gate. Returning `Ok(None)` means the payer is not a
/// machine with a runtime policy attached — the gate then falls back to
/// the static `DelegationScope` enforcement only.
pub trait SpendingPolicyResolver: Send + Sync {
    /// Resolves the runtime spending policy snapshot for `payer_did`.
    fn resolve(&self, payer_did: &str) -> Result<Option<SpendingPolicySnapshot>>;
}

/// Binds TDIP identities to payment credentials
pub struct IdentityPaymentBinder {
    registry: Arc<IdentityRegistry>,
    _verifier: Arc<IdentityVerifier>,
    spending_policy_resolver: Option<Arc<dyn SpendingPolicyResolver>>,
}

impl IdentityPaymentBinder {
    /// Creates a new identity payment binder
    pub fn new(registry: Arc<IdentityRegistry>, verifier: Arc<IdentityVerifier>) -> Self {
        Self {
            registry,
            _verifier: verifier,
            spending_policy_resolver: None,
        }
    }

    /// Attaches a [`SpendingPolicyResolver`] so payment validation
    /// enforces the agent's runtime per-transaction and per-day spend
    /// ceiling in addition to the static [`DelegationScope`].
    pub fn with_spending_policy_resolver(
        mut self,
        resolver: Arc<dyn SpendingPolicyResolver>,
    ) -> Self {
        self.spending_policy_resolver = Some(resolver);
        self
    }

    /// Validates that a payer identity can make a payment of the given amount
    ///
    /// Checks:
    /// 1. Identity exists and is active
    /// 2. For delegated identities: scope is active
    /// 3. Transaction value within delegation limit
    /// 4. Operation allowed by delegation scope
    /// 5. Payment protocol allowed by delegation scope
    /// 6. Chain allowed by delegation scope
    pub fn validate_payer(
        &self,
        payer_did: &str,
        amount: u128,
        operation: &str,
    ) -> Result<()> {
        self.validate_payer_for_protocol(payer_did, amount, operation, None, None)
    }

    /// Validates a payer with protocol and chain constraints
    pub fn validate_payer_for_protocol(
        &self,
        payer_did: &str,
        amount: u128,
        operation: &str,
        protocol: Option<&str>,
        chain: Option<&str>,
    ) -> Result<()> {
        // Resolve the identity
        let identity = self
            .registry
            .resolve(payer_did)
            .map_err(|e| PaymentError::IdentityError(e.to_string()))?;

        // Check identity is active
        if !identity.is_active() {
            return Err(PaymentError::IdentityError(format!(
                "payer identity {} is not active",
                payer_did
            )));
        }

        // For machine identities, check delegation scope
        if let Some(scope) = identity.delegation_scope() {
            if !scope.is_active() {
                return Err(PaymentError::IdentityError(
                    "delegation scope has expired".to_string(),
                ));
            }
            if !scope.is_value_allowed(amount) {
                return Err(PaymentError::IdentityError(format!(
                    "transaction value {} exceeds delegation limit",
                    amount
                )));
            }
            if !scope.is_operation_allowed(operation) {
                return Err(PaymentError::IdentityError(format!(
                    "operation '{}' not allowed by delegation scope",
                    operation
                )));
            }
            if let Some(proto) = protocol {
                if !scope.is_protocol_allowed(proto) {
                    return Err(PaymentError::IdentityError(format!(
                        "payment protocol '{}' not allowed by delegation scope",
                        proto
                    )));
                }
            }
            if let Some(ch) = chain {
                if !scope.is_chain_allowed(ch) {
                    return Err(PaymentError::IdentityError(format!(
                        "chain '{}' not allowed by delegation scope",
                        ch
                    )));
                }
            }

            // Runtime spending-policy gate (Phase C). The static
            // DelegationScope above is the *protocol* ceiling — what the
            // identity is structurally allowed to do. The runtime
            // SpendingPolicy is the *execution* ceiling — what the agent
            // is currently configured to spend in TNZO terms across all
            // its activity. Both must pass; failures are surfaced as the
            // same IdentityError variant so callers don't need to fork.
            if let Some(resolver) = self.spending_policy_resolver.as_deref() {
                if let Some(snap) = resolver.resolve(payer_did)? {
                    snap.check(amount)?;
                }
            }
        }

        debug!("Payer {} validated for {} amount={}", payer_did, operation, amount);
        Ok(())
    }

    /// Binds an identity to a payment credential
    pub fn bind_credential_to_identity(
        &self,
        credential: &mut PaymentCredential,
        identity: &TenzroIdentity,
    ) -> Result<()> {
        credential.payer_did = identity.did_string();
        credential
            .extra
            .insert("wallet_id".to_string(), serde_json::json!(identity.wallet_id));
        Ok(())
    }

    /// Verifies that a credential is bound to a valid identity
    pub fn verify_identity_binding(
        &self,
        credential: &PaymentCredential,
    ) -> Result<TenzroIdentity> {
        let identity = self
            .registry
            .resolve(&credential.payer_did)
            .map_err(|e| PaymentError::IdentityError(e.to_string()))?;

        if !identity.is_active() {
            return Err(PaymentError::IdentityError(format!(
                "payer identity {} is not active",
                credential.payer_did
            )));
        }

        Ok(identity)
    }

    /// Verifies that a payer has a valid identity in the registry
    ///
    /// This checks:
    /// 1. The identity exists in the registry
    /// 2. The identity is in an active state
    /// 3. For delegated identities, the delegation scope is valid
    pub fn verify_payer_identity(&self, payer_did: &str) -> Result<bool> {
        debug!("Verifying payer identity: {}", payer_did);

        // Resolve the identity from the registry
        let identity = match self.registry.resolve(payer_did) {
            Ok(id) => id,
            Err(_) => {
                debug!("Identity {} not found in registry", payer_did);
                return Ok(false);
            }
        };

        // Check if the identity is active
        if !identity.is_active() {
            debug!("Identity {} is not active", payer_did);
            return Ok(false);
        }

        // For machine identities with delegation scopes, verify the scope is still valid
        if let Some(scope) = identity.delegation_scope() {
            if !scope.is_active() {
                debug!("Identity {} has expired delegation scope", payer_did);
                return Ok(false);
            }
        }

        debug!("Identity {} verified successfully", payer_did);
        Ok(true)
    }
}
