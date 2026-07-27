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
use tenzro_types::primitives::BlockHeight;
use tenzro_types::principal_chain::{
    anonymous_chain_for_did, PrincipalChain, PrincipalChainResolver,
};
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

/// Coarse-grained lifecycle posture of a machine DID, projected from the
/// `tenzro-agent` `AgentState` FSM.
///
/// `tenzro-payments` does not depend on `tenzro-agent` directly — the node
/// implements the resolver and projects `AgentState` into this enum at
/// query time. The only states relevant to the payment gate are the
/// kill-switch tier (Paused/Quarantined/Terminated); all operational
/// states (Created/Active/Suspended) collapse into `Operational`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecyclePosture {
    /// Agent is in a normal operational state (Created/Active). Payment
    /// flow is gated only by `DelegationScope` + `SpendingPolicy`.
    Operational,
    /// Reversible kill-switch pause. Outbound payments are blocked while
    /// paused — the controller must `resume_paused_agent` first.
    Paused,
    /// Reversible kill-switch quarantine. Outbound payments are blocked
    /// (a stricter posture than Paused; staking rewards are also frozen).
    Quarantined,
    /// Irreversible termination. Outbound payments are permanently
    /// rejected; stake is slashed by the terminate handler.
    Terminated,
}

impl LifecyclePosture {
    /// True when the posture allows outbound payments to proceed past the
    /// kill-switch gate.
    pub fn allows_payment(&self) -> bool {
        matches!(self, LifecyclePosture::Operational)
    }

    /// Static label used in error messages and JSON-RPC envelopes.
    pub fn as_str(&self) -> &'static str {
        match self {
            LifecyclePosture::Operational => "operational",
            LifecyclePosture::Paused => "paused",
            LifecyclePosture::Quarantined => "quarantined",
            LifecyclePosture::Terminated => "terminated",
        }
    }
}

/// Resolves the kill-switch lifecycle posture for a machine DID.
///
/// Implemented by `tenzro-node` against `AgentRuntime::get_lifecycle()`.
/// Returning `Ok(None)` means the DID has no lifecycle record — for
/// example, a human DID or an agent that was registered before the
/// kill-switch axis existed. In that case the payment gate falls back to
/// `DelegationScope` + `SpendingPolicy` only and does not block on
/// posture.
pub trait LifecycleStateResolver: Send + Sync {
    /// Returns the current kill-switch posture for `payer_did`.
    fn resolve(&self, payer_did: &str) -> Result<Option<LifecyclePosture>>;
}

/// Snapshot of an on-chain escrow account, projected into the payment-gate
/// view.
///
/// `tenzro-payments` does not depend on `tenzro-settlement` types in its
/// trait surface — the node implements the resolver and projects
/// `EscrowAccount` into this struct. `payer_did` / `payee_did` are the DID
/// strings the agent and merchant signed their VDCs with, looked up by the
/// resolver from the on-chain payer/payee addresses.
#[derive(Debug, Clone)]
pub struct EscrowSnapshot {
    /// Escrow identifier (matches `escrow_id` on the AP2 mandate pair).
    pub escrow_id: String,
    /// DID of the on-chain payer (the AP2 *principal*, who funded the
    /// escrow at CheckoutMandate-issue time).
    pub payer_did: Option<String>,
    /// DID of the on-chain payee (the AP2 *agent* or merchant, depending on
    /// settlement model).
    pub payee_did: Option<String>,
    /// Locked amount, smallest unit of the asset.
    pub amount: u128,
    /// Asset symbol or registry ID.
    pub asset: String,
    /// True iff the escrow is currently in a state that admits release
    /// (i.e. `Funded` and not expired). False = released/refunded/expired.
    pub releasable: bool,
}

impl EscrowSnapshot {
    /// Returns `Ok(())` if a settlement of `total` against `agent_did`
    /// (PaymentMandate signer) and `principal_did` (CheckoutMandate signer)
    /// would be admitted by the on-chain escrow. Pure check — does not
    /// trigger release.
    ///
    /// Failure modes:
    /// - escrow is not releasable (already settled, refunded, or expired)
    /// - `total` exceeds the locked amount
    /// - `payer_did` is set on the snapshot and does not match
    ///   `principal_did` (someone else funded a same-named escrow — refuse)
    /// - `payee_did` is set on the snapshot and does not match `agent_did`
    ///   (wrong agent attempting to claim this escrow)
    pub fn check(&self, principal_did: &str, agent_did: &str, total: u128) -> Result<()> {
        if !self.releasable {
            return Err(PaymentError::VerificationFailed(format!(
                "escrow {} is not releasable (already settled, refunded, or expired)",
                self.escrow_id
            )));
        }
        if total > self.amount {
            return Err(PaymentError::VerificationFailed(format!(
                "AP2 cart total {} exceeds escrow {} locked amount {}",
                total, self.escrow_id, self.amount
            )));
        }
        if let Some(payer) = self.payer_did.as_ref()
            && payer != principal_did
        {
            return Err(PaymentError::VerificationFailed(format!(
                "escrow {} payer DID {} does not match CheckoutMandate principal {}",
                self.escrow_id, payer, principal_did
            )));
        }
        if let Some(payee) = self.payee_did.as_ref()
            && payee != agent_did
        {
            return Err(PaymentError::VerificationFailed(format!(
                "escrow {} payee DID {} does not match PaymentMandate agent {}",
                self.escrow_id, payee, agent_did
            )));
        }
        Ok(())
    }
}

/// Resolves an on-chain escrow snapshot for an `escrow_id` referenced by an
/// AP2 mandate pair.
///
/// Implemented by `tenzro-node` against `EscrowManager::get_escrow()`.
/// Returning `Ok(None)` means the escrow was not found on-chain — the AP2
/// validator MUST treat that as a hard failure when the mandate carries an
/// `escrow_id`. Returning `Err` is reserved for resolver-internal failures
/// (e.g. RocksDB I/O), not escrow-not-found.
pub trait EscrowResolver: Send + Sync {
    /// Returns the snapshot for `escrow_id`, or `Ok(None)` if no such
    /// escrow exists on-chain.
    fn resolve(&self, escrow_id: &str) -> Result<Option<EscrowSnapshot>>;
}

/// Binds TDIP identities to payment credentials
pub struct IdentityPaymentBinder {
    registry: Arc<IdentityRegistry>,
    _verifier: Arc<IdentityVerifier>,
    spending_policy_resolver: Option<Arc<dyn SpendingPolicyResolver>>,
    lifecycle_resolver: Option<Arc<dyn LifecycleStateResolver>>,
    #[cfg(feature = "mpp")]
    spt_ceiling_resolver: Option<Arc<dyn crate::mpp::stripe_spt::SptCeilingResolver>>,
}

impl IdentityPaymentBinder {
    /// Creates a new identity payment binder
    pub fn new(registry: Arc<IdentityRegistry>, verifier: Arc<IdentityVerifier>) -> Self {
        Self {
            registry,
            _verifier: verifier,
            spending_policy_resolver: None,
            lifecycle_resolver: None,
            #[cfg(feature = "mpp")]
            spt_ceiling_resolver: None,
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

    /// Attaches a [`LifecycleStateResolver`] so payment validation
    /// fails closed when the payer machine is in a kill-switch posture
    /// (Paused / Quarantined / Terminated). When no resolver is wired the
    /// gate is silently skipped — useful for human payers and tests.
    pub fn with_lifecycle_resolver(
        mut self,
        resolver: Arc<dyn LifecycleStateResolver>,
    ) -> Self {
        self.lifecycle_resolver = Some(resolver);
        self
    }

    /// Attaches a [`SptCeilingResolver`](crate::mpp::stripe_spt::SptCeilingResolver)
    /// so payment validation enforces Stripe SPT `usage_limits` as a
    /// fourth ceiling alongside `DelegationScope`, runtime
    /// `SpendingPolicy`, and the AP2 payment mandate's `total_amount`.
    ///
    /// The resolver is consulted by `validate_payer_with_spt` when the
    /// caller has extracted a granted-token reference from the credential.
    /// When no resolver is wired the SPT axis is silently skipped — useful
    /// for non-card MPP flows and tests.
    #[cfg(feature = "mpp")]
    pub fn with_spt_ceiling_resolver(
        mut self,
        resolver: Arc<dyn crate::mpp::stripe_spt::SptCeilingResolver>,
    ) -> Self {
        self.spt_ceiling_resolver = Some(resolver);
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

        // Kill-switch lifecycle gate (Agent-Swarm Spec 1). This runs
        // *before* the DelegationScope and SpendingPolicy ceilings — a
        // paused or quarantined machine cannot pay even within otherwise
        // valid delegation limits. Terminated agents are permanently
        // blocked. Operational + None (human/no-resolver) pass through.
        if let Some(resolver) = self.lifecycle_resolver.as_deref()
            && let Some(posture) = resolver.resolve(payer_did)?
            && !posture.allows_payment()
        {
            return Err(PaymentError::IdentityError(format!(
                "payer {} is {} (kill-switch); payments rejected",
                payer_did,
                posture.as_str()
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
            if let Some(proto) = protocol
                && !scope.is_protocol_allowed(proto)
            {
                return Err(PaymentError::IdentityError(format!(
                    "payment protocol '{}' not allowed by delegation scope",
                    proto
                )));
            }
            if let Some(ch) = chain
                && !scope.is_chain_allowed(ch)
            {
                return Err(PaymentError::IdentityError(format!(
                    "chain '{}' not allowed by delegation scope",
                    ch
                )));
            }

            // Runtime spending-policy gate (Phase C). The static
            // DelegationScope above is the *protocol* ceiling — what the
            // identity is structurally allowed to do. The runtime
            // SpendingPolicy is the *execution* ceiling — what the agent
            // is currently configured to spend in TNZO terms across all
            // its activity. Both must pass; failures are surfaced as the
            // same IdentityError variant so callers don't need to fork.
            if let Some(resolver) = self.spending_policy_resolver.as_deref()
                && let Some(snap) = resolver.resolve(payer_did)?
            {
                snap.check(amount)?;
            }
        }

        debug!("Payer {} validated for {} amount={}", payer_did, operation, amount);
        Ok(())
    }

    /// Four-ceiling payer validation: TDIP `DelegationScope` + runtime
    /// `SpendingPolicy` + lifecycle posture + Stripe SPT `usage_limits`.
    ///
    /// When `granted_token_id` is `Some`, the bound
    /// [`SptCeilingResolver`](crate::mpp::stripe_spt::SptCeilingResolver)
    /// is consulted and the per-token cap is enforced as a fourth ceiling
    /// alongside the existing three.
    ///
    /// `spt_amount` and `spt_currency` are the wire amount/currency
    /// presented to Stripe (smallest unit + lowercase three-letter ISO),
    /// which is what `usage_limits` is denominated in. They may differ
    /// from the on-chain `amount` (TNZO smallest unit) when the agent is
    /// settling a card-rail payment whose fiat amount is the SPT cap.
    ///
    /// Whichever ceiling is strictest wins.
    #[cfg(feature = "mpp")]
    #[allow(clippy::too_many_arguments)]
    pub fn validate_payer_with_spt(
        &self,
        payer_did: &str,
        amount: u128,
        operation: &str,
        protocol: Option<&str>,
        chain: Option<&str>,
        granted_token_id: Option<&str>,
        spt_amount: u64,
        spt_currency: &str,
    ) -> Result<()> {
        // First three ceilings (Delegation + lifecycle + SpendingPolicy).
        self.validate_payer_for_protocol(payer_did, amount, operation, protocol, chain)?;

        // Fourth ceiling — Stripe SPT usage_limits. Only consulted if the
        // caller extracted a granted-token reference from the credential
        // *and* an SptCeilingResolver is wired. Either being absent
        // collapses to the three-ceiling enforcement above (graceful
        // degradation for non-card MPP flows).
        if let (Some(token_id), Some(resolver)) = (
            granted_token_id,
            self.spt_ceiling_resolver.as_deref(),
        ) {
            match resolver.resolve(token_id)? {
                Some(snap) => {
                    snap.check(spt_amount, spt_currency)?;
                    debug!(
                        "SPT ceiling check passed: token={} amount={} currency={}",
                        token_id, spt_amount, spt_currency
                    );
                }
                None => {
                    return Err(PaymentError::VerificationFailed(format!(
                        "SPT granted_token {} not found in resolver — cannot verify usage_limits",
                        token_id
                    )));
                }
            }
        }

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

    /// Resolves the frozen `PrincipalChain` for a payer DID at receipt
    /// write time (Agent-Swarm Spec 5).
    ///
    /// Walks the registry's controller-DID chain via the
    /// `PrincipalChainResolver` impl on `IdentityRegistry`, snapshotting
    /// the controller's KYC tier. `frozen_at_block` is stamped into the
    /// returned chain so downstream auditors can correlate against block
    /// state. The chain is **frozen at write time** — later revocations
    /// of intermediate links do not invalidate the receipt's chain.
    pub fn resolve_payer_principal_chain(
        &self,
        payer_did: &str,
        frozen_at_block: impl Into<BlockHeight>,
    ) -> PrincipalChain {
        let resolver: &dyn PrincipalChainResolver = &*self.registry;
        resolver.resolve_by_did(payer_did, frozen_at_block.into())
    }

    /// Returns a frozen `PrincipalChain` for a payer DID with no live
    /// registry available (or when the binder is not yet wired).
    /// Produces a tombstoned anonymous chain rooted at the supplied DID.
    pub fn anonymous_principal_chain_for_did(
        payer_did: &str,
        frozen_at_block: impl Into<BlockHeight>,
    ) -> PrincipalChain {
        anonymous_chain_for_did(payer_did, frozen_at_block)
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
        if let Some(scope) = identity.delegation_scope()
            && !scope.is_active()
        {
            debug!("Identity {} has expired delegation scope", payer_did);
            return Ok(false);
        }

        debug!("Identity {} verified successfully", payer_did);
        Ok(true)
    }
}
