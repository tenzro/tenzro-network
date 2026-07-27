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

/// Adapts [`AgentRuntimeSpendingPolicyResolver`] to the meta-router's
/// [`tenzro_model::meta_router::BudgetGate`].
///
/// `tenzro-model` does not depend on `tenzro-payments`, so it declares a local
/// `BudgetGate` trait for the per-DID rolling-window admission check. This
/// adapter is the node-owned glue: it reuses the same per-machine
/// `SpendingPolicy` registry the payment gate consults, so intent-routed
/// dispatch and direct payments enforce one ceiling, not two divergent ones.
///
/// A DID with no bound policy resolves to `Ok(())` — the per-request budget
/// pre-filter in the meta-router still applies, matching how the payment binder
/// falls back to `DelegationScope`-only when no runtime policy exists.
pub struct SpendingPolicyBudgetGate {
    resolver: AgentRuntimeSpendingPolicyResolver,
}

impl SpendingPolicyBudgetGate {
    /// Wraps an [`AgentRuntime`] handle behind the meta-router budget gate.
    pub fn new(runtime: Arc<AgentRuntime>) -> Self {
        Self {
            resolver: AgentRuntimeSpendingPolicyResolver::new(runtime),
        }
    }
}

impl tenzro_model::meta_router::BudgetGate for SpendingPolicyBudgetGate {
    fn check(&self, payer_did: &str, amount: u128) -> tenzro_model::Result<()> {
        match self.resolver.resolve(payer_did) {
            Ok(Some(snapshot)) => snapshot.check(amount).map_err(|e| {
                tenzro_model::ModelError::RoutingError(format!(
                    "rolling-window budget check failed for {payer_did}: {e}"
                ))
            }),
            // No policy bound, or resolver error: admit. The per-request budget
            // pre-filter remains the binding cost cap; the resolver never fails
            // in practice (it is an in-memory lookup).
            _ => Ok(()),
        }
    }
}

/// Adapts [`TnzoToken`] to the meta-router's
/// [`tenzro_model::meta_router::BalanceProvider`].
///
/// `tenzro-model` does not depend on `tenzro-token`, so it declares a local
/// `BalanceProvider` trait for the wallet-balance ceiling. This node-owned glue
/// reads the payer's on-chain TNZO balance directly from the ledger, so the
/// meta-router never routes to a model the payer cannot pay for.
pub struct TnzoBalanceProvider {
    token: Arc<tenzro_token::TnzoToken>,
}

impl TnzoBalanceProvider {
    /// Wraps the node's [`TnzoToken`] handle behind the meta-router balance
    /// provider.
    pub fn new(token: Arc<tenzro_token::TnzoToken>) -> Self {
        Self { token }
    }
}

impl tenzro_model::meta_router::BalanceProvider for TnzoBalanceProvider {
    fn balance_of(&self, payer_address: &tenzro_types::primitives::Address) -> u128 {
        self.token.balance_of(payer_address)
    }
}

/// Adapts the node's [`TextEmbeddingRuntime`] to the meta-router's
/// [`tenzro_model::meta_router::PromptEmbedder`].
///
/// The runtime is shared with the agent memory tier, so a node that has loaded
/// an embedding model for either purpose serves both. The model is resolved per
/// call from whatever is currently loaded rather than pinned at construction:
/// operators load and unload embedding models through
/// `tenzro_loadTextEmbeddingModel` at runtime, and routing picks up the change
/// without a restart.
///
/// When no embedding model is loaded this returns an error, which the
/// meta-router absorbs by routing on declared metadata instead. Difficulty
/// estimation is an optimization, so an operator who never loads an embedding
/// model still gets working intent routing.
pub struct RuntimePromptEmbedder {
    runtime: Arc<tenzro_model::text_embedding_runtime::TextEmbeddingRuntime>,
    /// Model to prefer when several are loaded. Falls through to the first
    /// loaded model when unset or not currently loaded.
    preferred_model_id: Option<String>,
}

impl RuntimePromptEmbedder {
    /// Wraps the node's text-embedding runtime.
    pub fn new(
        runtime: Arc<tenzro_model::text_embedding_runtime::TextEmbeddingRuntime>,
    ) -> Self {
        Self {
            runtime,
            preferred_model_id: None,
        }
    }

    /// Pins a preferred embedding model. Routing still works if it is not
    /// loaded — another loaded model is used instead.
    #[must_use]
    pub fn with_preferred_model(mut self, model_id: impl Into<String>) -> Self {
        self.preferred_model_id = Some(model_id.into());
        self
    }

    fn resolve_model(&self) -> Option<String> {
        if let Some(ref preferred) = self.preferred_model_id
            && self.runtime.is_loaded(preferred)
        {
            return Some(preferred.clone());
        }
        // Deterministic pick: the loaded set is a DashMap, so sort so every
        // prompt lands in the same embedding space for as long as the set is
        // unchanged.
        let mut loaded = self.runtime.loaded_models();
        loaded.sort();
        loaded.into_iter().next()
    }
}

#[async_trait::async_trait]
impl tenzro_model::difficulty::PromptEmbedder for RuntimePromptEmbedder {
    async fn embed_prompt(&self, prompt: &str) -> tenzro_model::Result<Vec<f32>> {
        let model_id = self.resolve_model().ok_or_else(|| {
            tenzro_model::ModelError::ProviderNotAvailable(
                "no text-embedding model loaded for route difficulty estimation".to_string(),
            )
        })?;
        let result = self
            .runtime
            .embed(
                &model_id,
                vec![prompt.to_string()],
                tenzro_model::text_embedding_runtime::TextEmbedConfig::default(),
            )
            .await?;
        result.embeddings.into_iter().next().ok_or_else(|| {
            tenzro_model::ModelError::InferenceError(format!(
                "embedder {model_id} returned no vectors"
            ))
        })
    }
}
