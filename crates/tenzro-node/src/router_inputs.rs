//! The intent tier's inputs the node supplies: the payer's balance and the
//! prompt embedder.

use std::sync::Arc;

/// Adapts [`TnzoToken`] to the intent tier's
/// [`tenzro_model::routing::intent::BalanceProvider`].
///
/// `tenzro-model` does not depend on `tenzro-token`, so it declares a local
/// `BalanceProvider` trait for the wallet-balance ceiling. This node-owned glue
/// reads the payer's on-chain TNZO balance directly from the ledger, so the
/// intent tier never routes to a model the payer cannot pay for.
pub struct TnzoBalanceProvider {
    token: Arc<tenzro_token::TnzoToken>,
}

impl TnzoBalanceProvider {
    /// Wraps the node's [`TnzoToken`] handle behind the intent tier balance
    /// provider.
    pub fn new(token: Arc<tenzro_token::TnzoToken>) -> Self {
        Self { token }
    }
}

impl tenzro_model::routing::intent::BalanceProvider for TnzoBalanceProvider {
    fn balance_of(&self, payer_address: &tenzro_types::primitives::Address) -> u128 {
        self.token.balance_of(payer_address)
    }
}

/// Adapts the node's [`TextEmbeddingRuntime`] to the intent tier's
/// [`tenzro_model::routing::intent::PromptEmbedder`].
///
/// The runtime is shared with the agent memory tier, so a node that has loaded
/// an embedding model for either purpose serves both. The model is resolved per
/// call from whatever is currently loaded rather than pinned at construction:
/// operators load and unload embedding models through
/// `tenzro_loadTextEmbeddingModel` at runtime, and routing picks up the change
/// without a restart.
///
/// When no embedding model is loaded this returns an error, which the
/// intent tier absorbs by routing on declared metadata instead. Difficulty
/// estimation is an optimization, so an operator who never loads an embedding
/// model still gets working intent routing.
#[cfg(feature = "inference")]
pub struct RuntimePromptEmbedder {
    runtime: Arc<tenzro_model::text_embedding_runtime::TextEmbeddingRuntime>,
    /// Model to prefer when several are loaded. Falls through to the first
    /// loaded model when unset or not currently loaded.
    preferred_model_id: Option<String>,
}

#[cfg(feature = "inference")]
impl RuntimePromptEmbedder {
    /// Wraps the node's text-embedding runtime.
    pub fn new(runtime: Arc<tenzro_model::text_embedding_runtime::TextEmbeddingRuntime>) -> Self {
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
#[cfg(feature = "inference")]
impl tenzro_model::difficulty::PromptEmbedder for RuntimePromptEmbedder {
    async fn embed_prompt(&self, prompt: &str) -> tenzro_model::Result<Vec<f32>> {
        let model_id = self.resolve_model().ok_or_else(|| {
            tenzro_model::ModelError::ProviderNotAvailable(
                "no text-embedding model loaded for route difficulty estimation".to_string(),
            )
        })?;
        // Routing's own estimate, on a model the node picked.
        let result = tenzro_model::access::as_node(self.runtime.embed(
            &model_id,
            vec![prompt.into()],
            tenzro_model::text_embedding_runtime::TextEmbedConfig::default(),
        ))
        .await?;
        result.embeddings.into_iter().next().ok_or_else(|| {
            tenzro_model::ModelError::InferenceError(format!(
                "embedder {model_id} returned no vectors"
            ))
        })
    }
}
