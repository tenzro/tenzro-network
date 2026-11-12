//! Decision models.
//!
//! A decision model answers typed questions about a piece of text in one
//! forward pass: yes or no, one choice out of several, or a score on an
//! ordered scale. It generates no text, so there is nothing to parse, and
//! any node holding the same weights recomputes the same probabilities. It
//! runs in the node process on the Praecise engine, claimed and admitted
//! through the node's [`ModelHost`] like every other model.

use std::path::Path;
use std::sync::Arc;

use llama_cpp_2::model::LlamaModel;
use llama_cpp_2::model::params::LlamaModelParams;
pub use praecise_runtime::decision::{
    Answer as DecisionAnswer, DecisionOption, MAX_OPTIONS as MAX_DECISION_OPTIONS,
    MAX_QUESTIONS as MAX_DECISION_QUESTIONS, MAX_SCORE_LEVELS, MIN_SCORE_LEVELS, Question,
    QuestionKind,
};
use praecise_runtime::decision::{DecisionHead, DecisionOptions, decide};

use crate::error::{ModelError, Result};
use crate::model_host::{Engine, EngineModels, ModelHost};

/// A loaded decision model.
pub struct DecisionModel {
    model: LlamaModel,
    head: DecisionHead,
    /// Longest prompt, in tokens, the catalog entry declares.
    n_ctx: u32,
}

/// What a decision call returns.
#[derive(Debug, Clone, PartialEq)]
pub struct Decisions {
    /// One answer per question, in the request's order.
    pub answers: Vec<DecisionAnswer>,
    /// Tokens the prompts took, summed over the questions.
    pub tokens: usize,
}

/// Decision models loaded on this node.
pub struct DecisionRuntime {
    models: EngineModels<DecisionModel>,
}

impl std::fmt::Debug for DecisionRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DecisionRuntime")
            .field("loaded", &self.loaded())
            .finish()
    }
}

impl Default for DecisionRuntime {
    fn default() -> Self {
        Self::with_host(Arc::default())
    }
}

impl DecisionRuntime {
    /// A runtime that claims models and admits requests through `host`.
    pub fn with_host(host: Arc<ModelHost>) -> Self {
        Self {
            models: EngineModels::new(Engine::PraeciseTask("decision"), host),
        }
    }

    /// Load the decision model in `gguf` as `model_id`, answering prompts of
    /// up to `n_ctx` tokens. Blocking: call from a blocking thread.
    ///
    /// # Errors
    /// [`ModelError::EngineConflict`] when another engine holds the model id,
    /// or the backend's refusal to load the file, or [`ModelError::InvalidModel`]
    /// when the file is not a decision model the renderer was verified against.
    pub fn load(&self, model_id: &str, gguf: &Path, n_ctx: u32) -> Result<()> {
        let bytes = std::fs::metadata(gguf)?.len();
        self.models.load_reserving(model_id, bytes, || {
            let backend = crate::runtime::llama_backend();
            let params = LlamaModelParams::default().with_n_gpu_layers(1000);
            let model = crate::parse_jail::load_llama(&backend, gguf, &params)
                .map_err(|e| ModelError::InvalidModel(format!("decision model {model_id}: {e}")))?;
            let head = DecisionHead::from_model(&model)
                .map_err(|e| ModelError::InvalidModel(format!("{model_id}: {e}")))?;
            Ok(Arc::new(DecisionModel { model, head, n_ctx }))
        })
    }

    /// Unload a model, giving back its claim. `false` when it was not loaded.
    pub fn unload(&self, model_id: &str) -> bool {
        self.models.remove(model_id)
    }

    /// Ids of the loaded models.
    #[must_use]
    pub fn loaded(&self) -> Vec<String> {
        let mut ids = self.models.ids();
        ids.sort();
        ids
    }

    /// Whether `model_id` is loaded.
    #[must_use]
    pub fn contains(&self, model_id: &str) -> bool {
        self.models.contains(model_id)
    }

    /// Answer every question about `state`, after the caller's access check
    /// and a slot from the node's admission.
    ///
    /// # Errors
    /// [`ModelError::AccessDenied`] or [`ModelError::Busy`] from the shared
    /// path, [`ModelError::ModelNotFound`] when the model is not loaded,
    /// [`ModelError::InvalidInput`] for a request outside the limits
    /// ([`MAX_DECISION_QUESTIONS`], [`MAX_DECISION_OPTIONS`], 2 to 10 score
    /// levels, distinct ids and keys) or a prompt longer than the model's
    /// context, or the engine's refusal.
    pub async fn decide(
        &self,
        model_id: &str,
        state: serde_json::Value,
        questions: Vec<Question>,
    ) -> Result<Decisions> {
        check_request(&state, &questions)?;
        self.models
            .run(model_id, move |m| {
                let backend = crate::runtime::llama_backend();
                let options = DecisionOptions {
                    n_ctx: m.n_ctx,
                    ..DecisionOptions::default()
                };
                let answers = decide(&backend, &m.model, &m.head, &state, &questions, options)
                    .map_err(|e| ModelError::InferenceError(e.to_string()))?;
                let tokens = answers.iter().map(|a| a.tokens).sum();
                Ok(Decisions { answers, tokens })
            })
            .await
    }
}

/// The request limits, checked before a slot is taken so a malformed request
/// costs nothing.
pub fn check_request(state: &serde_json::Value, questions: &[Question]) -> Result<()> {
    let bad = |m: String| ModelError::InvalidInput(m);
    if state.is_null() {
        return Err(bad("state must be provided".into()));
    }
    if questions.is_empty() || questions.len() > MAX_DECISION_QUESTIONS {
        return Err(bad(format!(
            "a decision request carries 1 to {MAX_DECISION_QUESTIONS} questions, got {}",
            questions.len()
        )));
    }
    let mut ids: Vec<&str> = questions.iter().map(|q| q.id.as_str()).collect();
    ids.sort_unstable();
    ids.dedup();
    if ids.len() != questions.len() {
        return Err(bad("question ids must be distinct".into()));
    }
    for q in questions {
        q.validate().map_err(|e| bad(e.to_string()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    #[tokio::test]
    async fn deciding_with_a_model_that_is_not_loaded_is_refused() {
        let rt = DecisionRuntime::default();
        let q = Question::noul("q", "Is it?", Value::Null, Value::Null);
        let r = rt.decide("absent", json!("text"), vec![q]).await;
        assert!(matches!(r, Err(ModelError::ModelNotFound(_))), "{r:?}");
    }

    #[tokio::test]
    async fn a_request_outside_the_limits_is_refused_before_any_work() {
        let rt = DecisionRuntime::default();
        let none = rt.decide("absent", json!("t"), vec![]).await;
        assert!(matches!(none, Err(ModelError::InvalidInput(_))), "{none:?}");
        let many: Vec<Question> = (0..=MAX_DECISION_QUESTIONS)
            .map(|i| Question::noul(format!("q{i}"), "x?", Value::Null, Value::Null))
            .collect();
        let over = rt.decide("absent", json!("t"), many).await;
        assert!(matches!(over, Err(ModelError::InvalidInput(_))), "{over:?}");
        let null_state = rt
            .decide(
                "absent",
                Value::Null,
                vec![Question::noul("q", "x?", Value::Null, Value::Null)],
            )
            .await;
        assert!(matches!(null_state, Err(ModelError::InvalidInput(_))));
        let one_level = Question::score("s", "x?", vec![json!("a")]);
        let r = rt.decide("absent", json!("t"), vec![one_level]).await;
        assert!(matches!(r, Err(ModelError::InvalidInput(_))), "{r:?}");
        let dup = vec![
            Question::noul("q", "x?", Value::Null, Value::Null),
            Question::noul("q", "y?", Value::Null, Value::Null),
        ];
        assert!(matches!(
            rt.decide("absent", json!("t"), dup).await,
            Err(ModelError::InvalidInput(_))
        ));
    }
}
