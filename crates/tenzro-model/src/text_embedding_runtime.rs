//! Text embedding runtime backed by ONNX Runtime.
//!
//! ONNX is always-on in `tenzro-model` (same posture as `llama-cpp-2`).
//! A `StubTextEncoder` is retained as an inert no-op so unit tests in
//! callers can construct a runtime without ORT model files.
//!
//! # Scope
//!
//! Foundation text encoders in 2026 share the `[B, L]` int64 token tensor
//! + `[B, L]` int64 attention mask interface, but disagree on:
//!
//! - **Pooling**: decoder-only Qwen3-Embedding takes the *last* non-pad
//!   token; bidirectional BGE-M3 takes the CLS (first) token; some
//!   exports (EmbeddingGemma) ship a pre-pooled `sentence_embedding`
//!   output and need no pooling at all.
//! - **Padding side**: Qwen3-Embedding is a causal LM repurposed for
//!   embedding — it needs left-padding so the last token is always real.
//!   Bidirectional encoders use right-padding.
//! - **Output naming**: `sentence_embedding` (Optimum exports of
//!   sentence-transformers checkpoints), `last_hidden_state`
//!   (transformers.js exports), or the only output (legacy single-output
//!   exports). The runtime prefers `sentence_embedding` when present and
//!   otherwise pools `last_hidden_state` per-family.
//! - **Matryoshka**: EmbeddingGemma supports 768 → 512 → 256 → 128.
//!   The runtime truncates and re-normalizes after pooling when
//!   `requested_dim` is smaller than the native dim.
//!
//! # Threading
//!
//! `TextEmbeddingRuntime` is `Send + Sync` and holds loaded ONNX
//! sessions in a `DashMap` keyed by model_id. ORT sessions are not
//! safe to call concurrently, so each session lives behind a
//! `parking_lot::Mutex`. Inference is dispatched through
//! `tokio::task::spawn_blocking`.

use std::path::Path;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::error::{ModelError, Result};

/// Configuration for a text-embedding request.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TextEmbedConfig {
    /// Optional Matryoshka dimension. Must be `<= embedding_dim()`.
    /// Catalog entries that support MRL list valid dims in their
    /// `matryoshka_dims` field; the runtime accepts any value
    /// `<= embedding_dim` and truncates+renormalizes.
    #[serde(default)]
    pub requested_dim: Option<u32>,
    /// L2-normalize the output embedding. Most retrieval pipelines want
    /// this on; downstream classification heads want it off.
    #[serde(default)]
    pub normalize: bool,
}

/// Result of a text-embedding call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TextEmbedResult {
    /// Embedding vectors, one per input string. Outer length =
    /// `inputs.len()`, inner length = effective embedding dim
    /// (post-Matryoshka if requested).
    pub embeddings: Vec<Vec<f32>>,
    /// Effective embedding dim used (after Matryoshka truncation).
    pub dim: usize,
    /// Tokens consumed across the batch, excluding padding. Batching pads every
    /// input up to the longest one in the batch; those pad positions are an
    /// artifact of how the tensor is shaped, not work the caller asked for, so
    /// this counts attention-mask positions rather than `batch × seq_len`.
    pub prompt_tokens: u32,
    /// Total inference wall time in milliseconds (tokenize + ORT run).
    pub generation_time_ms: u64,
}

/// Family of text encoder. Drives padding side and pooling strategy.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum TextEncoderFamily {
    /// Decoder-only causal LM repurposed as an embedding model
    /// (Qwen3-Embedding). Left-padding, last-token pooling.
    Qwen3,
    /// Bidirectional encoder, CLS pooling (BGE-M3, Snowflake Arctic
    /// Embed L v2.0 use [CLS] at position 0).
    Cls,
    /// Bidirectional encoder, mean pooling over non-pad positions
    /// (ModernBERT-embed base/large).
    Mean,
    /// Pre-pooled `sentence_embedding` output (EmbeddingGemma's Optimum
    /// export). The runtime asserts the `sentence_embedding` output is
    /// present at load time when this family is chosen.
    SentenceEmbedding,
}

/// Trait for text encoders. Implementations adapt model-specific
/// tokenization and pooling to a common signature.
pub trait TextEncoder: Send + Sync {
    /// Encode a batch of strings to dense vectors.
    fn embed(&self, inputs: &[String], config: &TextEmbedConfig) -> Result<TextEmbedResult>;

    /// Native embedding dimension (before any Matryoshka truncation).
    fn embedding_dim(&self) -> usize;

    /// Maximum sequence length the tokenizer will produce.
    fn max_sequence_length(&self) -> usize;
}

/// Stub text encoder. Returns `ProviderNotAvailable` from every method.
/// Used by callers that want to construct a runtime without loading
/// an ORT model — e.g. unit tests of upper-layer plumbing.
#[derive(Debug, Default)]
pub struct StubTextEncoder;

impl StubTextEncoder {
    pub fn from_onnx(_path: impl AsRef<Path>, _tokenizer_path: impl AsRef<Path>) -> Result<Self> {
        Err(ModelError::ProviderNotAvailable(
            "StubTextEncoder cannot load real ONNX — use GenericTextEncoder::from_onnx".to_string(),
        ))
    }
}

impl TextEncoder for StubTextEncoder {
    fn embed(&self, _inputs: &[String], _config: &TextEmbedConfig) -> Result<TextEmbedResult> {
        Err(ModelError::ProviderNotAvailable(
            "StubTextEncoder is inert — register a GenericTextEncoder".to_string(),
        ))
    }
    fn embedding_dim(&self) -> usize {
        0
    }
    fn max_sequence_length(&self) -> usize {
        0
    }
}

mod onnx_backend {
    use super::*;
    use ndarray::Array2;
    use ort::session::Session;
    use ort::value::Tensor;
    use std::time::Instant;
    use tokenizers::{PaddingDirection, PaddingParams, PaddingStrategy, Tokenizer, TruncationParams};

    /// ORT-backed text encoder covering Qwen3-Embedding, BGE-M3,
    /// Snowflake Arctic Embed, and EmbeddingGemma. Pooling and padding
    /// side are picked per-family at load time.
    ///
    /// `Session::run` requires `&mut self` in ort 2.x, so the session is
    /// wrapped in a `Mutex` to expose a `&self` API. ONNX Runtime sessions
    /// are not safe to call concurrently from multiple threads regardless,
    /// so the mutex matches the underlying contract rather than restricting it.
    pub struct GenericTextEncoder {
        session: parking_lot::Mutex<Session>,
        tokenizer: Tokenizer,
        family: TextEncoderFamily,
        embedding_dim: usize,
        max_sequence_length: usize,
        /// Cached input names. Most exports use `input_ids` /
        /// `attention_mask`, but a few rename them — captured at load.
        input_ids_name: String,
        attention_mask_name: String,
        /// Optional `position_ids` input — required by some Qwen3 exports.
        position_ids_name: Option<String>,
        /// Optional `token_type_ids` input — required by some BERT-style
        /// exports (BGE-M3 declares it but accepts all-zeros).
        token_type_ids_name: Option<String>,
        /// Output name to read. Either `sentence_embedding` (pre-pooled)
        /// or `last_hidden_state` (needs pooling).
        output_name: String,
        /// Whether `output_name` is `sentence_embedding` (already pooled).
        output_is_pooled: bool,
    }

    impl GenericTextEncoder {
        /// Load an ONNX file and a tokenizer.json file. The family hint
        /// drives padding side + pooling strategy. The runtime introspects
        /// the session's input/output names and picks the right
        /// `sentence_embedding`/`last_hidden_state` output.
        pub fn from_onnx(
            onnx_path: impl AsRef<Path>,
            tokenizer_path: impl AsRef<Path>,
            family: TextEncoderFamily,
            embedding_dim: usize,
            max_sequence_length: usize,
        ) -> Result<Self> {
            let session = crate::onnx_session::build_onnx_session(onnx_path.as_ref(), "model")?;

            // Introspect inputs.
            let input_names: Vec<String> = session.inputs.iter().map(|i| i.name.clone()).collect();
            let input_ids_name = pick_input(&input_names, &["input_ids"])
                .ok_or_else(|| ModelError::InvalidModel(
                    "ONNX model is missing 'input_ids' input".to_string(),
                ))?;
            let attention_mask_name = pick_input(&input_names, &["attention_mask"])
                .ok_or_else(|| ModelError::InvalidModel(
                    "ONNX model is missing 'attention_mask' input".to_string(),
                ))?;
            let position_ids_name = pick_input(&input_names, &["position_ids"]);
            let token_type_ids_name = pick_input(&input_names, &["token_type_ids"]);

            // Introspect outputs. Prefer `sentence_embedding` when the
            // family asks for it; otherwise read `last_hidden_state` and
            // pool here.
            let output_names: Vec<String> =
                session.outputs.iter().map(|o| o.name.clone()).collect();
            let (output_name, output_is_pooled) = match family {
                TextEncoderFamily::SentenceEmbedding => {
                    let n = pick_input(&output_names, &["sentence_embedding"])
                        .ok_or_else(|| ModelError::InvalidModel(
                            "SentenceEmbedding family requires a 'sentence_embedding' output"
                                .to_string(),
                        ))?;
                    (n, true)
                }
                _ => {
                    // Prefer last_hidden_state; fall back to first output.
                    let n = pick_input(&output_names, &["last_hidden_state", "hidden_states"])
                        .or_else(|| output_names.first().cloned())
                        .ok_or_else(|| ModelError::InvalidModel(
                            "ONNX model has no outputs".to_string(),
                        ))?;
                    (n, false)
                }
            };

            // Load + configure tokenizer.
            let mut tokenizer = Tokenizer::from_file(tokenizer_path.as_ref())
                .map_err(|e| ModelError::InvalidModel(format!("tokenizer load: {}", e)))?;

            // Padding side per family.
            let padding_direction = match family {
                TextEncoderFamily::Qwen3 => PaddingDirection::Left,
                _ => PaddingDirection::Right,
            };
            let pad_id = tokenizer
                .get_padding()
                .map(|p| p.pad_id)
                .unwrap_or(0);
            let pad_token = tokenizer
                .get_padding()
                .map(|p| p.pad_token.clone())
                .unwrap_or_else(|| "[PAD]".to_string());
            tokenizer.with_padding(Some(PaddingParams {
                strategy: PaddingStrategy::BatchLongest,
                direction: padding_direction,
                pad_to_multiple_of: None,
                pad_id,
                pad_type_id: 0,
                pad_token,
            }));
            tokenizer
                .with_truncation(Some(TruncationParams {
                    max_length: max_sequence_length,
                    ..Default::default()
                }))
                .map_err(|e| ModelError::InvalidModel(format!("tokenizer truncation: {}", e)))?;

            Ok(Self {
                session: parking_lot::Mutex::new(session),
                tokenizer,
                family,
                embedding_dim,
                max_sequence_length,
                input_ids_name,
                attention_mask_name,
                position_ids_name,
                token_type_ids_name,
                output_name,
                output_is_pooled,
            })
        }

        /// Tokenize a batch and return `(input_ids, attention_mask)`
        /// tensors as `[B, L]` int64 ndarrays.
        fn tokenize(&self, inputs: &[String]) -> Result<(Array2<i64>, Array2<i64>)> {
            let encodings = self
                .tokenizer
                .encode_batch(inputs.to_vec(), true)
                .map_err(|e| ModelError::InferenceError(format!("tokenize: {}", e)))?;

            let batch_size = encodings.len();
            let seq_len = encodings.iter().map(|e| e.get_ids().len()).max().unwrap_or(0);

            let mut input_ids = Array2::<i64>::zeros((batch_size, seq_len));
            let mut attention_mask = Array2::<i64>::zeros((batch_size, seq_len));

            for (b, enc) in encodings.iter().enumerate() {
                for (i, (id, m)) in enc.get_ids().iter().zip(enc.get_attention_mask()).enumerate() {
                    input_ids[[b, i]] = *id as i64;
                    attention_mask[[b, i]] = *m as i64;
                }
            }
            Ok((input_ids, attention_mask))
        }
    }

    impl TextEncoder for GenericTextEncoder {
        fn embed(&self, inputs: &[String], config: &TextEmbedConfig) -> Result<TextEmbedResult> {
            if inputs.is_empty() {
                return Ok(TextEmbedResult {
                    embeddings: vec![],
                    dim: 0,
                    prompt_tokens: 0,
                    generation_time_ms: 0,
                });
            }
            let start = Instant::now();
            let (input_ids, attention_mask) = self.tokenize(inputs)?;
            let (batch_size, seq_len) = (input_ids.shape()[0], input_ids.shape()[1]);
            let prompt_tokens = attention_mask.iter().filter(|m| **m != 0).count() as u32;

            // Build extra optional inputs before the lock.
            let position_ids: Option<Array2<i64>> = if self.position_ids_name.is_some() {
                let mut pids = Array2::<i64>::zeros((batch_size, seq_len));
                for b in 0..batch_size {
                    for i in 0..seq_len {
                        pids[[b, i]] = i as i64;
                    }
                }
                Some(pids)
            } else {
                None
            };
            let token_type_ids: Option<Array2<i64>> = if self.token_type_ids_name.is_some() {
                Some(Array2::<i64>::zeros((batch_size, seq_len)))
            } else {
                None
            };

            // input_ids is consumed by the tensor; attention_mask must be
            // cloned because the pooling step below still needs it.
            let input_ids_tensor = Tensor::from_array(input_ids)
                .map_err(|e| ModelError::InferenceError(format!("ORT tensor input_ids: {}", e)))?;
            let attention_mask_tensor = Tensor::from_array(attention_mask.clone())
                .map_err(|e| ModelError::InferenceError(format!("ORT tensor attention_mask: {}", e)))?;

            // Build the input feed dynamically — we may have 2, 3, or 4
            // inputs depending on whether the export declares position_ids
            // and/or token_type_ids. `Vec<(K, V)>` where K: Into<Cow<str>>
            // and V: Into<SessionInputValue> auto-converts to SessionInputs
            // (see ort::session::input::SessionInputs::From<Vec<...>>).
            let (out_shape, out_data): (Vec<i64>, Vec<f32>) = {
                let mut session = self.session.lock();
                let mut feed: Vec<(String, ort::session::SessionInputValue<'_>)> =
                    Vec::with_capacity(4);
                feed.push((self.input_ids_name.clone(), input_ids_tensor.into()));
                feed.push((self.attention_mask_name.clone(), attention_mask_tensor.into()));
                if let (Some(name), Some(arr)) = (&self.position_ids_name, position_ids) {
                    let t = Tensor::from_array(arr).map_err(|e| {
                        ModelError::InferenceError(format!("ORT tensor position_ids: {}", e))
                    })?;
                    feed.push((name.clone(), t.into()));
                }
                if let (Some(name), Some(arr)) = (&self.token_type_ids_name, token_type_ids) {
                    let t = Tensor::from_array(arr).map_err(|e| {
                        ModelError::InferenceError(format!("ORT tensor token_type_ids: {}", e))
                    })?;
                    feed.push((name.clone(), t.into()));
                }

                let outputs = session
                    .run(feed)
                    .map_err(|e| ModelError::InferenceError(format!("ORT run: {}", e)))?;

                let out_value = outputs.get(self.output_name.as_str()).ok_or_else(|| {
                    ModelError::InferenceError(format!(
                        "missing output '{}' in run result",
                        self.output_name
                    ))
                })?;
                let (shape, data) = out_value
                    .try_extract_tensor::<f32>()
                    .map_err(|e| ModelError::InferenceError(format!("ORT extract: {}", e)))?;
                (shape.iter().copied().collect(), data.to_vec())
            };

            // Pool to per-row [D] vectors. Two cases:
            //  * already pooled: shape is [B, D] — split into rows.
            //  * needs pooling: shape is [B, L, D] — apply family pool.
            let mut embeddings: Vec<Vec<f32>> = if self.output_is_pooled {
                if out_shape.len() != 2 {
                    return Err(ModelError::InferenceError(format!(
                        "expected pooled output shape [B, D], got {:?}",
                        out_shape
                    )));
                }
                let b = out_shape[0] as usize;
                let d = out_shape[1] as usize;
                if b != batch_size {
                    return Err(ModelError::InferenceError(format!(
                        "batch mismatch: expected {}, got {}",
                        batch_size, b
                    )));
                }
                (0..b)
                    .map(|row| out_data[row * d..(row + 1) * d].to_vec())
                    .collect()
            } else {
                if out_shape.len() != 3 {
                    return Err(ModelError::InferenceError(format!(
                        "expected hidden-state shape [B, L, D], got {:?}",
                        out_shape
                    )));
                }
                let b = out_shape[0] as usize;
                let l = out_shape[1] as usize;
                let d = out_shape[2] as usize;
                if b != batch_size || l != seq_len {
                    return Err(ModelError::InferenceError(format!(
                        "shape mismatch: expected [{}, {}, D], got [{}, {}, {}]",
                        batch_size, seq_len, b, l, d
                    )));
                }
                pool_hidden_state(&out_data, &attention_mask, b, l, d, self.family)
            };

            // Matryoshka: truncate then renormalize when smaller dim
            // is requested.
            let mut effective_dim = self.embedding_dim;
            if let Some(req) = config.requested_dim {
                let req = req as usize;
                if req == 0 || req > self.embedding_dim {
                    return Err(ModelError::InvalidModel(format!(
                        "requested_dim {} out of range (1..={})",
                        req, self.embedding_dim
                    )));
                }
                if req < self.embedding_dim {
                    for v in embeddings.iter_mut() {
                        v.truncate(req);
                    }
                    effective_dim = req;
                }
            }

            // L2 normalize. Always on for Matryoshka (truncation
            // breaks norm); optional otherwise.
            let must_normalize = config.normalize || config.requested_dim.is_some();
            if must_normalize {
                for v in embeddings.iter_mut() {
                    l2_normalize(v);
                }
            }

            Ok(TextEmbedResult {
                embeddings,
                dim: effective_dim,
                prompt_tokens,
                generation_time_ms: start.elapsed().as_millis() as u64,
            })
        }

        fn embedding_dim(&self) -> usize {
            self.embedding_dim
        }

        fn max_sequence_length(&self) -> usize {
            self.max_sequence_length
        }
    }

    /// Pool `[B, L, D]` hidden states down to `[B, D]` per the family's
    /// pooling rule. Returns a `Vec<Vec<f32>>` of length B.
    fn pool_hidden_state(
        data: &[f32],
        attention_mask: &Array2<i64>,
        batch_size: usize,
        seq_len: usize,
        dim: usize,
        family: TextEncoderFamily,
    ) -> Vec<Vec<f32>> {
        let row_stride = seq_len * dim;
        let mut out = Vec::with_capacity(batch_size);
        for b in 0..batch_size {
            let row = &data[b * row_stride..(b + 1) * row_stride];
            let pooled = match family {
                TextEncoderFamily::Qwen3 => {
                    // Last non-pad token. With left-padding the last
                    // token is always real, but we still respect the
                    // mask in case the export uses right-padding.
                    let mut last_idx = seq_len.saturating_sub(1);
                    for i in (0..seq_len).rev() {
                        if attention_mask[[b, i]] == 1 {
                            last_idx = i;
                            break;
                        }
                    }
                    row[last_idx * dim..(last_idx + 1) * dim].to_vec()
                }
                TextEncoderFamily::Cls => {
                    // Position 0.
                    row[0..dim].to_vec()
                }
                TextEncoderFamily::Mean => {
                    let mut acc = vec![0.0f32; dim];
                    let mut count = 0usize;
                    for i in 0..seq_len {
                        if attention_mask[[b, i]] == 1 {
                            for d in 0..dim {
                                acc[d] += row[i * dim + d];
                            }
                            count += 1;
                        }
                    }
                    if count > 0 {
                        let inv = 1.0 / count as f32;
                        for v in acc.iter_mut().take(dim) {
                            *v *= inv;
                        }
                    }
                    acc
                }
                TextEncoderFamily::SentenceEmbedding => {
                    // Should never reach this branch — caller checks
                    // `output_is_pooled` first. Fall back to mean as a
                    // safety net rather than panic.
                    let mut acc = vec![0.0f32; dim];
                    for i in 0..seq_len {
                        for d in 0..dim {
                            acc[d] += row[i * dim + d];
                        }
                    }
                    let inv = 1.0 / seq_len as f32;
                    for v in acc.iter_mut().take(dim) {
                        *v *= inv;
                    }
                    acc
                }
            };
            out.push(pooled);
        }
        out
    }

    fn l2_normalize(v: &mut [f32]) {
        let norm: f32 = v.iter().map(|x| x * x).sum::<f32>().sqrt();
        if norm > 0.0 {
            let inv = 1.0 / norm;
            for x in v.iter_mut() {
                *x *= inv;
            }
        }
    }

    /// Pick the first matching name from `candidates` that appears in
    /// `available`. Returns `None` if no candidate matches.
    fn pick_input(available: &[String], candidates: &[&str]) -> Option<String> {
        for c in candidates {
            for a in available {
                if a == c {
                    return Some(a.clone());
                }
            }
        }
        None
    }
}

pub use onnx_backend::GenericTextEncoder;

/// Runtime that owns multiple loaded text encoders, keyed by model_id.
pub struct TextEmbeddingRuntime {
    models: dashmap::DashMap<String, Arc<dyn TextEncoder>>,
}

impl Default for TextEmbeddingRuntime {
    fn default() -> Self {
        Self::new()
    }
}

impl TextEmbeddingRuntime {
    pub fn new() -> Self {
        Self {
            models: dashmap::DashMap::new(),
        }
    }

    /// Register a pre-loaded encoder under `model_id`. Replaces any
    /// existing registration for the same id.
    pub fn register(&self, model_id: impl Into<String>, model: Arc<dyn TextEncoder>) {
        self.models.insert(model_id.into(), model);
    }

    /// Load an ONNX text encoder from disk and register it.
    pub fn load_onnx(
        &self,
        model_id: impl Into<String>,
        onnx_path: impl AsRef<Path>,
        tokenizer_path: impl AsRef<Path>,
        family: TextEncoderFamily,
        embedding_dim: usize,
        max_sequence_length: usize,
    ) -> Result<()> {
        let model = GenericTextEncoder::from_onnx(
            onnx_path,
            tokenizer_path,
            family,
            embedding_dim,
            max_sequence_length,
        )?;
        self.models
            .insert(model_id.into(), Arc::new(model) as Arc<dyn TextEncoder>);
        Ok(())
    }

    pub fn unregister(&self, model_id: &str) -> bool {
        self.models.remove(model_id).is_some()
    }

    pub fn is_loaded(&self, model_id: &str) -> bool {
        self.models.contains_key(model_id)
    }

    pub fn loaded_models(&self) -> Vec<String> {
        self.models.iter().map(|kv| kv.key().clone()).collect()
    }

    /// Embed strings with a registered encoder. Dispatched to
    /// `spawn_blocking` so the async caller's runtime isn't stalled.
    pub async fn embed(
        &self,
        model_id: &str,
        inputs: Vec<String>,
        config: TextEmbedConfig,
    ) -> Result<TextEmbedResult> {
        let model = self
            .models
            .get(model_id)
            .map(|kv| Arc::clone(kv.value()))
            .ok_or_else(|| ModelError::ModelNotFound(model_id.to_string()))?;
        tokio::task::spawn_blocking(move || model.embed(&inputs, &config))
            .await
            .map_err(|e| ModelError::InferenceError(format!("spawn_blocking: {}", e)))?
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_starts_empty() {
        let rt = TextEmbeddingRuntime::new();
        assert!(rt.loaded_models().is_empty());
        assert!(!rt.is_loaded("anything"));
    }

    #[test]
    fn unregister_returns_false_when_absent() {
        let rt = TextEmbeddingRuntime::new();
        assert!(!rt.unregister("missing"));
    }

    #[test]
    fn stub_encoder_returns_provider_not_available() {
        let stub = StubTextEncoder;
        let res = stub.embed(&["hello".into()], &TextEmbedConfig::default());
        assert!(matches!(res, Err(ModelError::ProviderNotAvailable(_))));
    }

    #[tokio::test]
    async fn embed_on_unknown_model_returns_not_found() {
        let rt = TextEmbeddingRuntime::new();
        let res = rt
            .embed("missing", vec!["x".into()], TextEmbedConfig::default())
            .await;
        assert!(matches!(res, Err(ModelError::ModelNotFound(_))));
    }

    /// Mock encoder used to verify dispatch + Matryoshka + normalize logic
    /// without an ONNX file.
    struct ConstantEncoder {
        dim: usize,
        value: f32,
    }
    impl TextEncoder for ConstantEncoder {
        fn embed(
            &self,
            inputs: &[String],
            config: &TextEmbedConfig,
        ) -> Result<TextEmbedResult> {
            let mut embeddings: Vec<Vec<f32>> = (0..inputs.len())
                .map(|_| vec![self.value; self.dim])
                .collect();
            let mut effective = self.dim;
            if let Some(req) = config.requested_dim {
                let req = req as usize;
                for v in embeddings.iter_mut() {
                    v.truncate(req);
                }
                effective = req;
            }
            if config.normalize || config.requested_dim.is_some() {
                for v in embeddings.iter_mut() {
                    let n: f32 = v.iter().map(|x| x * x).sum::<f32>().sqrt();
                    if n > 0.0 {
                        for x in v.iter_mut() {
                            *x /= n;
                        }
                    }
                }
            }
            Ok(TextEmbedResult {
                embeddings,
                dim: effective,
                // No tokenizer behind this mock, so approximate by word count.
                prompt_tokens: inputs
                    .iter()
                    .map(|s| s.split_whitespace().count() as u32)
                    .sum(),
                generation_time_ms: 0,
            })
        }
        fn embedding_dim(&self) -> usize {
            self.dim
        }
        fn max_sequence_length(&self) -> usize {
            512
        }
    }

    #[tokio::test]
    async fn runtime_dispatches_to_registered_model() {
        let rt = TextEmbeddingRuntime::new();
        rt.register("k", Arc::new(ConstantEncoder { dim: 4, value: 1.0 }));
        let r = rt
            .embed("k", vec!["a".into(), "b".into()], TextEmbedConfig::default())
            .await
            .unwrap();
        assert_eq!(r.dim, 4);
        assert_eq!(r.embeddings.len(), 2);
        assert_eq!(r.embeddings[0], vec![1.0; 4]);
    }

    #[tokio::test]
    async fn matryoshka_truncates_and_renormalizes() {
        let rt = TextEmbeddingRuntime::new();
        rt.register("k", Arc::new(ConstantEncoder { dim: 8, value: 2.0 }));
        let cfg = TextEmbedConfig {
            requested_dim: Some(4),
            normalize: false,
        };
        let r = rt.embed("k", vec!["x".into()], cfg).await.unwrap();
        assert_eq!(r.dim, 4);
        assert_eq!(r.embeddings[0].len(), 4);
        let n: f32 = r.embeddings[0].iter().map(|v| v * v).sum::<f32>().sqrt();
        assert!((n - 1.0).abs() < 1e-6, "expected unit norm after MRL, got {}", n);
    }
}
