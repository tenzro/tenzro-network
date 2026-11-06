//! Text embedding runtime: ONNX text encoders, and pooled embedders on the
//! Praecise engine ([`crate::praecise_embedder`]), which also read pictures
//! and video.
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

use crate::catalog::EmbeddingTemplate;
use crate::error::{ModelError, Result};
use crate::model_host::{Engine, EngineModels, ModelHost};

pub use praecise_onnx::text_embedding::{
    EmbedInput, EmbedRole, GenericTextEncoder, TextEmbedConfig, TextEmbedResult, TextEncoder,
    TextEncoderFamily,
};

/// Apply a family's [`EmbeddingTemplate`] to one input string for the given
/// role. Pure data-in-data-out — the encoder calls this once per input
/// before tokenization; no model-name branching lives here or anywhere
/// downstream of it.
pub fn apply_embedding_template(
    template: &EmbeddingTemplate,
    role: &EmbedRole,
    text: &str,
) -> String {
    match (template, role) {
        (EmbeddingTemplate::None, _) => text.to_string(),
        (EmbeddingTemplate::InstructQuery { .. }, EmbedRole::Document { .. }) => text.to_string(),
        (EmbeddingTemplate::InstructQuery { default_task }, EmbedRole::Query { task }) => {
            let task = task.as_deref().unwrap_or(default_task);
            // Verified byte-for-byte against Qwen3-Embedding's own
            // `get_detailed_instruct` example: no space after "Query:".
            format!("Instruct: {}\nQuery:{}", task, text)
        }
        (EmbeddingTemplate::GemmaTask { .. }, EmbedRole::Document { title }) => {
            format!(
                "title: {} | text: {}",
                title.as_deref().unwrap_or("none"),
                text
            )
        }
        (EmbeddingTemplate::GemmaTask { default_task }, EmbedRole::Query { task }) => {
            let task = task.as_deref().unwrap_or(default_task);
            format!("task: {} | query: {}", task, text)
        }
        (EmbeddingTemplate::NomicPrefix, EmbedRole::Document { .. }) => {
            format!("search_document: {}", text)
        }
        (EmbeddingTemplate::NomicPrefix, EmbedRole::Query { .. }) => {
            format!("search_query: {}", text)
        }
        (EmbeddingTemplate::QueryPassagePrefix, EmbedRole::Document { .. }) => {
            format!("passage: {}", text)
        }
        (EmbeddingTemplate::QueryPassagePrefix, EmbedRole::Query { .. }) => {
            format!("query: {}", text)
        }
        // The engine writes the instruction into the checkpoint's own chat
        // template (see `chat_instruction`); the input goes in as it is.
        (EmbeddingTemplate::ChatInstruct { .. }, _) => text.to_string(),
    }
}

/// The instruction a chat-instruct template gives the engine for `role`:
/// the caller's task or the template's default for a query, the document
/// task for a document. `None` for templates applied as a text prefix.
pub fn chat_instruction<'a>(
    template: &'a EmbeddingTemplate,
    role: &'a EmbedRole,
) -> Option<&'a str> {
    match (template, role) {
        (EmbeddingTemplate::ChatInstruct { document_task, .. }, EmbedRole::Document { .. }) => {
            Some(document_task.as_str())
        }
        (EmbeddingTemplate::ChatInstruct { default_task, .. }, EmbedRole::Query { task }) => {
            Some(task.as_deref().unwrap_or(default_task))
        }
        _ => None,
    }
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
    fn embed(
        &self,
        _inputs: &[EmbedInput],
        _config: &TextEmbedConfig,
    ) -> praecise_onnx::Result<TextEmbedResult> {
        Err(praecise_onnx::Error::ProviderNotAvailable(
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

/// The engine's form of a catalog embedding template.
fn engine_template(
    template: EmbeddingTemplate,
) -> praecise_onnx::text_embedding::EmbeddingTemplate {
    use praecise_onnx::text_embedding::EmbeddingTemplate as Engine;
    match template {
        EmbeddingTemplate::None => Engine::None,
        EmbeddingTemplate::InstructQuery { default_task } => Engine::InstructQuery { default_task },
        EmbeddingTemplate::GemmaTask { default_task } => Engine::GemmaTask { default_task },
        EmbeddingTemplate::NomicPrefix => Engine::NomicPrefix,
        EmbeddingTemplate::QueryPassagePrefix => Engine::QueryPassagePrefix,
        EmbeddingTemplate::ChatInstruct {
            default_task,
            document_task,
        } => Engine::ChatInstruct {
            default_task,
            document_task,
        },
    }
}

/// Runtime that owns the loaded embedders, keyed by model_id: ONNX text
/// encoders, and pooled embedders on the Praecise engine (text, and with a
/// projector pictures and video). A model id is held by one of them.
pub struct TextEmbeddingRuntime {
    onnx: EngineModels<dyn TextEncoder>,
    praecise: EngineModels<dyn TextEncoder>,
}

impl Default for TextEmbeddingRuntime {
    fn default() -> Self {
        Self::new()
    }
}

impl TextEmbeddingRuntime {
    pub fn new() -> Self {
        Self::with_host(Arc::default())
    }

    /// A runtime that claims models and admits requests through `host`.
    pub fn with_host(host: Arc<ModelHost>) -> Self {
        Self {
            onnx: EngineModels::new(Engine::Onnx("text-embedding"), Arc::clone(&host)),
            praecise: EngineModels::new(Engine::PraeciseTask("embed"), host),
        }
    }

    /// Register a pre-loaded ONNX encoder under `model_id`. Replaces any
    /// existing registration for the same id.
    pub fn register(&self, model_id: impl Into<String>, model: Arc<dyn TextEncoder>) -> Result<()> {
        self.onnx.insert(model_id, model)
    }

    /// Load an ONNX text encoder from disk and register it.
    pub fn load_onnx(
        &self,
        model_id: impl Into<String>,
        onnx_path: impl AsRef<Path>,
        tokenizer_path: impl AsRef<Path>,
        family: TextEncoderFamily,
        embedding_template: EmbeddingTemplate,
        embedding_dim: usize,
        max_sequence_length: usize,
    ) -> Result<()> {
        self.onnx.load(model_id, || {
            crate::onnx_session::declare()?;
            let model = GenericTextEncoder::from_onnx(
                onnx_path,
                tokenizer_path,
                family,
                engine_template(embedding_template),
                embedding_dim,
                max_sequence_length,
            )?;
            Ok(Arc::new(model) as Arc<dyn TextEncoder>)
        })
    }

    /// Load a pooled embedder in GGUF form on the Praecise engine, with its
    /// projector when it is a vision-language embedder, and register it.
    /// Blocking: call from a blocking thread.
    pub fn load_praecise(
        &self,
        model_id: &str,
        gguf: &Path,
        projector: Option<crate::projector::ProjectorFile<'_>>,
        embedding_template: EmbeddingTemplate,
        embedding_dim: usize,
        max_sequence_length: usize,
    ) -> Result<()> {
        let mut bytes = std::fs::metadata(gguf)?.len();
        if let Some(p) = &projector {
            bytes += std::fs::metadata(p.path)?.len();
        }
        self.praecise.load_reserving(model_id, bytes, || {
            let model = crate::praecise_embedder::PraeciseEmbedder::load(
                model_id,
                gguf,
                projector,
                embedding_template,
                embedding_dim,
                max_sequence_length,
            )?;
            Ok(Arc::new(model) as Arc<dyn TextEncoder>)
        })
    }

    pub fn unregister(&self, model_id: &str) -> bool {
        self.onnx.remove(model_id) || self.praecise.remove(model_id)
    }

    pub fn is_loaded(&self, model_id: &str) -> bool {
        self.onnx.contains(model_id) || self.praecise.contains(model_id)
    }

    pub fn loaded_models(&self) -> Vec<String> {
        let mut ids = self.onnx.ids();
        ids.extend(self.praecise.ids());
        ids
    }

    /// Embed inputs with a registered encoder, through its engine's
    /// admission, on a blocking thread.
    pub async fn embed(
        &self,
        model_id: &str,
        inputs: Vec<EmbedInput>,
        config: TextEmbedConfig,
    ) -> Result<TextEmbedResult> {
        let models = if self.praecise.contains(model_id) {
            &self.praecise
        } else {
            &self.onnx
        };
        models
            .run(model_id, move |model| {
                model.embed(&inputs, &config).map_err(ModelError::from)
            })
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn instruct_query_prefixes_only_the_query_role() {
        let t = EmbeddingTemplate::InstructQuery {
            default_task: "retrieve relevant passages".into(),
        };
        assert_eq!(
            apply_embedding_template(&t, &EmbedRole::Query { task: None }, "capital of France"),
            "Instruct: retrieve relevant passages\nQuery:capital of France"
        );
        assert_eq!(
            apply_embedding_template(
                &t,
                &EmbedRole::Query {
                    task: Some("find code examples".into())
                },
                "capital of France"
            ),
            "Instruct: find code examples\nQuery:capital of France"
        );
        // Document role: no prefix at all, per Qwen3-Embedding's own docs.
        assert_eq!(
            apply_embedding_template(
                &t,
                &EmbedRole::Document { title: None },
                "Paris is the capital of France."
            ),
            "Paris is the capital of France."
        );
    }

    #[test]
    fn gemma_task_prefixes_both_roles_differently() {
        let t = EmbeddingTemplate::GemmaTask {
            default_task: "search result".into(),
        };
        assert_eq!(
            apply_embedding_template(&t, &EmbedRole::Query { task: None }, "capital of France"),
            "task: search result | query: capital of France"
        );
        assert_eq!(
            apply_embedding_template(
                &t,
                &EmbedRole::Document { title: None },
                "Paris is the capital of France."
            ),
            "title: none | text: Paris is the capital of France."
        );
        assert_eq!(
            apply_embedding_template(
                &t,
                &EmbedRole::Document {
                    title: Some("France".into())
                },
                "Paris is the capital of France."
            ),
            "title: France | text: Paris is the capital of France."
        );
    }

    #[test]
    fn nomic_prefix_differs_by_role() {
        let t = EmbeddingTemplate::NomicPrefix;
        assert_eq!(
            apply_embedding_template(&t, &EmbedRole::Query { task: None }, "x"),
            "search_query: x"
        );
        assert_eq!(
            apply_embedding_template(&t, &EmbedRole::Document { title: None }, "x"),
            "search_document: x"
        );
    }

    #[test]
    fn chat_instruct_names_the_instruction_and_leaves_the_input() {
        let t = EmbeddingTemplate::ChatInstruct {
            default_task: "Retrieve relevant documents for the query.".into(),
            document_task: "Represent the user's input.".into(),
        };
        let query = EmbedRole::Query { task: None };
        let document = EmbedRole::Document { title: None };
        let asked = EmbedRole::Query {
            task: Some("Find code".into()),
        };
        assert_eq!(
            chat_instruction(&t, &query),
            Some("Retrieve relevant documents for the query.")
        );
        assert_eq!(
            chat_instruction(&t, &document),
            Some("Represent the user's input.")
        );
        assert_eq!(chat_instruction(&t, &asked), Some("Find code"));
        assert_eq!(apply_embedding_template(&t, &query, "x"), "x");
        assert_eq!(chat_instruction(&EmbeddingTemplate::None, &query), None);
    }

    #[test]
    fn query_passage_prefix_differs_by_role() {
        let t = EmbeddingTemplate::QueryPassagePrefix;
        assert_eq!(
            apply_embedding_template(&t, &EmbedRole::Query { task: None }, "x"),
            "query: x"
        );
        assert_eq!(
            apply_embedding_template(&t, &EmbedRole::Document { title: None }, "x"),
            "passage: x"
        );
    }

    #[test]
    fn none_template_never_prefixes() {
        let t = EmbeddingTemplate::None;
        assert_eq!(
            apply_embedding_template(&t, &EmbedRole::Query { task: None }, "x"),
            "x"
        );
        assert_eq!(
            apply_embedding_template(&t, &EmbedRole::Document { title: None }, "x"),
            "x"
        );
    }

    #[test]
    fn default_role_is_document() {
        assert_eq!(EmbedRole::default(), EmbedRole::Document { title: None });
    }

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
        assert!(matches!(
            res,
            Err(praecise_onnx::Error::ProviderNotAvailable(_))
        ));
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
            inputs: &[EmbedInput],
            config: &TextEmbedConfig,
        ) -> praecise_onnx::Result<TextEmbedResult> {
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
                    .map(|s| s.text.as_deref().unwrap_or("").split_whitespace().count() as u32)
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

    /// An ONNX text encoder against its source checkpoint, from vectors the
    /// reference script wrote. Each text already carries any instruction or
    /// role prefix, so it is embedded as a document with no template.
    /// `TENZRO_ENCODER_POOLING` is `sentence` (pre-pooled output) or `mean`.
    #[tokio::test]
    async fn an_onnx_encoder_matches_its_source_checkpoint() {
        let var = |k: &str| std::env::var(k).ok();
        let (Some(onnx), Some(tokenizer), Some(expected), Some(dim), Some(pooling)) = (
            var("TENZRO_ENCODER_ONNX"),
            var("TENZRO_ENCODER_TOKENIZER"),
            var("TENZRO_ENCODER_EXPECTED"),
            var("TENZRO_ENCODER_DIM"),
            var("TENZRO_ENCODER_POOLING"),
        ) else {
            return;
        };
        let family = match pooling.as_str() {
            "sentence" => TextEncoderFamily::SentenceEmbedding,
            "mean" => TextEncoderFamily::Mean,
            other => panic!("unknown pooling {other}"),
        };
        let exp: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(expected).unwrap()).unwrap();
        let texts: Vec<String> = serde_json::from_value(exp["texts"].clone()).unwrap();
        let want: Vec<Vec<f32>> = serde_json::from_value(exp["embeddings"].clone()).unwrap();
        let rt = TextEmbeddingRuntime::new();
        rt.load_onnx(
            "parity",
            onnx,
            tokenizer,
            family,
            EmbeddingTemplate::None,
            dim.parse().unwrap(),
            8192,
        )
        .unwrap();
        let mut worst = 1f32;
        for (text, want) in texts.iter().zip(&want) {
            let cfg = TextEmbedConfig {
                normalize: true,
                ..Default::default()
            };
            let got = rt
                .embed("parity", vec![text.as_str().into()], cfg)
                .await
                .unwrap();
            let cos: f32 = got.embeddings[0].iter().zip(want).map(|(a, b)| a * b).sum();
            worst = worst.min(cos);
        }
        eprintln!("worst cosine {worst} over {} texts", texts.len());
        assert!(worst > 0.999, "worst cosine {worst}");
    }

    /// The vision-language embedder on the Praecise engine against the
    /// checkpoint's own pipeline, from the vectors, token ids and media that
    /// `tools/gguf-export/embed_reference.py` wrote: text, pictures (PNG,
    /// JPEG, alpha, one past the pipeline's size limit), a picture with text,
    /// and videos given as frames (one sampled down to the pipeline's frame
    /// count). Each input is embedded alone, then the inputs of one role in
    /// one request. Needs `TENZRO_VL_GGUF`, `TENZRO_VL_MMPROJ` and
    /// `TENZRO_VL_EXPECTED`.
    #[cfg(feature = "mtmd")]
    #[tokio::test]
    #[ignore = "needs the embedder weights and reference: TENZRO_VL_GGUF, TENZRO_VL_MMPROJ and TENZRO_VL_EXPECTED"]
    async fn a_vision_language_embedder_matches_its_source_checkpoint() {
        let (Ok(gguf), Ok(mmproj), Ok(expected)) = (
            std::env::var("TENZRO_VL_GGUF"),
            std::env::var("TENZRO_VL_MMPROJ"),
            std::env::var("TENZRO_VL_EXPECTED"),
        ) else {
            panic!(
                "TENZRO_VL_GGUF, TENZRO_VL_MMPROJ and TENZRO_VL_EXPECTED must name the embedder, its projector and the reference"
            );
        };
        crate::seeded_catalog();
        let entry = crate::catalog::get_embed_model_by_id("qwen3-vl-embedding-2b").unwrap();
        let spec = entry.vision_input.clone().unwrap();
        let expected = std::path::PathBuf::from(expected);
        let exp: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&expected).unwrap()).unwrap();
        let reference: crate::catalog::VisionPreprocess =
            serde_json::from_value(exp["spec"].clone()).unwrap();
        assert_eq!(
            reference, spec,
            "the catalog sizes pictures as the pipeline does"
        );
        let media = expected.with_file_name(format!(
            "{}-media",
            expected.file_stem().unwrap().to_str().unwrap()
        ));
        let rt = TextEmbeddingRuntime::new();
        let projector = crate::projector::ProjectorFile {
            path: std::path::Path::new(&mmproj),
            input: &spec,
        };
        rt.load_praecise(
            "vl",
            std::path::Path::new(&gguf),
            Some(projector),
            entry.embedding_template.clone(),
            entry.embedding_dim as usize,
            entry.max_sequence_length as usize,
        )
        .unwrap();
        let read = |f: &serde_json::Value| std::fs::read(media.join(f.as_str().unwrap())).unwrap();
        let cos = |a: &[f32], b: &[f32]| a.iter().zip(b).map(|(x, y)| x * y).sum::<f32>();
        let role_of = |name: &str| {
            if name == "query" {
                EmbedRole::Query { task: None }
            } else {
                EmbedRole::Document { title: None }
            }
        };
        let mut worst = 1f32;
        let mut by_role: std::collections::BTreeMap<String, (Vec<EmbedInput>, Vec<Vec<f32>>)> =
            Default::default();
        for case in exp["cases"].as_array().unwrap() {
            let input = EmbedInput {
                text: case["text"].as_str().map(str::to_string),
                image: case.get("image").map(read),
                video: case
                    .get("video")
                    .map(|v| v.as_array().unwrap().iter().map(read).collect()),
            };
            let role_name = case["role"].as_str().unwrap().to_string();
            let want: Vec<f32> = serde_json::from_value(case["embedding"].clone()).unwrap();
            let cfg = TextEmbedConfig {
                role: role_of(&role_name),
                ..Default::default()
            };
            let got = rt.embed("vl", vec![input.clone()], cfg).await.unwrap();
            let c = cos(&got.embeddings[0], &want);
            let tokens = case["input_ids"].as_array().unwrap().len() as u32;
            eprintln!(
                "{role_name} {}: cosine {c:.7}, tokens {} (reference {tokens})",
                case.get("image")
                    .or(case.get("text"))
                    .map(|v| v.to_string())
                    .unwrap_or_default(),
                got.prompt_tokens
            );
            assert_eq!(got.prompt_tokens, tokens, "token count");
            worst = worst.min(c);
            let entry = by_role.entry(role_name).or_default();
            entry.0.push(input);
            entry.1.push(want);
        }
        for (role_name, (inputs, wants)) in by_role {
            let cfg = TextEmbedConfig {
                role: role_of(&role_name),
                ..Default::default()
            };
            let got = rt.embed("vl", inputs, cfg).await.unwrap();
            for (g, w) in got.embeddings.iter().zip(&wants) {
                worst = worst.min(cos(g, w));
            }
            eprintln!(
                "{role_name} batch of {}: worst so far {worst:.7}",
                wants.len()
            );
        }
        let peak = std::fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|s| {
                s.lines()
                    .find(|l| l.starts_with("VmHWM:"))
                    .map(str::to_string)
            });
        eprintln!("worst cosine {worst:.7}; peak resident {peak:?}");
        assert!(worst >= 0.9999, "worst cosine {worst}");
    }

    #[tokio::test]
    async fn runtime_dispatches_to_registered_model() {
        let rt = TextEmbeddingRuntime::new();
        rt.register("k", Arc::new(ConstantEncoder { dim: 4, value: 1.0 }))
            .unwrap();
        let r = rt
            .embed(
                "k",
                vec!["a".into(), "b".into()],
                TextEmbedConfig::default(),
            )
            .await
            .unwrap();
        assert_eq!(r.dim, 4);
        assert_eq!(r.embeddings.len(), 2);
        assert_eq!(r.embeddings[0], vec![1.0; 4]);
    }

    #[tokio::test]
    async fn matryoshka_truncates_and_renormalizes() {
        let rt = TextEmbeddingRuntime::new();
        rt.register("k", Arc::new(ConstantEncoder { dim: 8, value: 2.0 }))
            .unwrap();
        let cfg = TextEmbedConfig {
            requested_dim: Some(4),
            normalize: false,
            role: EmbedRole::default(),
        };
        let r = rt.embed("k", vec!["x".into()], cfg).await.unwrap();
        assert_eq!(r.dim, 4);
        assert_eq!(r.embeddings[0].len(), 4);
        let n: f32 = r.embeddings[0].iter().map(|v| v * v).sum::<f32>().sqrt();
        assert!(
            (n - 1.0).abs() < 1e-6,
            "expected unit norm after MRL, got {}",
            n
        );
    }
}
