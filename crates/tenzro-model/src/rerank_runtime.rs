//! Rerankers.
//!
//! A reranker is a cross-encoder in GGUF form that scores how well each
//! document answers a query. It runs in the node process on the Praecise
//! engine, on the same llama.cpp backend and device as every other model this
//! node serves, and is claimed and admitted through the node's
//! [`ModelHost`] like them. Every (query, document) pair is scored on its
//! own, so a pair's score does not depend on what else the request carried
//! and any node holding the same weights reproduces it.
//!
//! A vision-language reranker loads with its projector, and then either side
//! of a pair may carry text, a picture and a video (as frames), in the same
//! input shape the embedders take ([`EmbedInput`]). Pictures and frames are
//! sized exactly as the checkpoint's own pipeline sizes them
//! ([`crate::vision_input`]) and laid out in the pair the way its own
//! pipeline lays them out: the video, then the picture, then the text.

use std::path::Path;
use std::sync::Arc;

use llama_cpp_2::model::LlamaModel;
use llama_cpp_2::model::params::LlamaModelParams;
use praecise_runtime::rerank::{RerankOptions, rerank};

use crate::error::{ModelError, Result};
use crate::model_host::{Engine, EngineModels, ModelHost};
pub use crate::projector::ProjectorFile;
#[cfg(feature = "mtmd")]
use crate::projector::{Projector, media_input};
use crate::text_embedding_runtime::EmbedInput;

/// Largest number of documents one request may score.
pub const MAX_RERANK_DOCUMENTS: usize = 1_000;

/// A loaded reranker.
pub struct RerankModel {
    /// Declared ahead of `model`: the projector is dropped first.
    #[cfg(feature = "mtmd")]
    vision: Option<Projector>,
    model: LlamaModel,
}

/// One document's score.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DocumentScore {
    /// The document's position in the request.
    pub index: usize,
    /// The model's relevance score.
    pub score: f32,
    /// Tokens the (query, document) pair took.
    pub tokens: usize,
}

/// Rerankers loaded on this node.
pub struct RerankRuntime {
    models: EngineModels<RerankModel>,
}

impl std::fmt::Debug for RerankRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RerankRuntime")
            .field("loaded", &self.loaded())
            .finish()
    }
}

impl Default for RerankRuntime {
    fn default() -> Self {
        Self::with_host(Arc::default())
    }
}

impl RerankRuntime {
    /// A runtime that claims models and admits requests through `host`.
    pub fn with_host(host: Arc<ModelHost>) -> Self {
        Self {
            models: EngineModels::new(Engine::PraeciseTask("rerank"), host),
        }
    }

    /// Load the reranker in `gguf` as `model_id`, every layer on the device,
    /// with its projector when it is a vision-language reranker. Blocking:
    /// call from a blocking thread.
    ///
    /// # Errors
    /// [`ModelError::EngineConflict`] when another engine holds the model id,
    /// or the backend's refusal to load either file.
    pub fn load(
        &self,
        model_id: &str,
        gguf: &Path,
        projector: Option<ProjectorFile<'_>>,
    ) -> Result<()> {
        let mut bytes = std::fs::metadata(gguf)?.len();
        if let Some(p) = &projector {
            bytes += std::fs::metadata(p.path)?.len();
        }
        self.models.load_reserving(model_id, bytes, || {
            let backend = crate::runtime::llama_backend();
            let params = LlamaModelParams::default().with_n_gpu_layers(1000);
            let model = crate::parse_jail::load_llama(&backend, gguf, &params)
                .map_err(|e| ModelError::InvalidModel(format!("reranker {model_id}: {e}")))?;
            if model.n_cls_out() == 0 {
                return Err(ModelError::InvalidModel(format!(
                    "{model_id} has no classification head; it is not a reranker"
                )));
            }
            #[cfg(feature = "mtmd")]
            let vision = projector
                .map(|p| crate::projector::load(model_id, &model, p))
                .transpose()?;
            #[cfg(not(feature = "mtmd"))]
            if projector.is_some() {
                return Err(ModelError::InvalidModel(format!(
                    "{model_id} needs its projector, and this build has no multimodal support"
                )));
            }
            Ok(Arc::new(RerankModel {
                #[cfg(feature = "mtmd")]
                vision,
                model,
            }))
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

    /// Score every document against `query`, after the caller's access check
    /// and a slot from the node's admission. Either side may carry pictures
    /// and video when the model was loaded with its projector.
    ///
    /// # Errors
    /// [`ModelError::AccessDenied`] or [`ModelError::Busy`] from the shared
    /// path, [`ModelError::ModelNotFound`] when the model is not loaded,
    /// [`ModelError::InferenceError`] for an empty or oversized request,
    /// [`ModelError::InvalidInput`] for media a text-only reranker cannot
    /// read or a picture that cannot be decoded, or the engine's refusal.
    pub async fn rerank(
        &self,
        model_id: &str,
        query: EmbedInput,
        documents: Vec<EmbedInput>,
    ) -> Result<Vec<DocumentScore>> {
        if documents.is_empty() || documents.len() > MAX_RERANK_DOCUMENTS {
            return Err(ModelError::InferenceError(format!(
                "a rerank request carries 1 to {MAX_RERANK_DOCUMENTS} documents"
            )));
        }
        let id = model_id.to_string();
        self.models
            .run(model_id, move |m| {
                let backend = crate::runtime::llama_backend();
                #[cfg(feature = "mtmd")]
                if let Some(vision) = &m.vision {
                    return rerank_with_media(&backend, &m.model, vision, &query, &documents);
                }
                let text = |side: &EmbedInput| -> Result<String> {
                    if side.has_media() {
                        return Err(ModelError::InvalidInput(format!(
                            "{id} is a text reranker: it reads no pictures or video"
                        )));
                    }
                    Ok(side
                        .text
                        .clone()
                        .unwrap_or_else(|| praecise_runtime::embed::EMPTY_INPUT.to_string()))
                };
                let query = text(&query)?;
                let documents = documents.iter().map(text).collect::<Result<Vec<_>>>()?;
                let docs: Vec<&str> = documents.iter().map(String::as_str).collect();
                let scores = rerank(&backend, &m.model, &query, &docs, RerankOptions::default())
                    .map_err(|e| ModelError::InferenceError(e.to_string()))?;
                Ok(scores.into_iter().map(DocumentScore::from).collect())
            })
            .await
    }
}

impl From<praecise_runtime::rerank::RerankScore> for DocumentScore {
    fn from(s: praecise_runtime::rerank::RerankScore) -> Self {
        Self {
            index: s.index,
            score: s.score,
            tokens: s.tokens,
        }
    }
}

#[cfg(feature = "mtmd")]
fn rerank_with_media(
    backend: &llama_cpp_2::llama_backend::LlamaBackend,
    model: &LlamaModel,
    vision: &Projector,
    query: &EmbedInput,
    documents: &[EmbedInput],
) -> Result<Vec<DocumentScore>> {
    let marker = llama_cpp_2::mtmd::mtmd_default_marker();
    let query = media_input(query, &vision.input, marker, false)?;
    let documents = documents
        .iter()
        .map(|d| media_input(d, &vision.input, marker, false))
        .collect::<Result<Vec<_>>>()?;
    let options = RerankOptions {
        n_ctx: model.n_ctx_train(),
        ..RerankOptions::default()
    };
    let projector = vision
        .context
        .lock()
        .map_err(|_| ModelError::InferenceError("the projector lock is poisoned".into()))?;
    let scores = praecise_runtime::rerank::rerank_media(
        backend, model, &projector, &query, &documents, options,
    )
    .map_err(|e| ModelError::InferenceError(e.to_string()))?;
    Ok(scores.into_iter().map(DocumentScore::from).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn reranking_with_a_model_that_is_not_loaded_is_refused() {
        let rt = RerankRuntime::default();
        let r = rt.rerank("absent", "q".into(), vec!["d".into()]).await;
        assert!(matches!(r, Err(ModelError::ModelNotFound(_))), "{r:?}");
    }

    #[tokio::test]
    async fn an_empty_or_oversized_request_is_refused_before_any_work() {
        let rt = RerankRuntime::default();
        let empty = rt.rerank("absent", "q".into(), vec![]).await;
        assert!(
            matches!(empty, Err(ModelError::InferenceError(_))),
            "{empty:?}"
        );
        let many = vec![EmbedInput::default(); MAX_RERANK_DOCUMENTS + 1];
        let over = rt.rerank("absent", "q".into(), many).await;
        assert!(
            matches!(over, Err(ModelError::InferenceError(_))),
            "{over:?}"
        );
    }

    /// Scores from the quantized GGUF against the source checkpoint's P(yes)
    /// (softmax over the "yes" and "no" logits) on the same prompt, written by
    /// the reference script: every probability within the quantization's
    /// noise and the ranking identical.
    #[tokio::test]
    async fn a_reranker_matches_its_source_checkpoint() {
        let (Ok(gguf), Ok(expected)) = (
            std::env::var("TENZRO_RERANK_GGUF"),
            std::env::var("TENZRO_RERANK_EXPECTED"),
        ) else {
            return;
        };
        let exp: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(expected).unwrap()).unwrap();
        let query = EmbedInput::text(exp["query"].as_str().unwrap());
        let documents: Vec<String> = serde_json::from_value(exp["documents"].clone()).unwrap();
        let documents: Vec<EmbedInput> = documents.into_iter().map(EmbedInput::from).collect();
        let want: Vec<f32> = serde_json::from_value(exp["p_yes"].clone()).unwrap();
        let rt = RerankRuntime::default();
        rt.load("parity", std::path::Path::new(&gguf), None)
            .unwrap();
        let mut got = rt.rerank("parity", query, documents).await.unwrap();
        got.sort_by_key(|s| s.index);
        let mut worst = 0f32;
        for (g, w) in got.iter().zip(&want) {
            worst = worst.max((g.score - w).abs());
        }
        let order = |v: &[f32]| {
            let mut i: Vec<usize> = (0..v.len()).collect();
            i.sort_by(|a, b| v[*b].total_cmp(&v[*a]));
            i
        };
        let scores: Vec<f32> = got.iter().map(|s| s.score).collect();
        assert_eq!(
            order(&scores),
            order(&want),
            "ranking differs: {scores:?} vs {want:?}"
        );
        assert!(
            worst < 0.05,
            "max P(yes) error {worst}: {scores:?} vs {want:?}"
        );
    }

    /// Pictures and video end to end against the checkpoint's own pipeline,
    /// from the reference script's sources: every pair side is written and
    /// sized as the pipeline wrote and sized it, and every P(yes) is within
    /// 1e-2 of the pipeline's.
    #[cfg(feature = "mtmd")]
    #[tokio::test]
    async fn a_vision_language_reranker_matches_its_source_checkpoint() {
        let (Ok(gguf), Ok(mmproj), Ok(dir)) = (
            std::env::var("TENZRO_VLRR_GGUF"),
            std::env::var("TENZRO_VLRR_MMPROJ"),
            std::env::var("TENZRO_VLRR_MEDIA"),
        ) else {
            return;
        };
        let dir = std::path::PathBuf::from(dir);
        let exp: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(dir.join("expected.json")).unwrap())
                .unwrap();
        crate::seeded_catalog();
        let entry = crate::catalog::get_rerank_model_by_id("qwen3-vl-reranker-2b").unwrap();
        let spec = entry.vision_input.clone().unwrap();
        let marker = llama_cpp_2::mtmd::mtmd_default_marker();
        let read = |name: &str| std::fs::read(dir.join(name)).unwrap();
        let input = |side: &serde_json::Value| {
            let src = &side["source"];
            EmbedInput {
                text: src["text"].as_str().map(str::to_string),
                image: src["image"].as_str().map(read),
                video: src["video"]
                    .as_array()
                    .map(|v| v.iter().map(|f| read(f.as_str().unwrap())).collect()),
            }
        };
        let mut worst_pixel = 0u8;
        let mut check_side = |side: &serde_json::Value| {
            let got = media_input(&input(side), &spec, marker, false).unwrap();
            assert_eq!(got.text, side["text"].as_str().unwrap(), "pair side text");
            let want = side["pictures"].as_array().unwrap();
            assert_eq!(got.pictures.len(), want.len(), "picture count");
            for (g, w) in got.pictures.iter().zip(want) {
                assert_eq!(
                    u64::from(g.width),
                    w["width"].as_u64().unwrap(),
                    "picture width"
                );
                assert_eq!(
                    u64::from(g.height),
                    w["height"].as_u64().unwrap(),
                    "picture height"
                );
                assert_eq!(g.video_frame, w["video_frame"].as_bool().unwrap());
                let pixels = read(w["file"].as_str().unwrap());
                let d = g
                    .rgb
                    .iter()
                    .zip(&pixels)
                    .map(|(a, b)| a.abs_diff(*b))
                    .max()
                    .unwrap_or(0);
                worst_pixel = worst_pixel.max(d);
            }
        };
        for case in exp["cases"].as_array().unwrap() {
            check_side(&case["query"]);
            for d in case["documents"].as_array().unwrap() {
                check_side(d);
            }
        }
        eprintln!("largest pixel difference from the pipeline: {worst_pixel}");
        assert!(
            worst_pixel <= 1,
            "pixels differ from the pipeline by up to {worst_pixel}"
        );

        let rt = RerankRuntime::default();
        let projector = ProjectorFile {
            path: std::path::Path::new(&mmproj),
            input: &spec,
        };
        rt.load("vl-parity", std::path::Path::new(&gguf), Some(projector))
            .unwrap();
        let mut worst = 0f32;
        for case in exp["cases"].as_array().unwrap() {
            let documents: Vec<EmbedInput> = case["documents"]
                .as_array()
                .unwrap()
                .iter()
                .map(input)
                .collect();
            let want: Vec<f32> = serde_json::from_value(case["p_yes"].clone()).unwrap();
            let tokens: Vec<usize> = serde_json::from_value(case["n_tokens"].clone()).unwrap();
            let mut got = rt
                .rerank("vl-parity", input(&case["query"]), documents)
                .await
                .unwrap();
            got.sort_by_key(|s| s.index);
            for ((g, w), t) in got.iter().zip(&want).zip(&tokens) {
                eprintln!(
                    "{}[{}]: {:.6} vs {:.6}, {} tokens",
                    case["name"], g.index, g.score, w, g.tokens
                );
                assert_eq!(g.tokens, *t, "token count");
                worst = worst.max((g.score - w).abs());
            }
        }
        let peak = std::fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|s| {
                s.lines()
                    .find(|l| l.starts_with("VmHWM:"))
                    .map(str::to_string)
            });
        eprintln!("worst |P(yes) difference| {worst:.6}; peak resident {peak:?}");
        assert!(worst < 1e-2, "worst P(yes) difference {worst}");
    }
}
