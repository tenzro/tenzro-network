//! Pooled embedders on the Praecise engine.
//!
//! A decoder embedder in GGUF form runs in the node process on the Praecise
//! engine, on the same llama.cpp backend and device as every other model this
//! node serves. Each input is written into the checkpoint's own chat
//! template, with the instruction as the system turn, decoded on its own in a
//! fresh sequence and pooled at its last position, so its vector does not
//! depend on what else the request carried. A vision-language embedder loads
//! with its projector, and an input may then carry text, a picture and a
//! video (as frames) together, laid out as the checkpoint's own pipeline lays
//! them out ([`crate::projector::media_input`]).
//!
//! Vectors are the checkpoint's own: always unit length, cut to the
//! requested dimensions and normalised again.

use std::path::Path;
use std::time::Instant;

use llama_cpp_2::model::LlamaModel;
use llama_cpp_2::model::params::LlamaModelParams;
use praecise_runtime::embed::{EMPTY_INPUT, EmbedOptions, Embedding, embed};

use crate::catalog::EmbeddingTemplate;
use crate::error::{ModelError, Result};
use crate::projector::ProjectorFile;
#[cfg(feature = "mtmd")]
use crate::projector::{Projector, media_input};
use crate::text_embedding_runtime::{
    EmbedInput, TextEmbedConfig, TextEmbedResult, TextEncoder, chat_instruction,
};

/// A loaded embedder.
pub struct PraeciseEmbedder {
    /// Declared ahead of `model`: the projector is dropped first.
    #[cfg(feature = "mtmd")]
    vision: Option<Projector>,
    model: LlamaModel,
    template: EmbeddingTemplate,
    embedding_dim: usize,
    max_sequence_length: usize,
}

impl PraeciseEmbedder {
    /// Load the embedder in `gguf`, every layer on the device, with its
    /// projector when it is a vision-language embedder. Blocking: call from a
    /// blocking thread.
    ///
    /// # Errors
    /// [`ModelError::InvalidModel`] when the template is not one the engine
    /// writes, the file's width is not `embedding_dim`, or the backend
    /// refuses either file.
    pub fn load(
        model_id: &str,
        gguf: &Path,
        projector: Option<ProjectorFile<'_>>,
        template: EmbeddingTemplate,
        embedding_dim: usize,
        max_sequence_length: usize,
    ) -> Result<Self> {
        if !matches!(template, EmbeddingTemplate::ChatInstruct { .. }) {
            return Err(ModelError::InvalidModel(format!(
                "{model_id}: the engine takes its instruction through the chat template (chat-instruct)"
            )));
        }
        let backend = crate::runtime::llama_backend();
        let params = LlamaModelParams::default().with_n_gpu_layers(1000);
        let model = crate::parse_jail::load_llama(&backend, gguf, &params)
            .map_err(|e| ModelError::InvalidModel(format!("embedder {model_id}: {e}")))?;
        let width = usize::try_from(model.n_embd()).unwrap_or(0);
        if width != embedding_dim {
            return Err(ModelError::InvalidModel(format!(
                "{model_id}: the file is {width} wide, the catalog says {embedding_dim}"
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
        Ok(Self {
            #[cfg(feature = "mtmd")]
            vision,
            model,
            template,
            embedding_dim,
            max_sequence_length,
        })
    }

    fn pooled(
        &self,
        inputs: &[EmbedInput],
        instruction: &str,
        options: EmbedOptions,
    ) -> Result<Vec<Embedding>> {
        let backend = crate::runtime::llama_backend();
        let engine = |e: praecise_runtime::error::Error| ModelError::InferenceError(e.to_string());
        #[cfg(feature = "mtmd")]
        if let Some(vision) = &self.vision {
            let marker = llama_cpp_2::mtmd::mtmd_default_marker();
            let media = inputs
                .iter()
                .map(|i| media_input(i, &vision.input, marker, true))
                .collect::<Result<Vec<_>>>()?;
            let projector = vision
                .context
                .lock()
                .map_err(|_| ModelError::InferenceError("the projector lock is poisoned".into()))?;
            return praecise_runtime::embed::embed_media(
                &backend,
                &self.model,
                &projector,
                instruction,
                &media,
                options,
            )
            .map_err(engine);
        }
        if inputs.iter().any(EmbedInput::has_media) {
            return Err(ModelError::InvalidInput(
                "this model embeds text only; pictures and video need a vision-language embedder"
                    .to_string(),
            ));
        }
        let texts: Vec<&str> = inputs
            .iter()
            .map(|i| {
                i.text
                    .as_deref()
                    .filter(|t| !t.is_empty())
                    .unwrap_or(EMPTY_INPUT)
            })
            .collect();
        embed(&backend, &self.model, instruction, &texts, options).map_err(engine)
    }
}

impl TextEncoder for PraeciseEmbedder {
    fn embed(
        &self,
        inputs: &[EmbedInput],
        config: &TextEmbedConfig,
    ) -> praecise_onnx::Result<TextEmbedResult> {
        let start = Instant::now();
        let dimensions = match config.requested_dim.map(|d| d as usize) {
            Some(d) if d == 0 || d > self.embedding_dim => {
                return Err(praecise_onnx::Error::InvalidInput(format!(
                    "requested_dim {d} is outside 1..={}",
                    self.embedding_dim
                )));
            }
            other => other,
        };
        if inputs.is_empty() {
            return Ok(TextEmbedResult {
                embeddings: vec![],
                dim: dimensions.unwrap_or(self.embedding_dim),
                prompt_tokens: 0,
                generation_time_ms: 0,
            });
        }
        let instruction = chat_instruction(&self.template, &config.role).ok_or_else(|| {
            praecise_onnx::Error::InvalidModel("the embedder has no chat instruction".into())
        })?;
        let options = EmbedOptions {
            n_ctx: u32::try_from(self.max_sequence_length).unwrap_or(u32::MAX),
            dimensions,
            ..EmbedOptions::default()
        };
        let mut pooled = self.pooled(inputs, instruction, options)?;
        pooled.sort_by_key(|e| e.index);
        let prompt_tokens = pooled.iter().map(|e| e.tokens).sum::<usize>();
        Ok(TextEmbedResult {
            dim: dimensions.unwrap_or(self.embedding_dim),
            embeddings: pooled.into_iter().map(|e| e.vector).collect(),
            prompt_tokens: u32::try_from(prompt_tokens).unwrap_or(u32::MAX),
            generation_time_ms: u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX),
        })
    }

    fn embedding_dim(&self) -> usize {
        self.embedding_dim
    }

    fn max_sequence_length(&self) -> usize {
        self.max_sequence_length
    }
}
