//! Media generation.
//!
//! A media model runs in process on the Praecise diffusion engine, on the
//! same ggml backend and device as every other model this node serves. It is
//! claimed and admitted through the node's [`ModelHost`], so a model is loaded
//! once and every request goes through the same access check and queue. A
//! model is loaded from the checkpoint files the catalog pins; on a host with
//! GPU hardware it never runs on the CPU.
//!
//! A unified model that writes images as tokens of its language backbone
//! (Janus-Pro) runs its backbone on llama.cpp and its image head and decoder
//! on the diffusion engine's backend, both on the same device.

use std::io::Cursor;
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use llama_cpp_2::context::params::{KvCacheType, LlamaContextParams, LlamaPoolingType};
use llama_cpp_2::model::params::LlamaModelParams;
use llama_cpp_2::model::{AddBos, LlamaModel};
use llama_cpp_2::token::LlamaToken;
use parking_lot::Mutex;
use praecise_diffusion::flux3::release::{
    PolicyRelease, RawObservation, ReleasedPolicy, frames_from_grid,
};
use praecise_diffusion::janus::{JanusImageHead, JanusVqDecoder};
use praecise_diffusion::trellis2::RgbaImage;
use praecise_diffusion::wan_video::Wan22;
use praecise_diffusion::{
    AceStep, ActionMode, ActionRequest, CheckpointFiles, Cosmos3, Flux2Klein, H3Condition,
    H3Partition, H3Request, LoadOptions, Ltx2Pipeline, Ltx2Request, MAX_REFERENCE_PIXELS,
    MatrixGame, MiniMaxH3Pipeline, MusicRequest, Precision, QwenImage21, QwenImageEdit, Request,
    Request3d, RgbImage, SessionConfig, Timings, Trellis2, Trellis2Files, Trellis2Path, Video,
    VideoRequest, WorldModel, WorldSession, ZImage, action_resolution_tier,
};
use praecise_runtime::image_gen::{JanusRequest, TokenSampling, generate_janus, unconditioned};
use tenzro_types::{MediaGenExpertRole, MediaGenInputRole, MediaGenKind, MediaGenParams};

use crate::error::{ModelError, Result};
use crate::model_host::{Engine, EngineModels, ModelHost};

/// What a load reports back.
#[derive(Debug, Clone, serde::Serialize)]
pub struct MediaModelInfo {
    /// Catalog model id.
    pub model_id: String,
    /// The backend device the model runs on.
    pub device: String,
    /// Device bytes held by the weights, when the engine reports them.
    pub resident_bytes: u64,
    /// Whether guidance has no effect (step-distilled checkpoint).
    pub distilled: bool,
}

/// One finished render.
#[derive(Debug, Clone)]
pub struct Rendered {
    /// Encoded output.
    pub bytes: Vec<u8>,
    /// IANA media type of `bytes`.
    pub mime: String,
    /// Seed the starting noise was drawn from.
    pub seed: u64,
    /// Wall-clock milliseconds spent generating.
    pub generation_ms: u64,
}

/// The intermediate latent a high-noise expert hands to its low-noise
/// partner.
#[derive(Debug, Clone)]
pub struct Latent {
    /// Serialised latent.
    pub bytes: Vec<u8>,
    /// Steps of the schedule already run.
    pub steps_completed: u32,
}

/// What a render produced.
#[derive(Debug, Clone)]
pub enum Output {
    /// A finished output.
    Media(Rendered),
    /// A latent to hand over (the high-noise half of a split schedule).
    Latent(Latent),
}

/// Refuses an input whose role this pipeline does not read, so no signed
/// input is silently ignored.
fn only_roles(
    id: &str,
    inputs: &[(MediaGenInputRole, Vec<u8>)],
    used: &[MediaGenInputRole],
) -> Result<()> {
    match inputs.iter().find(|(r, _)| !used.contains(r)) {
        Some((role, _)) => Err(ModelError::InvalidModel(format!(
            "{id} does not read a {role} input"
        ))),
        None => Ok(()),
    }
}

/// The bytes of the job's input in `role`, for roles a job carries at most once.
fn input_of(inputs: &[(MediaGenInputRole, Vec<u8>)], role: MediaGenInputRole) -> Option<&[u8]> {
    inputs
        .iter()
        .find(|(r, _)| *r == role)
        .map(|(_, b)| b.as_slice())
}

/// The images an image edit conditions on: every edit source and reference,
/// in the job's order. A mask is refused: no served pipeline inpaints.
fn edit_images(
    id: &str,
    kind: MediaGenKind,
    inputs: &[(MediaGenInputRole, Vec<u8>)],
) -> Result<Vec<RgbImage>> {
    only_roles(
        id,
        inputs,
        &[MediaGenInputRole::EditSource, MediaGenInputRole::Reference],
    )?;
    let images = inputs
        .iter()
        .map(|(_, b)| prepare_reference(b))
        .collect::<Result<Vec<_>>>()?;
    if kind == MediaGenKind::Image2Image && images.is_empty() {
        return Err(ModelError::InvalidModel(format!(
            "{kind} on {id} needs an edit_source or reference input"
        )));
    }
    Ok(images)
}

/// The one observation an action policy acts on.
fn observation<'a>(
    id: &str,
    kind: MediaGenKind,
    inputs: &'a [(MediaGenInputRole, Vec<u8>)],
) -> Result<&'a [u8]> {
    only_roles(id, inputs, &[MediaGenInputRole::Observation])?;
    input_of(inputs, MediaGenInputRole::Observation).ok_or_else(|| {
        ModelError::InvalidModel(format!("{kind} on {id} needs an observation input"))
    })
}

/// How many checkpoint directories `pipeline_class` loads from. A pipeline
/// that reads one gets a single directory even when its entry's files come
/// from several sources (the node assembles them into one).
pub fn source_directories(pipeline_class: &str) -> usize {
    if matches!(
        pipeline_class,
        "LTX2Pipeline" | "Flux3ActionPipeline" | "MatrixGame3I2VPipeline" | "JanusProPipeline"
    ) {
        2
    } else {
        1
    }
}

/// One job, or one expert's half of a split job.
#[derive(Debug, Clone)]
pub struct RenderJob {
    /// Job id.
    pub job_id: String,
    /// Job kind.
    pub kind: MediaGenKind,
    /// Generation parameters.
    pub params: MediaGenParams,
    /// Seed for the starting noise.
    pub seed: u64,
    /// The requester's address, which scopes caches of prompt encodings.
    pub requester: [u8; 32],
    /// The job's inputs in the job's order, each with the role the requester
    /// signed for it.
    pub inputs: Vec<(MediaGenInputRole, Vec<u8>)>,
    /// Which expert's half to run; `None` runs the whole schedule.
    pub role: Option<MediaGenExpertRole>,
    /// The handed-over latent, for the low-noise half.
    pub inbound_latent: Option<Vec<u8>>,
}

/// One loaded native media model.
struct NativeModel {
    info: MediaModelInfo,
    pipeline: Mutex<Pipeline>,
}

/// A loaded native pipeline, one variant per ported pipeline class.
enum Pipeline {
    Flux2(Flux2Klein),
    ZImage(ZImage),
    AceStep(AceStep),
    Cosmos3(Cosmos3),
    Ltx2(Ltx2Pipeline),
    MiniMaxH3(Box<MiniMaxH3Pipeline>),
    QwenEdit(QwenImageEdit),
    Qwen21(QwenImage21),
    Flux3Action(Box<ReleasedPolicy>),
    Wan22(Wan22),
    MatrixGame(MatrixGame),
    Janus(Box<Janus>),
    Trellis2(Box<Trellis2>),
}

/// The MIME type of a binary glTF asset.
pub const GLB_MIME: &str = "model/gltf-binary";

/// Janus-Pro: a language backbone that predicts image tokens, its image head
/// and embedder, and the VQ decoder that turns a token grid into pixels.
struct Janus {
    model: LlamaModel,
    head: JanusImageHead,
    decoder: JanusVqDecoder,
    bos: LlamaToken,
    pad: LlamaToken,
    boi: LlamaToken,
}

// SAFETY: the head's tensor handles point into the graphs the head owns, on
// the backend it owns; nothing else holds them, and the pipeline mutex keeps
// every use of the model on one thread at a time.
unsafe impl Send for Janus {}

impl Janus {
    /// The backbone from `gguf`, the head and decoder from the checkpoint
    /// directory, and the backend device's name.
    fn load(
        checkpoint: &Path,
        gguf: &Path,
        opts: LoadOptions,
    ) -> std::result::Result<(Self, String), String> {
        let config: serde_json::Value = std::fs::read(checkpoint.join("generation_config.json"))
            .map_err(|e| format!("generation_config.json: {e}"))
            .and_then(|b| serde_json::from_slice(&b).map_err(|e| e.to_string()))?;
        let token = |v: Option<&serde_json::Value>, name: &str| {
            v.and_then(serde_json::Value::as_i64)
                .and_then(|t| i32::try_from(t).ok())
                .map(LlamaToken)
                .ok_or_else(|| format!("generation_config.json names no {name}"))
        };
        let bos = token(config.get("bos_token_id"), "bos_token_id")?;
        let pad = token(config.get("pad_token_id"), "pad_token_id")?;
        let boi = token(
            config.pointer("/generation_kwargs/boi_token_id"),
            "generation_kwargs.boi_token_id",
        )?;
        // The head runs in f32 like the reference; it is a small share of
        // the weights. Two rows per call: the prompt and its unconditioned copy.
        let backend = opts.backend().map_err(|e| e.to_string())?;
        let device = backend.name().to_string();
        let head = JanusImageHead::load(checkpoint, backend, Precision::F32, 2)
            .map_err(|e| format!("image head: {e}"))?;
        let decoder =
            JanusVqDecoder::load(checkpoint, opts.backend().map_err(|e| e.to_string())?, true)
                .map_err(|e| format!("VQ decoder: {e}"))?;
        let model = crate::parse_jail::load_llama(
            &crate::runtime::llama_backend(),
            gguf,
            &LlamaModelParams::default(),
        )
        .map_err(|e| format!("backbone {}: {e}", gguf.display()))?;
        Ok((
            Self {
                model,
                head,
                decoder,
                bos,
                pad,
                boi,
            },
            device,
        ))
    }

    fn resident_bytes(&self) -> usize {
        self.model.size() as usize + self.head.bytes()
    }

    /// One image for `prompt` under guidance `scale`, sampled from `seed`:
    /// interleaved 8-bit RGB and its side.
    fn generate(&mut self, prompt: &str, scale: f32, seed: u64) -> Result<(Vec<u8>, u32)> {
        let (bos, pad, boi) = (self.bos, self.pad, self.boi);
        let Self {
            model,
            head,
            decoder,
            ..
        } = self;
        let failed = |what: &str, e: &dyn std::fmt::Display| {
            ModelError::InferenceError(format!("{what}: {e}"))
        };
        // The checkpoint's chat template for one user turn, then the
        // begin-of-image token that opens the image.
        let text = format!(
            "<|User|>: {}\n\n<|Assistant|>:<begin_of_image>",
            prompt.trim()
        );
        let mut cond = vec![bos];
        cond.extend(
            model
                .str_to_token(&text, AddBos::Never)
                .map_err(|e| failed("prompt", &e))?,
        );
        if cond.last() != Some(&boi) {
            return Err(ModelError::InvalidModel(
                "the backbone's vocabulary does not hold the begin-of-image token".into(),
            ));
        }
        let uncond = unconditioned(&cond, &[bos, boi], pad);
        let n = (cond.len() + head.config().tokens_per_image() + 16) as u32;
        // Attention stays in f32, as the reference keeps it.
        let params = LlamaContextParams::default()
            .with_n_ctx(NonZeroU32::new(2 * n))
            .with_n_batch(2 * n)
            .with_n_ubatch(2 * n)
            .with_n_seq_max(2)
            .with_embeddings(true)
            .with_pooling_type(LlamaPoolingType::None)
            .with_type_k(KvCacheType::F32)
            .with_type_v(KvCacheType::F32)
            .with_flash_attention(false);
        let mut ctx = model
            .new_context(&crate::runtime::llama_backend(), params)
            .map_err(|e| failed("context", &e))?;
        let req = JanusRequest {
            cond: &cond,
            uncond: Some(&uncond),
            sampling: TokenSampling {
                guidance_scale: scale,
                seed,
                ..TokenSampling::default()
            },
            forced: None,
            keep_logits: false,
        };
        let image =
            generate_janus(&mut ctx, head, decoder, &req).map_err(|e| failed("render", &e))?;
        Ok((planar_to_rgb(&image.pixels, image.side), image.side as u32))
    }
}

/// Planar RGB `[3, side, side]` in `[-1, 1]` as interleaved 8-bit RGB, scaled
/// and clipped as the reference does.
fn planar_to_rgb(pixels: &[f32], side: usize) -> Vec<u8> {
    let plane = side * side;
    (0..plane)
        .flat_map(|i| {
            (0..3)
                .map(move |c| ((pixels[c * plane + i] + 1.0) / 2.0 * 255.0).clamp(0.0, 255.0) as u8)
        })
        .collect()
}

/// Media models loaded on this node.
pub struct MediaRuntime {
    native: EngineModels<NativeModel>,
}

impl std::fmt::Debug for MediaRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MediaRuntime")
            .field("loaded", &self.loaded())
            .finish()
    }
}

/// The pipeline classes the native engine runs: the one dispatch slot a
/// ported pipeline plugs into. A catalog entry is `native` only when its
/// `pipeline_class` is here; every other entry is `planned`.
pub const NATIVE_PIPELINES: &[&str] = &[
    "Flux2KleinPipeline",
    "ZImagePipeline",
    "AceStepPipeline",
    "Cosmos3OmniPipeline",
    "LTX2Pipeline",
    "Flux3ActionPipeline",
    "WanPipeline",
    "MatrixGame3I2VPipeline",
    "QwenImageEditPlusPipeline",
    "QwenImage21Pipeline",
    "MiniMaxH3ModularPipeline",
    "JanusProPipeline",
    "Trellis2ImageTo3DPipeline",
];

impl Default for MediaRuntime {
    fn default() -> Self {
        Self::with_host(Arc::default())
    }
}

impl MediaRuntime {
    /// A runtime that claims models and admits requests through `host`.
    pub fn with_host(host: Arc<ModelHost>) -> Self {
        Self {
            native: EngineModels::new(Engine::Diffusion, host),
        }
    }

    /// Load the checkpoint fetched into `dirs`, one directory per source
    /// repository in catalog order (`file_bytes` of weights, reserved in the
    /// node's memory ledger first) as `model_id` on the in-process engine.
    /// Every pipeline reads one directory except LTX-2, which reads the
    /// single-file checkpoint from the first and its text encoder and
    /// tokenizer from the second, a FLUX 3 action policy, which reads the
    /// policy from the first and the base it names from the second, and the
    /// action world model, which reads its world transformer from the first
    /// and the text encoder, tokenizer, autoencoder and scheduler of the
    /// Wan2.2 entry it requires from the second, and Janus-Pro, which reads
    /// its image head and decoder from the first and the language backbone,
    /// the GGUF its entry names, from the second. Blocking: call from a
    /// blocking thread.
    ///
    /// # Errors
    /// [`ModelError::EngineConflict`] when another engine holds the model id,
    /// [`ModelError::InsufficientMemory`] when the node cannot hold it, an
    /// invalid model when the directories do not match the pipeline, or the
    /// engine's load failure (including the refusal to run on the CPU
    /// of a GPU host).
    pub fn load(
        &self,
        model_id: &str,
        pipeline_class: &str,
        dirs: &[PathBuf],
        file_bytes: u64,
        precision: Precision,
    ) -> Result<MediaModelInfo> {
        if !NATIVE_PIPELINES.contains(&pipeline_class) {
            return Err(ModelError::InvalidModel(format!(
                "{model_id}: the native engine has no {pipeline_class} pipeline"
            )));
        }
        let sources = source_directories(pipeline_class);
        if dirs.len() != sources {
            return Err(ModelError::InvalidModel(format!(
                "{model_id}: {pipeline_class} loads from {sources} source directories, got {}",
                dirs.len()
            )));
        }
        let mut info = None;
        self.native.load_reserving(model_id, file_bytes, || {
            let files = CheckpointFiles::new(&dirs[0]);
            let opts = LoadOptions {
                precision,
                ..LoadOptions::default()
            };
            let failed =
                |e: praecise_diffusion::Error| ModelError::InvalidModel(format!("{model_id}: {e}"));
            let (pipeline, device, resident_bytes, distilled) = match pipeline_class {
                "Flux2KleinPipeline" => {
                    let p = Flux2Klein::load(&files, opts).map_err(failed)?;
                    let d = (p.device().to_string(), p.resident_bytes(), p.is_distilled());
                    (Pipeline::Flux2(p), d.0, d.1, d.2)
                }
                "ZImagePipeline" => {
                    let p = ZImage::load(&files, opts).map_err(failed)?;
                    let d = (p.device().to_string(), p.resident_bytes());
                    (Pipeline::ZImage(p), d.0, d.1, false)
                }
                "AceStepPipeline" => {
                    let p = AceStep::load(&files, opts).map_err(failed)?;
                    let d = (p.device().to_string(), p.resident_bytes(), p.is_turbo());
                    (Pipeline::AceStep(p), d.0, d.1, d.2)
                }
                "QwenImageEditPlusPipeline" => {
                    let p = QwenImageEdit::load(&files, opts).map_err(failed)?;
                    let d = (p.device().to_string(), p.resident_bytes());
                    (Pipeline::QwenEdit(p), d.0, d.1, false)
                }
                "QwenImage21Pipeline" => {
                    let p = QwenImage21::load(&files, opts).map_err(failed)?;
                    let d = (p.device().to_string(), p.resident_bytes());
                    (Pipeline::Qwen21(p), d.0, d.1, false)
                }
                "Flux3ActionPipeline" => {
                    let p = PolicyRelease::open(&dirs[0], &dirs[1])
                        .and_then(|r| r.load_policy(opts))
                        .map_err(failed)?;
                    let d = (p.policy().device().to_string(), p.policy().resident_bytes());
                    (Pipeline::Flux3Action(Box::new(p)), d.0, d.1, false)
                }
                "LTX2Pipeline" => {
                    // The source holding `text_encoder/` is the prompt encoder; every
                    // other source holds checkpoint files (the single file, or its
                    // sections split over GGUF and safetensors files, and an
                    // optional latent upsampler).
                    let text = dirs
                        .iter()
                        .find(|d| d.join("text_encoder").is_dir())
                        .ok_or_else(|| {
                            ModelError::InvalidModel(format!(
                                "{model_id}: no source holds text_encoder/"
                            ))
                        })?;
                    let roots: Vec<_> = dirs.iter().filter(|d| *d != text).cloned().collect();
                    let p = Ltx2Pipeline::load_dir(&roots, text, opts).map_err(failed)?;
                    let d = (p.device().to_string(), p.resident_bytes());
                    let distilled = tenzro_catalog::get_media_gen_model_by_id(model_id)
                        .is_some_and(|m| m.distilled);
                    (Pipeline::Ltx2(p), d.0, d.1, distilled)
                }
                "MiniMaxH3ModularPipeline" => {
                    // An entry whose own files are the reference-conditioned
                    // transformer serves reference images; the rest serve
                    // prompts and keyframes.
                    let reference = tenzro_catalog::entry(model_id).is_some_and(|e| {
                        e.components
                            .iter()
                            .any(|c| c.view_path().starts_with("transformer_ref/"))
                    });
                    let partition = if reference {
                        H3Partition::Reference
                    } else {
                        H3Partition::Keyframe
                    };
                    let p = MiniMaxH3Pipeline::load(&files, opts, partition).map_err(failed)?;
                    let d = (p.device().to_string(), p.resident_bytes());
                    (Pipeline::MiniMaxH3(Box::new(p)), d.0, d.1, false)
                }
                "WanPipeline" => {
                    let p = Wan22::load(&files, opts).map_err(failed)?;
                    let d = (p.device().to_string(), p.resident_bytes());
                    (Pipeline::Wan22(p), d.0, d.1, false)
                }
                "MatrixGame3I2VPipeline" => {
                    let p = MatrixGame::load(&files, &CheckpointFiles::new(&dirs[1]), opts)
                        .map_err(failed)?;
                    let d = (p.device().to_string(), p.resident_bytes());
                    (Pipeline::MatrixGame(p), d.0, d.1, false)
                }
                "JanusProPipeline" => {
                    let gguf = tenzro_catalog::get_media_gen_model_by_id(model_id)
                        .and_then(|m| m.gguf_file)
                        .ok_or_else(|| {
                            ModelError::InvalidModel(format!(
                                "{model_id}: the entry names no backbone GGUF"
                            ))
                        })?;
                    let (p, device) = Janus::load(&dirs[0], &dirs[1].join(gguf), opts)
                        .map_err(|e| ModelError::InvalidModel(format!("{model_id}: {e}")))?;
                    let bytes = p.resident_bytes();
                    (Pipeline::Janus(Box::new(p)), device, bytes, false)
                }
                "Trellis2ImageTo3DPipeline" => {
                    let device = opts.backend().map_err(failed)?.name().to_string();
                    let files = Trellis2Files {
                        root: dirs[0].clone(),
                    };
                    let p = Trellis2::load(&files, opts, Trellis2Path::R512).map_err(failed)?;
                    let bytes = p.resident_bytes();
                    (Pipeline::Trellis2(Box::new(p)), device, bytes, false)
                }
                _ => {
                    let p = Cosmos3::load(&files, opts).map_err(failed)?;
                    let d = (p.device().to_string(), p.resident_bytes());
                    (Pipeline::Cosmos3(p), d.0, d.1, false)
                }
            };
            let i = MediaModelInfo {
                model_id: model_id.to_string(),
                device,
                resident_bytes: resident_bytes as u64,
                distilled,
            };
            info = Some(i.clone());
            Ok(Arc::new(NativeModel {
                info: i,
                pipeline: Mutex::new(pipeline),
            }))
        })?;
        Ok(info.expect("set by a successful load"))
    }

    /// Drop a loaded model, giving back its
    /// claim. `false` when it was not loaded.
    pub fn unload(&self, model_id: &str) -> bool {
        self.native.remove(model_id)
    }

    /// Ids of the loaded models.
    #[must_use]
    pub fn loaded(&self) -> Vec<String> {
        let mut ids = self.native.ids();
        ids.sort();
        ids
    }

    /// Load report for a loaded model.
    #[must_use]
    pub fn info(&self, model_id: &str) -> Option<MediaModelInfo> {
        self.native.get(model_id).map(|m| m.info.clone())
    }

    /// Render one job (or one expert's half of it), after the caller's access
    /// check and a slot from the node's admission.
    ///
    /// # Errors
    /// [`ModelError::AccessDenied`] or [`ModelError::Busy`] from the shared
    /// path, [`ModelError::ModelNotFound`] when the model is not loaded,
    /// [`ModelError::InvalidModel`] for a job the model does not serve, or the
    /// engine's failure.
    pub async fn render(&self, model_id: &str, job: RenderJob) -> Result<Output> {
        if self.native.contains(model_id) {
            return self.render_native(model_id, job).await.map(Output::Media);
        }
        Err(ModelError::ModelNotFound(model_id.to_string()))
    }

    async fn render_native(&self, model_id: &str, job: RenderJob) -> Result<Rendered> {
        if job.role.is_some() {
            return Err(ModelError::InvalidModel(format!(
                "{model_id} does not split its schedule"
            )));
        }
        let kind = job.kind;
        let params = job.params;
        let inputs = job.inputs;
        let seed = job.seed;
        let id = model_id.to_string();
        self.native
            .run(model_id, move |m| {
                let mut pipeline = m.pipeline.lock();
                let engine = |e: praecise_diffusion::Error| ModelError::InferenceError(e.to_string());
                let refuse = || ModelError::InvalidModel(format!("{id} does not serve {kind}"));
                match (&mut *pipeline, kind) {
                    (p @ (Pipeline::Flux2(_) | Pipeline::ZImage(_)), MediaGenKind::Text2Image | MediaGenKind::Image2Image) => {
                        if kind == MediaGenKind::Image2Image && matches!(p, Pipeline::ZImage(_)) {
                            return Err(refuse());
                        }
                        let references = edit_images(&id, kind, &inputs)?;
                        let req = Request {
                            prompt: params.prompt.clone(),
                            references,
                            width: params.width,
                            height: params.height,
                            steps: params.steps,
                            guidance_scale: params.guidance_scale,
                            seed,
                        };
                        let image = match p {
                            Pipeline::Flux2(f) => f.generate(&req),
                            Pipeline::ZImage(z) => z.generate(&req),
                            _ => unreachable!("matched above"),
                        }
                        .map_err(engine)?;
                        let t = image.timings;
                        Ok(Rendered {
                            bytes: encode_png(image.width, image.height, image.rgb)?,
                            mime: "image/png".to_string(),
                            seed,
                            generation_ms: t.encode_ms + t.denoise_ms + t.decode_ms,
                        })
                    }
                    (p @ (Pipeline::QwenEdit(_) | Pipeline::Qwen21(_)), MediaGenKind::Text2Image | MediaGenKind::Image2Image) => {
                        if kind == MediaGenKind::Text2Image && matches!(p, Pipeline::QwenEdit(_)) {
                            return Err(refuse());
                        }
                        // Multi-image edits read every image in the job's order.
                        let references = edit_images(&id, kind, &inputs)?;
                        let req = Request {
                            prompt: params.prompt.clone(),
                            references,
                            width: params.width,
                            height: params.height,
                            steps: params.steps,
                            guidance_scale: params.guidance_scale,
                            seed,
                        };
                        let image = match p {
                            Pipeline::QwenEdit(e) => e.generate(&req),
                            Pipeline::Qwen21(q) => q.generate(&req),
                            _ => unreachable!("matched above"),
                        }
                        .map_err(engine)?;
                        let t = image.timings;
                        Ok(Rendered {
                            bytes: encode_png(image.width, image.height, image.rgb)?,
                            mime: "image/png".to_string(),
                            seed,
                            generation_ms: t.encode_ms + t.denoise_ms + t.decode_ms,
                        })
                    }
                    (Pipeline::AceStep(p), MediaGenKind::Text2Audio) => {
                        let audio = p.generate(&music_request(&params, seed)?).map_err(engine)?;
                        let t = audio.timings;
                        Ok(Rendered {
                            bytes: audio.wav_pcm16(),
                            mime: "audio/wav".to_string(),
                            seed,
                            generation_ms: t.encode_ms + t.denoise_ms + t.decode_ms,
                        })
                    }
                    (p @ (Pipeline::Cosmos3(_) | Pipeline::Wan22(_)), MediaGenKind::Text2Video | MediaGenKind::Image2Video) => {
                        only_roles(&id, &inputs, &[MediaGenInputRole::FirstFrame])?;
                        let image = match (kind, input_of(&inputs, MediaGenInputRole::FirstFrame)) {
                            (MediaGenKind::Image2Video, Some(bytes)) => Some(fit_frame(bytes, params.width, params.height)?),
                            (MediaGenKind::Image2Video, None) => {
                                return Err(ModelError::InvalidModel(format!("{kind} on {id} needs a first_frame input")));
                            }
                            _ => None,
                        };
                        let req = VideoRequest {
                            prompt: params.prompt.clone(),
                            negative_prompt: params.negative_prompt.clone(),
                            image,
                            width: params.width,
                            height: params.height,
                            num_frames: params.num_frames.ok_or_else(|| ModelError::InvalidModel(format!("{kind} needs num_frames")))?,
                            fps: params.fps.ok_or_else(|| ModelError::InvalidModel(format!("{kind} needs fps")))? as f32,
                            steps: params.steps,
                            guidance_scale: params.guidance_scale,
                            seed,
                        };
                        let video = match p {
                            Pipeline::Cosmos3(c) => c.generate(&req),
                            Pipeline::Wan22(w) => w.generate(&req),
                            _ => unreachable!("matched above"),
                        }
                        .map_err(engine)?;
                        let t = video.timings;
                        Ok(Rendered {
                            bytes: video.mp4(None).map_err(engine)?,
                            mime: "video/mp4".to_string(),
                            seed,
                            generation_ms: t.encode_ms + t.denoise_ms + t.decode_ms,
                        })
                    }
                    (Pipeline::Ltx2(p), MediaGenKind::Text2Video) => {
                        only_roles(&id, &inputs, &[])?;
                        let spec = tenzro_catalog::get_media_gen_model_by_id(&id);
                        let distilled = spec.as_ref().is_some_and(|m| m.distilled);
                        let upsample = distilled && spec.as_ref().is_some_and(|m| m.latent_upsampler.is_some());
                        // A distilled checkpoint runs its fixed schedule without guidance.
                        let base = if distilled { Ltx2Request::distilled(String::new(), upsample) } else { Ltx2Request::default() };
                        let mut req = Ltx2Request {
                            prompt: params.prompt.clone(),
                            negative_prompt: params.negative_prompt.clone().unwrap_or_default(),
                            width: params.width as usize,
                            height: params.height as usize,
                            num_frames: params.num_frames.ok_or_else(|| ModelError::InvalidModel(format!("{kind} needs num_frames")))? as usize,
                            fps: params.fps.ok_or_else(|| ModelError::InvalidModel(format!("{kind} needs fps")))? as f32,
                            steps: params.steps as usize,
                            seed,
                            ..base
                        };
                        if !distilled {
                            req.video.scale = params.guidance_scale;
                        }
                        let out = p.generate(&req).map_err(engine)?;
                        let t = out.video.timings;
                        Ok(Rendered {
                            bytes: out.mp4().map_err(engine)?,
                            mime: "video/mp4".to_string(),
                            seed,
                            generation_ms: t.encode_ms + t.denoise_ms + t.decode_ms,
                        })
                    }
                    (Pipeline::MiniMaxH3(p), MediaGenKind::Text2Video | MediaGenKind::Image2Video) => {
                        // Guidance-distilled at a fixed 24 fps: no guidance, no negative prompt.
                        if params.fps.is_some_and(|f| f != 24) {
                            return Err(ModelError::InvalidModel(format!("{id} renders at 24 fps")));
                        }
                        // Keyframe weights take a first and/or last frame;
                        // reference weights take their references in order.
                        let condition = match (kind, p.partition()) {
                            (MediaGenKind::Text2Video, H3Partition::Keyframe) => H3Condition::Text,
                            (MediaGenKind::Image2Video, H3Partition::Keyframe) => {
                                only_roles(&id, &inputs, &[MediaGenInputRole::FirstFrame, MediaGenInputRole::LastFrame])?;
                                let frame = |role| input_of(&inputs, role).map(decode_rgb).transpose();
                                let (first, last) = (frame(MediaGenInputRole::FirstFrame)?, frame(MediaGenInputRole::LastFrame)?);
                                if first.is_none() && last.is_none() {
                                    return Err(ModelError::InvalidModel(format!("{kind} on {id} needs a first_frame or last_frame input")));
                                }
                                H3Condition::Keyframes { first, last }
                            }
                            (MediaGenKind::Image2Video, H3Partition::Reference) => {
                                only_roles(&id, &inputs, &[MediaGenInputRole::Reference])?;
                                let refs = inputs.iter().map(|(_, b)| decode_rgb(b)).collect::<Result<Vec<_>>>()?;
                                if refs.is_empty() {
                                    return Err(ModelError::InvalidModel(format!("{kind} on {id} needs a reference input")));
                                }
                                H3Condition::References(refs)
                            }
                            _ => return Err(refuse()),
                        };
                        let req = H3Request {
                            condition,
                            prompt: params.prompt.clone(),
                            num_frames: params.num_frames.ok_or_else(|| ModelError::InvalidModel(format!("{kind} needs num_frames")))? as usize,
                            width: Some(params.width as usize),
                            height: Some(params.height as usize),
                            steps: params.steps as usize,
                            seed,
                        };
                        let out = p.generate(&req).map_err(engine)?;
                        let t = out.video.timings;
                        Ok(Rendered {
                            bytes: out.mp4().map_err(engine)?,
                            mime: "video/mp4".to_string(),
                            seed,
                            generation_ms: t.encode_ms + t.denoise_ms + t.decode_ms,
                        })
                    }
                    (Pipeline::Cosmos3(p), MediaGenKind::ActionPolicy) => {
                        let spec = tenzro_catalog::get_media_gen_model_by_id(&id).and_then(|m| m.action).ok_or_else(refuse)?;
                        let bytes = observation(&id, kind, &inputs)?;
                        let started = std::time::Instant::now();
                        let actions = run_policy(p, &spec, &params, bytes, seed).map_err(|e| match e {
                            RunError::Engine(e) => engine(e),
                            RunError::Request(e) => e,
                        })?;
                        let body = serde_json::json!({
                            "embodiment": spec.embodiment,
                            "action_dim": spec.action_dim,
                            "chunk_len": spec.chunk_len,
                            "control_hz": spec.control_hz,
                            "chunks": actions,
                        });
                        Ok(Rendered {
                            bytes: serde_json::to_vec(&body).map_err(|e| ModelError::InferenceError(e.to_string()))?,
                            mime: "application/json".to_string(),
                            seed,
                            generation_ms: started.elapsed().as_millis() as u64,
                        })
                    }
                    (Pipeline::Flux3Action(p), MediaGenKind::ActionPolicy) => {
                        let started = std::time::Instant::now();
                        let bytes = observation(&id, kind, &inputs)?;
                        let chunks = act(p, &params, bytes, seed)?;
                        let r = p.release();
                        let body = serde_json::json!({
                            "embodiment": tenzro_catalog::get_media_gen_model_by_id(&id).and_then(|m| m.action).map(|a| a.embodiment),
                            "action_dim": r.config.action_dim,
                            "chunk_len": r.config.chunk_size,
                            "execute_steps": r.config.n_action_steps,
                            "control_hz": r.config.fps,
                            "chunks": chunks,
                        });
                        Ok(Rendered {
                            bytes: serde_json::to_vec(&body).map_err(|e| ModelError::InferenceError(e.to_string()))?,
                            mime: "application/json".to_string(),
                            seed,
                            generation_ms: started.elapsed().as_millis() as u64,
                        })
                    }
                    (Pipeline::Janus(j), MediaGenKind::Text2Image) => {
                        only_roles(&id, &inputs, &[])?;
                        if params.negative_prompt.is_some() {
                            return Err(ModelError::InvalidModel(format!(
                                "{id} guides against an unconditioned prompt and reads no negative prompt"
                            )));
                        }
                        let side = j.decoder.image_side() as u32;
                        if (params.width, params.height) != (side, side) {
                            return Err(ModelError::InvalidModel(format!("{id} renders {side}x{side} images")));
                        }
                        // One step per image token.
                        let tokens = j.head.config().tokens_per_image() as u32;
                        if params.steps != tokens {
                            return Err(ModelError::InvalidModel(format!(
                                "{id} predicts {tokens} image tokens, one per step: set steps to {tokens}"
                            )));
                        }
                        let started = std::time::Instant::now();
                        let (rgb, side) = j.generate(&params.prompt, params.guidance_scale, seed)?;
                        Ok(Rendered {
                            bytes: encode_png(side, side, rgb)?,
                            mime: "image/png".to_string(),
                            seed,
                            generation_ms: started.elapsed().as_millis() as u64,
                        })
                    }
                    (Pipeline::Trellis2(p), MediaGenKind::Image23d) => {
                        let spec = tenzro_catalog::get_media_gen_model_by_id(&id).ok_or_else(refuse)?;
                        let image = object_image(&id, kind, &params, &inputs)?;
                        if params.voxel_resolution.is_some_and(|r| r != 512) {
                            return Err(ModelError::InvalidModel(format!("{id} builds its surface on a 512^3 grid")));
                        }
                        // The checkpoint sets each stage's guidance; a job asks for exactly that.
                        if params.guidance_scale != spec.default_guidance_scale {
                            return Err(ModelError::InvalidModel(format!(
                                "{id} guides each stage as its checkpoint sets: guidance_scale is {}",
                                spec.default_guidance_scale
                            )));
                        }
                        let mut req = Request3d::new(image, seed);
                        req.steps = Some(params.steps as usize);
                        let started = std::time::Instant::now();
                        let asset = p.generate(&req).map_err(engine)?;
                        Ok(Rendered {
                            bytes: asset.glb,
                            mime: GLB_MIME.to_string(),
                            seed,
                            generation_ms: started.elapsed().as_millis() as u64,
                        })
                    }
                    (p @ (Pipeline::Wan22(_) | Pipeline::MatrixGame(_)), MediaGenKind::WorldModel) => {
                        only_roles(&id, &inputs, &[MediaGenInputRole::FirstFrame])?;
                        let first = input_of(&inputs, MediaGenInputRole::FirstFrame).map(|b| fit_frame(b, params.width, params.height)).transpose()?;
                        let started = std::time::Instant::now();
                        let video = match p {
                            Pipeline::Wan22(w) => run_world(&*w, &params, first.as_ref(), seed),
                            Pipeline::MatrixGame(m) => run_world(&*m, &params, first.as_ref(), seed),
                            _ => unreachable!("matched above"),
                        }
                        .map_err(|e| match e {
                            RunError::Engine(e) => engine(e),
                            RunError::Request(e) => e,
                        })?;
                        Ok(Rendered {
                            bytes: video.mp4(None).map_err(engine)?,
                            mime: "video/mp4".to_string(),
                            seed,
                            generation_ms: started.elapsed().as_millis() as u64,
                        })
                    }
                    _ => Err(refuse()),
                }
            })
            .await
    }
}

enum RunError {
    Engine(praecise_diffusion::Error),
    Request(ModelError),
}

/// Latent frames a world chunk generates, when the job names none.
const WORLD_CHUNK_LATENT_FRAMES: usize = 2;
/// Latent frames conditioning each world chunk, when the job names none.
const WORLD_MEMORY_LATENT_FRAMES: usize = 2;

/// Roll a world model forward until `params.num_frames` frames are out.
///
/// Actions come from `metadata.actions`: one row of `action_dims` values per
/// output frame (none for a model without action input). The frames of the
/// last chunk past `num_frames` are generated under the final row and
/// dropped. `metadata.chunk_latent_frames` and `metadata.memory_latent_frames`
/// set the chunk and memory sizes.
fn run_world<M: WorldModel>(
    model: &M,
    params: &MediaGenParams,
    first: Option<&RgbImage>,
    seed: u64,
) -> std::result::Result<Video, RunError> {
    let bad = |m: String| RunError::Request(ModelError::InvalidModel(m));
    let frames = params
        .num_frames
        .ok_or_else(|| bad("world_model needs num_frames".into()))? as usize;
    let fps = params
        .fps
        .ok_or_else(|| bad("world_model needs fps".into()))? as f32;
    let size = |key: &str, default: usize| -> std::result::Result<usize, RunError> {
        match params.metadata.get(key) {
            None => Ok(default),
            Some(v) => v
                .as_u64()
                .filter(|n| (1..=64).contains(n))
                .map(|n| n as usize)
                .ok_or_else(|| bad(format!("{key} must be 1..=64"))),
        }
    };
    let memory = size("memory_latent_frames", WORLD_MEMORY_LATENT_FRAMES)?;
    let cfg = SessionConfig {
        width: params.width,
        height: params.height,
        fps,
        chunk_latent_frames: size("chunk_latent_frames", WORLD_CHUNK_LATENT_FRAMES)?,
        memory_latent_frames: memory,
        history_latent_frames: memory,
        steps: params.steps,
        guidance_scale: params.guidance_scale,
        seed,
    };
    let dims = model.action_dims();
    let rows: Vec<Vec<f32>> = match params.metadata.get("actions") {
        None if dims == 0 => Vec::new(),
        None => {
            return Err(bad(format!(
                "this world model needs metadata.actions: {frames} rows of {dims} values"
            )));
        }
        Some(v) => {
            serde_json::from_value(v.clone()).map_err(|e| bad(format!("metadata.actions: {e}")))?
        }
    };
    if dims > 0 && (rows.len() != frames || rows.iter().any(|r| r.len() != dims)) {
        return Err(bad(format!(
            "metadata.actions must hold {frames} rows of {dims} values"
        )));
    }
    if dims == 0 && !rows.is_empty() {
        return Err(bad("this world model takes no actions".into()));
    }

    let negative = params.negative_prompt.as_deref().unwrap_or("");
    let mut session = WorldSession::start(model, cfg, &params.prompt, negative, first)
        .map_err(RunError::Engine)?;
    let plane = params.width as usize * params.height as usize * 3;
    let mut rgb = Vec::with_capacity(plane * frames);
    let mut out = 0usize;
    // The first frame, when given, is frame 0 and takes no action.
    let mut row = usize::from(first.is_some());
    let mut evaluations = 0u32;
    while out < frames {
        let n = session.pixel_frames_next();
        let actions: Vec<f32> = if dims == 0 {
            Vec::new()
        } else {
            (row..row + n)
                .flat_map(|r| rows[r.min(frames - 1)].iter().copied())
                .collect()
        };
        row += n;
        let chunk = session.step(&actions).map_err(RunError::Engine)?;
        evaluations = evaluations.saturating_add(chunk.evaluations);
        let keep = (chunk.frames as usize).min(frames - out);
        rgb.extend_from_slice(&chunk.rgb[..keep * plane]);
        out += keep;
    }
    Ok(Video {
        width: params.width,
        height: params.height,
        frames: frames as u32,
        fps,
        rgb,
        seed,
        evaluations,
        timings: Timings::default(),
    })
}

/// Roll a policy out for `params.action_chunks` chunks from one observation:
/// each chunk starts from the last frame the previous one rendered.
fn run_policy(
    p: &mut Cosmos3,
    spec: &tenzro_catalog::ActionPolicySpec,
    params: &MediaGenParams,
    observation: &[u8],
    seed: u64,
) -> std::result::Result<Vec<Vec<Vec<f32>>>, RunError> {
    let bad = |m: String| RunError::Request(ModelError::InvalidModel(m));
    let chunks = params
        .action_chunks
        .ok_or_else(|| bad("action_policy needs action_chunks".into()))?;
    let resolution_tier = action_resolution_tier(params.height, params.width).ok_or_else(|| {
        bad(format!(
            "{}x{} is not an observation canvas of this policy",
            params.width, params.height
        ))
    })?;
    let view_point = params
        .metadata
        .get("view_point")
        .and_then(|v| v.as_str())
        .unwrap_or("ego_view")
        .to_string();
    let mut frame =
        fit_frame(observation, params.width, params.height).map_err(RunError::Request)?;
    let mut out = Vec::with_capacity(chunks as usize);
    for k in 0..chunks {
        let req = ActionRequest {
            mode: ActionMode::Policy,
            embodiment: spec.embodiment.clone(),
            prompt: params.prompt.clone(),
            negative_prompt: params.negative_prompt.clone(),
            view_point: view_point.clone(),
            resolution_tier,
            chunk_size: spec.chunk_len,
            frames: vec![frame],
            actions: None,
            fps: params.fps.unwrap_or(spec.control_hz) as f32,
            steps: params.steps,
            guidance_scale: params.guidance_scale,
            seed: seed.wrapping_add(u64::from(k)),
        };
        let res = p.generate_action(&req).map_err(RunError::Engine)?;
        let actions = res
            .actions
            .ok_or_else(|| bad("the policy returned no actions".into()))?;
        let v = res.video;
        let plane = (v.width * v.height * 3) as usize;
        let last = v.rgb[v.rgb.len() - plane..].to_vec();
        frame = RgbImage {
            width: v.width,
            height: v.height,
            rgb: last,
        };
        out.push(actions);
    }
    Ok(out)
}

/// Rows of `width` numbers from `metadata[key]` (an array of arrays).
fn rows(params: &MediaGenParams, key: &str, width: usize) -> Result<Option<Vec<f32>>> {
    let Some(v) = params.metadata.get(key) else {
        return Ok(None);
    };
    let bad =
        || ModelError::InvalidModel(format!("metadata.{key} must be rows of {width} numbers"));
    let mut out = Vec::new();
    for row in v.as_array().ok_or_else(bad)? {
        let r = row
            .as_array()
            .filter(|r| r.len() == width)
            .ok_or_else(bad)?;
        for x in r {
            let f = x.as_f64().filter(|f| f.is_finite()).ok_or_else(bad)?;
            out.push(f as f32);
        }
    }
    Ok(Some(out))
}

/// Run an action policy on one observation: `bytes` is an image grid with
/// one row per observed time step (oldest first) and one column per camera
/// in the model's camera order; `metadata.state` holds the measured state
/// rows and `metadata.commands` the absolute command history, both one row
/// per time step in the robot's own units. The `action_chunks` chunks are a
/// closed-loop rollout from that history, every chunk drawn from the noise of
/// `seed`: each chunk after the first is conditioned on the previous one's
/// execution steps (`execute_steps`) as if the robot reached every executed
/// command and the cameras held their last frame. Commands are absolute.
fn act(
    p: &ReleasedPolicy,
    params: &MediaGenParams,
    bytes: &[u8],
    seed: u64,
) -> Result<Vec<Vec<Vec<f32>>>> {
    let r = p.release();
    let d = r.config.action_dim;
    let frames = r.observation_frames();
    let img = image::load_from_memory(bytes)
        .map_err(|e| ModelError::InvalidModel(format!("observation image: {e}")))?
        .to_rgb8();
    let (w, h) = img.dimensions();
    let cameras = frames_from_grid(
        w as usize,
        h as usize,
        img.as_raw(),
        r.camera_keys.len(),
        frames,
    )
    .map_err(|e| ModelError::InvalidModel(e.to_string()))?;
    let states = rows(params, "state", d)?
        .ok_or_else(|| ModelError::InvalidModel("metadata.state is required".into()))?;
    let commands = rows(params, "commands", d)?;
    let obs = RawObservation {
        cameras: &cameras,
        states: &states,
        commands: commands.as_deref(),
        instruction: &params.prompt,
    };
    let engine = |e: praecise_diffusion::Error| match e {
        praecise_diffusion::Error::Request(m) => ModelError::InvalidModel(m),
        e => ModelError::InferenceError(e.to_string()),
    };
    let mut rollout = p.rollout(&params.prompt, seed);
    rollout.prime(&obs).map_err(engine)?;
    (0..params.action_chunks.unwrap_or(1))
        .map(|_| {
            Ok(rollout
                .chunk()
                .map_err(engine)?
                .chunks(d)
                .map(<[f32]>::to_vec)
                .collect())
        })
        .collect()
}

/// The text-to-music request for `params`. The style prompt is `prompt`; the
/// lyrics, their language and the optional musical controls ride in
/// `metadata` (`lyrics`, `language`, `bpm`, `keyscale`, `timesignature`).
fn music_request(params: &MediaGenParams, seed: u64) -> Result<MusicRequest> {
    let duration_secs = params
        .audio_duration_secs
        .ok_or_else(|| ModelError::InvalidModel("text2audio needs audio_duration_secs".into()))?;
    let meta = |k: &str| {
        params
            .metadata
            .get(k)
            .map(|v| v.as_str().map_or_else(|| v.to_string(), str::to_string))
    };
    let bpm =
        match meta("bpm") {
            Some(v) => Some(v.parse::<u32>().map_err(|_| {
                ModelError::InvalidModel(format!("bpm '{v}' is not a whole number"))
            })?),
            None => None,
        };
    Ok(MusicRequest {
        prompt: params.prompt.clone(),
        lyrics: meta("lyrics").unwrap_or_default(),
        language: meta("language").unwrap_or_else(|| "en".to_string()),
        duration_secs,
        steps: Some(params.steps),
        guidance_scale: Some(params.guidance_scale),
        shift: None,
        seed,
        bpm,
        keyscale: meta("keyscale"),
        timesignature: meta("timesignature"),
    })
}

/// The one reference image a 3D job conditions on: the object on a
/// transparent background, at the size the job's `width` and `height` sign
/// for. A job that also carries a prompt is refused, since nothing reads it.
fn object_image(
    id: &str,
    kind: MediaGenKind,
    params: &MediaGenParams,
    inputs: &[(MediaGenInputRole, Vec<u8>)],
) -> Result<RgbaImage> {
    only_roles(id, inputs, &[MediaGenInputRole::Reference])?;
    if !params.prompt.trim().is_empty() || params.negative_prompt.is_some() {
        return Err(ModelError::InvalidModel(format!(
            "{id} conditions on its reference image alone and reads no prompt"
        )));
    }
    let [(_, bytes)] = inputs else {
        return Err(ModelError::InvalidModel(format!(
            "{kind} on {id} needs exactly one reference input"
        )));
    };
    let img = image::load_from_memory(bytes)
        .map_err(|e| ModelError::InvalidModel(format!("input image: {e}")))?
        .to_rgba8();
    let (w, h) = img.dimensions();
    if (w, h) != (params.width, params.height) {
        return Err(ModelError::InvalidModel(format!(
            "the reference image is {w}x{h}, the job names {}x{}",
            params.width, params.height
        )));
    }
    if img.pixels().all(|p| p.0[3] == 255) {
        return Err(ModelError::InvalidModel(
            "the reference image has no transparent background around the object".into(),
        ));
    }
    Ok(RgbaImage {
        width: w,
        height: h,
        data: img.into_raw(),
    })
}

/// Decode a conditioning frame and bring it to exactly `width` x `height`:
/// scaled to cover the frame keeping its aspect, then centre-cropped.
/// An input image as 8-bit RGB at its own size.
fn decode_rgb(bytes: &[u8]) -> Result<RgbImage> {
    let img = image::load_from_memory(bytes)
        .map_err(|e| ModelError::InvalidModel(format!("input image: {e}")))?
        .to_rgb8();
    let (width, height) = img.dimensions();
    Ok(RgbImage {
        width,
        height,
        rgb: img.into_raw(),
    })
}

fn fit_frame(bytes: &[u8], width: u32, height: u32) -> Result<RgbImage> {
    let img = image::load_from_memory(bytes)
        .map_err(|e| ModelError::InvalidModel(format!("input image: {e}")))?
        .resize_to_fill(width, height, image::imageops::FilterType::Lanczos3)
        .to_rgb8();
    Ok(RgbImage {
        width,
        height,
        rgb: img.into_raw(),
    })
}

/// Side lengths of a reference image are a multiple of this.
const REFERENCE_CELL: u32 = 16;

/// Decode a reference image and bring it to a size the engine accepts: scaled
/// down to at most [`MAX_REFERENCE_PIXELS`] keeping its aspect, then
/// centre-cropped so both sides are a multiple of [`REFERENCE_CELL`].
fn prepare_reference(bytes: &[u8]) -> Result<RgbImage> {
    let img = image::load_from_memory(bytes)
        .map_err(|e| ModelError::InvalidModel(format!("input image: {e}")))?
        .to_rgb8();
    let (w, h) = img.dimensions();
    let area = f64::from(w) * f64::from(h);
    let img = if area > f64::from(MAX_REFERENCE_PIXELS) {
        let s = (f64::from(MAX_REFERENCE_PIXELS) / area).sqrt();
        let (nw, nh) = (
            ((f64::from(w) * s) as u32).max(1),
            ((f64::from(h) * s) as u32).max(1),
        );
        image::imageops::resize(&img, nw, nh, image::imageops::FilterType::Lanczos3)
    } else {
        img
    };
    let (w, h) = img.dimensions();
    let (cw, ch) = (
        w / REFERENCE_CELL * REFERENCE_CELL,
        h / REFERENCE_CELL * REFERENCE_CELL,
    );
    if cw == 0 || ch == 0 {
        return Err(ModelError::InvalidModel(format!(
            "input image {w}x{h} is smaller than {REFERENCE_CELL} pixels"
        )));
    }
    let cropped = image::imageops::crop_imm(&img, (w - cw) / 2, (h - ch) / 2, cw, ch).to_image();
    Ok(RgbImage {
        width: cw,
        height: ch,
        rgb: cropped.into_raw(),
    })
}

fn encode_png(width: u32, height: u32, rgb: Vec<u8>) -> Result<Vec<u8>> {
    let buf = image::RgbImage::from_raw(width, height, rgb).ok_or_else(|| {
        ModelError::InferenceError("render returned a buffer of the wrong size".into())
    })?;
    let mut out = Cursor::new(Vec::new());
    buf.write_to(&mut out, image::ImageFormat::Png)
        .map_err(|e| ModelError::InferenceError(format!("png encode: {e}")))?;
    Ok(out.into_inner())
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    fn params() -> MediaGenParams {
        MediaGenParams {
            prompt: "x".into(),
            negative_prompt: None,
            width: 64,
            height: 64,
            num_frames: None,
            fps: None,
            steps: 1,
            guidance_scale: 1.0,
            voxel_resolution: None,
            audio_duration_secs: None,
            action_chunks: None,
            session_hold_secs: None,
            seed: None,
            inputs: Vec::new(),
            metadata: HashMap::new(),
        }
    }

    fn job(kind: MediaGenKind) -> RenderJob {
        RenderJob {
            job_id: "j".into(),
            kind,
            params: params(),
            seed: 1,
            requester: [0; 32],
            inputs: Vec::new(),
            role: None,
            inbound_latent: None,
        }
    }

    #[test]
    fn a_pipeline_reads_inputs_in_job_order_and_refuses_roles_it_does_not_use() {
        use MediaGenInputRole as R;
        let png = |w: u32| encode_png(w, 64, vec![0; (w * 64 * 3) as usize]).unwrap();
        let edits = vec![
            (R::EditSource, png(64)),
            (R::Reference, png(128)),
            (R::EditSource, png(192)),
        ];
        let images = edit_images("m", MediaGenKind::Image2Image, &edits).unwrap();
        assert_eq!(
            images.iter().map(|i| i.width).collect::<Vec<_>>(),
            vec![64, 128, 192]
        );

        let masked = vec![(R::EditSource, png(64)), (R::Mask, png(64))];
        assert!(
            edit_images("m", MediaGenKind::Image2Image, &masked)
                .unwrap_err()
                .to_string()
                .contains("mask")
        );
        assert!(edit_images("m", MediaGenKind::Image2Image, &[]).is_err());
        assert!(
            edit_images("m", MediaGenKind::Text2Image, &[])
                .unwrap()
                .is_empty()
        );

        let frames = vec![(R::FirstFrame, vec![1u8]), (R::LastFrame, vec![2u8])];
        assert!(
            only_roles("m", &frames, &[R::FirstFrame])
                .unwrap_err()
                .to_string()
                .contains("last_frame")
        );
        assert!(only_roles("m", &frames, &[R::FirstFrame, R::LastFrame]).is_ok());
        assert_eq!(input_of(&frames, R::LastFrame), Some(&[2u8][..]));
        assert!(observation("m", MediaGenKind::ActionPolicy, &frames).is_err());
        assert_eq!(
            observation(
                "m",
                MediaGenKind::ActionPolicy,
                &[(R::Observation, vec![9u8])]
            )
            .unwrap(),
            &[9u8][..]
        );
    }

    #[tokio::test]
    async fn rendering_a_model_that_is_not_loaded_is_refused() {
        let rt = MediaRuntime::default();
        assert!(matches!(
            rt.render("absent", job(MediaGenKind::Text2Image)).await,
            Err(ModelError::ModelNotFound(_))
        ));
    }

    #[test]
    fn a_model_another_engine_holds_is_refused_before_any_file_is_read() {
        let host = Arc::new(ModelHost::default());
        host.claim("flux2-klein-4b", Engine::Praecise)
            .unwrap()
            .commit();
        let rt = MediaRuntime::with_host(host);
        let refused = rt
            .load(
                "flux2-klein-4b",
                "Flux2KleinPipeline",
                &[PathBuf::from("/nonexistent")],
                1,
                Precision::Bf16,
            )
            .unwrap_err();
        assert!(
            matches!(refused, ModelError::EngineConflict { .. }),
            "{refused}"
        );
    }

    #[test]
    fn a_pipeline_the_native_engine_lacks_is_refused_before_any_file_is_read() {
        let rt = MediaRuntime::default();
        let refused = rt
            .load(
                "qwen-image",
                "QwenImagePipeline",
                &[PathBuf::from("/nonexistent")],
                1,
                Precision::Bf16,
            )
            .unwrap_err();
        assert!(matches!(refused, ModelError::InvalidModel(_)), "{refused}");
    }

    #[test]
    fn a_checkpoint_needs_one_directory_per_source_its_pipeline_reads() {
        let rt = MediaRuntime::default();
        let one = [PathBuf::from("/nonexistent")];
        let refused = rt
            .load("ltx-2.3-22b-dev", "LTX2Pipeline", &one, 1, Precision::Bf16)
            .unwrap_err();
        assert!(
            refused.to_string().contains("2 source directories"),
            "{refused}"
        );
        let two = [PathBuf::from("/nonexistent"), PathBuf::from("/nonexistent")];
        let refused = rt
            .load("z-image-turbo", "ZImagePipeline", &two, 1, Precision::Bf16)
            .unwrap_err();
        assert!(
            refused.to_string().contains("1 source directories"),
            "{refused}"
        );
        let refused = rt
            .load(
                "matrix-game-3",
                "MatrixGame3I2VPipeline",
                &one,
                1,
                Precision::Bf16,
            )
            .unwrap_err();
        assert!(
            refused.to_string().contains("2 source directories"),
            "{refused}"
        );
        assert!(rt.loaded().is_empty());
    }

    #[test]
    fn the_qwen_edit_pipeline_reads_one_checkpoint_directory() {
        let rt = MediaRuntime::default();
        let two = [PathBuf::from("/nonexistent"), PathBuf::from("/nonexistent")];
        let refused = rt
            .load(
                "qwen-image-edit",
                "QwenImageEditPlusPipeline",
                &two,
                1,
                Precision::Bf16,
            )
            .unwrap_err();
        assert!(
            refused.to_string().contains("1 source directories"),
            "{refused}"
        );
        let one = [PathBuf::from("/nonexistent")];
        let failed = rt
            .load(
                "qwen-image-edit",
                "QwenImageEditPlusPipeline",
                &one,
                1,
                Precision::Bf16,
            )
            .unwrap_err();
        assert!(matches!(failed, ModelError::InvalidModel(_)), "{failed}");
        assert!(
            !failed.to_string().contains("has no"),
            "the pipeline is native: {failed}"
        );
        assert!(rt.loaded().is_empty());
    }

    #[test]
    fn the_qwen_image_21_pipeline_reads_one_checkpoint_directory() {
        let rt = MediaRuntime::default();
        let two = [PathBuf::from("/nonexistent"), PathBuf::from("/nonexistent")];
        let refused = rt
            .load(
                "qwen-image-2.1",
                "QwenImage21Pipeline",
                &two,
                1,
                Precision::Bf16,
            )
            .unwrap_err();
        assert!(
            refused.to_string().contains("1 source directories"),
            "{refused}"
        );
        let one = [PathBuf::from("/nonexistent")];
        let failed = rt
            .load(
                "qwen-image-2.1",
                "QwenImage21Pipeline",
                &one,
                1,
                Precision::Bf16,
            )
            .unwrap_err();
        assert!(
            !failed.to_string().contains("has no"),
            "the pipeline is native: {failed}"
        );
        assert!(rt.loaded().is_empty());
    }

    #[test]
    fn minimax_h3_loads_from_one_checkpoint_directory() {
        let rt = MediaRuntime::default();
        let one = [PathBuf::from("/nonexistent")];
        let two = [PathBuf::from("/nonexistent"), PathBuf::from("/nonexistent")];
        let refused = rt
            .load(
                "minimax-h3",
                "MiniMaxH3ModularPipeline",
                &two,
                1,
                Precision::Bf16,
            )
            .unwrap_err();
        assert!(refused.to_string().contains("1 source"), "{refused}");
        let failed = rt
            .load(
                "minimax-h3",
                "MiniMaxH3ModularPipeline",
                &one,
                1,
                Precision::Bf16,
            )
            .unwrap_err();
        assert!(
            !failed.to_string().contains("has no"),
            "the pipeline is native: {failed}"
        );
        assert!(rt.loaded().is_empty());
    }

    #[test]
    fn every_native_catalog_entry_runs_on_a_native_pipeline() {
        use crate::catalog::MediaGenStatus;
        tenzro_catalog::install_test_seed();
        let native: Vec<_> = crate::get_media_gen_catalog()
            .into_iter()
            .filter(|e| e.status == MediaGenStatus::Native)
            .collect();
        assert!(!native.is_empty());
        for e in native {
            assert!(
                NATIVE_PIPELINES.contains(&e.pipeline_class.as_str()),
                "{}",
                e.id
            );
        }
    }

    fn png_of(w: u32, h: u32) -> Vec<u8> {
        let rgb: Vec<u8> = (0..w * h * 3).map(|i| (i % 251) as u8).collect();
        encode_png(w, h, rgb).unwrap()
    }

    #[test]
    fn a_reference_is_cropped_to_whole_cells_around_its_centre() {
        let r = prepare_reference(&png_of(70, 37)).unwrap();
        assert_eq!((r.width, r.height), (64, 32));
        assert_eq!(r.rgb.len(), 64 * 32 * 3);
    }

    #[test]
    fn a_large_reference_is_scaled_to_the_pixel_budget_before_cropping() {
        let r = prepare_reference(&png_of(2048, 1024)).unwrap();
        assert!(r.width * r.height <= MAX_REFERENCE_PIXELS);
        assert_eq!((r.width % 16, r.height % 16), (0, 0));
        assert!(r.width > r.height, "aspect kept");
    }

    #[test]
    fn a_reference_smaller_than_one_cell_or_not_an_image_is_refused() {
        assert!(prepare_reference(&png_of(8, 8)).is_err());
        assert!(prepare_reference(b"not an image").is_err());
    }

    #[test]
    fn janus_reads_two_sources_and_trellis_one_assembled_checkpoint() {
        tenzro_catalog::install_test_seed();
        let rt = MediaRuntime::default();
        let one = [PathBuf::from("/nonexistent")];
        let refused = rt
            .load("janus-pro-1b", "JanusProPipeline", &one, 1, Precision::Bf16)
            .unwrap_err();
        assert!(
            refused.to_string().contains("2 source directories"),
            "{refused}"
        );
        // Both sources, but no checkpoint in them: refused at the first file read.
        let two = [PathBuf::from("/nonexistent"), PathBuf::from("/nonexistent")];
        let refused = rt
            .load("janus-pro-1b", "JanusProPipeline", &two, 1, Precision::Bf16)
            .unwrap_err();
        assert!(
            refused.to_string().contains("generation_config.json"),
            "{refused}"
        );
        let refused = rt
            .load(
                "trellis2-4b",
                "Trellis2ImageTo3DPipeline",
                &two,
                1,
                Precision::Bf16,
            )
            .unwrap_err();
        assert!(
            refused.to_string().contains("1 source directories"),
            "{refused}"
        );
        assert!(rt.loaded().is_empty());
    }

    fn rgba_png(w: u32, h: u32, alpha: impl Fn(u32, u32) -> u8) -> Vec<u8> {
        let mut img = image::RgbaImage::new(w, h);
        for (x, y, p) in img.enumerate_pixels_mut() {
            *p = image::Rgba([200, 40, 40, alpha(x, y)]);
        }
        let mut out = Cursor::new(Vec::new());
        img.write_to(&mut out, image::ImageFormat::Png).unwrap();
        out.into_inner()
    }

    #[test]
    fn a_3d_job_reads_one_object_image_of_the_size_it_signs_and_no_prompt() {
        use MediaGenInputRole as R;
        let kind = MediaGenKind::Image23d;
        let object = rgba_png(64, 64, |x, y| {
            if (16..48).contains(&x) && (16..48).contains(&y) {
                255
            } else {
                0
            }
        });
        let mut p = params();
        p.prompt.clear();
        let img = object_image("m", kind, &p, &[(R::Reference, object.clone())]).unwrap();
        assert_eq!((img.width, img.height), (64, 64));
        assert_eq!(img.data[3], 0, "the corner is transparent");

        let refuse = |p: &MediaGenParams, inputs: &[(R, Vec<u8>)]| {
            object_image("m", kind, p, inputs).unwrap_err().to_string()
        };
        assert!(refuse(&params(), &[(R::Reference, object.clone())]).contains("no prompt"));
        assert!(refuse(&p, &[]).contains("exactly one"));
        assert!(
            refuse(
                &p,
                &[
                    (R::Reference, object.clone()),
                    (R::Reference, object.clone())
                ]
            )
            .contains("exactly one")
        );
        assert!(refuse(&p, &[(R::EditSource, object.clone())]).contains("edit_source"));
        let mut wide = p.clone();
        wide.width = 128;
        assert!(refuse(&wide, &[(R::Reference, object)]).contains("64x64"));
        let opaque = rgba_png(64, 64, |_, _| 255);
        assert!(refuse(&p, &[(R::Reference, opaque)]).contains("transparent"));
    }

    #[test]
    fn janus_pixels_are_scaled_from_the_unit_range_and_clipped() {
        // One 2x2 image, planar: red, green, blue planes.
        let pixels = [
            -1.0, 1.0, 0.0, 2.0, //
            1.0, -1.0, 0.0, -2.0, //
            0.0, 0.0, 1.0, 1.0,
        ];
        assert_eq!(
            planar_to_rgb(&pixels, 2),
            vec![0, 255, 127, 255, 0, 127, 127, 127, 255, 255, 0, 255]
        );
    }

    #[test]
    fn png_encoding_round_trips_the_pixels() {
        let rgb: Vec<u8> = (0..(4 * 3 * 3)).map(|i| i as u8).collect();
        let png = encode_png(4, 3, rgb.clone()).unwrap();
        let back = image::load_from_memory(&png).unwrap().to_rgb8();
        assert_eq!(back.into_raw(), rgb);
    }
}
