//! Serving one model whose blocks run on several of an operator's machines.
//!
//! The split itself is Praecise's layer pipeline: every machine loads a
//! contiguous range of the model's blocks, hidden states travel between them
//! over links both ends authenticate, and the machine with the first blocks
//! drives generation. This module runs either side on its own thread:
//!
//! - [`PipelineDriver`]: the first stage. It holds the token embedding, serves
//!   generation requests one at a time, and is registered with the
//!   [`crate::runtime::ModelRuntime`] like any loaded model.
//! - [`spawn_stage`]: any later stage. It loads its blocks, listens, and serves
//!   the driver's sessions until the process stops.
//!
//! A stage that fails or stops answering fails the request in flight with an
//! error naming it. The next request reconnects to the same plan; nothing is
//! ever served from a different set of machines.

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, mpsc};

use llama_cpp_2::llama_backend::LlamaBackend;
use llama_cpp_2::model::LlamaModel;
use llama_cpp_2::model::params::LlamaModelParams;
use parking_lot::RwLock;
use praecise_runtime::pipeline::driver::{DriverOptions, Pipeline};
use praecise_runtime::pipeline::stage::{self, StageOptions};
use praecise_runtime::pipeline::{PipelineError, PipelinePlan};
use praecise_runtime::{BatchPrompt, ChatTemplateSource, GenerationConfig, InferenceResult};
use tracing::{info, warn};

use crate::error::{ModelError, Result};

pub use praecise_runtime::pipeline::driver::DriverOptions as PipelineDriverOptions;
pub use praecise_runtime::pipeline::stage::StageOptions as PipelineStageOptions;
pub use praecise_runtime::pipeline::{
    LayerRange, PipelineError as LayerPipelineError, PipelinePlan as LayerPipelinePlan,
    StageAuthenticator, StageSpec, split_layers,
};

/// What a pipeline stage is doing, for status surfaces.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case", tag = "state", content = "detail")]
pub enum StageState {
    /// Loading its blocks.
    Loading,
    /// Connected (driver) or listening (later stage).
    Serving,
    /// Stopped with an error; a driver retries on the next request.
    Failed(String),
}

fn model_error(e: PipelineError) -> ModelError {
    ModelError::InferenceError(e.to_string())
}

fn load_stage(
    backend: &LlamaBackend,
    gguf: &Path,
    plan: &PipelinePlan,
    index: usize,
    gpu: bool,
) -> Result<LlamaModel> {
    let layers = plan
        .stages
        .get(index)
        .ok_or_else(|| ModelError::InvalidModel(format!("pipeline plan has no stage {index}")))?
        .layers;
    let params = LlamaModelParams::default()
        .with_n_gpu_layers(if gpu { 1000 } else { 0 })
        .with_layer_stage(layers.begin, layers.end);
    let model = crate::parse_jail::load_llama(backend, gguf, &params).map_err(|e| {
        ModelError::InvalidModel(format!(
            "loading blocks {}..{} of {}: {e}",
            layers.begin,
            layers.end,
            gguf.display()
        ))
    })?;
    stage::check_model(&model, plan, index).map_err(|e| ModelError::InvalidModel(e.to_string()))?;
    Ok(model)
}

/// Load stage `index` (not the first) of `plan` and serve it on `listen` on a
/// dedicated thread for the life of the process. Returns once the blocks are
/// loaded and the socket is bound, so a load or bind failure is reported to the
/// caller rather than logged.
///
/// # Errors
///
/// A plan that does not name this stage, a model that does not fit the plan,
/// or a socket that cannot be bound.
#[allow(clippy::too_many_arguments)]
pub fn spawn_stage(
    backend: Arc<LlamaBackend>,
    gguf: PathBuf,
    plan: PipelinePlan,
    index: usize,
    listen: String,
    auth: Arc<dyn StageAuthenticator>,
    opts: StageOptions,
    gpu: bool,
) -> Result<Arc<RwLock<StageState>>> {
    if index == 0 {
        return Err(ModelError::InvalidModel(
            "stage 0 drives the pipeline; it does not listen".into(),
        ));
    }
    plan.validate()
        .map_err(|e| ModelError::InvalidModel(e.to_string()))?;
    let state = Arc::new(RwLock::new(StageState::Loading));
    let (ready_tx, ready_rx) = mpsc::channel::<Result<()>>();
    let thread_state = Arc::clone(&state);
    std::thread::Builder::new()
        .name(format!("pipeline-stage-{index}"))
        .spawn(move || {
            let model = match load_stage(&backend, &gguf, &plan, index, gpu) {
                Ok(m) => m,
                Err(e) => {
                    let _ = ready_tx.send(Err(e));
                    return;
                }
            };
            let listener = match TcpListener::bind(&listen) {
                Ok(l) => l,
                Err(e) => {
                    let _ = ready_tx.send(Err(ModelError::Other(format!("binding {listen}: {e}"))));
                    return;
                }
            };
            *thread_state.write() = StageState::Serving;
            let _ = ready_tx.send(Ok(()));
            info!(stage = index, %listen, "serving layer-pipeline stage");
            let err = stage::serve(
                &listener,
                &backend,
                &model,
                &plan,
                index,
                auth.as_ref(),
                &opts,
            );
            let reason = match err {
                Ok(()) => "stopped".to_string(),
                Err(e) => e.to_string(),
            };
            warn!(stage = index, %reason, "layer-pipeline stage stopped");
            *thread_state.write() = StageState::Failed(reason);
        })
        .map_err(|e| ModelError::Other(format!("spawning the stage thread: {e}")))?;
    ready_rx
        .recv()
        .map_err(|_| ModelError::Other("the stage thread exited before loading".into()))??;
    Ok(state)
}

struct Job {
    prompt: BatchPrompt,
    config: GenerationConfig,
    token_tx: Option<tokio::sync::mpsc::Sender<String>>,
    reasoning_tx: Option<tokio::sync::mpsc::Sender<String>>,
    cancel: Arc<AtomicBool>,
    reply: tokio::sync::oneshot::Sender<Result<InferenceResult>>,
}

/// The first stage of a pipeline, serving generation requests.
pub struct PipelineDriver {
    jobs: std::sync::Mutex<Option<mpsc::Sender<Job>>>,
    state: Arc<RwLock<StageState>>,
    n_stages: usize,
    plan_digest: [u8; 32],
    /// The served model's chat template.
    chat_template: Option<ChatTemplateSource>,
}

impl std::fmt::Debug for PipelineDriver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PipelineDriver")
            .field("n_stages", &self.n_stages)
            .field("state", &*self.state.read())
            .finish_non_exhaustive()
    }
}

impl PipelineDriver {
    /// Load stage 0 of `plan` and connect to the rest of the pipeline on a
    /// dedicated thread. Returns once the first connection is up, so an
    /// unreachable or unauthenticated stage is reported to the caller.
    ///
    /// # Errors
    ///
    /// A model that does not fit the plan, or any stage that cannot be reached
    /// or does not prove its identity.
    pub fn start(
        backend: Arc<LlamaBackend>,
        gguf: PathBuf,
        plan: PipelinePlan,
        auth: Arc<dyn StageAuthenticator>,
        opts: DriverOptions,
        enable_thinking: bool,
        gpu: bool,
    ) -> Result<Self> {
        plan.validate()
            .map_err(|e| ModelError::InvalidModel(e.to_string()))?;
        let state = Arc::new(RwLock::new(StageState::Loading));
        let (jobs_tx, jobs_rx) = mpsc::channel::<Job>();
        let (ready_tx, ready_rx) = mpsc::channel::<Result<Option<ChatTemplateSource>>>();
        let n_stages = plan.stages.len();
        let plan_digest = plan.digest();
        let thread_state = Arc::clone(&state);
        std::thread::Builder::new()
            .name("pipeline-driver".into())
            .spawn(move || {
                let model = match load_stage(&backend, &gguf, &plan, 0, gpu) {
                    Ok(m) => m,
                    Err(e) => {
                        let _ = ready_tx.send(Err(e));
                        return;
                    }
                };
                let connect = || Pipeline::connect(&backend, &model, &plan, auth.as_ref(), &opts);
                let mut pipe = match connect() {
                    Ok(p) => Some(p),
                    Err(e) => {
                        let _ = ready_tx.send(Err(model_error(e)));
                        return;
                    }
                };
                *thread_state.write() = StageState::Serving;
                let _ = ready_tx.send(Ok(ChatTemplateSource::from_model(&model).ok()));
                info!(stages = plan.stages.len(), "layer pipeline connected");
                for job in jobs_rx {
                    if pipe.is_none() {
                        match connect() {
                            Ok(p) => {
                                *thread_state.write() = StageState::Serving;
                                info!("layer pipeline reconnected");
                                pipe = Some(p);
                            }
                            Err(e) => {
                                *thread_state.write() = StageState::Failed(e.to_string());
                                let _ = job.reply.send(Err(model_error(e)));
                                continue;
                            }
                        }
                    }
                    let Some(p) = pipe.as_mut() else { continue };
                    let mut config = job.config;
                    config.reasoning_tx = job.reasoning_tx;
                    let result = p.generate(
                        &job.prompt,
                        &config,
                        enable_thinking,
                        job.token_tx.as_ref(),
                        Some(job.cancel.as_ref()),
                    );
                    if let Err(e) = &result
                        && matches!(e, PipelineError::StageFailed { .. } | PipelineError::Timeout(_) | PipelineError::Io(_)) {
                            warn!(error = %e, "layer pipeline failed; reconnecting on the next request");
                            *thread_state.write() = StageState::Failed(e.to_string());
                            pipe = None;
                        }
                    let _ = job.reply.send(result.map_err(model_error));
                }
            })
            .map_err(|e| ModelError::Other(format!("spawning the pipeline driver: {e}")))?;
        let chat_template = ready_rx.recv().map_err(|_| {
            ModelError::Other("the pipeline driver exited before connecting".into())
        })??;
        Ok(Self {
            jobs: std::sync::Mutex::new(Some(jobs_tx)),
            state,
            n_stages,
            plan_digest,
            chat_template,
        })
    }

    /// The served model's chat template, for rendering a chat turn.
    pub fn chat_template(&self) -> Option<&ChatTemplateSource> {
        self.chat_template.as_ref()
    }

    /// Generate a reply. Requests queue and run one at a time.
    ///
    /// # Errors
    ///
    /// A stopped driver, or the failure of any stage.
    pub async fn generate(
        &self,
        prompt: BatchPrompt,
        config: &GenerationConfig,
        token_tx: Option<tokio::sync::mpsc::Sender<String>>,
        reasoning_tx: Option<tokio::sync::mpsc::Sender<String>>,
    ) -> Result<InferenceResult> {
        let (reply, rx) = tokio::sync::oneshot::channel();
        let cancel = Arc::new(AtomicBool::new(false));
        let job = Job {
            prompt,
            config: config.clone(),
            token_tx,
            reasoning_tx,
            cancel: Arc::clone(&cancel),
            reply,
        };
        {
            let jobs = self
                .jobs
                .lock()
                .map_err(|_| ModelError::Other("pipeline driver poisoned".into()))?;
            let sender = jobs.as_ref().ok_or_else(|| {
                ModelError::InferenceError("the layer pipeline is stopped".into())
            })?;
            sender.send(job).map_err(|_| {
                ModelError::InferenceError("the layer pipeline driver has stopped".into())
            })?;
        }
        // a caller that goes away stops the generation at its next token
        struct CancelOnDrop(Arc<AtomicBool>);
        impl Drop for CancelOnDrop {
            fn drop(&mut self) {
                self.0.store(true, std::sync::atomic::Ordering::Relaxed);
            }
        }
        let _cancel = CancelOnDrop(cancel);
        rx.await.map_err(|_| {
            ModelError::InferenceError("the layer pipeline driver dropped the request".into())
        })?
    }

    /// Stop taking requests; the driver thread ends after the one in flight.
    pub fn shutdown(&self) {
        if let Ok(mut jobs) = self.jobs.lock() {
            jobs.take();
        }
    }

    /// The driver's state.
    pub fn state(&self) -> StageState {
        self.state.read().clone()
    }

    /// Number of stages, this one included.
    pub fn n_stages(&self) -> usize {
        self.n_stages
    }

    /// Digest of the plan every stage agreed on.
    pub fn plan_digest(&self) -> [u8; 32] {
        self.plan_digest
    }
}
