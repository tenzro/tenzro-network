//! What the model runtimes share with the node that hosts them: which engine
//! holds each loaded model, the engines the node runs out of process, and the
//! admission every ONNX, media and speech request runs through.
//!
//! A model is loaded by exactly one engine. The llama.cpp path
//! ([`crate::ModelRuntime`]), every ONNX runtime, the diffusion engine, every
//! hosted engine and every node-owned runtime host
//! ([`crate::runtime_host`]) claim a model id here before loading it,
//! through Praecise's engine set
//! ([`praecise_host::Engines`]), and a claim held by a different engine
//! refuses the load with [`ModelError::EngineConflict`]: the same model never
//! sits in memory twice under two engines.
//!
//! Hosted engines (vLLM, SGLang, TensorRT-LLM, transformers) run in confined
//! runtime hosts the node starts and supervises, one per model, from the
//! pinned environments in [`EnginesConfig`]. Which models they serve is the
//! operator's [`EnginesConfig::models`]; every other model is served by
//! llama.cpp. Their memory is admitted against the node's one memory budget
//! ([`crate::memory_budget::global`]).
//!
//! ONNX, media and speech requests take a slot from the node's
//! [`TrafficManager`], the same admission layer inference uses, under one
//! queue per engine. ONNX slot counts and queue depths come from
//! [`crate::onnx_session::settings`]; the diffusion engine and each runtime
//! host run one request at a time. When slots and queue are full the request
//! fails with [`ModelError::Busy`], which carries when to retry.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use dashmap::DashMap;
use praecise_host::EngineEnv;
use praecise_host::engines::{Budget, Claim, EngineStatus, Engines, HostedModel};
use praecise_runtime::backend::{Backend, Integration};

use crate::error::{ModelError, Result};
use crate::memory_budget::Tier;
use crate::traffic::{QosClass, RequestGuard, Shape, TrafficManager};

/// The engine a model is loaded by.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Engine {
    /// The Praecise engine over llama.cpp (GGUF weights), in the node process.
    Praecise,
    /// One of the ONNX runtimes, named by its modality.
    Onnx(&'static str),
    /// A hosted engine in a runtime host the node supervises.
    Hosted(Backend),
    /// The Praecise diffusion engine (media generation), in the node process.
    Diffusion,
    /// A Praecise engine task served outside the language-model scheduler (reranking,
    /// speech synthesis), in the node process, named by its task.
    PraeciseTask(&'static str),
}

impl std::fmt::Display for Engine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Praecise => f.write_str(Backend::LlamaCpp.as_str()),
            Self::Onnx(kind) => write!(f, "onnx/{kind}"),
            Self::Hosted(backend) => f.write_str(backend.as_str()),
            Self::Diffusion => f.write_str("diffusion"),
            Self::PraeciseTask(task) => write!(f, "praecise/{task}"),
        }
    }
}

impl Engine {
    /// The admission queue this engine's requests share, and its slot count
    /// and queue depth. `None` for the language-model engines, whose requests
    /// are admitted by their own schedulers.
    fn admission(self) -> Option<(String, u32, u32)> {
        let settings = crate::onnx_session::settings();
        match self {
            Self::Onnx(kind) => Some((
                format!("onnx/{kind}"),
                settings.concurrency,
                settings.queue_depth,
            )),
            // A generation already saturates the device.
            Self::Diffusion => Some(("diffusion".to_string(), 1, settings.queue_depth)),
            // A task builds its own context per call; one at a time per task
            // keeps it from crowding the language models on the device.
            Self::PraeciseTask(task) => Some((format!("praecise/{task}"), 1, settings.queue_depth)),
            // Each host process serves one request at a time.
            Self::Praecise | Self::Hosted(_) => None,
        }
    }
}

// The `[engines]` table builds without the engine, so a node configuration
// parses the same in every build.
pub use crate::engine_config::{EnginesConfig, EnvironmentPin};

/// The node's memory ledger, as the budget every engine that reserves
/// through [`ModelHost`] is admitted against. Keys are model ids, as for every
/// other resident model. As for a language-model load, the ledger decides and
/// the machine's measured free memory can veto; a vetoed reservation is given
/// back before the refusal.
#[derive(Debug)]
struct NodeMemory;

impl Budget for NodeMemory {
    fn reserve(&self, model_id: &str, bytes: u64) -> praecise_host::Result<()> {
        crate::memory_budget::global()
            .admit(model_id, Tier::Resident, bytes)
            .map_err(|denied| praecise_host::Error::OverBudget {
                model_id: model_id.to_string(),
                needed: denied.requested_bytes,
                free: denied.tier_available_bytes,
            })?;
        if let Err(denied) =
            crate::ground::global().admits(model_id, crate::ground::Axis::Memory, bytes)
        {
            crate::memory_budget::global().release(model_id);
            return Err(praecise_host::Error::OverBudget {
                model_id: model_id.to_string(),
                needed: bytes,
                free: denied
                    .measured_free
                    .map_or(0, |f| f.saturating_sub(denied.margin)),
            });
        }
        Ok(())
    }

    fn give_back(&self, model_id: &str) {
        crate::memory_budget::global().release(model_id);
    }
}

/// A Praecise engine error in the node's terms.
pub(crate) fn engine_error(e: praecise_host::Error) -> ModelError {
    match e {
        praecise_host::Error::Conflict {
            model_id,
            held_by,
            requested,
        } => ModelError::EngineConflict {
            model_id,
            held_by,
            requested,
        },
        praecise_host::Error::OverBudget {
            model_id,
            needed,
            free,
        } => ModelError::InsufficientMemory {
            model_id,
            required_mb: needed / 1_048_576,
            available_mb: free / 1_048_576,
        },
        other => ModelError::InferenceError(other.to_string()),
    }
}

/// Shared by every runtime of one node. See the module docs.
#[derive(Debug)]
pub struct ModelHost {
    engines: Engines,
    environments: HashMap<Backend, EngineEnv>,
    assigned: BTreeMap<String, Backend>,
    scratch_dir: Option<PathBuf>,
    traffic: TrafficManager,
}

impl Default for ModelHost {
    fn default() -> Self {
        Self::new(TrafficManager::default())
    }
}

impl ModelHost {
    /// A host with no hosted engines, whose ONNX requests are admitted by
    /// `traffic`.
    pub fn new(traffic: TrafficManager) -> Self {
        Self {
            engines: Engines::new(Arc::new(NodeMemory)),
            environments: HashMap::new(),
            assigned: BTreeMap::new(),
            scratch_dir: None,
            traffic,
        }
    }

    /// A host that also runs the hosted engines `config` declares.
    ///
    /// Refuses a configuration naming an unknown or linked backend, a model
    /// assigned to a backend with no environment, two environments for one
    /// backend, or hosted models with no scratch directory.
    pub fn with_engines(traffic: TrafficManager, config: &EnginesConfig) -> Result<Self> {
        let hosted = |name: &str| -> Result<Backend> {
            let backend =
                Backend::parse(name).map_err(|e| ModelError::InvalidModel(e.to_string()))?;
            if backend.supports().integration != Integration::Hosted {
                return Err(ModelError::InvalidModel(format!(
                    "{backend} runs in the node process; only hosted backends take an environment or a model assignment"
                )));
            }
            Ok(backend)
        };
        let mut host = Self::new(traffic);
        for pin in &config.environments {
            let backend = hosted(&pin.backend)?;
            let env = EngineEnv::adapter(backend, &pin.root, &pin.digest).map_err(engine_error)?;
            if host.environments.insert(backend, env).is_some() {
                return Err(ModelError::InvalidModel(format!(
                    "two environments configured for {backend}"
                )));
            }
        }
        for (model_id, name) in &config.models {
            let backend = hosted(name)?;
            if !host.environments.contains_key(&backend) {
                return Err(ModelError::InvalidModel(format!(
                    "{model_id} is assigned to {backend}, which has no pinned environment"
                )));
            }
            host.assigned.insert(model_id.clone(), backend);
        }
        if !host.assigned.is_empty() && config.scratch_dir.is_none() {
            return Err(ModelError::InvalidModel(
                "hosted models need engines.scratch_dir".into(),
            ));
        }
        host.scratch_dir = config.scratch_dir.clone();
        Ok(host)
    }

    /// Claim `model_id` for the in-process `engine` ahead of loading it.
    ///
    /// Refuses when another engine holds the model. A claim the same engine
    /// already holds (a reload) succeeds and is left as it is. The returned
    /// [`Claim`] gives a new claim back on drop unless the load
    /// [`commit`](Claim::commit)s it, so a failed load leaves no claim behind.
    /// In-process loads admit their memory themselves, so the claim reserves
    /// none.
    pub fn claim(&self, model_id: &str, engine: Engine) -> Result<Claim<'_>> {
        self.engines
            .claim(model_id, &engine.to_string(), 0)
            .map_err(engine_error)
    }

    /// Claim `model_id` for the in-process `engine` and reserve its memory in
    /// the node's ledger: `file_bytes` of weights with the same load headroom
    /// a language-model load is admitted with. Refused when another engine
    /// holds the model or the memory is not there. The reservation is given
    /// back with the claim, on a failed load or on [`release`](Self::release).
    pub fn claim_with_memory(
        &self,
        model_id: &str,
        engine: Engine,
        file_bytes: u64,
    ) -> Result<Claim<'_>> {
        let bytes = crate::memory_budget::MemoryBudget::with_headroom(file_bytes).max(1);
        self.engines
            .claim(model_id, &engine.to_string(), bytes)
            .map_err(engine_error)
    }

    /// Give back `engine`'s claim on `model_id` after unloading it. A claim
    /// held by another engine is left alone. A hosted engine's runtime host
    /// stops once its last request ends.
    pub fn release(&self, model_id: &str, engine: Engine) {
        self.engines.release(model_id, &engine.to_string());
    }

    /// The hosted backend the operator assigned `model_id` to, if any.
    pub fn backend_for(&self, model_id: &str) -> Option<Backend> {
        self.assigned.get(model_id).copied()
    }

    /// Start `model_id`'s assigned hosted engine over the checkpoint in
    /// `model_dir`, admitting `bytes` of memory. Blocking until the model is
    /// loaded; refused when any engine already holds the model.
    pub fn serve_hosted(
        &self,
        model_id: &str,
        model_dir: &Path,
        bytes: u64,
    ) -> Result<Arc<HostedModel>> {
        let backend = self.backend_for(model_id).ok_or_else(|| {
            ModelError::InvalidModel(format!("{model_id} is not assigned to a hosted engine"))
        })?;
        let env = &self.environments[&backend];
        let scratch = self
            .scratch_dir
            .as_ref()
            .expect("validated with the assignments")
            .join(model_id.replace(['/', '\\'], "_"));
        self.engines
            .serve(
                model_id,
                env,
                model_dir,
                &scratch,
                serde_json::json!({}),
                bytes,
            )
            .map_err(engine_error)
    }

    /// Every claimed model, its engine and that engine's health.
    pub fn engine_status(&self) -> Vec<EngineStatus> {
        self.engines.status()
    }

    /// Take one of `engine`'s slots, waiting in its queue while they are all
    /// busy.
    pub async fn admit(&self, engine: Engine) -> Result<RequestGuard> {
        let (key, slots, depth) = engine.admission().ok_or_else(|| {
            ModelError::InvalidModel(format!("{engine} admits through its own scheduler"))
        })?;
        self.traffic.declare_limits(&key, slots, depth);
        self.traffic
            .acquire(&key, QosClass::Interactive, Shape::new(0, 1))
            .await
            .map_err(ModelError::Busy)
    }
}

/// The loaded models of one runtime, keyed by model id.
///
/// Every ONNX runtime and the diffusion engine keep their models here, so
/// each one claims model ids through the shared [`ModelHost`] and runs
/// requests through its access check and admission.
pub struct EngineModels<M: ?Sized> {
    engine: Engine,
    host: Arc<ModelHost>,
    models: DashMap<String, Arc<M>>,
}

impl<M: ?Sized + Send + Sync + 'static> EngineModels<M> {
    /// An empty registry for `engine`, sharing `host`.
    pub fn new(engine: Engine, host: Arc<ModelHost>) -> Self {
        Self {
            engine,
            host,
            models: DashMap::new(),
        }
    }

    fn engine(&self) -> Engine {
        self.engine
    }

    /// Load a model with `build` and register it under `model_id`.
    ///
    /// The claim is taken before `build` runs, so a model another engine
    /// holds is refused before any weights are read. Replaces a model this
    /// runtime already holds under the same id.
    pub fn load(
        &self,
        model_id: impl Into<String>,
        build: impl FnOnce() -> Result<Arc<M>>,
    ) -> Result<()> {
        let model_id = model_id.into();
        let claim = self.host.claim(&model_id, self.engine())?;
        let model = build()?;
        self.models.insert(model_id, model);
        claim.commit();
        Ok(())
    }

    /// As [`load`](Self::load), for a model whose memory the node's ledger
    /// must hold: `file_bytes` of weights are reserved (see
    /// [`ModelHost::claim_with_memory`]) before `build` runs, and given back
    /// if it fails or when the model is removed.
    pub fn load_reserving(
        &self,
        model_id: impl Into<String>,
        file_bytes: u64,
        build: impl FnOnce() -> Result<Arc<M>>,
    ) -> Result<()> {
        let model_id = model_id.into();
        let claim = self
            .host
            .claim_with_memory(&model_id, self.engine(), file_bytes)?;
        let model = build()?;
        self.models.insert(model_id, model);
        claim.commit();
        Ok(())
    }

    /// Register an already-built model under `model_id`.
    pub fn insert(&self, model_id: impl Into<String>, model: Arc<M>) -> Result<()> {
        self.load(model_id, || Ok(model))
    }

    /// Unregister `model_id`, giving back its claim. Returns whether it was
    /// loaded.
    pub fn remove(&self, model_id: &str) -> bool {
        let removed = self.models.remove(model_id).is_some();
        if removed {
            self.host.release(model_id, self.engine());
        }
        removed
    }

    pub fn contains(&self, model_id: &str) -> bool {
        self.models.contains_key(model_id)
    }

    pub fn ids(&self) -> Vec<String> {
        self.models.iter().map(|kv| kv.key().clone()).collect()
    }

    pub fn get(&self, model_id: &str) -> Option<Arc<M>> {
        self.models.get(model_id).map(|kv| Arc::clone(kv.value()))
    }

    /// Run `infer` on `model_id` once the caller is allowed to use it and a
    /// slot is free, on a blocking thread so the async caller is not stalled.
    pub async fn run<R, F>(&self, model_id: &str, infer: F) -> Result<R>
    where
        R: Send + 'static,
        F: FnOnce(&M) -> Result<R> + Send + 'static,
    {
        crate::access::check(model_id)?;
        let model = self
            .get(model_id)
            .ok_or_else(|| ModelError::ModelNotFound(model_id.to_string()))?;
        let _slot = self.host.admit(self.engine).await?;
        tokio::task::spawn_blocking(move || infer(&model))
            .await
            .map_err(|e| ModelError::InferenceError(format!("spawn_blocking: {e}")))?
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_model_is_held_by_one_engine() {
        let host = ModelHost::default();
        host.claim("m", Engine::Praecise).unwrap().commit();
        let refused = host
            .claim("m", Engine::Onnx("text-embedding"))
            .err()
            .unwrap();
        assert!(
            matches!(&refused, ModelError::EngineConflict { held_by, .. } if held_by == "llama.cpp"),
            "{refused}"
        );
        // The holder may reload it.
        host.claim("m", Engine::Praecise).unwrap().commit();
        host.release("m", Engine::Praecise);
        host.claim("m", Engine::Onnx("text-embedding"))
            .unwrap()
            .commit();
        assert!(
            host.claim("m", Engine::Praecise).is_err(),
            "now held by ONNX"
        );
    }

    #[test]
    fn two_onnx_runtimes_cannot_hold_one_model() {
        let host = Arc::new(ModelHost::default());
        let vision: EngineModels<str> =
            EngineModels::new(Engine::Onnx("vision"), Arc::clone(&host));
        let detection: EngineModels<str> =
            EngineModels::new(Engine::Onnx("detection"), Arc::clone(&host));
        vision.insert("clip", Arc::from("weights")).unwrap();
        let refused = detection.insert("clip", Arc::from("weights")).unwrap_err();
        assert!(
            matches!(refused, ModelError::EngineConflict { .. }),
            "{refused}"
        );
        assert!(!detection.contains("clip"));
        assert!(vision.remove("clip"));
        detection.insert("clip", Arc::from("weights")).unwrap();
    }

    #[test]
    fn a_refused_load_reads_no_weights_and_a_failed_load_leaves_no_claim() {
        let host = Arc::new(ModelHost::default());
        host.claim("m", Engine::Praecise).unwrap().commit();
        let onnx: EngineModels<str> =
            EngineModels::new(Engine::Onnx("forecast"), Arc::clone(&host));
        let mut built = false;
        onnx.load("m", || {
            built = true;
            Ok(Arc::from("weights"))
        })
        .unwrap_err();
        assert!(!built, "the conflict is found before loading");

        let failed = onnx.load("other", || Err(ModelError::InvalidModel("corrupt".into())));
        assert!(failed.is_err());
        assert!(
            host.claim("other", Engine::Praecise).is_ok(),
            "a failed load gives its claim back"
        );
    }

    #[tokio::test]
    async fn onnx_requests_run_through_bounded_admission() {
        let host = Arc::new(ModelHost::default());
        let models: EngineModels<str> = EngineModels::new(Engine::Onnx("test"), Arc::clone(&host));
        models.insert("m", Arc::from("weights")).unwrap();
        let out = crate::access::as_node(models.run("m", |w| Ok(w.len()))).await;
        assert_eq!(out.unwrap(), 7);

        let settings = crate::onnx_session::settings();
        let mut held = Vec::new();
        for _ in 0..settings.concurrency {
            held.push(host.admit(Engine::Onnx("test")).await.expect("a free slot"));
        }
        let mut waiting = Vec::new();
        for _ in 0..settings.queue_depth {
            let host = Arc::clone(&host);
            waiting.push(tokio::spawn(async move {
                host.admit(Engine::Onnx("test")).await.map(drop)
            }));
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        let busy = host
            .admit(Engine::Onnx("test"))
            .await
            .expect_err("slots and queue are full");
        assert!(matches!(busy, ModelError::Busy(_)), "{busy}");
        assert!(busy.to_string().contains("retry after"), "{busy}");

        drop(held);
        for w in waiting {
            w.await
                .unwrap()
                .expect("queued requests run once slots free");
        }
    }

    #[tokio::test]
    async fn diffusion_runs_one_generation_at_a_time_and_queues_the_rest() {
        let host = Arc::new(ModelHost::default());
        let first = host.admit(Engine::Diffusion).await.expect("a free slot");
        let second = {
            let host = Arc::clone(&host);
            tokio::spawn(async move { host.admit(Engine::Diffusion).await.map(drop) })
        };
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert!(
            !second.is_finished(),
            "the second generation waits for the first"
        );
        drop(first);
        second.await.unwrap().expect("runs once the first finishes");
    }

    #[tokio::test]
    async fn the_llm_path_is_not_admitted_here() {
        let host = ModelHost::default();
        assert!(host.admit(Engine::Praecise).await.is_err());
        assert!(
            host.admit(Engine::PraeciseTask("rerank")).await.is_ok(),
            "an in-process task outside the scheduler is admitted here"
        );
    }

    #[test]
    fn diffusion_and_the_llm_path_cannot_hold_one_model() {
        let host = Arc::new(ModelHost::default());
        let media: EngineModels<str> = EngineModels::new(Engine::Diffusion, Arc::clone(&host));
        media
            .insert("flux2-klein-4b", Arc::from("weights"))
            .unwrap();
        assert!(matches!(
            host.claim("flux2-klein-4b", Engine::Praecise).err(),
            Some(ModelError::EngineConflict { .. })
        ));
    }
}
