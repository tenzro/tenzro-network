//! Training.
//!
//! A node trains a low-rank adapter on a catalog model in its own process,
//! on the Praecise engine over the same llama.cpp backend that serves the
//! model ([`praecise_train`]), on a CUDA device. Training is compute like
//! serving: the model is claimed for the task `training` through the node's
//! [`ModelHost`], so a model this node trains is not also loaded by another
//! engine, and rounds are admitted one at a time.
//!
//! A round runs a number of supervised steps from a starting state (fresh
//! adapter weights or the state a previous round ended at) over a shard of
//! prompt and completion pairs, every step in deterministic mode: each op of
//! each step must run on the CUDA device in its audited deterministic kernel
//! set, or the round is refused. The round's commitment binds the base
//! weights, the shard, the recipe, the seed, the kernel class, the steps and
//! the states it started and ended at, so a second machine of the same kernel
//! class that replays the round reaches the same commitment, adapter and
//! state, bit for bit.
//!
//! A build without CUDA, or a machine without a CUDA device, refuses to load
//! a model for training: training never moves to the CPU.

use std::path::Path;
use std::sync::Arc;

use llama_cpp_2::model::params::LlamaModelParams;
use llama_cpp_2::model::{AddBos, LlamaModel};
use praecise_train::checkpoint::TrainState;
use praecise_train::engine::{EngineConfig, LoraTrainer, SftExample, init_lora_weights};
use praecise_train::kernel_class::{Backend, KernelClass};
use praecise_train::recipe::{AdapterSpec, Objective, OptimizerSpec, Precision, Recipe};
use praecise_train::round::{SftRound, run_sft_round};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::error::{ModelError, Result};
use crate::model_host::{Engine, EngineModels, ModelHost};

/// Most records one round may carry.
pub const MAX_ROUND_RECORDS: usize = 4_096;
/// Most steps one round may take.
pub const MAX_ROUND_STEPS: u64 = 10_000;
/// Longest sequence a round trains on, in tokens.
pub const MAX_SEQ_LEN: u32 = 8_192;
/// Most sequences one step may carry.
pub const MAX_BATCH: u32 = 64;
/// Highest adapter rank.
pub const MAX_RANK: u32 = 256;
/// Tokens of the first record's prompt every step's probe commits to.
const PROBE_TOKENS: usize = 16;

/// The recipe of a supervised `LoRA` round, as a job states it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LoraRecipe {
    /// Adapter rank.
    pub rank: u32,
    /// Adapter scale numerator: the update is `(alpha / rank) * B A x`.
    pub alpha: f32,
    /// Base weight name suffixes that receive an adapter, e.g. `attn_q.weight`.
    pub targets: Vec<String>,
    /// `AdamW` learning rate.
    pub lr: f32,
    /// `AdamW` first-moment decay.
    pub beta1: f32,
    /// `AdamW` second-moment decay.
    pub beta2: f32,
    /// `AdamW` epsilon.
    pub eps: f32,
    /// Decoupled weight decay.
    pub weight_decay: f32,
    /// Tokens per sequence; longer records are cut to it.
    pub seq_len: u32,
    /// Sequences per step.
    pub batch: u32,
    /// Global gradient-norm clip, 0 for none.
    pub grad_clip: f32,
}

impl LoraRecipe {
    /// Bounds a round enforces before loading anything.
    ///
    /// # Errors
    /// [`ModelError::InvalidInput`] naming the first bound broken.
    pub fn validate(&self) -> Result<()> {
        let bad = |m: &str| Err(ModelError::InvalidInput(m.to_string()));
        if self.rank == 0 || self.rank > MAX_RANK {
            return bad("the adapter rank is 1 to 256");
        }
        if self.targets.is_empty()
            || self.targets.len() > 16
            || self.targets.iter().any(|t| t.is_empty() || t.len() > 64)
        {
            return bad("an adapter names 1 to 16 target weights of 1 to 64 bytes");
        }
        if self.seq_len < 2 || self.seq_len > MAX_SEQ_LEN {
            return bad("a sequence is 2 to 8192 tokens");
        }
        if self.batch == 0 || self.batch > MAX_BATCH {
            return bad("a step carries 1 to 64 sequences");
        }
        let finite = [
            self.alpha,
            self.lr,
            self.beta1,
            self.beta2,
            self.eps,
            self.weight_decay,
            self.grad_clip,
        ];
        if finite.iter().any(|v| !v.is_finite() || *v < 0.0) || self.lr == 0.0 {
            return bad(
                "recipe numbers are finite and not negative, and the learning rate is positive",
            );
        }
        if self.beta1 >= 1.0 || self.beta2 >= 1.0 {
            return bad("moment decays are below 1");
        }
        Ok(())
    }

    /// The engine recipe.
    #[must_use]
    pub fn to_recipe(&self) -> Recipe {
        Recipe {
            objective: Objective::Sft,
            optimizer: OptimizerSpec::AdamW {
                lr: self.lr,
                beta1: self.beta1,
                beta2: self.beta2,
                eps: self.eps,
                weight_decay: self.weight_decay,
            },
            adapter: Some(AdapterSpec {
                rank: self.rank,
                alpha: self.alpha,
                targets: self.targets.clone(),
            }),
            precision: Precision::F32,
            seq_len: self.seq_len,
            batch: self.batch,
            grad_clip: self.grad_clip,
        }
    }
}

/// One supervised record: the loss counts the completion's tokens only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TextRecord {
    /// Text the model is given.
    pub prompt: String,
    /// Text the model learns to produce after it.
    pub completion: String,
}

/// SHA-256 of a shard as a job states it: the canonical JSON of its records.
#[must_use]
pub fn records_digest(records: &[TextRecord]) -> [u8; 32] {
    Sha256::digest(serde_json::to_vec(records).unwrap_or_default()).into()
}

/// Where a round starts.
#[derive(Debug, Clone)]
pub enum RoundStart {
    /// Fresh adapter weights drawn from this seed.
    Fresh {
        /// Seed of the adapter's initial weights.
        adapter_seed: u64,
    },
    /// The state a previous round ended at.
    Resume {
        /// Seed of the initial weights the run started from.
        adapter_seed: u64,
        /// The saved state ([`TrainState::payload`]).
        state: Vec<u8>,
        /// Steps the run had taken.
        steps_taken: u64,
    },
}

/// A round as a job asks for it.
#[derive(Debug, Clone)]
pub struct RoundRequest {
    /// The recipe.
    pub recipe: LoraRecipe,
    /// The shard.
    pub records: Vec<TextRecord>,
    /// Seed of batch selection.
    pub sample_seed: u64,
    /// Steps to take.
    pub steps: u64,
    /// Where the round starts.
    pub start: RoundStart,
}

/// What a round produced.
#[derive(Debug, Clone)]
pub struct RoundResult {
    /// The commitment a replay agrees on.
    pub commitment: [u8; 32],
    /// SHA-256 of the base model's weights file.
    pub base_sha256: [u8; 32],
    /// Root of the tokenized shard.
    pub data_root: [u8; 32],
    /// Hash of the engine recipe.
    pub recipe_hash: [u8; 32],
    /// Kernel class the steps ran on.
    pub kernel_class: String,
    /// Index of the first step.
    pub first_step: u64,
    /// Steps taken.
    pub steps: u64,
    /// Root of the state the round started from.
    pub start_root: [u8; 32],
    /// Root of the state it ended at.
    pub end_root: [u8; 32],
    /// Head of the round's step log.
    pub log_head: [u8; 32],
    /// The step log ([`praecise_train::steplog::StepLog::encode`]).
    pub log: Vec<u8>,
    /// Objective value of each step.
    pub losses: Vec<f64>,
    /// The state the round ended at ([`TrainState::payload`]).
    pub state: Vec<u8>,
    /// The adapter, as a GGUF `LoRA` file the runtime serves.
    pub adapter: Vec<u8>,
    /// SHA-256 of `adapter`.
    pub adapter_sha256: [u8; 32],
    /// Tokens the round ran forward and backward.
    pub trained_tokens: u64,
}

/// A base model loaded for training.
pub struct TrainModel {
    model: LlamaModel,
    arch: String,
    base_sha256: [u8; 32],
    kernel_class: KernelClass,
}

/// Models loaded for training on this node.
pub struct RoundTrainer {
    models: EngineModels<TrainModel>,
}

impl std::fmt::Debug for RoundTrainer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RoundTrainer")
            .field("loaded", &self.models.ids())
            .finish()
    }
}

impl Default for RoundTrainer {
    fn default() -> Self {
        Self::with_host(Arc::default())
    }
}

/// The CUDA device a round runs on, as a kernel class: the device's model
/// name fixes its architecture and SM count, which the matrix kernels choose
/// their split from.
#[cfg(feature = "cuda")]
fn cuda_kernel_class() -> Result<KernelClass> {
    let device = llama_cpp_2::list_llama_ggml_backend_devices()
        .into_iter()
        .find(|d| d.backend.eq_ignore_ascii_case("cuda"))
        .ok_or_else(|| {
            ModelError::InvalidModel(
                "training runs on a CUDA device, and this machine has none".into(),
            )
        })?;
    let arch: String = device
        .description
        .to_ascii_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    Ok(KernelClass::new(Backend::Cuda, arch.trim_matches('-')))
}

#[cfg(not(feature = "cuda"))]
fn cuda_kernel_class() -> Result<KernelClass> {
    Err(ModelError::InvalidModel(
        "training runs on a CUDA device, and this build has no CUDA support".into(),
    ))
}

impl RoundTrainer {
    /// A runtime that claims models and admits rounds through `host`.
    pub fn with_host(host: Arc<ModelHost>) -> Self {
        Self {
            models: EngineModels::new(Engine::PraeciseTask("training"), host),
        }
    }

    /// Load the base model in `gguf` as `model_id` for training, every layer
    /// on the CUDA device, with weights in the layout the backward pass reads.
    ///
    /// # Errors
    /// A build or machine without CUDA, [`ModelError::EngineConflict`] when
    /// another engine holds the model id, or the backend's refusal.
    pub fn load(&self, model_id: &str, gguf: &Path) -> Result<()> {
        let kernel_class = cuda_kernel_class()?;
        let bytes = std::fs::metadata(gguf)?.len();
        let base_sha256 = file_sha256(gguf)?;
        self.models.load_reserving(model_id, bytes, || {
            let backend = crate::runtime::llama_backend();
            let params = LlamaModelParams::default()
                .with_n_gpu_layers(u32::MAX)
                .with_use_extra_bufts(false);
            let model = crate::parse_jail::load_llama(&backend, gguf, &params)
                .map_err(|e| ModelError::InvalidModel(format!("training {model_id}: {e}")))?;
            let arch = model.meta_val_str("general.architecture").map_err(|e| {
                ModelError::InvalidModel(format!("{model_id} names no architecture: {e}"))
            })?;
            Ok(Arc::new(TrainModel {
                model,
                arch,
                base_sha256,
                kernel_class,
            }))
        })
    }

    /// Unload a model. `false` when it was not loaded.
    pub fn unload(&self, model_id: &str) -> bool {
        self.models.remove(model_id)
    }

    /// Models loaded for training.
    pub fn loaded(&self) -> Vec<String> {
        self.models.ids()
    }

    /// Whether `model_id` is loaded for training.
    pub fn contains(&self, model_id: &str) -> bool {
        self.models.contains(model_id)
    }

    /// Run one round on `model_id`.
    ///
    /// # Errors
    /// [`ModelError::InvalidInput`] for a request out of bounds, and the
    /// engine's refusals, among them any op that leaves the device or has no
    /// deterministic kernel there.
    pub async fn run_round(&self, model_id: &str, request: RoundRequest) -> Result<RoundResult> {
        validate(&request)?;
        self.models.run(model_id, move |m| round(m, &request)).await
    }
}

fn validate(request: &RoundRequest) -> Result<()> {
    request.recipe.validate()?;
    if request.records.is_empty() || request.records.len() > MAX_ROUND_RECORDS {
        return Err(ModelError::InvalidInput(
            "a round carries 1 to 4096 records".into(),
        ));
    }
    if request.steps == 0 || request.steps > MAX_ROUND_STEPS {
        return Err(ModelError::InvalidInput(
            "a round takes 1 to 10000 steps".into(),
        ));
    }
    if request.records.iter().any(|r| r.completion.is_empty()) {
        return Err(ModelError::InvalidInput(
            "every record has a completion".into(),
        ));
    }
    Ok(())
}

/// Root of a saved state ([`TrainState::payload`]).
///
/// # Errors
/// [`ModelError::InvalidInput`] for bytes that are not a saved state.
pub fn state_root(state: &[u8]) -> Result<[u8; 32]> {
    TrainState::from_payload(state)
        .map(|s| s.state_root().0)
        .map_err(|e| ModelError::InvalidInput(format!("not a saved training state: {e}")))
}

fn file_sha256(path: &Path) -> Result<[u8; 32]> {
    let mut f = std::fs::File::open(path)?;
    let mut h = Sha256::new();
    std::io::copy(&mut f, &mut h)?;
    Ok(h.finalize().into())
}

fn engine(e: praecise_train::Error) -> ModelError {
    match e {
        praecise_train::Error::Refused(m)
        | praecise_train::Error::Mismatch(m)
        | praecise_train::Error::Format(m) => ModelError::InferenceError(format!("training: {m}")),
        praecise_train::Error::Io(e) => ModelError::Io(e),
    }
}

/// A record as the engine trains on it: the prompt with the beginning-of-
/// sequence token, then the completion and the end-of-sequence token, the
/// completion's tokens as targets, cut to `seq_len`.
fn tokenize(model: &LlamaModel, record: &TextRecord, seq_len: usize) -> Result<SftExample> {
    let tok = |text: &str, bos: AddBos| {
        model
            .str_to_token(text, bos)
            .map_err(|e| ModelError::InvalidInput(format!("tokenizing a record: {e}")))
    };
    let prompt = tok(&record.prompt, AddBos::Always)?;
    let mut completion = tok(&record.completion, AddBos::Never)?;
    completion.push(model.token_eos());
    let mut tokens: Vec<i32> = prompt.iter().chain(&completion).map(|t| t.0).collect();
    let mut target_mask: Vec<bool> = (0..tokens.len())
        .map(|i| i >= prompt.len() && i > 0)
        .collect();
    tokens.truncate(seq_len);
    target_mask.truncate(seq_len);
    if tokens.len() < 2 || !target_mask.iter().any(|&m| m) {
        return Err(ModelError::InvalidInput(format!(
            "a record's prompt fills the {seq_len}-token sequence: no completion token is left to train on"
        )));
    }
    Ok(SftExample {
        tokens,
        target_mask,
    })
}

fn round(m: &TrainModel, request: &RoundRequest) -> Result<RoundResult> {
    let recipe = request.recipe.to_recipe();
    let seq_len = request.recipe.seq_len as usize;
    let records = request
        .records
        .iter()
        .map(|r| tokenize(&m.model, r, seq_len))
        .collect::<Result<Vec<_>>>()?;
    let probe: Vec<i32> = records[0]
        .tokens
        .iter()
        .copied()
        .take(PROBE_TOKENS)
        .collect();

    let dir = tempfile::Builder::new()
        .prefix("tenzro-training-")
        .tempdir()?;
    let init = dir.path().join("init.gguf");
    let (adapter_seed, resume) = match &request.start {
        RoundStart::Fresh { adapter_seed } => (*adapter_seed, None),
        RoundStart::Resume {
            adapter_seed,
            state,
            steps_taken,
        } => (*adapter_seed, Some((state, *steps_taken))),
    };
    let spec = recipe
        .adapter
        .clone()
        .ok_or_else(|| ModelError::InvalidInput("no adapter".into()))?;
    let weights = init_lora_weights(&m.model, &spec, adapter_seed).map_err(engine)?;
    llama_cpp_2::train::write_lora_gguf(&init, &m.arch, spec.alpha, &weights).map_err(|e| {
        ModelError::InferenceError(format!("training: writing the initial adapter: {e}"))
    })?;

    let backend = crate::runtime::llama_backend();
    let config = EngineConfig {
        n_ctx: request.recipe.seq_len,
        n_threads: std::thread::available_parallelism()
            .map_or(4, |n| i32::try_from(n.get()).unwrap_or(4)),
        deterministic: Some(Backend::Cuda),
        pooling: None,
    };
    let mut trainer =
        LoraTrainer::new(&backend, &m.model, &init, recipe.clone(), config).map_err(engine)?;
    if let Some((state, steps_taken)) = resume {
        let state = TrainState::from_payload(state).map_err(engine)?;
        trainer.load_state(&state, steps_taken).map_err(engine)?;
    }
    let base_root = praecise_train::hash::Digest(m.base_sha256);
    let kernel_class = m.kernel_class.id();
    let outcome = run_sft_round(
        &mut trainer,
        &SftRound {
            base_root,
            sample_seed: request.sample_seed,
            kernel_class: kernel_class.clone(),
            steps: request.steps,
            records: &records,
            probe: &probe,
        },
    )
    .map_err(engine)?;
    let state = trainer.state().map_err(engine)?.payload();
    let adapter_path = dir.path().join("adapter.gguf");
    let adapter_sha256 = trainer
        .export_lora(&adapter_path, &m.arch)
        .map_err(engine)?;
    let adapter = std::fs::read(&adapter_path)?;

    Ok(RoundResult {
        commitment: outcome.commitment().0,
        base_sha256: m.base_sha256,
        data_root: outcome.data_root.0,
        recipe_hash: outcome.recipe_hash.0,
        kernel_class,
        first_step: outcome.first_step,
        steps: outcome.steps(),
        start_root: outcome.start_root.0,
        end_root: outcome.end_root.0,
        log_head: outcome.log.head().0,
        log: outcome.log.encode(),
        losses: outcome.losses(),
        state,
        adapter,
        adapter_sha256: adapter_sha256.0,
        trained_tokens: request.steps
            * u64::from(request.recipe.batch)
            * u64::from(request.recipe.seq_len),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn recipe() -> LoraRecipe {
        LoraRecipe {
            rank: 8,
            alpha: 16.0,
            targets: vec!["attn_q.weight".into(), "attn_v.weight".into()],
            lr: 1e-3,
            beta1: 0.9,
            beta2: 0.999,
            eps: 1e-8,
            weight_decay: 0.0,
            seq_len: 64,
            batch: 2,
            grad_clip: 1.0,
        }
    }

    #[test]
    fn recipes_are_bounded_and_map_to_an_adapter_recipe() {
        recipe().validate().unwrap();
        let r = recipe().to_recipe();
        assert_eq!(r.objective, Objective::Sft);
        assert_eq!(r.adapter.unwrap().rank, 8);
        for broken in [
            LoraRecipe {
                rank: 0,
                ..recipe()
            },
            LoraRecipe {
                targets: vec![],
                ..recipe()
            },
            LoraRecipe {
                seq_len: 1,
                ..recipe()
            },
            LoraRecipe {
                batch: 0,
                ..recipe()
            },
            LoraRecipe {
                lr: 0.0,
                ..recipe()
            },
            LoraRecipe {
                lr: f32::NAN,
                ..recipe()
            },
            LoraRecipe {
                beta2: 1.0,
                ..recipe()
            },
        ] {
            assert!(broken.validate().is_err(), "{broken:?}");
        }
    }

    #[test]
    fn requests_are_bounded() {
        let record = TextRecord {
            prompt: "a".into(),
            completion: "b".into(),
        };
        let ok = RoundRequest {
            recipe: recipe(),
            records: vec![record.clone()],
            sample_seed: 1,
            steps: 3,
            start: RoundStart::Fresh { adapter_seed: 7 },
        };
        validate(&ok).unwrap();
        assert!(
            validate(&RoundRequest {
                records: vec![],
                ..ok.clone()
            })
            .is_err()
        );
        assert!(
            validate(&RoundRequest {
                steps: 0,
                ..ok.clone()
            })
            .is_err()
        );
        assert!(
            validate(&RoundRequest {
                records: vec![TextRecord {
                    completion: String::new(),
                    ..record
                }],
                ..ok
            })
            .is_err()
        );
    }

    #[test]
    fn a_shard_digest_binds_every_record_in_order() {
        let a = TextRecord {
            prompt: "p".into(),
            completion: "c".into(),
        };
        let b = TextRecord {
            prompt: "p".into(),
            completion: "d".into(),
        };
        assert_ne!(
            records_digest(&[a.clone(), b.clone()]),
            records_digest(&[b, a])
        );
    }

    #[cfg(not(feature = "cuda"))]
    #[test]
    fn a_build_without_cuda_refuses_to_train() {
        let rt = RoundTrainer::default();
        let err = rt.load("m", Path::new("/nonexistent.gguf")).unwrap_err();
        assert!(err.to_string().contains("CUDA"), "{err}");
        assert!(!rt.contains("m"));
    }
}
