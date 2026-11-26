//! Inference sessions whose KV cache outlives a turn and can move between
//! nodes, and model weights held on standby.
//!
//! A continuity session keeps one context of its own on the single-context
//! path. Each turn prefills only the tokens its cache does not already hold,
//! so a multi-turn conversation never re-runs prefill over its history. The
//! positions a turn appended are exported as an incremental, integrity-checked
//! blob; another node serving the same weights rebuilds the session from the
//! chain of blobs and keeps decoding without prefill. A chain built from other
//! weights is refused before any cell is installed.
//!
//! A model on the batch engine serves sessions too. The engine holds a
//! sequence's cache while its turn runs and afterwards keeps it as the slot's
//! reusable prefix, which the session's next turn extends. A checkpoint there
//! is the cache of a turn's own sequence, copied out between two decode steps
//! while the turn runs: the conversation through that turn's prompt, and what
//! of its reply was decoded by then. It starts a chain of its own, at most
//! once per configured interval. A successor seeds the chain into a slot of
//! its engine, and the next turn reuses the positions its prompt shares with
//! it and prefills the rest, the last reply among it. A template may render
//! the end of a prompt differently from the same turn in a later history; an
//! attention cache is cut back to where they part, and a cache with recurrent
//! state cannot be, so on a model with recurrent layers such a turn has no
//! checkpoint and says so.
//!
//! Standby weights are staged in host memory, with no engine context and no
//! device memory, so activating them on a failover or a surge costs graph and
//! buffer setup rather than a read from storage.

use super::*;
use praecise_runtime::batching::SequenceResume;
use praecise_runtime::{ImportChain, KvBlob, ModelFingerprint, SequenceExport, SequenceImport};
use std::sync::atomic::AtomicU64;
use std::time::Duration;

/// The sequence a session decodes into.
const SEQ: i32 = 0;
/// The sequence reserved for staging exports and imports; never decoded into.
const SCRATCH: i32 = 1;

/// Whether a successor could take the session over after a turn without
/// reading the conversation again.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TurnCheckpoint {
    /// A checkpoint of this turn can be exported: the conversation through
    /// this turn's prompt, of which the next turn reuses what its own prompt
    /// shares with it.
    Ready,
    /// None was taken because the last one is newer than the checkpoint
    /// interval; that one, which ends before this turn, is what a successor
    /// gets.
    NotDue,
    /// Taking one failed, for the reason given. A successor replays the
    /// conversation from its messages.
    Unavailable(String),
}

/// What one session turn produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionTurn {
    pub text: String,
    /// Tokens in the rendered conversation this turn.
    pub prompt_tokens: u32,
    /// Of those, how many the session's cache already held (not prefilled).
    pub reused_tokens: u32,
    pub completion_tokens: u32,
    /// Whether this turn left a checkpoint.
    pub checkpoint: TurnCheckpoint,
}

/// One exported piece of a session's cache.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportedDelta {
    /// Which chain the blob extends. A session whose history was rewritten
    /// below what it had exported starts a new chain from position 0.
    pub chain: u32,
    /// The encoded blob (see `praecise_runtime::KvBlob`).
    pub blob: Vec<u8>,
}

/// An engine that serves sessions whose KV cache can be exported and rebuilt.
/// Every call blocks; callers run it off the async runtime.
pub trait SequenceEngine: Send + Sync {
    /// Identity of the weights `model_id` is served from here.
    fn fingerprint(&self, model_id: &str) -> Result<ModelFingerprint>;

    /// Run one turn of `session` over the whole conversation `messages`,
    /// prefilling only what the session's cache does not hold.
    fn turn(
        &self,
        model_id: &str,
        session: &str,
        messages: &[ChatMessage],
        config: &GenerationConfig,
    ) -> Result<SessionTurn>;

    /// The positions `session` appended since its last export, or `None` when
    /// it holds nothing its successor has not been sent.
    fn export_delta(&self, session: &str) -> Result<Option<ExportedDelta>>;

    /// Start `session`'s export over from position 0, as a new chain: its
    /// successor changed and holds nothing of it yet.
    fn restart_export(&self, session: &str) -> Result<()>;

    /// Rebuild `session` on `model_id` from a chain of encoded blobs, in order,
    /// replacing any state held for it. Returns the positions rebuilt.
    fn import_chain(&self, model_id: &str, session: &str, chain: &[Vec<u8>]) -> Result<u32>;

    /// Whether this engine holds `session`.
    fn has_session(&self, session: &str) -> bool;

    /// Drop `session` and its cache.
    fn close_session(&self, session: &str);
}

/// A model held on standby: resident in host memory, not serving.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct StandbyModel {
    pub model_id: String,
    pub bytes: u64,
    /// Whether the pages are locked in memory (false: resident, evictable).
    pub pinned: bool,
}

/// Session and standby state of one runtime.
#[derive(Default)]
pub(super) struct SessionStore {
    /// Weights file of each loaded model, for its fingerprint.
    paths: DashMap<String, PathBuf>,
    fingerprints: DashMap<String, ModelFingerprint>,
    #[cfg(unix)]
    staged: DashMap<String, Arc<praecise_runtime::StagedWeights>>,
    /// Sessions on the single-context path.
    sessions: DashMap<String, Arc<std::sync::Mutex<LlamaSession>>>,
    /// Sessions on a batch engine.
    batched: DashMap<String, Arc<std::sync::Mutex<BatchedSession>>>,
    /// Tokenizer of each batched model that serves sessions: its vocabulary
    /// and chat template, without weights.
    vocabs: DashMap<String, Arc<LlamaModel>>,
    /// Least time, in milliseconds, between two checkpoints of one batched
    /// session.
    checkpoint_interval_ms: AtomicU64,
    /// Models whose missing checkpoint has been reported.
    unchecked_reported: dashmap::DashSet<String>,
}

/// A session on a batch engine.
struct BatchedSession {
    model_id: String,
    /// Chain of `latest`: every checkpoint starts a chain of its own.
    chain: u32,
    /// The last checkpoint taken.
    latest: Option<Arc<Vec<u8>>>,
    /// Whether `latest` was exported since it was taken.
    exported: bool,
    taken_at: Option<std::time::Instant>,
    /// A chain taken over from the session's previous node, seeded into the
    /// engine by the next turn.
    imported: Option<Vec<Vec<u8>>>,
}

impl BatchedSession {
    fn new(model_id: &str) -> Self {
        Self {
            model_id: model_id.to_string(),
            chain: 0,
            latest: None,
            exported: false,
            taken_at: None,
            imported: None,
        }
    }
}

/// One session's context and token history.
///
/// `ctx` borrows the model inside `owner`; the `Arc` keeps that model alive
/// and in place for as long as the context exists, and field order drops the
/// context first.
struct LlamaSession {
    ctx: LlamaContext<'static>,
    model_id: String,
    /// The token at each cached position.
    tokens: Vec<LlamaToken>,
    export: SequenceExport,
    chain: u32,
    owner: Arc<tokio::sync::Mutex<LoadedModel>>,
}

// SAFETY: a session is only ever used under its own mutex, and the model its
// context reads is kept alive by `owner`.
unsafe impl Send for LlamaSession {}

impl SessionStore {
    pub(super) fn record_path(&self, model_id: &str, path: &Path) {
        self.paths.insert(model_id.to_string(), path.to_path_buf());
    }

    /// Drop everything held for an unloaded model.
    pub(super) fn forget_model(&self, model_id: &str) {
        self.paths.remove(model_id);
        self.fingerprints.remove(model_id);
        self.vocabs.remove(model_id);
        self.sessions
            .retain(|_, s| s.lock().map(|s| s.model_id != model_id).unwrap_or(false));
        self.batched
            .retain(|_, s| s.lock().map(|s| s.model_id != model_id).unwrap_or(false));
    }

    /// The staged weights for `model_id` at `path`, if they are staged.
    #[cfg(unix)]
    pub(super) fn staged_for(
        &self,
        model_id: &str,
        path: &Path,
    ) -> Option<Arc<praecise_runtime::StagedWeights>> {
        self.staged
            .get(model_id)
            .filter(|s| s.path() == path)
            .map(|s| s.clone())
    }
}

fn session_err(m: impl Into<String>) -> ModelError {
    ModelError::InferenceError(m.into())
}

impl ModelRuntime {
    /// Take a batched session's checkpoint at most once per `interval`. A turn
    /// that ends sooner after the last one is not checkpointed; the next turn
    /// past the interval is.
    pub fn set_session_checkpoint_interval(&self, interval: Duration) {
        let ms = u64::try_from(interval.as_millis()).unwrap_or(u64::MAX);
        self.sessions
            .checkpoint_interval_ms
            .store(ms, Ordering::Relaxed);
    }

    /// Identity of the weights at `path`, as `model_id` is served from them.
    pub(super) async fn weights_fingerprint(
        &self,
        model_id: &str,
        path: &Path,
    ) -> Result<ModelFingerprint> {
        if let Some(f) = self.sessions.fingerprints.get(model_id) {
            return Ok(*f);
        }
        let file = path.to_path_buf();
        let f = tokio::task::spawn_blocking(move || ModelFingerprint::of_file(&file))
            .await
            .map_err(|e| ModelError::Other(format!("fingerprinting {model_id}: {e}")))?
            .map_err(|e| ModelError::Other(format!("fingerprinting {model_id}: {e}")))?;
        self.sessions.fingerprints.insert(model_id.to_string(), f);
        Ok(f)
    }

    /// Stage `model_id`'s weights at `path` in host memory, without loading
    /// them into the engine. A later load of the same file activates them.
    #[cfg(unix)]
    pub fn stage_standby(&self, model_id: &str, path: &Path) -> Result<StandbyModel> {
        let staged = praecise_runtime::StagedWeights::stage(path)
            .map_err(|e| ModelError::Other(format!("staging {model_id}: {e}")))?;
        self.sessions.fingerprints.insert(
            model_id.to_string(),
            ModelFingerprint::of_bytes(staged.bytes()),
        );
        let info = StandbyModel {
            model_id: model_id.to_string(),
            bytes: staged.len() as u64,
            pinned: staged.pinned(),
        };
        self.sessions
            .staged
            .insert(model_id.to_string(), Arc::new(staged));
        Ok(info)
    }

    /// Standby staging needs `mmap`/`mlock`, which this platform lacks.
    #[cfg(not(unix))]
    pub fn stage_standby(&self, model_id: &str, _path: &Path) -> Result<StandbyModel> {
        Err(ModelError::Other(format!(
            "staging {model_id}: standby weights need a Unix host"
        )))
    }

    /// Models held on standby and not yet activated.
    pub fn standby_models(&self) -> Vec<StandbyModel> {
        #[cfg(unix)]
        {
            self.sessions
                .staged
                .iter()
                .filter(|s| !self.is_loaded(s.key()))
                .map(|s| StandbyModel {
                    model_id: s.key().clone(),
                    bytes: s.len() as u64,
                    pinned: s.pinned(),
                })
                .collect()
        }
        #[cfg(not(unix))]
        {
            Vec::new()
        }
    }

    /// The entry `model_id` serves sessions from: its single context or its
    /// batch engine.
    fn session_entry(&self, model_id: &str) -> Result<Arc<LoadedEntry>> {
        crate::access::check(model_id)?;
        let entry = self
            .loaded_models
            .get(model_id)
            .ok_or_else(|| ModelError::Other(format!("Model {model_id} not loaded")))?
            .value()
            .clone();
        match entry.as_ref() {
            LoadedEntry::Serial(_) | LoadedEntry::Batched(_) => Ok(entry),
            LoadedEntry::Hosted(backend, ..) => Err(session_err(format!(
                "model {model_id} is served by the hosted {backend} engine, which cannot \
                 export a session's cache"
            ))),
            LoadedEntry::Pipeline(_) => Err(session_err(format!(
                "model {model_id} is served across a layer pipeline, which cannot export a session's cache"
            ))),
        }
    }

    /// The tokenizer of batched `model_id`, loaded from its weights file
    /// without the weights.
    pub(super) fn session_vocab(&self, model_id: &str) -> Result<Arc<LlamaModel>> {
        if let Some(v) = self.sessions.vocabs.get(model_id) {
            return Ok(v.clone());
        }
        let path = self
            .sessions
            .paths
            .get(model_id)
            .map(|p| p.clone())
            .ok_or_else(|| ModelError::Other(format!("Model {model_id} not loaded")))?;
        let params = LlamaModelParams::default().with_vocab_only(true);
        let vocab = crate::parse_jail::load_llama(&self.backend, &path, &params)
            .map_err(|e| ModelError::Other(format!("loading the tokenizer of {model_id}: {e}")))?;
        let vocab = Arc::new(vocab);
        self.sessions
            .vocabs
            .insert(model_id.to_string(), vocab.clone());
        Ok(vocab)
    }

    fn batched_handle(&self, session: &str) -> Option<Arc<std::sync::Mutex<BatchedSession>>> {
        self.sessions.batched.get(session).map(|s| s.clone())
    }

    /// One turn of a session on `engine`.
    fn batched_turn(
        &self,
        engine: &BatchEngine,
        model_id: &str,
        session: &str,
        messages: &[ChatMessage],
        config: &GenerationConfig,
    ) -> Result<SessionTurn> {
        let handle = self
            .sessions
            .batched
            .entry(session.to_string())
            .or_insert_with(|| Arc::new(std::sync::Mutex::new(BatchedSession::new(model_id))))
            .clone();
        let mut s = handle
            .lock()
            .map_err(|_| session_err(format!("session {session} is poisoned")))?;
        if s.model_id != model_id {
            return Err(session_err(format!(
                "session {session} runs {}, not {model_id}",
                s.model_id
            )));
        }
        let vocab = self.session_vocab(model_id)?;
        let template = ChatTemplateSource::from_model(&vocab).ok();
        let turn = crate::tool_grammar::render_turn(
            &self.catalog.current(),
            template.as_ref(),
            model_id,
            messages,
            &[],
            config,
        )?;
        let prompt = turn.prompt;
        let wanted = vocab
            .str_to_token(&prompt, AddBos::Always)
            .map_err(|e| ModelError::Other(format!("Tokenization failed: {e}")))?;
        if wanted.is_empty() {
            return Err(session_err("the conversation rendered to no tokens"));
        }
        let mut config = self.batched_config(engine, &turn.config);
        // The session's slot prefix is reused by its own turns only.
        config.cache_salt = Some(format!("session/{session}"));
        // Every position this turn decodes that its prompt does not end up
        // reusing, whichever request of the turn decoded it.
        let mut prefilled = 0u32;
        // A cache with recurrent state holds one position only.
        let cuttable = !(vocab.is_recurrent() || vocab.is_hybrid());
        if let Some(chain) = s.imported.take() {
            prefilled += seed_chain(engine, session, &chain, &wanted, &config, cuttable)?;
        }

        let interval =
            Duration::from_millis(self.sessions.checkpoint_interval_ms.load(Ordering::Relaxed));
        let due = s.taken_at.is_none_or(|t| t.elapsed() >= interval);
        let (result_tx, result_rx) = tokio::sync::oneshot::channel();
        let request = BatchRequest {
            prompt: BatchPrompt::Raw(prompt),
            config: config.clone(),
            token_tx: None,
            result_tx,
            media: Vec::new(),
        };
        // A due checkpoint is copied out of this turn's own sequence: the
        // export travels with the request, so it holds the prompt however
        // soon the reply ends.
        let exporting = if due {
            Some(engine.submit_exporting(request)?.1)
        } else {
            engine.submit(request)?;
            None
        };
        let result = result_rx
            .blocking_recv()
            .map_err(|_| ModelError::Other("batch engine dropped the request".into()))?
            .map_err(ModelError::from)?;
        let copied = exporting.map(|exported| {
            exported
                .blocking_recv()
                .map_err(|_| ModelError::Other("batch engine dropped the checkpoint".into()))?
                .map_err(|e| session_err(format!("the turn's cache was not copied: {e}")))
        });
        prefilled += result.input_tokens.saturating_sub(result.cached_tokens);
        let mut checkpoint = TurnCheckpoint::NotDue;
        if let Some(copied) = copied {
            // A checkpoint is kept only for what the next turn can take from
            // it: its history is rendered here, through this turn's reply, and
            // compared with the positions copied.
            let kept = copied.and_then(|blob| {
                let mut through_reply = messages.to_vec();
                through_reply.push(ChatMessage {
                    role: "assistant".into(),
                    content: result.text.clone(),
                    ..Default::default()
                });
                let history = crate::tool_grammar::render_history(
                    &self.catalog.current(),
                    template.as_ref(),
                    model_id,
                    &through_reply,
                    &config,
                )?;
                let next: Vec<i32> = vocab
                    .str_to_token(&history, AddBos::Always)
                    .map_err(|e| ModelError::Other(format!("Tokenization failed: {e}")))?
                    .iter()
                    .map(|t| t.0)
                    .collect();
                let copied = KvBlob::decode(&blob)
                    .map_err(|e| session_err(e.to_string()))?
                    .tokens;
                checkpoint_reuse(&copied, &next, cuttable).map_err(session_err)?;
                Ok(blob)
            });
            match kept {
                Ok(blob) => {
                    s.latest = Some(Arc::new(blob));
                    s.exported = false;
                    s.chain += 1;
                    s.taken_at = Some(std::time::Instant::now());
                    checkpoint = TurnCheckpoint::Ready;
                }
                // The next turn is checkpointed instead.
                Err(e) => {
                    checkpoint = TurnCheckpoint::Unavailable(e.to_string());
                    if self
                        .sessions
                        .unchecked_reported
                        .insert(model_id.to_string())
                    {
                        warn!(
                            model = model_id,
                            session,
                            reason = %e,
                            "a turn of a batched session has no checkpoint; a successor \
                             replays the conversation from its messages instead of its cache"
                        );
                    } else {
                        debug!(session, error = %e, "no checkpoint of this turn");
                    }
                }
            }
        }
        Ok(SessionTurn {
            text: result.text,
            prompt_tokens: result.input_tokens,
            reused_tokens: result.input_tokens.saturating_sub(prefilled),
            completion_tokens: result.output_tokens,
            checkpoint,
        })
    }

    /// A fresh session context on `owner`'s model.
    fn new_session(
        &self,
        model_id: &str,
        owner: Arc<tokio::sync::Mutex<LoadedModel>>,
    ) -> Result<LlamaSession> {
        let fingerprint = self.fingerprint(model_id)?;
        let ctx = {
            let loaded = owner.blocking_lock();
            // SAFETY: the model lives inside `owner`'s allocation, which the
            // session holds for as long as the context exists.
            let model: &'static LlamaModel = unsafe { &*std::ptr::addr_of!(loaded.model) };
            let n_ctx = loaded.context_length.max(1);
            let arch = Self::model_arch(model);
            let params = Self::tuned_context_params_for(n_ctx, arch.as_deref())
                .with_n_seq_max(2)
                .with_kv_unified(true);
            model
                .new_context(&loaded.backend, params)
                .map_err(|e| ModelError::Other(format!("Failed to create context: {e}")))?
        };
        Ok(LlamaSession {
            ctx,
            model_id: model_id.to_string(),
            tokens: Vec::new(),
            export: SequenceExport::new(fingerprint, SEQ, SCRATCH),
            chain: 0,
            owner,
        })
    }

    fn session_handle(&self, session: &str) -> Result<Arc<std::sync::Mutex<LlamaSession>>> {
        self.sessions
            .sessions
            .get(session)
            .map(|s| s.clone())
            .ok_or_else(|| session_err(format!("session {session} is not held here")))
    }
}

/// The tokens a chain of encoded blobs holds, checked link by link against
/// `weights`.
fn chain_tokens(weights: ModelFingerprint, chain: &[Vec<u8>]) -> Result<Vec<i32>> {
    let mut import = ImportChain::new(weights);
    let mut tokens = Vec::new();
    for encoded in chain {
        let blob = KvBlob::decode(encoded).map_err(|e| session_err(e.to_string()))?;
        import.check(&blob).map_err(chain_err)?;
        let digest = KvBlob::digest_of(encoded).map_err(|e| session_err(e.to_string()))?;
        tokens.extend_from_slice(&blob.tokens);
        import.advance(&blob, digest);
    }
    Ok(tokens)
}

fn chain_err(e: praecise_runtime::Error) -> ModelError {
    match e {
        praecise_runtime::Error::ModelMismatch { expected, found } => ModelError::InferenceError(
            format!("KV chain was built with weights {found}, this node serves {expected}"),
        ),
        other => session_err(other.to_string()),
    }
}

/// How many positions the next turn takes from a checkpoint holding the tokens
/// `copied`, when its history renders as `next`: the positions the two share
/// from the start. All of them when the history extends the checkpoint. Fewer
/// when the template renders the end of the checkpointed prompt differently
/// in the history; an attention cache (`cuttable`) is then cut back to where
/// they part, and a cache with recurrent state, which holds its last position
/// only, cannot be used at all. The error is the reason no checkpoint is kept.
fn checkpoint_reuse(
    copied: &[i32],
    next: &[i32],
    cuttable: bool,
) -> std::result::Result<usize, String> {
    let shared = copied.iter().zip(next).take_while(|(a, b)| a == b).count();
    if shared == copied.len() && shared > 0 {
        return Ok(shared);
    }
    if shared == 0 {
        return Err("the next turn's history shares no position with this turn's cache".into());
    }
    if !cuttable {
        return Err(format!(
            "the next turn's history parts from this turn's cache at position {shared} of {}, \
             and a cache with recurrent state cannot be cut back",
            copied.len()
        ));
    }
    Ok(shared)
}

/// The token to feed after seeding a chain holding the tokens `held` for a
/// turn whose prompt is `wanted`, or `None` when the chain is of no use to
/// it. A prompt that extends the chain continues it with its next token. A
/// prompt that parts from the chain earlier still takes the positions they
/// share when the cache can be cut back (`cuttable`): the token fed is then
/// the prompt's first token after those, which lands after the chain and is
/// cut away with everything past where they part.
fn seed_token(held: &[i32], wanted: &[i32], cuttable: bool) -> Option<i32> {
    let shared = held.iter().zip(wanted).take_while(|(a, b)| a == b).count();
    if shared == 0 || shared >= wanted.len() {
        return None;
    }
    (shared == held.len() || cuttable).then(|| wanted[shared])
}

/// Rebuild `chain` in a slot of `engine` and leave it there as that slot's
/// cached prefix, for the turn about to run on `wanted`.
///
/// The engine continues a rebuilt sequence from the token after the chain, so
/// one token is fed ([`seed_token`]) and the one sampled after it dropped. The
/// turn then reuses the positions its prompt shares with the slot's prefix and
/// prefills the rest. A chain the prompt can take nothing from is not rebuilt,
/// and the turn prefills in full. Returns the positions decoded here: the one
/// token fed, or none.
fn seed_chain(
    engine: &BatchEngine,
    session: &str,
    chain: &[Vec<u8>],
    wanted: &[LlamaToken],
    config: &GenerationConfig,
    cuttable: bool,
) -> Result<u32> {
    let weights = engine.fingerprint().ok_or_else(|| {
        session_err(format!(
            "the engine of {} cannot import a KV chain",
            engine.model_id()
        ))
    })?;
    let held = chain_tokens(weights, chain)?;
    let wanted: Vec<i32> = wanted.iter().map(|t| t.0).collect();
    let Some(next_token) = seed_token(&held, &wanted, cuttable) else {
        warn!(
            session,
            positions = held.len(),
            "the conversation can take nothing from the session's checkpoint; the turn prefills it in full"
        );
        return Ok(0);
    };
    let mut step = config.clone();
    step.max_tokens = 1;
    step.stop.clear();
    let (result_tx, result_rx) = tokio::sync::oneshot::channel();
    engine.resume(SequenceResume {
        blobs: chain.to_vec(),
        next_token,
        generated: String::new(),
        config: step,
        token_tx: None,
        result_tx,
    })?;
    result_rx
        .blocking_recv()
        .map_err(|_| ModelError::Other("batch engine dropped the resume".into()))?
        .map_err(chain_err)?;
    Ok(1)
}

/// Decode `tokens` into the session sequence from position `start`, in
/// `n_batch`-sized calls. Returns the logits row of the last token.
fn prefill_from(
    ctx: &mut LlamaContext<'static>,
    start: usize,
    tokens: &[LlamaToken],
) -> Result<i32> {
    let n_batch = (ctx.n_batch() as usize).max(1);
    let mut batch = LlamaBatch::new(n_batch.min(tokens.len()), 1);
    let mut done = 0usize;
    let mut row = 0;
    while done < tokens.len() {
        let end = (done + n_batch).min(tokens.len());
        batch.clear();
        for (i, t) in tokens[done..end].iter().enumerate() {
            let last = done + i + 1 == tokens.len();
            batch
                .add(*t, (start + done + i) as i32, &[SEQ], last)
                .map_err(|e| ModelError::Other(format!("Batch add failed: {e}")))?;
            if last {
                row = i as i32;
            }
        }
        ctx.decode(&mut batch)
            .map_err(|e| ModelError::Other(format!("Prompt decode failed: {e}")))?;
        done = end;
    }
    Ok(row)
}

impl SequenceEngine for ModelRuntime {
    fn fingerprint(&self, model_id: &str) -> Result<ModelFingerprint> {
        if let Some(entry) = self.loaded_models.get(model_id)
            && let LoadedEntry::Batched(engine) = entry.value().as_ref()
            && let Some(f) = engine.fingerprint()
        {
            return Ok(f);
        }
        if let Some(f) = self.sessions.fingerprints.get(model_id) {
            return Ok(*f);
        }
        let path = self
            .sessions
            .paths
            .get(model_id)
            .map(|p| p.clone())
            .ok_or_else(|| ModelError::Other(format!("Model {model_id} not loaded")))?;
        let f = ModelFingerprint::of_file(&path)
            .map_err(|e| ModelError::Other(format!("fingerprinting {model_id}: {e}")))?;
        self.sessions.fingerprints.insert(model_id.to_string(), f);
        Ok(f)
    }

    fn turn(
        &self,
        model_id: &str,
        session: &str,
        messages: &[ChatMessage],
        config: &GenerationConfig,
    ) -> Result<SessionTurn> {
        let entry = self.session_entry(model_id)?;
        let owner = match entry.as_ref() {
            LoadedEntry::Serial(m) => m.clone(),
            LoadedEntry::Batched(engine) => {
                return self.batched_turn(engine, model_id, session, messages, config);
            }
            LoadedEntry::Hosted(..) | LoadedEntry::Pipeline(_) => {
                return Err(session_err(format!(
                    "model {model_id} cannot hold a session"
                )));
            }
        };
        let handle = match self.sessions.sessions.get(session) {
            Some(h) => h.clone(),
            None => {
                let fresh = Arc::new(std::sync::Mutex::new(
                    self.new_session(model_id, owner.clone())?,
                ));
                self.sessions
                    .sessions
                    .entry(session.to_string())
                    .or_insert(fresh)
                    .clone()
            }
        };
        let mut s = handle
            .lock()
            .map_err(|_| session_err(format!("session {session} is poisoned")))?;
        if s.model_id != model_id {
            return Err(session_err(format!(
                "session {session} runs {}, not {model_id}",
                s.model_id
            )));
        }
        // The model mutex serialises this session's decode with every other
        // request on the single-context path.
        let loaded = owner.blocking_lock();
        let template = ChatTemplateSource::from_model(&loaded.model).ok();
        let turn = crate::tool_grammar::render_turn(
            &self.catalog.current(),
            template.as_ref(),
            model_id,
            messages,
            &[],
            config,
        )?;
        let (prompt, config) = (turn.prompt, &turn.config);
        let wanted = loaded
            .model
            .str_to_token(&prompt, AddBos::Always)
            .map_err(|e| ModelError::Other(format!("Tokenization failed: {e}")))?;
        if wanted.is_empty() {
            return Err(session_err("the conversation rendered to no tokens"));
        }
        let n_ctx = s.ctx.n_ctx() as usize;
        if wanted.len() + config.max_tokens as usize > n_ctx {
            return Err(session_err(format!(
                "session {session} needs {} positions, the context holds {n_ctx}",
                wanted.len() + config.max_tokens as usize
            )));
        }

        // Keep the longest cached prefix of the conversation, and always
        // re-decode at least its last token so there are logits to sample.
        let held = s
            .tokens
            .iter()
            .zip(&wanted)
            .take_while(|(a, b)| a == b)
            .count();
        let keep = held.min(wanted.len() - 1);
        if keep < s.tokens.len() {
            s.ctx
                .clear_kv_cache_seq(Some(SEQ as u32), Some(keep as u32), None)
                .map_err(|e| session_err(e.to_string()))?;
            s.tokens.truncate(keep);
            if (keep as u32) < s.export.exported_to() {
                // History below the exported prefix changed: what the
                // successor holds no longer extends, so start a new chain.
                let fingerprint = self.fingerprint(model_id)?;
                s.export = SequenceExport::new(fingerprint, SEQ, SCRATCH);
                s.chain += 1;
            }
        }
        let fresh = &wanted[keep..];
        let mut row = prefill_from(&mut s.ctx, keep, fresh)?;
        s.tokens.extend_from_slice(fresh);

        let mut sampler = build_sampler_chain_with_grammar(config, None, loaded.model.n_vocab());
        let mut stream = StopStream::new(stops_with_terminators(&config.stop))
            .reading(config.reply_format.as_ref());
        let mut decoder = encoding_rs::UTF_8.new_decoder();
        let mut batch = LlamaBatch::new(1, 1);
        let mut completion = 0u32;
        while completion < config.max_tokens {
            let token = sampler.sample(&s.ctx, row);
            sampler.accept(token);
            if loaded.model.is_eog_token(token) {
                break;
            }
            completion += 1;
            if let Ok(piece) = loaded.model.token_to_piece(token, &mut decoder, true, None)
                && !stream.push(&piece, None)
            {
                break;
            }
            let pos = s.tokens.len() as i32;
            batch.clear();
            batch
                .add(token, pos, &[SEQ], true)
                .map_err(|e| ModelError::Other(format!("Batch add failed: {e}")))?;
            s.ctx
                .decode(&mut batch)
                .map_err(|e| ModelError::Other(format!("Decode failed: {e}")))?;
            s.tokens.push(token);
            row = 0;
            if stream.hit_stop() {
                break;
            }
        }
        let text = stream.finish_parts(None).map_err(ModelError::from)?.text;
        Ok(SessionTurn {
            text,
            prompt_tokens: wanted.len() as u32,
            reused_tokens: keep as u32,
            completion_tokens: completion,
            // This session's own context is copied out whenever it is asked for.
            checkpoint: TurnCheckpoint::Ready,
        })
    }

    fn export_delta(&self, session: &str) -> Result<Option<ExportedDelta>> {
        if let Some(handle) = self.batched_handle(session) {
            let mut s = handle
                .lock()
                .map_err(|_| session_err(format!("session {session} is poisoned")))?;
            if s.exported {
                return Ok(None);
            }
            let Some(latest) = s.latest.clone() else {
                return Ok(None);
            };
            s.exported = true;
            return Ok(Some(ExportedDelta {
                chain: s.chain,
                blob: latest.as_ref().clone(),
            }));
        }
        let handle = self.session_handle(session)?;
        let mut guard = handle
            .lock()
            .map_err(|_| session_err(format!("session {session} is poisoned")))?;
        let s = &mut *guard;
        let owner = s.owner.clone();
        let _serial = owner.blocking_lock();
        let blob = s
            .export
            .export(&mut s.ctx, &s.tokens)
            .map_err(|e| session_err(e.to_string()))?;
        Ok(Some(ExportedDelta {
            chain: s.chain,
            blob,
        }))
    }

    fn restart_export(&self, session: &str) -> Result<()> {
        if let Some(handle) = self.batched_handle(session) {
            let mut s = handle
                .lock()
                .map_err(|_| session_err(format!("session {session} is poisoned")))?;
            // A checkpoint is a whole chain: the new successor gets the last
            // one, under a chain id it has not seen. Without one, the next
            // turn takes one whatever the interval.
            if s.latest.is_some() {
                s.chain += 1;
                s.exported = false;
            } else {
                s.taken_at = None;
            }
            return Ok(());
        }
        let handle = self.session_handle(session)?;
        let mut s = handle
            .lock()
            .map_err(|_| session_err(format!("session {session} is poisoned")))?;
        let fingerprint = self.fingerprint(&s.model_id)?;
        s.export = SequenceExport::new(fingerprint, SEQ, SCRATCH);
        s.chain += 1;
        Ok(())
    }

    fn import_chain(&self, model_id: &str, session: &str, chain: &[Vec<u8>]) -> Result<u32> {
        let entry = self.session_entry(model_id)?;
        let fingerprint = self.fingerprint(model_id)?;
        let owner = match entry.as_ref() {
            LoadedEntry::Serial(m) => m.clone(),
            LoadedEntry::Batched(_) => {
                // Checked now, installed by the session's next turn, which
                // knows the conversation the chain has to be a prefix of.
                let positions = chain_tokens(fingerprint, chain)?.len() as u32;
                let mut s = BatchedSession::new(model_id);
                s.imported = Some(chain.to_vec());
                self.sessions.sessions.remove(session);
                self.sessions
                    .batched
                    .insert(session.to_string(), Arc::new(std::sync::Mutex::new(s)));
                return Ok(positions);
            }
            LoadedEntry::Hosted(..) | LoadedEntry::Pipeline(_) => {
                return Err(session_err(format!(
                    "model {model_id} cannot hold a session"
                )));
            }
        };
        let mut fresh = self.new_session(model_id, owner.clone())?;
        let mut import = SequenceImport::new(fingerprint, SEQ, SCRATCH);
        {
            let _serial = owner.blocking_lock();
            for encoded in chain {
                let blob = import.apply(&mut fresh.ctx, encoded).map_err(chain_err)?;
                fresh
                    .tokens
                    .extend(blob.tokens.iter().map(|t| LlamaToken(*t)));
            }
        }
        // The rebuilt positions are what the successor would re-export first.
        let rebuilt = import.next_pos();
        fresh.export = SequenceExport::new(fingerprint, SEQ, SCRATCH);
        self.sessions.batched.remove(session);
        self.sessions
            .sessions
            .insert(session.to_string(), Arc::new(std::sync::Mutex::new(fresh)));
        Ok(rebuilt)
    }

    fn has_session(&self, session: &str) -> bool {
        self.sessions.sessions.contains_key(session) || self.sessions.batched.contains_key(session)
    }

    fn close_session(&self, session: &str) {
        self.sessions.sessions.remove(session);
        self.sessions.batched.remove(session);
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn a_checkpoint_is_kept_for_what_the_next_history_shares_with_it() {
        // The next history extends the turn's prompt: all of it is reused,
        // with or without recurrent state.
        let prompt = [1, 10, 11, 12, 20];
        let extends = [1, 10, 11, 12, 20, 30, 31, 21];
        assert_eq!(checkpoint_reuse(&prompt, &extends, true), Ok(5));
        assert_eq!(checkpoint_reuse(&prompt, &extends, false), Ok(5));

        // The template closes the prompt with tokens the history does not
        // carry (20, 98, 99 against 20, 30): an attention cache is cut back to
        // where they part, a recurrent one is no checkpoint.
        let opened = [1, 10, 11, 12, 20, 98, 99];
        assert_eq!(checkpoint_reuse(&opened, &extends, true), Ok(5));
        let why = checkpoint_reuse(&opened, &extends, false).unwrap_err();
        assert!(
            why.contains("position 5 of 7") && why.contains("recurrent"),
            "{why}"
        );

        // Nothing shared, or nothing copied, is no checkpoint for anyone.
        assert!(checkpoint_reuse(&[7, 8], &extends, true).is_err());
        assert!(checkpoint_reuse(&[], &extends, true).is_err());
    }

    #[test]
    fn a_seeded_chain_is_continued_or_cut_back_and_never_misused() {
        let held = [1, 10, 11, 12, 20, 98, 99];
        // The prompt extends the chain: its next token continues it.
        let extends = [1, 10, 11, 12, 20, 98, 99, 30, 31];
        assert_eq!(seed_token(&held, &extends, false), Some(30));
        assert_eq!(seed_token(&held, &extends, true), Some(30));
        // The prompt parts from the chain at position 5: an attention cache
        // is seeded and fed the prompt's token there, a recurrent one is not
        // seeded.
        let parts = [1, 10, 11, 12, 20, 30, 31, 21];
        assert_eq!(seed_token(&held, &parts, true), Some(30));
        assert_eq!(seed_token(&held, &parts, false), None);
        // Nothing shared, an empty chain, or a prompt the chain already
        // covers: nothing to seed.
        assert_eq!(seed_token(&[7, 8], &parts, true), None);
        assert_eq!(seed_token(&[], &parts, true), None);
        assert_eq!(seed_token(&held, &held[..4], true), None);
        assert_eq!(seed_token(&held, &held, true), None);
    }

    /// A standby model is staged from its weights file in host memory with
    /// no engine context: it is listed as standby, not loaded, its
    /// fingerprint is that of the staged bytes, and a load of the same file
    /// finds the staged weights. An empty file is refused.
    #[tokio::test]
    async fn a_standby_model_is_staged_without_loading() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("m.gguf");
        let weights = vec![7u8; 8192];
        std::fs::write(&path, &weights).expect("weights");
        let rt = ModelRuntime::new(crate::catalog::CatalogCell::default()).expect("runtime");

        let staged = rt.stage_standby("m", &path).expect("staged");
        assert_eq!(staged.model_id, "m");
        assert_eq!(staged.bytes, weights.len() as u64);
        assert!(!rt.is_loaded("m"));
        assert_eq!(rt.standby_models(), vec![staged]);
        assert!(rt.sessions.staged_for("m", &path).is_some());
        assert!(
            rt.sessions
                .staged_for("m", &dir.path().join("other.gguf"))
                .is_none()
        );
        assert_eq!(
            rt.weights_fingerprint("m", &path)
                .await
                .expect("fingerprint"),
            ModelFingerprint::of_bytes(&weights)
        );

        let empty = dir.path().join("empty.gguf");
        std::fs::write(&empty, b"").expect("empty file");
        assert!(rt.stage_standby("e", &empty).is_err());
        assert_eq!(rt.standby_models().len(), 1);
    }
}
