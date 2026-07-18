//! Tenzro Train auto-provisioning daemon.
//!
//! When enabled (`[training] enabled = true`), the node runs a leader-gated
//! poll loop that reconciles the set of active training runs held in the
//! local [`tenzro_training::TrainingRuntime`] against a set of supervised
//! Python trainer subprocesses. For every run in `Enrolling` / `Training`
//! status, up to `max_concurrent_trainers`, the daemon spawns
//! `tenzro-trainer run` — the Python reference trainer — pointed at the
//! node's own local RPC endpoint. The trainer enrolls, runs the inner SGD
//! loop, and submits outer gradients back over JSON-RPC. No tensor library
//! is linked into the node; all tensor math stays in the Python process.
//!
//! ## Trainer identity
//!
//! The trainer's Ed25519 key is derived deterministically from the node's
//! own TDIP validator seed via HKDF domain separation (`trainer-seed` info
//! label). This is seamless (no separate secret to provision — the node
//! already holds its identity key), stable (the same trainer identity every
//! restart, so reward attribution is consistent), and safe (HKDF domain
//! separation means the trainer key can never be confused with the node's
//! on-chain signing key). The derived 32-byte seed is written to a
//! `0o600` file under `<data_dir>/trainer/` and handed to the Python CLI
//! via `--seed-file`. The trainer DID is
//! `did:tenzro:machine:trainer:<node-address-hex>`.
//!
//! ## Supervision
//!
//! Each trainer subprocess is tracked by `task_id`. On exit (clean or
//! crash) the run is eligible for a supervised restart on the next poll
//! tick, subject to an exponential backoff (`backoff_base_ms * 2^(n-1)`,
//! capped at `backoff_max_ms`) and a per-run restart ceiling
//! (`max_restarts`). A run that reaches `Completed` / `Failed` / `Cancelled`
//! has its trainer reaped and its supervision state cleared.
//!
//! ## Leader gate
//!
//! In a multi-node fleet, only the node that wins the consensus leader gate
//! (`is_leader_in_next_views`) auto-spawns trainers, so a run that this node
//! and its neighbours all hold does not get one redundant trainer per
//! validator. Nodes that are not validators (no consensus engine) run the
//! daemon ungated — a single-operator dev node trains locally.

use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use hkdf::Hkdf;
use parking_lot::Mutex;
use sha2::Sha256;
use tenzro_training::{TrainingRun, TrainingRunStatus, TrainingRuntime};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tokio::time::MissedTickBehavior;
use tracing::{debug, info, warn};
use zeroize::Zeroizing;

use crate::config::TrainingConfig;

/// HKDF `info` label separating the trainer seed from every other key
/// derived from the node identity.
const TRAINER_SEED_INFO: &[u8] = b"tenzro/train/trainer-seed";

/// Tick-authority gate: returns `true` when this node is authorised to
/// spawn trainers this tick. Wired to the consensus leader lookahead so
/// only one validator in a fleet provisions trainers per run.
pub type TickAuthorityFn = Arc<dyn Fn() -> bool + Send + Sync + 'static>;

/// Per-run supervision state.
struct TrainerSlot {
    /// The running child. `None` between an observed exit and the next
    /// respawn — the slot is retained to carry backoff + restart counters.
    child: Option<Child>,
    /// Consecutive restarts. Reset to 0 on a clean run-status transition
    /// away from active, or when the run first enters supervision.
    restarts: u32,
    /// Earliest wall-clock instant at which a respawn is allowed. Set when
    /// a subprocess exit is observed.
    next_spawn_at: Option<std::time::Instant>,
    /// `true` once the run left an active status and the slot is pending
    /// teardown on the next tick.
    reap: bool,
}

/// Trainer auto-provisioning daemon.
pub struct TrainerDaemon {
    config: TrainingConfig,
    runtime: Arc<TrainingRuntime>,
    /// Resolved Python interpreter path (verified importable at construction).
    python: String,
    /// URL the trainer uses to reach this node's local RPC.
    rpc_url: String,
    /// 32-byte trainer seed derived from the node identity (may be `None`
    /// when the node identity key could not be loaded — the trainer then
    /// runs with an ephemeral per-process key, which is degraded but not
    /// fatal for the Open tier).
    seed_file: Option<PathBuf>,
    /// Trainer DID handed to every `tenzro-trainer run` invocation.
    trainer_did: String,
    /// `task_id → TrainerSlot`.
    slots: Mutex<HashMap<String, TrainerSlot>>,
    /// Leader gate. `None` = ungated (single-operator / non-validator node).
    tick_authority: Option<TickAuthorityFn>,
}

impl TrainerDaemon {
    /// Build the daemon. Resolves + verifies the Python interpreter, derives
    /// the trainer seed from the node identity, and materialises the seed
    /// file. Returns `None` (with a log line) when the trainer runtime is
    /// unusable — a mis-configured trainer must not block node startup.
    ///
    /// `node_identity_seed` is the node's 32-byte TDIP Ed25519 secret seed
    /// (from `keypair.secret_key().as_bytes()`); `node_address_hex` is the
    /// node's on-chain address hex, used only to name the trainer DID.
    pub fn new(
        config: TrainingConfig,
        runtime: Arc<TrainingRuntime>,
        rpc_url: String,
        data_dir: &std::path::Path,
        node_identity_seed: Option<[u8; 32]>,
        node_address_hex: String,
    ) -> Option<Self> {
        if !config.enabled {
            return None;
        }

        let python = match resolve_python(&config) {
            Some(p) => p,
            None => {
                warn!(
                    "Tenzro Train daemon enabled but no Python interpreter with `tenzro-trainer` \
                     could be resolved — set [training].python_executable or [training].venv_path; \
                     trainer auto-provisioning is disabled"
                );
                return None;
            }
        };

        // Derive + persist the trainer seed. Degraded-but-not-fatal when the
        // node identity key is unavailable: the trainer falls back to an
        // ephemeral key (no --seed-file) so reward attribution is unstable,
        // but Open-tier training still proceeds.
        let seed_file = match node_identity_seed {
            Some(node_seed) => match materialise_trainer_seed(data_dir, &node_seed) {
                Ok(path) => Some(path),
                Err(e) => {
                    warn!(
                        "Could not write derived trainer seed ({}); trainer will run with an \
                         ephemeral key (unstable reward attribution)",
                        e
                    );
                    None
                }
            },
            None => {
                warn!(
                    "Node identity seed unavailable; trainer will run with an ephemeral key \
                     (unstable reward attribution)"
                );
                None
            }
        };

        let trainer_did = format!("did:tenzro:machine:trainer:{}", node_address_hex);

        info!(
            python = %python,
            rpc_url = %rpc_url,
            trainer_did = %trainer_did,
            seed_anchored = seed_file.is_some(),
            max_concurrent = config.max_concurrent_trainers,
            "Tenzro Train auto-provisioning daemon constructed"
        );

        Some(Self {
            config,
            runtime,
            python,
            rpc_url,
            seed_file,
            trainer_did,
            slots: Mutex::new(HashMap::new()),
            tick_authority: None,
        })
    }

    /// Attach the consensus leader gate so only one validator provisions
    /// trainers per run in a multi-node fleet.
    pub fn with_tick_authority(mut self, gate: TickAuthorityFn) -> Self {
        self.tick_authority = Some(gate);
        self
    }

    /// Spawn the poll loop. Mirrors [`SeedAgentDaemon::spawn`]: a
    /// `tokio::time::interval` with `MissedTickBehavior::Delay`, skipping the
    /// immediate first fire so the node finishes booting before the first
    /// reconcile.
    pub fn spawn(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        let poll = Duration::from_secs(self.config.poll_interval_secs.max(1));
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(poll);
            ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
            // Skip the immediate fire.
            ticker.tick().await;
            loop {
                ticker.tick().await;
                if let Some(gate) = &self.tick_authority
                    && !(gate)()
                {
                    debug!("Trainer daemon: not leader this tick, skipping reconcile");
                    continue;
                }
                self.reconcile().await;
            }
        })
    }

    /// One reconcile pass: reap finished/dead trainers, then spawn trainers
    /// for eligible runs up to the concurrency cap.
    async fn reconcile(&self) {
        let runs = self.runtime.list_runs();

        // Index active runs by task_id for teardown decisions.
        let active: HashMap<String, TrainingRun> = runs
            .into_iter()
            .filter(|r| is_active(r.status))
            .map(|r| (r.task_id.clone(), r))
            .collect();

        // Pass 1: poll every tracked child for exit; mark runs that left the
        // active set for reaping.
        {
            let mut slots = self.slots.lock();
            for (task_id, slot) in slots.iter_mut() {
                if !active.contains_key(task_id) {
                    slot.reap = true;
                    continue;
                }
                if let Some(child) = slot.child.as_mut() {
                    match child.try_wait() {
                        Ok(Some(status)) => {
                            let backoff = backoff_delay(
                                slot.restarts,
                                self.config.backoff_base_ms,
                                self.config.backoff_max_ms,
                            );
                            slot.child = None;
                            slot.restarts = slot.restarts.saturating_add(1);
                            slot.next_spawn_at =
                                Some(std::time::Instant::now() + backoff);
                            warn!(
                                task_id = %task_id,
                                exit = ?status.code(),
                                restarts = slot.restarts,
                                backoff_ms = backoff.as_millis() as u64,
                                "Trainer subprocess exited; scheduling supervised restart"
                            );
                        }
                        Ok(None) => { /* still running */ }
                        Err(e) => {
                            warn!(
                                task_id = %task_id,
                                "try_wait on trainer subprocess failed: {}; evicting",
                                e
                            );
                            slot.child = None;
                            slot.reap = true;
                        }
                    }
                }
            }
            // Drop reaped slots. Dropping the `Child` (kill_on_drop) tears
            // down any still-running process for a run that left the active
            // set (cancelled / completed / failed).
            slots.retain(|task_id, slot| {
                if slot.reap {
                    info!(task_id = %task_id, "Reaping trainer for inactive run");
                    false
                } else {
                    true
                }
            });
        }

        // Pass 2: spawn trainers for eligible runs, up to the concurrency
        // cap. Eligible = active status, not already running, and either
        // never-seen or past its backoff window and under the restart cap.
        let now = std::time::Instant::now();
        let mut to_spawn: Vec<TrainingRun> = Vec::new();
        {
            let slots = self.slots.lock();
            let live = slots
                .values()
                .filter(|s| s.child.is_some())
                .count();
            let mut budget = self.config.max_concurrent_trainers.saturating_sub(live);
            for (task_id, run) in active.iter() {
                if budget == 0 {
                    break;
                }
                match slots.get(task_id) {
                    Some(slot) if slot.child.is_some() => continue, // already running
                    Some(slot) => {
                        if slot.restarts >= self.config.max_restarts {
                            continue; // gave up on this run
                        }
                        if let Some(at) = slot.next_spawn_at
                            && now < at
                        {
                            continue; // still in backoff
                        }
                    }
                    None => {}
                }
                to_spawn.push(run.clone());
                budget -= 1;
            }
        }

        for run in to_spawn {
            self.spawn_trainer(&run).await;
        }
    }

    /// Spawn one `tenzro-trainer run` subprocess for `run`, tracking it in
    /// the slot map. Non-fatal on failure — a spawn error schedules a
    /// backoff restart the same way a subprocess exit does.
    async fn spawn_trainer(&self, run: &TrainingRun) {
        let task_id = run.task_id.clone();
        let shard_uri = run.task_spec.dataset_ref.clone();

        let mut cmd = Command::new(&self.python);
        cmd.arg("-m")
            .arg("tenzro_trainer.cli")
            .arg("run")
            .arg("--rpc-url")
            .arg(&self.rpc_url)
            .arg("--task-id")
            .arg(&task_id)
            .arg("--trainer-did")
            .arg(&self.trainer_did)
            .arg("--shard-uri")
            .arg(&shard_uri);
        if let Some(seed) = &self.seed_file {
            cmd.arg("--seed-file").arg(seed);
        }
        for extra in &self.config.trainer_extra_args {
            cmd.arg(extra);
        }
        cmd.env("TENZRO_RPC_URL", &self.rpc_url)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);

        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                warn!(
                    task_id = %task_id,
                    "Failed to spawn trainer subprocess: {}; scheduling backoff restart",
                    e
                );
                let mut slots = self.slots.lock();
                let slot = slots.entry(task_id.clone()).or_insert(TrainerSlot {
                    child: None,
                    restarts: 0,
                    next_spawn_at: None,
                    reap: false,
                });
                let backoff = backoff_delay(
                    slot.restarts,
                    self.config.backoff_base_ms,
                    self.config.backoff_max_ms,
                );
                slot.restarts = slot.restarts.saturating_add(1);
                slot.next_spawn_at = Some(std::time::Instant::now() + backoff);
                return;
            }
        };

        // Forward the trainer's stdout/stderr into the node's tracing layer
        // so operators see round progress without a separate log sink.
        if let Some(stdout) = child.stdout.take() {
            let tid = task_id.clone();
            tokio::spawn(async move {
                let mut lines = BufReader::new(stdout).lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    info!(task_id = %tid, "trainer: {}", line);
                }
            });
        }
        if let Some(stderr) = child.stderr.take() {
            let tid = task_id.clone();
            tokio::spawn(async move {
                let mut lines = BufReader::new(stderr).lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    debug!(task_id = %tid, "trainer stderr: {}", line);
                }
            });
        }

        info!(
            task_id = %task_id,
            shard_uri = %shard_uri,
            "Spawned Tenzro Train trainer subprocess"
        );

        let mut slots = self.slots.lock();
        let slot = slots.entry(task_id).or_insert(TrainerSlot {
            child: None,
            restarts: 0,
            next_spawn_at: None,
            reap: false,
        });
        slot.child = Some(child);
        slot.reap = false;
        slot.next_spawn_at = None;
    }

    /// Number of trainer subprocesses currently alive (for status RPC).
    pub fn live_trainer_count(&self) -> usize {
        self.slots
            .lock()
            .values()
            .filter(|s| s.child.is_some())
            .count()
    }

    /// Trainer DID handed to every provisioned trainer (for status RPC).
    pub fn trainer_did(&self) -> &str {
        &self.trainer_did
    }

    /// Configured maximum concurrent trainer subprocesses (for status RPC).
    pub fn max_concurrent_trainers(&self) -> usize {
        self.config.max_concurrent_trainers
    }
}

/// A run is "active" (a trainer should be running) in the enrollment /
/// training window only.
fn is_active(status: TrainingRunStatus) -> bool {
    matches!(
        status,
        TrainingRunStatus::Enrolling | TrainingRunStatus::Training
    )
}

/// Exponential backoff: `base * 2^(restarts.saturating_sub(1))`, capped at
/// `max`. `restarts == 0` (first-ever spawn) returns `Duration::ZERO`.
fn backoff_delay(restarts: u32, base_ms: u64, max_ms: u64) -> Duration {
    if restarts == 0 {
        return Duration::ZERO;
    }
    let shift = (restarts - 1).min(32);
    let scaled = base_ms.saturating_mul(1u64 << shift);
    Duration::from_millis(scaled.min(max_ms))
}

/// Resolve the Python interpreter: explicit `python_executable`, then
/// `<venv_path>/bin/python`, then `$TENZRO_TRAINING_VENV_PATH/bin/python`
/// (set by the opt-in trainer image so the daemon needs no extra config),
/// then `python3` / `python` on `PATH`. Verifies the `tenzro_trainer`
/// package is importable before returning.
fn resolve_python(config: &TrainingConfig) -> Option<String> {
    let mut candidates: Vec<String> = Vec::new();
    if let Some(explicit) = &config.python_executable {
        candidates.push(explicit.clone());
    }
    let venv_from_env = std::env::var("TENZRO_TRAINING_VENV_PATH").ok();
    for venv in config.venv_path.iter().chain(venv_from_env.iter()) {
        candidates.push(
            PathBuf::from(venv)
                .join("bin")
                .join("python")
                .to_string_lossy()
                .into_owned(),
        );
    }
    candidates.push("python3".to_string());
    candidates.push("python".to_string());

    candidates.into_iter().find(|cand| python_has_trainer(cand))
}

/// Verify `python -c "import tenzro_trainer"` succeeds (blocking — runs
/// once at daemon construction, before the async loop starts).
fn python_has_trainer(python: &str) -> bool {
    match std::process::Command::new(python)
        .arg("-c")
        .arg("import tenzro_trainer")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
    {
        Ok(status) => status.success(),
        Err(_) => false,
    }
}

/// Derive the trainer seed from the node identity via HKDF-SHA256 and write
/// it to `<data_dir>/trainer/trainer.seed` with `0o600` permissions.
/// Returns the seed-file path.
fn materialise_trainer_seed(
    data_dir: &std::path::Path,
    node_seed: &[u8; 32],
) -> std::io::Result<PathBuf> {
    let hk = Hkdf::<Sha256>::new(None, node_seed);
    let mut derived = Zeroizing::new([0u8; 32]);
    hk.expand(TRAINER_SEED_INFO, derived.as_mut())
        .map_err(|_| std::io::Error::other("hkdf expand failed"))?;

    let dir = data_dir.join("trainer");
    std::fs::create_dir_all(&dir)?;
    let path = dir.join("trainer.seed");
    std::fs::write(&path, derived.as_ref())?;
    set_seed_permissions(&path)?;
    Ok(path)
}

#[cfg(unix)]
fn set_seed_permissions(path: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn set_seed_permissions(_path: &std::path::Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_is_exponential_and_capped() {
        // restarts=0 → immediate.
        assert_eq!(backoff_delay(0, 2_000, 300_000), Duration::ZERO);
        // restarts=1 → base.
        assert_eq!(backoff_delay(1, 2_000, 300_000), Duration::from_millis(2_000));
        // restarts=2 → 2x base.
        assert_eq!(backoff_delay(2, 2_000, 300_000), Duration::from_millis(4_000));
        // restarts=3 → 4x base.
        assert_eq!(backoff_delay(3, 2_000, 300_000), Duration::from_millis(8_000));
        // Large restart count is capped at max.
        assert_eq!(
            backoff_delay(30, 2_000, 300_000),
            Duration::from_millis(300_000)
        );
    }

    #[test]
    fn only_enrolling_and_training_are_active() {
        assert!(is_active(TrainingRunStatus::Enrolling));
        assert!(is_active(TrainingRunStatus::Training));
        assert!(!is_active(TrainingRunStatus::Pending));
        assert!(!is_active(TrainingRunStatus::Completed));
        assert!(!is_active(TrainingRunStatus::Failed));
        assert!(!is_active(TrainingRunStatus::Cancelled));
    }

    #[test]
    fn derived_seed_differs_from_node_seed_and_is_stable() {
        let node_seed = [7u8; 32];
        let hk = Hkdf::<Sha256>::new(None, &node_seed);
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        hk.expand(TRAINER_SEED_INFO, &mut a).unwrap();
        let hk2 = Hkdf::<Sha256>::new(None, &node_seed);
        hk2.expand(TRAINER_SEED_INFO, &mut b).unwrap();
        assert_eq!(a, b, "derivation must be deterministic");
        assert_ne!(a, node_seed, "trainer seed must differ from node seed");
    }
}
