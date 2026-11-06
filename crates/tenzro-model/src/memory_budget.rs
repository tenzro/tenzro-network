//! Cross-modality memory budget.
//!
//! # Why this exists
//!
//! A node serves several model families out of one memory pool: GGUF language
//! models under llama.cpp, ONNX models under six runtimes (forecast, vision,
//! text-embedding, segmentation, detection, ASR), diffusion pipelines on the
//! Praecise diffusion engine, and engines in runtime hosts the node starts.
//! Before this module each of
//! those asked the operating system how much memory was free and admitted
//! itself if the answer was large enough.
//!
//! That is not a budget, it is a race. Three runtimes each observing 90 GiB
//! free will each admit a 40 GiB model, because none of them can see the
//! other two deciding the same thing. It also has no notion of memory that is
//! spoken for but not yet resident: RocksDB's block cache grows into whatever
//! is left, so "free right now" counts storage's future working set as
//! available to models.
//!
//! [`MemoryBudget`] replaces that with a single declared ledger. Admission is
//! an atomic check-and-commit against recorded commitments, not a reading of
//! free memory, so two concurrent loads cannot both be told yes.
//!
//! # Shape of the budget
//!
//! ```text
//! total ─┬─ reserve      OS, node process, iroh, cloud features
//!        ├─ Resident     always-loaded models: LLMs, ASR, embeddings, TTS,
//!        │               plus the node's storage cache and memtables and its
//!        │               consensus buffers, charged by the node
//!        └─ OnDemand     media-gen pipelines, loaded per job and evicted
//! ```
//!
//! The reserve is subtracted first and never lent out. The two tiers are
//! separately capped so a long-running chat model cannot crowd out the
//! diffusion worker, and a video pipeline cannot evict the LLM that is
//! serving requests. Tier ceilings sum to at most `total - reserve`;
//! [`BudgetConfig::validate`] rejects a configuration where they do not.
//!
//! # What a commitment means
//!
//! A commitment is a claim on the pool, recorded when a model is admitted and
//! dropped when it is unloaded. It is an estimate — `file_len` scaled by
//! [`LOAD_HEADROOM_NUM`]/[`LOAD_HEADROOM_DEN`] to cover KV cache, activations,
//! and allocator slop — not a measurement of resident set size. The budget's
//! job is to stop the node from promising more than it has, which requires
//! the estimate to be conservative rather than exact.
//!
//! # Engines outside the llama.cpp path
//!
//! The diffusion engine, hosted engines and the runtime hosts the node starts
//! reserve through [`crate::model_host::ModelHost`], whose engine claims call
//! the same [`MemoryBudget::admit`] and [`MemoryBudget::release`] under the
//! model id, so every engine draws on this one ledger.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::OnceLock;

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

/// Numerator of the headroom multiplier applied to a model's on-disk size to
/// estimate its resident footprint.
///
/// 1.35× covers KV cache, activation buffers, and allocator fragmentation.
/// It is deliberately generous: under-estimating produces an OOM kill that
/// takes the whole node down, while over-estimating only declines a load.
pub const LOAD_HEADROOM_NUM: u64 = 135;

/// Denominator of the headroom multiplier. See [`LOAD_HEADROOM_NUM`].
pub const LOAD_HEADROOM_DEN: u64 = 100;

/// Default reserve held back for the operating system, the node process
/// itself, RocksDB's block cache and write buffers, the iroh endpoint, and
/// the web/MCP/A2A service surfaces.
///
/// 16 GiB is sized for a node carrying a real RocksDB working set. A node
/// that only serves models can lower it; one running a busy validator with
/// deep history should raise it.
pub const DEFAULT_RESERVE_BYTES: u64 = 16 * 1024 * 1024 * 1024;

/// Fraction of the post-reserve pool granted to [`Tier::Resident`] when the
/// operator does not set tier ceilings explicitly, in percent.
///
/// Resident models are the ones answering requests continuously, so they get
/// the larger share. The remainder goes to [`Tier::OnDemand`].
pub const DEFAULT_RESIDENT_PCT: u64 = 60;

/// Which pool a commitment draws from.
///
/// The distinction is lifetime, not modality: a model that stays loaded to
/// answer requests is [`Tier::Resident`] whatever it does, and a pipeline
/// loaded for one job and evicted afterwards is [`Tier::OnDemand`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Tier {
    /// Models held loaded across requests: language models, ASR, embeddings,
    /// forecasting, TTS.
    Resident,
    /// Pipelines loaded for a single job and evicted under memory pressure:
    /// diffusion image and video generation.
    OnDemand,
}

impl fmt::Display for Tier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Resident => write!(f, "resident"),
            Self::OnDemand => write!(f, "on-demand"),
        }
    }
}

/// Operator-facing budget configuration.
///
/// `total_bytes` is normally the detected physical pool; it is a field rather
/// than a probe so a node can be told to use less than the machine has —
/// the correct setting when the node shares a host with other workloads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BudgetConfig {
    /// Total memory the node may account for, in bytes.
    pub total_bytes: u64,
    /// Held back from all tiers for the OS and the node process. The node's
    /// storage and consensus memory is charged to the resident tier instead.
    pub reserve_bytes: u64,
    /// Ceiling for [`Tier::Resident`]. `None` derives it from
    /// [`DEFAULT_RESIDENT_PCT`] of the post-reserve pool.
    pub resident_ceiling_bytes: Option<u64>,
    /// Ceiling for [`Tier::OnDemand`]. `None` gives it the post-reserve pool
    /// remaining after the resident ceiling.
    pub on_demand_ceiling_bytes: Option<u64>,
}

/// Why a configuration cannot be used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BudgetConfigError {
    /// The reserve is at least as large as the pool, leaving nothing to serve
    /// models from.
    ReserveExceedsTotal { total: u64, reserve: u64 },
    /// The tier ceilings together exceed what is left after the reserve, so
    /// honouring both would overcommit the machine.
    CeilingsExceedPool {
        pool: u64,
        resident: u64,
        on_demand: u64,
    },
}

impl fmt::Display for BudgetConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReserveExceedsTotal { total, reserve } => write!(
                f,
                "reserve of {} leaves nothing to serve models from in a total pool of {}",
                human(*reserve),
                human(*total)
            ),
            Self::CeilingsExceedPool {
                pool,
                resident,
                on_demand,
            } => write!(
                f,
                "tier ceilings ({} resident + {} on-demand = {}) exceed the {} available after the reserve",
                human(*resident),
                human(*on_demand),
                human(resident.saturating_add(*on_demand)),
                human(*pool)
            ),
        }
    }
}

impl std::error::Error for BudgetConfigError {}

impl BudgetConfig {
    /// Build a configuration for `total_bytes` using the default reserve and
    /// tier split.
    pub fn with_total(total_bytes: u64) -> Self {
        Self {
            total_bytes,
            reserve_bytes: DEFAULT_RESERVE_BYTES,
            resident_ceiling_bytes: None,
            on_demand_ceiling_bytes: None,
        }
    }

    /// Memory available to models once the reserve is taken out.
    pub fn pool_bytes(&self) -> u64 {
        self.total_bytes.saturating_sub(self.reserve_bytes)
    }

    /// Resolve the resident ceiling, applying the default split when unset.
    pub fn resident_ceiling(&self) -> u64 {
        self.resident_ceiling_bytes
            .unwrap_or_else(|| self.pool_bytes() / 100 * DEFAULT_RESIDENT_PCT)
    }

    /// Resolve the on-demand ceiling, applying the default split when unset.
    pub fn on_demand_ceiling(&self) -> u64 {
        self.on_demand_ceiling_bytes
            .unwrap_or_else(|| self.pool_bytes().saturating_sub(self.resident_ceiling()))
    }

    /// Reject configurations that promise more than the machine has.
    ///
    /// Called by [`MemoryBudget::new`], so an invalid configuration cannot
    /// reach a live budget.
    pub fn validate(&self) -> Result<(), BudgetConfigError> {
        if self.reserve_bytes >= self.total_bytes {
            return Err(BudgetConfigError::ReserveExceedsTotal {
                total: self.total_bytes,
                reserve: self.reserve_bytes,
            });
        }
        let resident = self.resident_ceiling();
        let on_demand = self.on_demand_ceiling();
        if resident.saturating_add(on_demand) > self.pool_bytes() {
            return Err(BudgetConfigError::CeilingsExceedPool {
                pool: self.pool_bytes(),
                resident,
                on_demand,
            });
        }
        Ok(())
    }
}

/// Which limit stopped a load.
///
/// The two want completely different responses and collapsing them is how an
/// operator spends an afternoon unloading their own models while something
/// else is eating the machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeniedBy {
    /// This node's own ledger is full. Unloading one of its models frees room.
    Ledger,
    /// The machine is short of memory regardless of what this node holds.
    ///
    /// Something outside the node has taken it. Unloading a model here may not
    /// help and the cause is elsewhere: a foreign process that preallocates
    /// nearly all of a unified memory pool leaves a ledger that committed
    /// nothing believing its whole resident tier is free.
    Machine,
}

/// A load was declined because it would breach the budget.
///
/// Carries what was asked for and what is actually free so the operator can
/// tell "this model is too big for the node" from "this model is too big
/// right now", which call for different responses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmissionDenied {
    /// Which limit was hit.
    pub denied_by: DeniedBy,
    /// What the machine reported as actually free at the moment of refusal.
    pub machine_available_bytes: u64,
    /// The commitment key that was refused.
    pub key: String,
    /// Which tier the request drew against.
    pub tier: Tier,
    /// Bytes requested, headroom already applied.
    pub requested_bytes: u64,
    /// Bytes free in that tier at the moment of refusal.
    pub tier_available_bytes: u64,
    /// The tier's ceiling, so a caller can see whether the request could ever
    /// have fit.
    pub tier_ceiling_bytes: u64,
}

impl fmt::Display for AdmissionDenied {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.denied_by == DeniedBy::Machine {
            return write!(
                f,
                "{} needs {} and this node's own budget has room, but the machine reports only \
                 {} free. Something outside this node is holding the memory -- unloading a \
                 model here may not help",
                self.key,
                human(self.requested_bytes),
                human(self.machine_available_bytes),
            );
        }
        if self.requested_bytes > self.tier_ceiling_bytes {
            write!(
                f,
                "{} needs {} but the {} tier's ceiling is {} — it cannot be served on this node \
                 without raising the ceiling",
                self.key,
                human(self.requested_bytes),
                self.tier,
                human(self.tier_ceiling_bytes)
            )
        } else {
            write!(
                f,
                "{} needs {} but only {} of the {} tier's {} is free — unload another model first",
                self.key,
                human(self.requested_bytes),
                human(self.tier_available_bytes),
                self.tier,
                human(self.tier_ceiling_bytes)
            )
        }
    }
}

impl std::error::Error for AdmissionDenied {}

/// One recorded claim on the pool.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Commitment {
    /// Opaque identifier, unique across tiers. Usually a model id.
    pub key: String,
    /// Which tier it draws from.
    pub tier: Tier,
    /// Bytes committed, headroom already applied.
    pub bytes: u64,
}

/// Point-in-time view of one tier, for operator reporting.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TierSnapshot {
    /// Which tier this describes.
    pub tier: Tier,
    /// The tier's ceiling in bytes.
    pub ceiling_bytes: u64,
    /// Sum of live commitments in this tier.
    pub committed_bytes: u64,
    /// `ceiling - committed`.
    pub available_bytes: u64,
    /// Live commitments, ordered by key.
    pub commitments: Vec<Commitment>,
}

/// Point-in-time view of the whole budget.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BudgetSnapshot {
    /// Total memory the node accounts for.
    pub total_bytes: u64,
    /// Held back for the OS, RocksDB, and node services.
    pub reserve_bytes: u64,
    /// `total - reserve`.
    pub pool_bytes: u64,
    /// Sum of live commitments across every tier.
    pub committed_bytes: u64,
    /// What the machine itself reports as available right now, where it can be
    /// read.
    ///
    /// The figure an operator actually needs, and the one this snapshot used to
    /// omit. Everything else here describes what *this node* has promised; only
    /// this says what is left after every other thing on the machine. The two
    /// diverge exactly when it matters -- a node holding nothing on a box whose
    /// memory something else has taken looks perfectly healthy by its own
    /// accounting.
    ///
    /// Read from the same source [`MemoryBudget::admit`] consults, so what an
    /// operator sees and what a load will be judged against cannot disagree.
    pub machine_available_bytes: u64,
    /// What remains of `machine_available_bytes` once the reserve is set aside.
    ///
    /// The number a load is actually measured against. Presented separately
    /// because the difference between the two is the part that is not
    /// available for models however free it looks.
    pub machine_usable_bytes: u64,
    /// Per-tier detail.
    pub tiers: Vec<TierSnapshot>,
}

#[derive(Debug)]
struct State {
    config: BudgetConfig,
    commitments: BTreeMap<String, Commitment>,
}

impl State {
    fn committed_in(&self, tier: Tier) -> u64 {
        self.commitments
            .values()
            .filter(|c| c.tier == tier)
            .map(|c| c.bytes)
            .sum()
    }

    fn ceiling_of(&self, tier: Tier) -> u64 {
        match tier {
            Tier::Resident => self.config.resident_ceiling(),
            Tier::OnDemand => self.config.on_demand_ceiling(),
        }
    }
}

/// The node's memory ledger.
///
/// Cheap to share: every method takes `&self` and locks internally. Cloning
/// is not offered on purpose — a duplicated budget would defeat the point, so
/// callers hold an `Arc<MemoryBudget>` or use [`global`].
#[derive(Debug)]
pub struct MemoryBudget {
    state: Mutex<State>,
    /// How this budget reads what the machine actually has free.
    ///
    /// Held rather than called statically so a test can put the machine in a
    /// known state, and so a platform whose real figure comes from somewhere
    /// other than the kernel — a unified-memory device with its own accounting
    /// — can supply it without changing every caller.
    machine: Box<dyn MachineMemory>,
}

impl MemoryBudget {
    /// Build a budget from a validated configuration.
    /// Replace how this budget reads actual machine memory.
    ///
    /// Present so a test can put the machine in a known state. Production uses
    /// [`SystemMemory`], installed by `new`.
    pub fn with_machine_memory(mut self, machine: Box<dyn MachineMemory>) -> Self {
        self.machine = machine;
        self
    }

    pub fn new(config: BudgetConfig) -> Result<Self, BudgetConfigError> {
        config.validate()?;
        Ok(Self {
            state: Mutex::new(State {
                config,
                commitments: BTreeMap::new(),
            }),
            machine: Box::new(SystemMemory),
        })
    }

    /// Apply the standard headroom multiplier to an on-disk size.
    ///
    /// Callers pass the result to [`admit`](Self::admit); it is exposed so a
    /// caller can show the operator what a load would cost before attempting
    /// it.
    pub fn with_headroom(file_len: u64) -> u64 {
        file_len.saturating_mul(LOAD_HEADROOM_NUM) / LOAD_HEADROOM_DEN
    }

    /// Claim `bytes` in `tier` under `key`.
    ///
    /// Atomic: the check and the commit happen under one lock, so concurrent
    /// admissions cannot both observe the same free space. Re-admitting a
    /// live key **replaces** its commitment rather than stacking a second one
    /// — reloading a model at a different context length adjusts the claim
    /// instead of double-counting it.
    ///
    /// The replacement is evaluated against the tier's usage *excluding* the
    /// old claim, so growing a commitment is checked honestly and shrinking
    /// one always succeeds.
    /// Change the resident ceiling on a *live* budget, without a restart.
    ///
    /// WHY THIS EXISTS. Switching a node's resource profile — the thing
    /// `tenzro-mode` does — used to require editing the config and restarting
    /// tenzro-node, which drops the validator and every in-flight request. A
    /// scheduled, per-window profile cannot restart at each boundary. The
    /// budget already holds its config behind the same `Mutex<State>` every
    /// other method locks, so the ceiling was always mutable in principle;
    /// there was simply no method to move it. This is that method.
    ///
    /// It does NOT evict anything. Lowering the ceiling below what is already
    /// committed is allowed and leaves existing residents in place — the
    /// autotuner's `EvictIdle` reconciles the overcommit as models fall idle,
    /// exactly as it does under load pressure. Refusing to lower the ceiling
    /// while overcommitted would make a scheduled shrink impossible, which is
    /// the opposite of the point; the overcommit is transient and self-heals.
    ///
    /// `None` restores the default split. The change is validated the same way
    /// construction is, so an impossible ceiling (larger than the pool) is
    /// rejected rather than silently clamped.
    pub fn set_resident_ceiling(
        &self,
        ceiling_bytes: Option<u64>,
    ) -> Result<(), BudgetConfigError> {
        let mut state = self.state.lock();
        // Validate a candidate config before committing it, so a live budget
        // never holds an invalid one — same contract as `new`.
        let mut candidate = state.config.clone();
        candidate.resident_ceiling_bytes = ceiling_bytes;
        // If resident returns to the default split, on-demand must too — leaving
        // a stale explicit on-demand ceiling beside a defaulted resident one can
        // make the two together exceed the pool. The default split is coherent
        // by construction; a half-explicit one is not.
        if ceiling_bytes.is_none() {
            candidate.on_demand_ceiling_bytes = None;
        }
        candidate.validate()?;
        state.config = candidate;
        Ok(())
    }

    /// The resident ceiling currently in force (after any runtime change).
    pub fn current_resident_ceiling(&self) -> u64 {
        self.state.lock().config.resident_ceiling()
    }

    pub fn admit(&self, key: &str, tier: Tier, bytes: u64) -> Result<(), AdmissionDenied> {
        let mut state = self.state.lock();
        let ceiling = state.ceiling_of(tier);

        let displaced = state
            .commitments
            .get(key)
            .filter(|c| c.tier == tier)
            .map(|c| c.bytes)
            .unwrap_or(0);
        let committed = state.committed_in(tier).saturating_sub(displaced);
        let available = ceiling.saturating_sub(committed);

        if bytes > available {
            return Err(AdmissionDenied {
                denied_by: DeniedBy::Ledger,
                machine_available_bytes: self.machine.available_bytes(),
                key: key.to_string(),
                tier,
                requested_bytes: bytes,
                tier_available_bytes: available,
                tier_ceiling_bytes: ceiling,
            });
        }

        // The ledger says yes. Now ask the machine, because the ledger only
        // knows what THIS node promised and the memory may already be gone.
        //
        // Without this check, a foreign process that has taken nearly all of a
        // unified pool leaves this ledger (which committed nothing) believing
        // its whole resident tier is free, and it admits a load into memory
        // that does not exist.
        //
        // The reserve is subtracted because it is not spare — it is what the
        // operating system, the storage engine and the validator need in order
        // to keep running. A load that eats into it does not fail cleanly:
        // exhausting memory can take down other services on the host,
        // including the ones used to reach and manage it.
        let free = self.machine.available_bytes();
        let usable = free.saturating_sub(state.config.reserve_bytes);
        if bytes > usable {
            return Err(AdmissionDenied {
                denied_by: DeniedBy::Machine,
                machine_available_bytes: free,
                key: key.to_string(),
                tier,
                requested_bytes: bytes,
                tier_available_bytes: available,
                tier_ceiling_bytes: ceiling,
            });
        }

        state.commitments.insert(
            key.to_string(),
            Commitment {
                key: key.to_string(),
                tier,
                bytes,
            },
        );
        Ok(())
    }

    /// Record `bytes` the node's own services hold under `key`, replacing
    /// what was charged under it before.
    ///
    /// A charge is not a request: the storage engine's cache and memtables
    /// and the consensus buffers are memory the node needs in order to run,
    /// so the ledger records them rather than deciding on them. What they
    /// hold is then unavailable to model loads, which is how every consumer
    /// draws from this one budget. A charge that takes a tier past its
    /// ceiling leaves that tier with nothing to admit until it shrinks.
    pub fn charge(&self, key: &str, tier: Tier, bytes: u64) {
        self.state.lock().commitments.insert(
            key.to_string(),
            Commitment {
                key: key.to_string(),
                tier,
                bytes,
            },
        );
    }

    /// Drop the commitment held under `key`, returning what it held.
    ///
    /// Idempotent: releasing an unknown key returns `None` rather than
    /// erroring, so an unload path that runs twice does not fail the second
    /// time.
    pub fn release(&self, key: &str) -> Option<Commitment> {
        self.state.lock().commitments.remove(key)
    }

    /// Bytes still claimable in `tier`.
    pub fn available_in(&self, tier: Tier) -> u64 {
        let state = self.state.lock();
        state
            .ceiling_of(tier)
            .saturating_sub(state.committed_in(tier))
    }

    /// Whether `bytes` would be admitted in `tier` right now.
    ///
    /// Advisory only — the answer can be stale by the time a load starts, so
    /// [`admit`](Self::admit) remains the authority. Useful for scheduling
    /// decisions, such as choosing which pipeline to evict.
    /// Whether `bytes` would be admitted in `tier` right now.
    ///
    /// The preflight a loader runs before spending minutes reading weights off
    /// disk. It asks both questions `admit` asks — a preflight that consulted
    /// only the ledger would wave through exactly the load that then fails.
    ///
    /// Advisory, and necessarily so: the machine can change between this call
    /// and the load. `admit` is the decision; this only avoids obvious waste.
    pub fn would_admit(&self, tier: Tier, bytes: u64) -> bool {
        if self.available_in(tier) < bytes {
            return false;
        }
        // The same machine check `admit` makes. Without it this returns true
        // for exactly the load that then fails -- and the caller only finds
        // out after reading the weights off disk.
        let reserve = self.state.lock().config.reserve_bytes;
        bytes <= self.machine.available_bytes().saturating_sub(reserve)
    }

    /// Full operator-facing view of the ledger.
    pub fn snapshot(&self) -> BudgetSnapshot {
        let state = self.state.lock();
        let tiers = [Tier::Resident, Tier::OnDemand]
            .into_iter()
            .map(|tier| {
                let ceiling = state.ceiling_of(tier);
                let committed = state.committed_in(tier);
                TierSnapshot {
                    tier,
                    ceiling_bytes: ceiling,
                    committed_bytes: committed,
                    available_bytes: ceiling.saturating_sub(committed),
                    commitments: state
                        .commitments
                        .values()
                        .filter(|c| c.tier == tier)
                        .cloned()
                        .collect(),
                }
            })
            .collect::<Vec<_>>();

        let machine_available_bytes = self.machine.available_bytes();
        let machine_usable_bytes =
            machine_available_bytes.saturating_sub(state.config.reserve_bytes);
        BudgetSnapshot {
            machine_available_bytes,
            machine_usable_bytes,
            total_bytes: state.config.total_bytes,
            reserve_bytes: state.config.reserve_bytes,
            pool_bytes: state.config.pool_bytes(),
            committed_bytes: tiers.iter().map(|t| t.committed_bytes).sum(),
            tiers,
        }
    }
}

/// Holds a commitment in the [`global`] budget and releases it on drop
/// unless [`commit`](Self::commit) is called first.
///
/// A load has many failure points between admission and the model actually
/// being resident: the file may not parse, the GPU allocation may fail, the
/// batch engine may refuse to spawn. Every one of those returns through `?`.
/// Without a guard each such path leaks its commitment, and the tier shrinks
/// a little every time a load fails — until nothing can be loaded at all and
/// the only fix is a restart.
///
/// Disarm it once the model is registered and the unload path has taken
/// responsibility for releasing.
#[derive(Debug)]
pub struct AdmissionGuard {
    key: Option<String>,
}

impl AdmissionGuard {
    /// Guard the commitment recorded under `key`.
    pub fn new(key: impl Into<String>) -> Self {
        Self {
            key: Some(key.into()),
        }
    }

    /// Give up ownership of the commitment: the caller's unload path now owns
    /// releasing it.
    pub fn commit(mut self) {
        self.key = None;
    }
}

impl Drop for AdmissionGuard {
    fn drop(&mut self) {
        if let Some(key) = self.key.take() {
            global().release(&key);
        }
    }
}

/// The process-wide budget.
///
/// Initialised once at node startup with the operator's configuration. The
/// fallback exists so library tests and CLI-embedded runtimes work without a
/// node: it sizes itself from detected physical memory, which is the right
/// answer for a process that is the only thing on the box.
static GLOBAL: OnceLock<MemoryBudget> = OnceLock::new();

/// Install the process-wide budget.
///
/// Returns `false` if one was already installed, in which case `config` is
/// discarded — first writer wins, so a late caller cannot quietly widen a
/// budget the operator set at startup.
pub fn install_global(config: BudgetConfig) -> Result<bool, BudgetConfigError> {
    let budget = MemoryBudget::new(config)?;
    Ok(GLOBAL.set(budget).is_ok())
}

/// How the budget learns what is actually free on the machine.
///
/// Separate from the ledger because they answer different questions. The ledger
/// knows what *this node* has promised; only the machine knows what is left
/// after everything else running on it. A budget that consulted only its own
/// accounting is correct about itself and blind to its neighbours, and that
/// blindness is what allows a load to be admitted into memory that is already
/// gone.
///
/// A source that cannot answer returns `None`, and admission then falls back to
/// the ledger alone rather than refusing everything — an unreadable machine is
/// not evidence of a full one.
pub trait MachineMemory: std::fmt::Debug + Send + Sync + 'static {
    /// Bytes a new allocation could actually obtain right now.
    ///
    /// Returns a number, never "I don't know". An implementation that cannot
    /// read its platform is not finished, and the honest response to that is to
    /// write the implementation rather than to hand admission an absence it
    /// then has to decide what to do with.
    ///
    /// This was briefly an `Option`, and the branch handling `None` skipped the
    /// machine check entirely -- reinstating, silently and by default, exactly
    /// the blindness this trait exists to remove. A check that can be switched
    /// off by a platform failing to answer is not a check.
    fn available_bytes(&self) -> u64;
}

/// Reads what the operating system says is available.
///
/// `MemAvailable` rather than `MemFree`: free memory excludes reclaimable page
/// cache, so a healthy machine looks empty and a busy one looks full. Available
/// is the kernel's own estimate of what a new allocation can get, which is the
/// question being asked.
///
/// A caveat this cannot fix and that callers on unified-memory hardware must
/// know: on a unified-memory host the GPU driver's allocations may not be
/// charged to the process's memory cgroup — a 10.7 GiB GPU allocation has been
/// observed showing as 377 MiB in `memory.current`. Reading the system-wide figure is therefore right and
/// reading a cgroup's would be wrong, and a node that bounded itself with
/// `MemoryMax` would be bounding something the driver ignores.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemMemory;

impl MachineMemory for SystemMemory {
    fn available_bytes(&self) -> u64 {
        let mut sys = sysinfo::System::new();
        sys.refresh_memory();
        sys.available_memory()
    }
}

/// The process-wide budget, initialising from detected memory if the node has
/// not installed one.
pub fn global() -> &'static MemoryBudget {
    GLOBAL.get_or_init(|| {
        let mut sys = sysinfo::System::new();
        sys.refresh_memory();
        let total = sys.total_memory();
        // A machine smaller than the default reserve is a test container or a
        // very small VM. Fall back to lending out three quarters of it rather
        // than refusing to build a budget at all.
        let config = if total > DEFAULT_RESERVE_BYTES * 2 {
            BudgetConfig::with_total(total)
        } else {
            BudgetConfig {
                total_bytes: total,
                reserve_bytes: total / 4,
                resident_ceiling_bytes: None,
                on_demand_ceiling_bytes: None,
            }
        };
        MemoryBudget::new(config).expect("derived budget config is valid by construction")
    })
}

/// Render a byte count the way an operator reads it.
fn human(bytes: u64) -> String {
    const GIB: f64 = 1_073_741_824.0;
    const MIB: f64 = 1_048_576.0;
    let b = bytes as f64;
    if b >= GIB {
        format!("{:.1} GiB", b / GIB)
    } else {
        format!("{:.0} MiB", b / MIB)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // GIB is already defined further down in this module.

    /// A machine whose free memory a test decides. Every budget in these
    /// tests uses one, so no result depends on the host running them. The
    /// ledger tests give it the whole configured total: an otherwise idle
    /// machine of that size.
    #[derive(Debug)]
    struct Fixed(u64);
    impl MachineMemory for Fixed {
        fn available_bytes(&self) -> u64 {
            self.0
        }
    }

    fn budget_with(free: u64) -> MemoryBudget {
        MemoryBudget::new(BudgetConfig {
            total_bytes: 121 * GIB,
            reserve_bytes: 16 * GIB,
            resident_ceiling_bytes: None,
            on_demand_ceiling_bytes: None,
        })
        .unwrap()
        .with_machine_memory(Box::new(Fixed(free)))
    }

    /// A foreign process that preallocates takes almost the whole unified pool.
    /// This ledger has committed nothing, so by its own accounting the entire
    /// resident tier is free; admitting an 18.6 GiB model into memory that is
    /// already gone would leave the host unresponsive.
    ///
    /// The ledger is still right about itself. That is the point: being right
    /// about yourself is not the same as being right.
    #[test]
    fn a_load_is_refused_when_something_outside_the_node_took_the_memory() {
        let b = budget_with(2 * GIB);
        let err = b
            .admit("muse-glimmer-30b", Tier::Resident, 18_600 * 1_048_576)
            .expect_err("the machine has 2 GiB free; this must not be admitted");

        assert_eq!(err.denied_by, DeniedBy::Machine);
        assert_eq!(err.machine_available_bytes, 2 * GIB);
        assert!(
            err.tier_available_bytes > 18_600 * 1_048_576,
            "the ledger itself had room, which is exactly why it used to say yes"
        );
        let msg = err.to_string();
        assert!(msg.contains("outside this node"), "{msg}");
    }

    /// And the two refusals are told apart, because they call for opposite
    /// responses: unload one of mine, versus go and find what else is running.
    #[test]
    fn a_full_ledger_and_a_full_machine_are_different_refusals() {
        let roomy = budget_with(100 * GIB);
        // Fill the tier from the ledger side.
        let ceiling = roomy.current_resident_ceiling();
        roomy.admit("first", Tier::Resident, ceiling).unwrap();
        let err = roomy.admit("second", Tier::Resident, 4 * GIB).unwrap_err();
        assert_eq!(err.denied_by, DeniedBy::Ledger);
        assert!(err.to_string().contains("unload another model"), "{err}");
    }

    /// The reserve is not spare. It is what the OS, the storage engine and the
    /// validator need to keep running, and a load that eats into it does not
    /// fail cleanly: exhausting memory can take down other services on the
    /// host, including the ones used to reach and manage it.
    #[test]
    fn the_reserve_is_not_lent_out_to_a_load() {
        // 20 GiB free, 16 GiB of it reserved: only 4 GiB is really available.
        let b = budget_with(20 * GIB);
        assert!(b.admit("small", Tier::Resident, 3 * GIB).is_ok());
        let err = b.admit("big", Tier::Resident, 6 * GIB).unwrap_err();
        assert_eq!(err.denied_by, DeniedBy::Machine);
    }

    /// **There is no way past the machine check.** It was briefly possible for
    /// a platform to return "I don't know", and the branch handling that
    /// skipped the check entirely -- reinstating by default the blindness this
    /// exists to remove. A check a platform can switch off by failing to answer
    /// is not a check, so `MachineMemory` returns a number and every admission
    /// is measured against it.
    ///
    /// A machine reporting nothing free admits nothing, rather than admitting
    /// everything.
    #[test]
    fn a_machine_with_nothing_free_admits_nothing() {
        let b = budget_with(0);
        let err = b.admit("model", Tier::Resident, 1).unwrap_err();
        assert_eq!(err.denied_by, DeniedBy::Machine);
        assert_eq!(err.machine_available_bytes, 0);
        assert!(!b.would_admit(Tier::Resident, 1));
    }

    /// And the snapshot reports the same figures the decision used, so an
    /// operator reading headroom sees what a load will actually be judged
    /// against.
    #[test]
    fn the_snapshot_reports_what_admission_measures() {
        let b = budget_with(40 * GIB);
        let snap = b.snapshot();
        assert_eq!(snap.machine_available_bytes, 40 * GIB);
        assert_eq!(snap.machine_usable_bytes, 40 * GIB - snap.reserve_bytes);
        // A load at exactly the usable figure fits; one byte more does not.
        assert!(b.would_admit(Tier::Resident, snap.machine_usable_bytes));
        assert!(!b.would_admit(Tier::Resident, snap.machine_usable_bytes + 1));
    }

    /// The preflight asks both questions. One that consulted only the ledger
    /// would wave through exactly the load that then fails, after the caller
    /// had spent minutes reading weights off a disk.
    #[test]
    fn the_preflight_agrees_with_the_decision() {
        let starved = budget_with(2 * GIB);
        assert!(!starved.would_admit(Tier::Resident, 18 * GIB));
        assert!(starved.admit("m", Tier::Resident, 18 * GIB).is_err());

        let roomy = budget_with(100 * GIB);
        assert!(roomy.would_admit(Tier::Resident, 18 * GIB));
        assert!(roomy.admit("m", Tier::Resident, 18 * GIB).is_ok());
    }

    /// Releasing gives the room back, so an operator who unloads can load
    /// again. Without this the ledger would drift upward until a restart.
    #[test]
    fn releasing_returns_the_room() {
        let b = budget_with(100 * GIB);
        b.admit("a", Tier::Resident, 20 * GIB).unwrap();
        let before = b.available_in(Tier::Resident);
        assert!(b.release("a").is_some());
        assert_eq!(b.available_in(Tier::Resident), before + 20 * GIB);
        assert!(b.release("a").is_none(), "releasing twice is not an error");
    }

    const GIB: u64 = 1024 * 1024 * 1024;

    fn budget(
        total_gib: u64,
        reserve_gib: u64,
        resident_gib: u64,
        on_demand_gib: u64,
    ) -> MemoryBudget {
        MemoryBudget::new(BudgetConfig {
            total_bytes: total_gib * GIB,
            reserve_bytes: reserve_gib * GIB,
            resident_ceiling_bytes: Some(resident_gib * GIB),
            on_demand_ceiling_bytes: Some(on_demand_gib * GIB),
        })
        .expect("test config is valid")
        .with_machine_memory(Box::new(Fixed(total_gib * GIB)))
    }

    #[test]
    fn the_reserve_is_never_lent_to_a_tier() {
        // 121 GiB machine, 16 held back: the tiers can only see 105.
        let cfg = BudgetConfig::with_total(121 * GIB);
        assert_eq!(cfg.pool_bytes(), 121 * GIB - DEFAULT_RESERVE_BYTES);
        assert_eq!(
            cfg.resident_ceiling() + cfg.on_demand_ceiling(),
            cfg.pool_bytes()
        );
    }

    #[test]
    fn a_config_that_promises_more_than_the_machine_has_is_refused() {
        let err = BudgetConfig {
            total_bytes: 100 * GIB,
            reserve_bytes: 16 * GIB,
            resident_ceiling_bytes: Some(60 * GIB),
            on_demand_ceiling_bytes: Some(40 * GIB),
        }
        .validate()
        .expect_err("60 + 40 exceeds the 84 left after the reserve");
        assert!(matches!(err, BudgetConfigError::CeilingsExceedPool { .. }));
    }

    #[test]
    fn a_reserve_larger_than_the_machine_is_refused() {
        let err = BudgetConfig {
            total_bytes: 8 * GIB,
            reserve_bytes: 16 * GIB,
            resident_ceiling_bytes: None,
            on_demand_ceiling_bytes: None,
        }
        .validate()
        .expect_err("nothing would be left to serve from");
        assert!(matches!(err, BudgetConfigError::ReserveExceedsTotal { .. }));
    }

    #[test]
    fn two_concurrent_loads_cannot_both_take_the_same_space() {
        // The bug this whole module exists to prevent: both loads look at a
        // 60 GiB tier holding nothing, and both want 40 GiB.
        let b = budget(121, 16, 60, 45);
        b.admit("llm", Tier::Resident, 40 * GIB)
            .expect("first fits");
        let denied = b
            .admit("coder", Tier::Resident, 40 * GIB)
            .expect_err("second must not also fit");
        assert_eq!(denied.tier_available_bytes, 20 * GIB);
        assert_eq!(denied.tier_ceiling_bytes, 60 * GIB);
    }

    #[test]
    fn tiers_do_not_borrow_from_each_other() {
        // A full resident tier must not stop a media-gen pipeline loading,
        // and vice versa — that separation is the point of having tiers.
        let b = budget(121, 16, 60, 45);
        b.admit("llm", Tier::Resident, 60 * GIB)
            .expect("fills resident");
        assert_eq!(b.available_in(Tier::Resident), 0);
        b.admit("wan", Tier::OnDemand, 45 * GIB)
            .expect("on-demand is untouched by a full resident tier");
        assert_eq!(b.available_in(Tier::OnDemand), 0);
    }

    #[test]
    fn releasing_returns_the_space_to_its_own_tier() {
        let b = budget(121, 16, 60, 45);
        b.admit("zimage", Tier::OnDemand, 44 * GIB).expect("fits");
        assert!(!b.would_admit(Tier::OnDemand, 44 * GIB));
        let freed = b.release("zimage").expect("was committed");
        assert_eq!(freed.bytes, 44 * GIB);
        assert!(b.would_admit(Tier::OnDemand, 44 * GIB));
    }

    #[test]
    fn releasing_an_unknown_key_is_not_an_error() {
        // Unload paths can run twice; the second must not fail.
        let b = budget(121, 16, 60, 45);
        assert!(b.release("never-loaded").is_none());
    }

    #[test]
    fn re_admitting_a_live_key_replaces_rather_than_stacks() {
        // Reloading at a longer context grows the claim. Stacking would
        // double-count and wedge the tier.
        let b = budget(121, 16, 60, 45);
        b.admit("llm", Tier::Resident, 30 * GIB).expect("initial");
        b.admit("llm", Tier::Resident, 50 * GIB)
            .expect("grow in place — 50 fits in 60 once the old 30 is displaced");
        assert_eq!(b.available_in(Tier::Resident), 10 * GIB);
        b.admit("llm", Tier::Resident, 20 * GIB).expect("shrink");
        assert_eq!(b.available_in(Tier::Resident), 40 * GIB);
    }

    #[test]
    fn a_model_too_big_for_the_tier_says_so_distinctly() {
        // "never fits" and "does not fit right now" need different operator
        // responses, so the message distinguishes them.
        let b = budget(121, 16, 60, 45);
        let denied = b
            .admit("deepseek-v4-pro", Tier::Resident, 200 * GIB)
            .expect_err("far over the ceiling");
        let msg = denied.to_string();
        assert!(msg.contains("cannot be served on this node"), "{msg}");

        b.admit("llm", Tier::Resident, 50 * GIB).expect("fits");
        let denied = b
            .admit("coder", Tier::Resident, 20 * GIB)
            .expect_err("would fit in an empty tier but not now");
        let msg = denied.to_string();
        assert!(msg.contains("unload another model first"), "{msg}");
    }

    #[test]
    fn headroom_is_applied_above_the_on_disk_size() {
        // 1.35x — a 20 GiB GGUF must not be admitted as 20 GiB.
        assert_eq!(MemoryBudget::with_headroom(100), 135);
        assert!(MemoryBudget::with_headroom(20 * GIB) > 20 * GIB);
    }

    #[test]
    fn the_snapshot_accounts_for_every_byte() {
        let b = budget(121, 16, 60, 45);
        b.admit("llm", Tier::Resident, 21 * GIB).expect("fits");
        b.admit("coder", Tier::Resident, 18 * GIB).expect("fits");
        b.admit("wan", Tier::OnDemand, 34 * GIB).expect("fits");

        let snap = b.snapshot();
        assert_eq!(snap.total_bytes, 121 * GIB);
        assert_eq!(snap.reserve_bytes, 16 * GIB);
        assert_eq!(snap.pool_bytes, 105 * GIB);
        assert_eq!(snap.committed_bytes, 73 * GIB);

        let resident = &snap.tiers[0];
        assert_eq!(resident.tier, Tier::Resident);
        assert_eq!(resident.committed_bytes, 39 * GIB);
        assert_eq!(resident.available_bytes, 21 * GIB);
        assert_eq!(resident.commitments.len(), 2);

        let on_demand = &snap.tiers[1];
        assert_eq!(on_demand.committed_bytes, 34 * GIB);
        assert_eq!(on_demand.available_bytes, 11 * GIB);
    }

    #[test]
    fn a_mixed_stack_on_a_large_unified_host_fits_with_the_reserve_intact() {
        // A 121 GiB unified-memory host, 16 GiB reserved for the OS,
        // RocksDB and node services. Resident tier holds the two MoE language
        // models plus the small ONNX runtimes; the on-demand tier holds one
        // diffusion pipeline at a time.
        let b = MemoryBudget::new(BudgetConfig::with_total(121 * GIB))
            .expect("valid")
            .with_machine_memory(Box::new(Fixed(121 * GIB)));

        for (id, gib) in [
            ("qwen3.6-35b-a3b", 22),
            ("qwen3-coder-30b-a3b", 19),
            ("timesfm-2.5", 4),
            ("parakeet-tdt-0.6b-v3", 2),
            ("siglip2-base", 1),
            ("tts", 4),
        ] {
            b.admit(id, Tier::Resident, gib * GIB)
                .unwrap_or_else(|e| panic!("{id} should fit: {e}"));
        }

        // Wan 2.2 TI2V-5B is the largest single pipeline in the plan.
        b.admit("wan2.2-ti2v-5b", Tier::OnDemand, 35 * GIB)
            .expect("one pipeline at a time fits the on-demand tier");

        let snap = b.snapshot();
        assert!(
            snap.committed_bytes <= snap.pool_bytes,
            "committed {} must not exceed the {} pool",
            snap.committed_bytes,
            snap.pool_bytes
        );
        // The reserve is still whole: nothing was lent out of it.
        assert_eq!(snap.total_bytes - snap.pool_bytes, DEFAULT_RESERVE_BYTES);
    }

    #[test]
    fn the_resident_ceiling_can_be_changed_on_a_live_budget_without_a_restart() {
        // The whole point of scheduled profiles: move the ceiling on a running
        // node. 121 GiB machine; start at a 47 GiB resident ceiling (tenzro-mode
        // "code"), switch to 25 GiB ("video"), both while the budget is live.
        let b = budget(121, 16, 47, 58);
        assert_eq!(b.current_resident_ceiling(), 47 * GIB);

        b.set_resident_ceiling(Some(25 * GIB))
            .expect("shrink is valid");
        assert_eq!(b.current_resident_ceiling(), 25 * GIB);

        b.set_resident_ceiling(Some(47 * GIB))
            .expect("grow back is valid");
        assert_eq!(b.current_resident_ceiling(), 47 * GIB);
    }

    #[test]
    fn a_ceiling_larger_than_the_pool_is_rejected_not_clamped() {
        // A profile that promises more than the machine has must fail loudly at
        // set time, the same way construction refuses it — never silently clamp.
        let b = budget(121, 16, 47, 58);
        let err = b.set_resident_ceiling(Some(200 * GIB)).unwrap_err();
        // The ceiling did not move.
        assert_eq!(b.current_resident_ceiling(), 47 * GIB);
        let _ = err; // any BudgetConfigError is correct; the invariant is "unchanged".
    }

    #[test]
    fn lowering_the_ceiling_below_what_is_committed_is_allowed_and_does_not_evict() {
        // A scheduled shrink must be possible even while models are resident.
        // The overcommit is transient; the autotuner's EvictIdle reconciles it
        // as models fall idle. Refusing here would make a scheduled shrink
        // impossible, which is the opposite of the feature.
        let b = budget(121, 16, 47, 58);
        b.admit("qwen3.8-27b", Tier::Resident, 18 * GIB)
            .expect("fits under 47");
        b.admit("muse-glimmer-30b", Tier::Resident, 17 * GIB)
            .expect("35 total, fits");

        // Now switch to a 25 GiB ceiling while 35 GiB is committed.
        b.set_resident_ceiling(Some(25 * GIB))
            .expect("shrink is allowed while overcommitted");
        assert_eq!(b.current_resident_ceiling(), 25 * GIB);

        // The residents are untouched — nothing was force-evicted; the
        // committed total still reflects both models.
        let snap = b.snapshot();
        assert!(
            snap.committed_bytes >= 35 * GIB,
            "residents were not evicted"
        );
    }

    #[test]
    fn passing_none_restores_the_default_split() {
        // Same reserve the budget() helper uses (16 GiB), so the default split
        // is computed over the same pool.
        let b = budget(121, 16, 47, 58);
        b.set_resident_ceiling(None).expect("none is valid");
        // With no explicit ceiling, resident_ceiling() applies DEFAULT_RESIDENT_PCT
        // of the post-reserve pool: (121 - 16) GiB * pct.
        let expected = BudgetConfig {
            total_bytes: 121 * GIB,
            reserve_bytes: 16 * GIB,
            resident_ceiling_bytes: None,
            on_demand_ceiling_bytes: None,
        }
        .resident_ceiling();
        assert_eq!(b.current_resident_ceiling(), expected);
    }
}
