//! Cross-modality memory budget.
//!
//! # Why this exists
//!
//! A node serves several model families out of one memory pool: GGUF language
//! models under llama.cpp, ONNX models under six runtimes (forecast, vision,
//! text-embedding, segmentation, detection, ASR), and diffusion pipelines in
//! the out-of-process Python media-gen worker. Before this module each of
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
//! total ─┬─ reserve      OS, node process, RocksDB, iroh, cloud features
//!        ├─ Resident     always-loaded models: LLMs, ASR, embeddings, TTS
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
//! # Out-of-process participants
//!
//! The Python media-gen worker cannot share this process's memory. It holds
//! commitments through the node's RPC surface, which calls the same
//! [`MemoryBudget::admit`] and [`MemoryBudget::release`] as in-process
//! runtimes do. That is the whole reason admission is keyed by an opaque
//! string rather than by a typed model handle.

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
    /// Held back from all tiers for the OS, RocksDB, and node services.
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

/// A load was declined because it would breach the budget.
///
/// Carries what was asked for and what is actually free so the operator can
/// tell "this model is too big for the node" from "this model is too big
/// right now", which call for different responses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmissionDenied {
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
}

impl MemoryBudget {
    /// Build a budget from a validated configuration.
    pub fn new(config: BudgetConfig) -> Result<Self, BudgetConfigError> {
        config.validate()?;
        Ok(Self {
            state: Mutex::new(State {
                config,
                commitments: BTreeMap::new(),
            }),
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
    pub fn would_admit(&self, tier: Tier, bytes: u64) -> bool {
        bytes <= self.available_in(tier)
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

        BudgetSnapshot {
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
    fn the_stack_this_box_is_planned_for_fits_with_the_reserve_intact() {
        // The concrete plan: 121 GiB DGX Spark, 16 GiB reserved for the OS,
        // RocksDB and node services. Resident tier holds the two MoE language
        // models plus the small ONNX runtimes; the on-demand tier holds one
        // diffusion pipeline at a time.
        let b = MemoryBudget::new(BudgetConfig::with_total(121 * GIB)).expect("valid");

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
}
