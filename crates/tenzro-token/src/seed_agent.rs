//! SeedAgent treasury allocation primitive (Agent-Swarm Spec 10).
//!
//! The full spec ([seed-agent.md](../../../docs/architecture/agent-swarm/seed-agent.md))
//! describes a treasury earmark that funds protocol-owned autonomous
//! agents during the first 12 mainnet months. SeedAgents register TDIP
//! identities, post bonds, and exercise the full stack (inference, 7683
//! intents, channels, bridges) so that providers, template marketplaces,
//! and dispute pipelines have real volume before organic demand arrives.
//!
//! This module lands the on-chain accounting primitives:
//!
//! - [`TreasuryEarmark`] — the singleton allocation record with decay
//!   schedule and aggregate draw counters.
//! - [`Charter`] — a governance-signed mandate enumerating which
//!   operations a class of SeedAgents may perform, with spend caps and a
//!   counterparty filter.
//! - [`SeedAgentRecord`] — per-agent provisioning state: which charter
//!   the agent operates under, how much of its allocation is used, and
//!   the agent DID + bond reference.
//! - [`SeedAgentEarmarkManager`] — owns the singleton + charter set +
//!   per-agent registry with optional RocksDB write-through.
//!
//! All of Spec 10 is now shipped: the primitives + hydration + read
//! access, the governance executor wiring (charter add/modify/terminate /
//! earmark / status), the per-month decay enforcement at refill, the
//! off-chain [`SeedAgentDaemon`](crate::seed_agent_daemon::SeedAgentDaemon)
//! that drives monthly refills and pauses agents under sunsetted charters,
//! the [`SEED_AGENTS_TOPIC`](crate::seed_agent_gossip::SEED_AGENTS_TOPIC)
//! gossipsub fan-out (`tenzro/seed-agents`), and the sunset wind-down sweep
//! ([`SeedAgentEarmarkManager::sunset_wind_down_sweep`]) that
//! Paused→Quarantined→Terminated agents under sunsetted charters and
//! disposes the residual surplus.
//!
//! Storage layout (`CF_TOKENS`):
//! - `seed_earmark:singleton` → JSON-encoded [`TreasuryEarmark`].
//! - `seed_charter:<charter_id_hex>` → JSON-encoded [`Charter`].
//! - `seed_agent:<agent_did>` → JSON-encoded [`SeedAgentRecord`].
//!
//! All TNZO amounts are 18-decimal base units, consistent with the rest
//! of `tenzro-token`.

use crate::error::{Result, TokenError};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tenzro_storage::{KvStore, WriteOp, CF_TOKENS};
use tenzro_types::primitives::{Hash, Timestamp};
use tracing::{debug, info};

/// Storage key for the singleton [`TreasuryEarmark`] under `CF_TOKENS`.
pub const SEED_EARMARK_KEY: &[u8] = b"seed_earmark:singleton";
/// Prefix for per-charter records: `seed_charter:<charter_id_hex>`.
pub const SEED_CHARTER_PREFIX: &[u8] = b"seed_charter:";
/// Prefix for per-agent records: `seed_agent:<agent_did>`.
pub const SEED_AGENT_PREFIX: &[u8] = b"seed_agent:";

/// Default bootstrap window: 12 months in milliseconds.
pub const DEFAULT_BOOTSTRAP_MONTHS: u8 = 12;

/// Default disposition for surplus at sunset, encoded as the
/// percentage to *burn*; the remainder returns to general treasury.
/// `5000 bps = 50%`. Matches seed-agent.md §"Sunset and wind-down":
/// *"Default action absent a governance vote: burn 50% / return 50%."*
pub const DEFAULT_SURPLUS_BURN_BPS: u16 = 5000;

/// Default grace window between Paused → Quarantined and Quarantined →
/// Terminated sweeps, in milliseconds. Seven days gives any in-flight
/// counterparty operation (channel close, 7683 settle, dispute window)
/// time to resolve before the agent is wallet-drained.
pub const DEFAULT_QUARANTINE_GRACE_MS: i64 = 7 * 86_400_000;

/// Length of a "month" in milliseconds for decay accounting purposes.
/// Uses a fixed 30-day window so month-index arithmetic is deterministic
/// independent of calendar drift. 30 * 86_400_000.
pub const MONTH_MILLIS: i64 = 30 * 86_400_000;

/// Operations that a [`Charter`] may permit.
///
/// Enumeration matches seed-agent.md §"Charters". Any operation not in
/// this set is rejected by SeedAgent admission, regardless of charter
/// signature — this is a closed set of bootstrap activities.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OperationKind {
    /// Pay real providers for real inferences (charter C1).
    InferenceConsumer,
    /// Post tasks, accept solutions (extension of C1).
    TaskMarketplaceConsumer,
    /// Spawn child agents from templates and exercise spawn flow (C4).
    TemplateInstantiator,
    /// Exercise LZ/Wormhole/CCT/deBridge with small amounts (C2).
    BridgeUser,
    /// Open and resolve micropayment channels (C3).
    SettlementProbe,
    /// Open 7683 intents to be filled by external solvers (C5).
    Settler7683Probe,
    /// Bounded adversarial action for dispute pipeline exercise (C6).
    DisputeFiler,
}

impl OperationKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            OperationKind::InferenceConsumer => "inference_consumer",
            OperationKind::TaskMarketplaceConsumer => "task_marketplace_consumer",
            OperationKind::TemplateInstantiator => "template_instantiator",
            OperationKind::BridgeUser => "bridge_user",
            OperationKind::SettlementProbe => "settlement_probe",
            OperationKind::Settler7683Probe => "settler_7683_probe",
            OperationKind::DisputeFiler => "dispute_filer",
        }
    }
}

/// Per-month maximum draw cap, in 18-decimal TNZO base units.
///
/// `month` is 0-indexed from `bootstrap_start`; month 12 (and beyond)
/// must have `max_draw_wei == 0` for the schedule to be valid.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DecayPoint {
    pub month: u8,
    pub max_draw_wei: u128,
}

/// Spend caps applied to agents operating under a charter.
///
/// All amounts are 18-decimal TNZO base units. Caps are enforced by the
/// off-chain daemon at refill time and (when the governance executor
/// wires up the on-chain enforcement) checked at admission against
/// per-agent draw counters.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SpendCaps {
    /// Daily cap per agent (18-decimal base units).
    pub daily_cap_wei: u128,
    /// Cumulative monthly cap per agent.
    pub monthly_cap_wei: u128,
    /// Maximum amount that can leave on a single transaction.
    pub per_tx_cap_wei: u128,
}

impl SpendCaps {
    /// Reasonable C1-class genesis defaults: 10 TNZO/day per agent,
    /// 200 TNZO/month, 1 TNZO/tx. Governance tunes these per charter.
    pub fn default_inference_caps() -> Self {
        Self {
            daily_cap_wei: 10_u128 * 1_000_000_000_000_000_000,
            monthly_cap_wei: 200_u128 * 1_000_000_000_000_000_000,
            per_tx_cap_wei: 1_000_000_000_000_000_000,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.per_tx_cap_wei > self.daily_cap_wei {
            return Err(TokenError::InvalidParameter(
                "per_tx_cap > daily_cap".into(),
            ));
        }
        if self.daily_cap_wei > self.monthly_cap_wei {
            return Err(TokenError::InvalidParameter(
                "daily_cap > monthly_cap".into(),
            ));
        }
        Ok(())
    }
}

/// Optional throughput target for charters that want to drive a steady
/// load (e.g. C1: ~10 inferences/min). Advisory only — caps still bind.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TargetThroughput {
    /// Operations per second, scaled by 1000 (i.e. 167 = 0.167 ops/s
    /// = 10 ops/min). Avoids float in serialized form.
    pub ops_per_sec_milli: u32,
}

/// Counterparty admission filter applied to all SeedAgent transactions.
///
/// SeedAgents are forbidden from transacting with each other (would be
/// wash) and may optionally be restricted to a denylist of known-bad
/// actors. The admission check enforces:
///   1. counterparty `is_seed_agent` flag is `false`;
///   2. counterparty DID is not in `denied_dids`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CounterpartyFilter {
    /// If true, reject any counterparty whose TDIP identity has
    /// `is_seed_agent == true`. Always set in initial charters.
    pub deny_other_seed_agents: bool,
    /// Explicit DID denylist. Empty by default.
    pub denied_dids: Vec<String>,
}

impl Default for CounterpartyFilter {
    fn default() -> Self {
        Self {
            deny_other_seed_agents: true,
            denied_dids: Vec::new(),
        }
    }
}

/// A governance-signed mandate enumerating what a class of SeedAgents
/// may do. Charters are immutable from agent perspective (only governance
/// can mutate or sunset them).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Charter {
    pub charter_id: Hash,
    pub name: String,
    pub purpose: String,
    pub operations: Vec<OperationKind>,
    pub spend_caps: SpendCaps,
    pub target_throughput: Option<TargetThroughput>,
    pub counterparty_filter: CounterpartyFilter,
    pub sunset: Timestamp,
    /// Set to false by governance to wind down a charter without waiting
    /// for sunset; `enabled == false` blocks new agent provisioning under
    /// this charter and signals existing agents to wind down.
    pub enabled: bool,
}

impl Charter {
    pub fn validate(&self) -> Result<()> {
        if self.name.is_empty() {
            return Err(TokenError::InvalidParameter("charter name empty".into()));
        }
        if self.operations.is_empty() {
            return Err(TokenError::InvalidParameter(
                "charter has no operations".into(),
            ));
        }
        self.spend_caps.validate()?;
        Ok(())
    }
}

/// Per-month draw schedule. Indexed by month-from-bootstrap-start.
///
/// `seed-agent.md` reasonable shape: 100% allocation drawable in months
/// 1-3, 75% in months 4-6, 50% in months 7-9, 25% in months 10-12, 0%
/// thereafter. Total draws ≤ ~80% of allocation; the remainder either
/// extends past month 12 (governance vote) or returns to treasury.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DecaySchedule {
    pub points: Vec<DecayPoint>,
}

impl DecaySchedule {
    /// Default 12-month schedule scaled relative to a base monthly draw.
    /// `base_monthly_draw_wei` is the cap for months 1-3 (100% rate).
    pub fn default_with_base(base_monthly_draw_wei: u128) -> Self {
        let p = base_monthly_draw_wei;
        let pct = |bps: u32| -> u128 {
            // (p * bps) / 10_000 with u128 safety
            let prod = p.saturating_mul(bps as u128);
            prod / 10_000
        };
        let points = vec![
            DecayPoint { month: 0, max_draw_wei: pct(10_000) },
            DecayPoint { month: 1, max_draw_wei: pct(10_000) },
            DecayPoint { month: 2, max_draw_wei: pct(10_000) },
            DecayPoint { month: 3, max_draw_wei: pct(7_500) },
            DecayPoint { month: 4, max_draw_wei: pct(7_500) },
            DecayPoint { month: 5, max_draw_wei: pct(7_500) },
            DecayPoint { month: 6, max_draw_wei: pct(5_000) },
            DecayPoint { month: 7, max_draw_wei: pct(5_000) },
            DecayPoint { month: 8, max_draw_wei: pct(5_000) },
            DecayPoint { month: 9, max_draw_wei: pct(2_500) },
            DecayPoint { month: 10, max_draw_wei: pct(2_500) },
            DecayPoint { month: 11, max_draw_wei: pct(2_500) },
            DecayPoint { month: 12, max_draw_wei: 0 },
        ];
        Self { points }
    }

    /// Maximum draw permitted in `month` from bootstrap_start.
    /// Months past the schedule end return 0 (hard sunset).
    pub fn cap_for_month(&self, month: u8) -> u128 {
        self.points
            .iter()
            .find(|p| p.month == month)
            .map(|p| p.max_draw_wei)
            .unwrap_or(0)
    }

    pub fn validate(&self) -> Result<()> {
        if self.points.is_empty() {
            return Err(TokenError::InvalidParameter(
                "decay schedule empty".into(),
            ));
        }
        // Final month must be 0 (hard sunset).
        let last = self.points.last().unwrap();
        if last.max_draw_wei != 0 {
            return Err(TokenError::InvalidParameter(format!(
                "decay schedule does not sunset (final month {} max_draw_wei = {})",
                last.month, last.max_draw_wei
            )));
        }
        // Months must be strictly ascending, no duplicates.
        for w in self.points.windows(2) {
            if w[1].month <= w[0].month {
                return Err(TokenError::InvalidParameter(
                    "decay schedule months not strictly ascending".into(),
                ));
            }
        }
        Ok(())
    }
}

/// The singleton TreasuryEarmark for SeedAgents.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreasuryEarmark {
    pub name: String,
    /// Genesis-allocated TNZO, in 18-decimal base units.
    pub initial_allocation_wei: u128,
    /// Remaining unspent allocation.
    pub allocation_remaining_wei: u128,
    /// Cumulative TNZO drawn since bootstrap_start (audit-only).
    pub total_drawn_wei: u128,
    pub bootstrap_start: Timestamp,
    pub bootstrap_end: Timestamp,
    pub decay_schedule: DecaySchedule,
    /// Number of SeedAgents currently provisioned (not Terminated).
    pub seed_agent_count: u32,
    /// Identifiers of charters under this earmark.
    pub charter_ids: Vec<Hash>,
    /// Master kill switch (governance dial). When false, no new agent
    /// provisioning is admitted and the daemon should wind down.
    pub enabled: bool,
    /// Surplus disposition at sunset, in basis points to *burn* (the
    /// remainder returns to general treasury).
    pub surplus_burn_bps: u16,
    /// Index of the month currently being drawn against (0-based from
    /// `bootstrap_start`). When the observed month advances at refill
    /// time, `current_month` rolls forward and `month_drawn_wei` resets.
    pub current_month: u8,
    /// Cumulative draw within `current_month`, in 18-decimal base units.
    /// Reset to 0 when `current_month` advances. Bounded above by
    /// `decay_schedule.cap_for_month(current_month) * seed_agent_count`
    /// — that is, every active agent may draw the per-month cap once.
    pub month_drawn_wei: u128,
}

impl Default for TreasuryEarmark {
    fn default() -> Self {
        Self {
            name: "SeedAgent".to_string(),
            initial_allocation_wei: 0,
            allocation_remaining_wei: 0,
            total_drawn_wei: 0,
            bootstrap_start: Timestamp::default(),
            bootstrap_end: Timestamp::default(),
            decay_schedule: DecaySchedule { points: Vec::new() },
            seed_agent_count: 0,
            charter_ids: Vec::new(),
            enabled: true,
            surplus_burn_bps: DEFAULT_SURPLUS_BURN_BPS,
            current_month: 0,
            month_drawn_wei: 0,
        }
    }
}

impl TreasuryEarmark {
    /// Compute the 0-indexed month relative to `bootstrap_start` for the
    /// given timestamp. Saturates at 0 for `now < bootstrap_start` and at
    /// 255 for very-far-future timestamps. Uses fixed [`MONTH_MILLIS`].
    pub fn month_index_for(&self, now: Timestamp) -> u8 {
        let now_ms = now.as_millis();
        let start_ms = self.bootstrap_start.as_millis();
        if now_ms <= start_ms {
            return 0;
        }
        let diff = now_ms - start_ms;
        let months = diff / MONTH_MILLIS;
        if months > u8::MAX as i64 {
            u8::MAX
        } else {
            months as u8
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.surplus_burn_bps > 10_000 {
            return Err(TokenError::InvalidParameter(format!(
                "surplus_burn_bps {} > 10000",
                self.surplus_burn_bps
            )));
        }
        if self.allocation_remaining_wei > self.initial_allocation_wei {
            return Err(TokenError::InvalidParameter(
                "allocation_remaining > initial_allocation".into(),
            ));
        }
        if self.bootstrap_end.as_millis() < self.bootstrap_start.as_millis() {
            return Err(TokenError::InvalidParameter(
                "bootstrap_end before bootstrap_start".into(),
            ));
        }
        // An empty schedule is permitted only at genesis (when no allocation
        // has been seeded yet).
        if self.initial_allocation_wei > 0 {
            self.decay_schedule.validate()?;
        }
        Ok(())
    }
}

/// Status of an individual SeedAgent in its provisioning lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SeedAgentStatus {
    /// Provisioned and operating per its charter.
    Active,
    /// Paused by governance; resumable.
    Paused,
    /// Quarantined by governance; existing positions unwind, no new ops.
    Quarantined,
    /// Terminated; bond withdrawn, wallet drained, no further activity.
    Terminated,
}

impl SeedAgentStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            SeedAgentStatus::Active => "active",
            SeedAgentStatus::Paused => "paused",
            SeedAgentStatus::Quarantined => "quarantined",
            SeedAgentStatus::Terminated => "terminated",
        }
    }
}

/// Per-agent SeedAgent provisioning record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeedAgentRecord {
    /// Machine DID of the SeedAgent.
    pub agent_did: String,
    /// Controller (governance) DID — well-known, e.g.
    /// `did:tenzro:org:treasury:seedagents`.
    pub controller_did: String,
    /// Charter under which this agent operates.
    pub charter_id: Hash,
    pub status: SeedAgentStatus,
    /// Cumulative TNZO drawn from earmark allocation for this agent.
    pub allocation_used_wei: u128,
    /// Posted bond identifier (link to AgentBond Spec 9). May be unset
    /// during provisioning before the bond is posted.
    pub bond_id: Option<Hash>,
    pub provisioned_at: Timestamp,
    pub last_active: Timestamp,
}

impl SeedAgentRecord {
    pub fn new(
        agent_did: String,
        controller_did: String,
        charter_id: Hash,
        provisioned_at: Timestamp,
    ) -> Self {
        Self {
            agent_did,
            controller_did,
            charter_id,
            status: SeedAgentStatus::Active,
            allocation_used_wei: 0,
            bond_id: None,
            provisioned_at,
            last_active: provisioned_at,
        }
    }
}

/// Result of a [`SeedAgentEarmarkManager::refill_agent_monthly`] call.
///
/// `granted_wei` is the actually-disbursed amount after clamping against
/// both the charter's monthly cap and the global decay schedule cap for
/// the current month. `granted_wei == 0` means the schedule has sunsetted
/// (month past final point) or the earmark is exhausted/disabled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefillResult {
    pub agent_did: String,
    pub requested_wei: u128,
    pub granted_wei: u128,
    pub allocation_remaining_wei: u128,
    pub month: u8,
    pub schedule_cap_for_month_wei: u128,
}

/// Disposition of the unspent earmark surplus at hard sunset.
///
/// Produced by [`SeedAgentEarmarkManager::dispose_surplus_at_sunset`] when
/// every charter has sunsetted and no Active/Paused/Quarantined agents
/// remain. The caller (governance executor or wind-down sweeper) enacts
/// the on-chain effect: `burn_wei` is removed from circulating supply via
/// [`crate::tnzo::TnzoToken::burn`]; `treasury_wei` is deposited to the
/// general [`crate::treasury::NetworkTreasury`] under the TNZO asset.
///
/// The manager itself only zeroes `allocation_remaining_wei` and flips
/// `enabled` to `false` — token-supply effects are caller-owned so this
/// crate stays free of cycles with the treasury module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SurplusDisposition {
    /// Surplus that was disposed at sunset (`burn_wei + treasury_wei`).
    pub total_wei: u128,
    /// Portion to burn (`total * surplus_burn_bps / 10_000`).
    pub burn_wei: u128,
    /// Portion to return to the general treasury (`total - burn_wei`).
    pub treasury_wei: u128,
    /// `surplus_burn_bps` at the time of disposition (audit).
    pub surplus_burn_bps: u16,
}

/// Outcome of one [`SeedAgentEarmarkManager::sunset_wind_down_sweep`]
/// invocation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WindDownReport {
    /// Agent DIDs transitioned Paused → Quarantined this sweep.
    pub quarantined: Vec<String>,
    /// Agent DIDs transitioned Quarantined → Terminated this sweep.
    pub terminated: Vec<String>,
    /// Surplus disposition if all charters have sunsetted and no
    /// non-Terminated agents remain. `None` if the wind-down condition
    /// has not been reached (or surplus already disposed).
    pub surplus: Option<SurplusDisposition>,
}

/// Manages the SeedAgent earmark + charters + per-agent registry, with
/// optional RocksDB write-through under `CF_TOKENS`.
///
/// Construction:
/// - [`SeedAgentEarmarkManager::new`] — pure in-memory (tests).
/// - [`SeedAgentEarmarkManager::with_storage`] — write-through and
///   hydrated from disk on startup.
pub struct SeedAgentEarmarkManager {
    earmark: parking_lot::RwLock<TreasuryEarmark>,
    charters: dashmap::DashMap<Hash, Charter>,
    agents: dashmap::DashMap<String, SeedAgentRecord>,
    storage: Option<Arc<dyn KvStore>>,
}

impl Default for SeedAgentEarmarkManager {
    fn default() -> Self {
        Self::new()
    }
}

impl SeedAgentEarmarkManager {
    /// In-memory manager with default genesis earmark (0 allocation).
    pub fn new() -> Self {
        Self {
            earmark: parking_lot::RwLock::new(TreasuryEarmark::default()),
            charters: dashmap::DashMap::new(),
            agents: dashmap::DashMap::new(),
            storage: None,
        }
    }

    /// Construct with RocksDB write-through and hydrate the earmark
    /// singleton, all charters, and all agent records from disk.
    pub fn with_storage(storage: Arc<dyn KvStore>) -> Result<Self> {
        let mgr = Self {
            earmark: parking_lot::RwLock::new(TreasuryEarmark::default()),
            charters: dashmap::DashMap::new(),
            agents: dashmap::DashMap::new(),
            storage: Some(storage.clone()),
        };
        mgr.hydrate_from_storage()?;
        Ok(mgr)
    }

    /// Read a snapshot of the singleton earmark.
    pub fn earmark(&self) -> TreasuryEarmark {
        self.earmark.read().clone()
    }

    /// Returns the charter with the given id, if present.
    pub fn get_charter(&self, charter_id: &Hash) -> Option<Charter> {
        self.charters.get(charter_id).map(|c| c.clone())
    }

    /// All known charters, ordered by name for stable RPC output.
    pub fn list_charters(&self) -> Vec<Charter> {
        let mut v: Vec<Charter> = self.charters.iter().map(|e| e.value().clone()).collect();
        v.sort_by(|a, b| a.name.cmp(&b.name));
        v
    }

    /// Returns the SeedAgent record for `agent_did`, if registered.
    pub fn get_agent(&self, agent_did: &str) -> Option<SeedAgentRecord> {
        self.agents.get(agent_did).map(|a| a.clone())
    }

    /// All SeedAgents, optionally filtered to a single charter.
    pub fn list_agents(&self, charter_id: Option<&Hash>) -> Vec<SeedAgentRecord> {
        self.agents
            .iter()
            .filter(|e| match charter_id {
                Some(cid) => &e.value().charter_id == cid,
                None => true,
            })
            .map(|e| e.value().clone())
            .collect()
    }

    /// Returns true if `agent_did` is currently a SeedAgent (any status
    /// except Terminated). Used by the counterparty filter check.
    pub fn is_seed_agent(&self, agent_did: &str) -> bool {
        match self.agents.get(agent_did) {
            Some(a) => !matches!(a.value().status, SeedAgentStatus::Terminated),
            None => false,
        }
    }

    /// Replace the singleton earmark. Validates and persists.
    pub fn apply_earmark(&self, new: TreasuryEarmark) -> Result<()> {
        new.validate()?;
        {
            let mut guard = self.earmark.write();
            *guard = new.clone();
        }
        self.persist_earmark(&new)?;
        info!(
            initial_allocation = new.initial_allocation_wei,
            charters = new.charter_ids.len(),
            "SeedAgent earmark updated"
        );
        Ok(())
    }

    /// Add or replace a charter (governance write path).
    pub fn upsert_charter(&self, charter: Charter) -> Result<()> {
        charter.validate()?;
        self.charters
            .insert(charter.charter_id, charter.clone());
        self.persist_charter(&charter)?;
        // Sync charter id list onto the earmark if needed.
        let needs_sync = {
            let guard = self.earmark.read();
            !guard.charter_ids.contains(&charter.charter_id)
        };
        if needs_sync {
            let snapshot = {
                let mut guard = self.earmark.write();
                guard.charter_ids.push(charter.charter_id);
                guard.clone()
            };
            self.persist_earmark(&snapshot)?;
        }
        debug!(charter = %charter.name, "SeedAgent charter upserted");
        Ok(())
    }

    /// Register a SeedAgent under a known charter. Bumps
    /// `seed_agent_count` on the earmark and persists.
    pub fn register_agent(&self, record: SeedAgentRecord) -> Result<()> {
        if !self.charters.contains_key(&record.charter_id) {
            return Err(TokenError::InvalidParameter(format!(
                "unknown charter_id {:?}",
                record.charter_id
            )));
        }
        let new_record = !self.agents.contains_key(&record.agent_did);
        self.agents
            .insert(record.agent_did.clone(), record.clone());
        self.persist_agent(&record)?;
        if new_record {
            let snapshot = {
                let mut guard = self.earmark.write();
                guard.seed_agent_count = guard.seed_agent_count.saturating_add(1);
                guard.clone()
            };
            self.persist_earmark(&snapshot)?;
        }
        debug!(
            agent = %record.agent_did,
            charter = ?record.charter_id,
            "SeedAgent registered"
        );
        Ok(())
    }

    /// Update an agent's status (governance pause/quarantine/terminate
    /// or daemon-driven wind-down).
    pub fn set_agent_status(
        &self,
        agent_did: &str,
        status: SeedAgentStatus,
    ) -> Result<()> {
        let record = {
            let mut entry = self
                .agents
                .get_mut(agent_did)
                .ok_or_else(|| TokenError::InvalidParameter(
                    format!("unknown SeedAgent {}", agent_did),
                ))?;
            entry.status = status;
            entry.last_active = Timestamp::now();
            entry.value().clone()
        };
        self.persist_agent(&record)?;
        debug!(
            agent = %agent_did,
            status = %status.as_str(),
            "SeedAgent status updated"
        );
        Ok(())
    }

    /// Refill an agent's allocation, enforcing the per-month decay
    /// schedule and charter caps.
    ///
    /// Granted amount = `min(requested_wei, charter.monthly_cap_wei,
    /// schedule_cap_for_month, earmark.allocation_remaining_wei)`.
    /// The earmark's `current_month` rolls forward when `now`
    /// crosses a month boundary; `month_drawn_wei` resets at the
    /// rollover. The cap is further constrained by the *remaining*
    /// month-budget across all agents (so multi-agent draws inside
    /// the same month cannot exceed schedule × seed_agent_count).
    ///
    /// Errors:
    /// - earmark `enabled == false` or `allocation_remaining_wei == 0`
    /// - agent is not registered or is Terminated
    /// - the agent's charter is not enabled
    /// - the agent's charter has been sunsetted (current `now` past
    ///   `charter.sunset`)
    ///
    /// On success, persists both the earmark and the agent record.
    pub fn refill_agent_monthly(
        &self,
        agent_did: &str,
        requested_wei: u128,
        now: Timestamp,
    ) -> Result<RefillResult> {
        if requested_wei == 0 {
            return Err(TokenError::InvalidParameter(
                "refill requested_wei == 0".into(),
            ));
        }

        // Look up agent + charter under read locks.
        let agent_snapshot = self
            .agents
            .get(agent_did)
            .map(|e| e.value().clone())
            .ok_or_else(|| {
                TokenError::InvalidParameter(format!(
                    "unknown SeedAgent {}",
                    agent_did
                ))
            })?;
        if matches!(agent_snapshot.status, SeedAgentStatus::Terminated) {
            return Err(TokenError::InvalidParameter(format!(
                "SeedAgent {} is Terminated",
                agent_did
            )));
        }
        if !matches!(agent_snapshot.status, SeedAgentStatus::Active) {
            return Err(TokenError::InvalidParameter(format!(
                "SeedAgent {} is not Active (status={})",
                agent_did,
                agent_snapshot.status.as_str()
            )));
        }
        let charter = self
            .charters
            .get(&agent_snapshot.charter_id)
            .map(|e| e.value().clone())
            .ok_or_else(|| {
                TokenError::InvalidParameter(format!(
                    "SeedAgent {} references unknown charter {:?}",
                    agent_did, agent_snapshot.charter_id
                ))
            })?;
        if !charter.enabled {
            return Err(TokenError::InvalidParameter(format!(
                "charter {:?} is disabled",
                charter.charter_id
            )));
        }
        if now.as_millis() >= charter.sunset.as_millis()
            && charter.sunset.as_millis() != 0
        {
            return Err(TokenError::InvalidParameter(format!(
                "charter {:?} has sunsetted",
                charter.charter_id
            )));
        }

        // Mutate the earmark under the write lock: roll month forward
        // if needed, then compute the granted amount.
        let (granted, snapshot) = {
            let mut guard = self.earmark.write();
            if !guard.enabled {
                return Err(TokenError::InvalidParameter(
                    "SeedAgent earmark disabled".into(),
                ));
            }
            if guard.allocation_remaining_wei == 0 {
                return Err(TokenError::InvalidParameter(
                    "SeedAgent earmark exhausted".into(),
                ));
            }

            // Roll month forward if `now` lands in a later month than
            // the recorded `current_month`.
            let observed_month = guard.month_index_for(now);
            if observed_month > guard.current_month {
                guard.current_month = observed_month;
                guard.month_drawn_wei = 0;
            }

            let schedule_cap = guard
                .decay_schedule
                .cap_for_month(guard.current_month);
            // Per-agent cap = min(schedule, charter monthly cap, requested).
            let per_agent_cap = schedule_cap
                .min(charter.spend_caps.monthly_cap_wei)
                .min(requested_wei);

            // Across all agents this month, the earmark caps the total
            // monthly draw at `schedule_cap * seed_agent_count` (so each
            // agent gets its own monthly cap, summed). Compute the
            // remaining month-budget and clamp to it.
            let month_budget = schedule_cap
                .saturating_mul(guard.seed_agent_count as u128);
            let month_remaining = month_budget
                .saturating_sub(guard.month_drawn_wei);

            let mut granted = per_agent_cap.min(month_remaining);
            // Cannot exceed the global allocation remaining.
            granted = granted.min(guard.allocation_remaining_wei);

            if granted == 0 {
                let snapshot = RefillResult {
                    agent_did: agent_did.to_string(),
                    requested_wei,
                    granted_wei: 0,
                    allocation_remaining_wei: guard.allocation_remaining_wei,
                    month: guard.current_month,
                    schedule_cap_for_month_wei: schedule_cap,
                };
                return Ok(snapshot);
            }

            guard.allocation_remaining_wei = guard
                .allocation_remaining_wei
                .saturating_sub(granted);
            guard.total_drawn_wei = guard
                .total_drawn_wei
                .saturating_add(granted);
            guard.month_drawn_wei = guard
                .month_drawn_wei
                .saturating_add(granted);

            let snapshot = guard.clone();
            (granted, snapshot)
        };

        // Persist updated earmark.
        self.persist_earmark(&snapshot)?;

        // Mutate + persist the agent record.
        let agent_record = {
            let mut entry = self
                .agents
                .get_mut(agent_did)
                .ok_or_else(|| TokenError::InvalidParameter(
                    format!("unknown SeedAgent {}", agent_did),
                ))?;
            entry.allocation_used_wei = entry
                .allocation_used_wei
                .saturating_add(granted);
            entry.last_active = now;
            entry.value().clone()
        };
        self.persist_agent(&agent_record)?;

        info!(
            agent = %agent_did,
            charter = ?charter.charter_id,
            requested = requested_wei,
            granted = granted,
            month = snapshot.current_month,
            remaining = snapshot.allocation_remaining_wei,
            "SeedAgent monthly refill"
        );

        Ok(RefillResult {
            agent_did: agent_did.to_string(),
            requested_wei,
            granted_wei: granted,
            allocation_remaining_wei: snapshot.allocation_remaining_wei,
            month: snapshot.current_month,
            schedule_cap_for_month_wei: snapshot
                .decay_schedule
                .cap_for_month(snapshot.current_month),
        })
    }

    /// Single-shot wind-down sweep (Spec 10 Task #44). Pure state-machine —
    /// no external callbacks. The caller passes `now` (injectable for tests)
    /// and a `quarantine_grace_ms` cooldown; the manager:
    ///
    /// 1. Transitions every `Paused` agent under a sunsetted/disabled
    ///    charter to `Quarantined`. Records `last_active = now`.
    /// 2. Transitions every `Quarantined` agent whose `last_active`
    ///    exceeds `now - quarantine_grace_ms` (i.e. cooldown elapsed) to
    ///    `Terminated`.
    /// 3. If **all** charters have sunsetted (`sunset != 0 && now >= sunset`)
    ///    or are disabled, AND no Active/Paused/Quarantined agents remain
    ///    after steps 1+2, computes [`SurplusDisposition`] over the
    ///    earmark's `allocation_remaining_wei`, zeros that field, and
    ///    flips `enabled = false` on the earmark.
    ///
    /// Returns a [`WindDownReport`] describing the transitions + optional
    /// surplus disposition. The caller (governance executor or daemon
    /// sunset hook) enacts the on-chain surplus split: burn portion +
    /// treasury deposit.
    ///
    /// Idempotent: a second call after the earmark is sunsetted and zeroed
    /// returns an empty report. Subsequent quarantine→terminate sweeps
    /// continue to drain any agents that survived the first pass.
    pub fn sunset_wind_down_sweep(
        &self,
        now: Timestamp,
        quarantine_grace_ms: i64,
    ) -> Result<WindDownReport> {
        let mut report = WindDownReport::default();

        // --- step 1: Paused → Quarantined under sunsetted/disabled charter
        for agent in self.list_agents(None) {
            if !matches!(agent.status, SeedAgentStatus::Paused) {
                continue;
            }
            let charter = self.charters.get(&agent.charter_id).map(|e| e.value().clone());
            let should_quarantine = match charter {
                None => true, // dangling charter — quarantine defensively
                Some(c) => {
                    !c.enabled
                        || (c.sunset.as_millis() != 0
                            && now.as_millis() >= c.sunset.as_millis())
                }
            };
            if !should_quarantine {
                continue;
            }
            self.set_agent_status_at(&agent.agent_did, SeedAgentStatus::Quarantined, now)?;
            report.quarantined.push(agent.agent_did);
        }

        // --- step 2: Quarantined → Terminated after cooldown
        for agent in self.list_agents(None) {
            if !matches!(agent.status, SeedAgentStatus::Quarantined) {
                continue;
            }
            let age = now.as_millis().saturating_sub(agent.last_active.as_millis());
            if age < quarantine_grace_ms {
                continue;
            }
            self.set_agent_status_at(&agent.agent_did, SeedAgentStatus::Terminated, now)?;
            // Bump the earmark counter — `seed_agent_count` tracks
            // *non-Terminated* agents (see field docs).
            {
                let snapshot = {
                    let mut guard = self.earmark.write();
                    guard.seed_agent_count = guard.seed_agent_count.saturating_sub(1);
                    guard.clone()
                };
                self.persist_earmark(&snapshot)?;
            }
            report.terminated.push(agent.agent_did);
        }

        // --- step 3: dispose surplus iff all charters sunset/disabled
        //             AND no Active/Paused/Quarantined agents remain.
        let all_charters_sunset = {
            let charters = self.list_charters();
            !charters.is_empty()
                && charters.iter().all(|c| {
                    !c.enabled
                        || (c.sunset.as_millis() != 0
                            && now.as_millis() >= c.sunset.as_millis())
                })
        };
        let no_live_agents = self.list_agents(None).iter().all(|a| {
            matches!(a.status, SeedAgentStatus::Terminated)
        });

        if all_charters_sunset && no_live_agents {
            let snapshot = self.earmark.read().clone();
            let remaining = snapshot.allocation_remaining_wei;
            if remaining > 0 || snapshot.enabled {
                let burn_bps = snapshot.surplus_burn_bps.min(10_000) as u128;
                // burn_wei = floor(remaining * burn_bps / 10000).
                // u128 safe: remaining ≤ initial allocation (genesis bound).
                let burn = remaining.saturating_mul(burn_bps) / 10_000;
                let treasury = remaining.saturating_sub(burn);
                let disposition = SurplusDisposition {
                    total_wei: remaining,
                    burn_wei: burn,
                    treasury_wei: treasury,
                    surplus_burn_bps: snapshot.surplus_burn_bps,
                };
                // Zero the surplus + freeze the earmark.
                let new_snapshot = {
                    let mut guard = self.earmark.write();
                    guard.allocation_remaining_wei = 0;
                    guard.enabled = false;
                    guard.clone()
                };
                self.persist_earmark(&new_snapshot)?;
                info!(
                    total = disposition.total_wei,
                    burn = disposition.burn_wei,
                    treasury = disposition.treasury_wei,
                    burn_bps = disposition.surplus_burn_bps,
                    "SeedAgent earmark surplus disposed at sunset"
                );
                report.surplus = Some(disposition);
            }
        }

        Ok(report)
    }

    /// Internal: like [`set_agent_status`] but pins `last_active` to the
    /// caller-supplied timestamp (the sweep uses this so the quarantine
    /// cooldown is anchored to sweep time, not wall clock).
    fn set_agent_status_at(
        &self,
        agent_did: &str,
        status: SeedAgentStatus,
        now: Timestamp,
    ) -> Result<()> {
        let record = {
            let mut entry = self
                .agents
                .get_mut(agent_did)
                .ok_or_else(|| TokenError::InvalidParameter(
                    format!("unknown SeedAgent {}", agent_did),
                ))?;
            entry.status = status;
            entry.last_active = now;
            entry.value().clone()
        };
        self.persist_agent(&record)?;
        debug!(
            agent = %agent_did,
            status = %status.as_str(),
            "SeedAgent status updated (sweep)"
        );
        Ok(())
    }

    // --- internal: hydration + persistence -------------------------------

    fn hydrate_from_storage(&self) -> Result<()> {
        let storage = self
            .storage
            .as_ref()
            .expect("hydrate_from_storage requires storage");

        // Pre-launch policy: no backcompat shims. If a persisted record
        // was written by an older schema and can't deserialize, drop it
        // and reseed from defaults. No live users, no data to preserve.

        // Earmark singleton.
        match storage.get(CF_TOKENS, SEED_EARMARK_KEY)? {
            Some(bytes) => match serde_json::from_slice::<TreasuryEarmark>(&bytes) {
                Ok(earmark) => {
                    *self.earmark.write() = earmark;
                }
                Err(e) => {
                    tracing::warn!(
                        target: "tenzro_token::seed_agent",
                        error = %e,
                        "persisted SeedAgent earmark is from an older schema; reseeding from default"
                    );
                    let genesis = TreasuryEarmark::default();
                    self.persist_earmark(&genesis)?;
                }
            },
            None => {
                let genesis = TreasuryEarmark::default();
                self.persist_earmark(&genesis)?;
            }
        }

        // Charters.
        let charter_keys =
            storage.get_keys_with_prefix(CF_TOKENS, SEED_CHARTER_PREFIX)?;
        for key in charter_keys {
            let Some(bytes) = storage.get(CF_TOKENS, &key)? else { continue };
            match serde_json::from_slice::<Charter>(&bytes) {
                Ok(charter) => {
                    self.charters.insert(charter.charter_id, charter);
                }
                Err(e) => {
                    tracing::warn!(
                        target: "tenzro_token::seed_agent",
                        key = %String::from_utf8_lossy(&key),
                        error = %e,
                        "dropping unreadable SeedAgent charter (pre-launch flag-day)"
                    );
                    storage.write_batch_sync(vec![WriteOp::Delete {
                        cf: CF_TOKENS.to_string(),
                        key: key.clone(),
                    }])?;
                }
            }
        }

        // Agents.
        let agent_keys =
            storage.get_keys_with_prefix(CF_TOKENS, SEED_AGENT_PREFIX)?;
        for key in agent_keys {
            let Some(bytes) = storage.get(CF_TOKENS, &key)? else { continue };
            match serde_json::from_slice::<SeedAgentRecord>(&bytes) {
                Ok(record) => {
                    self.agents.insert(record.agent_did.clone(), record);
                }
                Err(e) => {
                    tracing::warn!(
                        target: "tenzro_token::seed_agent",
                        key = %String::from_utf8_lossy(&key),
                        error = %e,
                        "dropping unreadable SeedAgent record (pre-launch flag-day)"
                    );
                    storage.write_batch_sync(vec![WriteOp::Delete {
                        cf: CF_TOKENS.to_string(),
                        key: key.clone(),
                    }])?;
                }
            }
        }

        info!(
            charters = self.charters.len(),
            agents = self.agents.len(),
            "SeedAgent earmark manager hydrated"
        );
        Ok(())
    }

    fn persist_earmark(&self, earmark: &TreasuryEarmark) -> Result<()> {
        let Some(storage) = &self.storage else { return Ok(()); };
        let bytes = serde_json::to_vec(earmark).map_err(|e| {
            TokenError::StorageError(format!("encode SeedAgent earmark: {}", e))
        })?;
        storage.write_batch_sync(vec![WriteOp::Put {
            cf: CF_TOKENS.to_string(),
            key: SEED_EARMARK_KEY.to_vec(),
            value: bytes,
        }])?;
        Ok(())
    }

    fn persist_charter(&self, charter: &Charter) -> Result<()> {
        let Some(storage) = &self.storage else { return Ok(()); };
        let bytes = serde_json::to_vec(charter).map_err(|e| {
            TokenError::StorageError(format!("encode SeedAgent charter: {}", e))
        })?;
        let mut key = SEED_CHARTER_PREFIX.to_vec();
        key.extend_from_slice(charter.charter_id.as_bytes());
        storage.write_batch_sync(vec![WriteOp::Put {
            cf: CF_TOKENS.to_string(),
            key,
            value: bytes,
        }])?;
        Ok(())
    }

    fn persist_agent(&self, record: &SeedAgentRecord) -> Result<()> {
        let Some(storage) = &self.storage else { return Ok(()); };
        let bytes = serde_json::to_vec(record).map_err(|e| {
            TokenError::StorageError(format!("encode SeedAgent record: {}", e))
        })?;
        let mut key = SEED_AGENT_PREFIX.to_vec();
        key.extend_from_slice(record.agent_did.as_bytes());
        storage.write_batch_sync(vec![WriteOp::Put {
            cf: CF_TOKENS.to_string(),
            key,
            value: bytes,
        }])?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(byte: u8) -> Hash {
        Hash::new([byte; 32])
    }

    #[test]
    fn operation_kind_strings_are_stable() {
        assert_eq!(OperationKind::InferenceConsumer.as_str(), "inference_consumer");
        assert_eq!(OperationKind::DisputeFiler.as_str(), "dispute_filer");
    }

    #[test]
    fn spend_caps_validate_ordering() {
        let bad = SpendCaps {
            daily_cap_wei: 5,
            monthly_cap_wei: 100,
            per_tx_cap_wei: 10, // > daily
        };
        assert!(bad.validate().is_err());

        let good = SpendCaps::default_inference_caps();
        assert!(good.validate().is_ok());
    }

    #[test]
    fn decay_schedule_default_sunsets_at_month_12() {
        let s = DecaySchedule::default_with_base(1_000);
        assert_eq!(s.cap_for_month(0), 1_000);
        assert_eq!(s.cap_for_month(3), 750);
        assert_eq!(s.cap_for_month(6), 500);
        assert_eq!(s.cap_for_month(9), 250);
        assert_eq!(s.cap_for_month(12), 0);
        assert_eq!(s.cap_for_month(50), 0); // hard sunset
        assert!(s.validate().is_ok());
    }

    #[test]
    fn decay_schedule_rejects_non_zero_final() {
        let s = DecaySchedule {
            points: vec![
                DecayPoint { month: 0, max_draw_wei: 1_000 },
                DecayPoint { month: 1, max_draw_wei: 500 }, // doesn't end at zero
            ],
        };
        assert!(s.validate().is_err());
    }

    #[test]
    fn earmark_default_is_consistent() {
        let e = TreasuryEarmark::default();
        assert_eq!(e.surplus_burn_bps, DEFAULT_SURPLUS_BURN_BPS);
        assert_eq!(e.initial_allocation_wei, 0);
        assert!(e.enabled);
        // Empty schedule is permitted at genesis.
        assert!(e.validate().is_ok());
    }

    #[test]
    fn manager_upsert_charter_then_register_agent() {
        let mgr = SeedAgentEarmarkManager::new();

        let charter = Charter {
            charter_id: h(0xC1),
            name: "InferenceLoad".to_string(),
            purpose: "Steady inference load on registered models".to_string(),
            operations: vec![OperationKind::InferenceConsumer],
            spend_caps: SpendCaps::default_inference_caps(),
            target_throughput: Some(TargetThroughput { ops_per_sec_milli: 167 }),
            counterparty_filter: CounterpartyFilter::default(),
            sunset: Timestamp::new(1_000_000),
            enabled: true,
        };
        mgr.upsert_charter(charter.clone()).unwrap();
        assert_eq!(mgr.list_charters().len(), 1);
        assert_eq!(mgr.get_charter(&h(0xC1)).unwrap().name, "InferenceLoad");

        // Earmark.charter_ids syncs.
        assert_eq!(mgr.earmark().charter_ids.len(), 1);

        // Register an agent under this charter.
        let agent = SeedAgentRecord::new(
            "did:tenzro:machine:seed:001".to_string(),
            "did:tenzro:org:treasury:seedagents".to_string(),
            h(0xC1),
            Timestamp::new(1_000),
        );
        mgr.register_agent(agent.clone()).unwrap();
        assert_eq!(mgr.earmark().seed_agent_count, 1);
        assert!(mgr.is_seed_agent("did:tenzro:machine:seed:001"));

        // Re-registering the same DID does not double-bump the count.
        mgr.register_agent(agent).unwrap();
        assert_eq!(mgr.earmark().seed_agent_count, 1);
    }

    #[test]
    fn manager_register_unknown_charter_fails() {
        let mgr = SeedAgentEarmarkManager::new();
        let agent = SeedAgentRecord::new(
            "did:tenzro:machine:seed:002".to_string(),
            "did:tenzro:org:treasury:seedagents".to_string(),
            h(0xFF),
            Timestamp::new(1_000),
        );
        assert!(mgr.register_agent(agent).is_err());
    }

    #[test]
    fn manager_set_agent_status_terminated_drops_seed_flag() {
        let mgr = SeedAgentEarmarkManager::new();

        let charter = Charter {
            charter_id: h(0xC2),
            name: "BridgeProbe".to_string(),
            purpose: "Quarterly small TNZO bridge probes".to_string(),
            operations: vec![OperationKind::BridgeUser],
            spend_caps: SpendCaps::default_inference_caps(),
            target_throughput: None,
            counterparty_filter: CounterpartyFilter::default(),
            sunset: Timestamp::new(2_000_000),
            enabled: true,
        };
        mgr.upsert_charter(charter).unwrap();

        let agent = SeedAgentRecord::new(
            "did:tenzro:machine:seed:bridge".to_string(),
            "did:tenzro:org:treasury:seedagents".to_string(),
            h(0xC2),
            Timestamp::new(1_000),
        );
        mgr.register_agent(agent).unwrap();
        assert!(mgr.is_seed_agent("did:tenzro:machine:seed:bridge"));

        mgr.set_agent_status(
            "did:tenzro:machine:seed:bridge",
            SeedAgentStatus::Terminated,
        )
        .unwrap();
        // Terminated agents are no longer counterparty-filter-active.
        assert!(!mgr.is_seed_agent("did:tenzro:machine:seed:bridge"));
    }

    #[test]
    fn earmark_validates_allocation_invariants() {
        let mut e = TreasuryEarmark {
            initial_allocation_wei: 100,
            allocation_remaining_wei: 200, // > initial
            ..TreasuryEarmark::default()
        };
        assert!(e.validate().is_err());

        e.allocation_remaining_wei = 50;
        e.surplus_burn_bps = 10_001; // > 100%
        assert!(e.validate().is_err());

        e.surplus_burn_bps = 5_000;
        e.bootstrap_start = Timestamp::new(2_000);
        e.bootstrap_end = Timestamp::new(1_000); // before start
        assert!(e.validate().is_err());

        e.bootstrap_end = Timestamp::new(3_000);
        e.decay_schedule = DecaySchedule::default_with_base(10);
        assert!(e.validate().is_ok());
    }

    fn seeded_manager_for_refill() -> SeedAgentEarmarkManager {
        let mgr = SeedAgentEarmarkManager::new();

        // Allocation: 10_000 TNZO base units; base monthly draw 100.
        // Default schedule: month 0..=2 → 100, 3..=5 → 75, 6..=8 → 50,
        // 9..=11 → 25, 12 → 0.
        let earmark = TreasuryEarmark {
            name: "SeedAgent".to_string(),
            initial_allocation_wei: 10_000,
            allocation_remaining_wei: 10_000,
            total_drawn_wei: 0,
            bootstrap_start: Timestamp::new(0),
            bootstrap_end: Timestamp::new(MONTH_MILLIS * 12),
            decay_schedule: DecaySchedule::default_with_base(100),
            seed_agent_count: 0,
            charter_ids: Vec::new(),
            enabled: true,
            surplus_burn_bps: DEFAULT_SURPLUS_BURN_BPS,
            current_month: 0,
            month_drawn_wei: 0,
        };
        mgr.apply_earmark(earmark).unwrap();

        let charter = Charter {
            charter_id: h(0xC1),
            name: "InferenceLoad".to_string(),
            purpose: "Steady inference load".to_string(),
            operations: vec![OperationKind::InferenceConsumer],
            spend_caps: SpendCaps {
                daily_cap_wei: 50,
                monthly_cap_wei: 1_000,
                per_tx_cap_wei: 10,
            },
            target_throughput: None,
            counterparty_filter: CounterpartyFilter::default(),
            sunset: Timestamp::new(MONTH_MILLIS * 12),
            enabled: true,
        };
        mgr.upsert_charter(charter).unwrap();

        // Two agents under the same charter.
        for did in ["did:tenzro:machine:seed:a", "did:tenzro:machine:seed:b"] {
            mgr.register_agent(SeedAgentRecord::new(
                did.to_string(),
                "did:tenzro:org:treasury:seedagents".into(),
                h(0xC1),
                Timestamp::new(0),
            ))
            .unwrap();
        }
        mgr
    }

    #[test]
    fn refill_clamps_to_schedule_in_month_0() {
        let mgr = seeded_manager_for_refill();
        // Month 0: schedule cap = 100. Charter monthly cap = 1_000.
        // Request 80 → granted 80. Request 90 → only 20 left in the
        // per-agent slot (already used 80) but the global month_budget
        // is schedule_cap × seed_agent_count = 200, of which 80 used →
        // 120 remaining. So second agent can still draw up to charter
        // monthly_cap; the constraint is global.
        let r1 = mgr
            .refill_agent_monthly("did:tenzro:machine:seed:a", 80, Timestamp::new(0))
            .unwrap();
        assert_eq!(r1.granted_wei, 80);
        assert_eq!(r1.month, 0);
        assert_eq!(r1.schedule_cap_for_month_wei, 100);

        // Same agent requests 90 again — clamped by remaining month budget
        // (200 - 80 = 120) and by schedule cap per-agent (100). per_agent_cap
        // = min(100, 1000, 90) = 90. month_remaining = 120. granted = 90.
        let r2 = mgr
            .refill_agent_monthly("did:tenzro:machine:seed:a", 90, Timestamp::new(0))
            .unwrap();
        assert_eq!(r2.granted_wei, 90);
    }

    #[test]
    fn refill_clamps_to_charter_monthly_cap() {
        let mgr = seeded_manager_for_refill();
        // Charter monthly_cap = 1_000 — requested 2_000 clamped to schedule
        // (100) first, well below charter cap. Use a larger schedule by
        // advancing to a far-future test scenario: instead, prove charter
        // cap binds when smaller than schedule × seed_agent_count.
        // Tighten charter monthly_cap to 30 and re-upsert.
        let mut charter = mgr.get_charter(&h(0xC1)).unwrap();
        charter.spend_caps.monthly_cap_wei = 30;
        charter.spend_caps.daily_cap_wei = 30;
        charter.spend_caps.per_tx_cap_wei = 30;
        mgr.upsert_charter(charter).unwrap();

        let r = mgr
            .refill_agent_monthly(
                "did:tenzro:machine:seed:a",
                500,
                Timestamp::new(0),
            )
            .unwrap();
        assert_eq!(r.granted_wei, 30);
    }

    #[test]
    fn refill_rolls_month_forward() {
        let mgr = seeded_manager_for_refill();
        // Draw at month 0.
        let r0 = mgr
            .refill_agent_monthly("did:tenzro:machine:seed:a", 50, Timestamp::new(0))
            .unwrap();
        assert_eq!(r0.month, 0);
        // Advance to month 3 (schedule cap = 75).
        let later = Timestamp::new(MONTH_MILLIS * 3);
        let r3 = mgr
            .refill_agent_monthly("did:tenzro:machine:seed:a", 100, later)
            .unwrap();
        assert_eq!(r3.month, 3);
        assert_eq!(r3.schedule_cap_for_month_wei, 75);
        // per_agent_cap = min(75, 1000, 100) = 75. month_drawn_wei was
        // reset on the rollover, so granted = 75.
        assert_eq!(r3.granted_wei, 75);
    }

    #[test]
    fn refill_after_sunset_grants_zero() {
        let mgr = seeded_manager_for_refill();
        // Month 12 → schedule cap 0. Charter sunset is at month 12, so
        // the charter rejects refills past sunset. Move now to month
        // 11.5 to keep before sunset but on the 0-cap month edge: use
        // month 13 to test schedule-zero outside charter sunset. Instead,
        // bump charter sunset further.
        let mut charter = mgr.get_charter(&h(0xC1)).unwrap();
        charter.sunset = Timestamp::new(MONTH_MILLIS * 24);
        mgr.upsert_charter(charter).unwrap();

        let later = Timestamp::new(MONTH_MILLIS * 12);
        let r = mgr
            .refill_agent_monthly("did:tenzro:machine:seed:a", 100, later)
            .unwrap();
        assert_eq!(r.granted_wei, 0);
        assert_eq!(r.schedule_cap_for_month_wei, 0);
    }

    #[test]
    fn refill_rejects_disabled_charter() {
        let mgr = seeded_manager_for_refill();
        let mut charter = mgr.get_charter(&h(0xC1)).unwrap();
        charter.enabled = false;
        mgr.upsert_charter(charter).unwrap();

        let err = mgr
            .refill_agent_monthly("did:tenzro:machine:seed:a", 10, Timestamp::new(0))
            .unwrap_err();
        match err {
            TokenError::InvalidParameter(msg) => {
                assert!(msg.contains("disabled"), "{}", msg);
            }
            other => panic!("unexpected err: {:?}", other),
        }
    }

    #[test]
    fn refill_rejects_paused_or_terminated_agent() {
        let mgr = seeded_manager_for_refill();
        mgr.set_agent_status(
            "did:tenzro:machine:seed:a",
            SeedAgentStatus::Paused,
        )
        .unwrap();
        assert!(mgr
            .refill_agent_monthly("did:tenzro:machine:seed:a", 10, Timestamp::new(0))
            .is_err());

        mgr.set_agent_status(
            "did:tenzro:machine:seed:b",
            SeedAgentStatus::Terminated,
        )
        .unwrap();
        assert!(mgr
            .refill_agent_monthly("did:tenzro:machine:seed:b", 10, Timestamp::new(0))
            .is_err());
    }

    #[test]
    fn refill_drains_allocation_remaining() {
        let mgr = SeedAgentEarmarkManager::new();
        let earmark = TreasuryEarmark {
            name: "SeedAgent".into(),
            initial_allocation_wei: 50,
            allocation_remaining_wei: 50,
            total_drawn_wei: 0,
            bootstrap_start: Timestamp::new(0),
            bootstrap_end: Timestamp::new(MONTH_MILLIS * 12),
            decay_schedule: DecaySchedule::default_with_base(1_000),
            seed_agent_count: 0,
            charter_ids: Vec::new(),
            enabled: true,
            surplus_burn_bps: DEFAULT_SURPLUS_BURN_BPS,
            current_month: 0,
            month_drawn_wei: 0,
        };
        mgr.apply_earmark(earmark).unwrap();
        mgr.upsert_charter(Charter {
            charter_id: h(0xC1),
            name: "T".into(),
            purpose: "T".into(),
            operations: vec![OperationKind::InferenceConsumer],
            spend_caps: SpendCaps {
                daily_cap_wei: 1_000,
                monthly_cap_wei: 1_000,
                per_tx_cap_wei: 1_000,
            },
            target_throughput: None,
            counterparty_filter: CounterpartyFilter::default(),
            sunset: Timestamp::new(MONTH_MILLIS * 12),
            enabled: true,
        })
        .unwrap();
        mgr.register_agent(SeedAgentRecord::new(
            "did:tenzro:machine:seed:x".into(),
            "did:tenzro:org:treasury:seedagents".into(),
            h(0xC1),
            Timestamp::new(0),
        ))
        .unwrap();

        // Schedule cap month 0 = 1_000, but allocation remaining only 50.
        let r = mgr
            .refill_agent_monthly("did:tenzro:machine:seed:x", 200, Timestamp::new(0))
            .unwrap();
        assert_eq!(r.granted_wei, 50);
        assert_eq!(r.allocation_remaining_wei, 0);

        // Subsequent refill → exhausted error.
        let err = mgr
            .refill_agent_monthly("did:tenzro:machine:seed:x", 1, Timestamp::new(0))
            .unwrap_err();
        match err {
            TokenError::InvalidParameter(msg) => {
                assert!(msg.contains("exhausted"), "{}", msg);
            }
            other => panic!("unexpected err: {:?}", other),
        }
    }

    #[test]
    fn list_agents_filters_by_charter() {
        let mgr = SeedAgentEarmarkManager::new();
        for (cid, name) in [(0xA1u8, "A"), (0xA2u8, "B")] {
            mgr.upsert_charter(Charter {
                charter_id: h(cid),
                name: name.to_string(),
                purpose: "test".into(),
                operations: vec![OperationKind::InferenceConsumer],
                spend_caps: SpendCaps::default_inference_caps(),
                target_throughput: None,
                counterparty_filter: CounterpartyFilter::default(),
                sunset: Timestamp::new(0),
                enabled: true,
            })
            .unwrap();
        }

        for (i, cid) in [(1, 0xA1u8), (2, 0xA1u8), (3, 0xA2u8)].iter() {
            mgr.register_agent(SeedAgentRecord::new(
                format!("did:tenzro:machine:seed:{}", i),
                "did:tenzro:org:treasury:seedagents".into(),
                h(*cid),
                Timestamp::new(0),
            ))
            .unwrap();
        }

        assert_eq!(mgr.list_agents(None).len(), 3);
        assert_eq!(mgr.list_agents(Some(&h(0xA1))).len(), 2);
        assert_eq!(mgr.list_agents(Some(&h(0xA2))).len(), 1);
    }

    /// Build a manager with a sunsettable charter at `charter_sunset` and
    /// `n` agents under it, all `Paused` at `t0`. Used by the wind-down
    /// sweep tests.
    fn seeded_manager_for_sweep(
        n: usize,
        charter_sunset: Timestamp,
        charter_enabled: bool,
    ) -> SeedAgentEarmarkManager {
        let mgr = SeedAgentEarmarkManager::new();
        let earmark = TreasuryEarmark {
            name: "SeedAgent".into(),
            initial_allocation_wei: 1_000,
            allocation_remaining_wei: 1_000,
            total_drawn_wei: 0,
            bootstrap_start: Timestamp::new(0),
            bootstrap_end: Timestamp::new(MONTH_MILLIS * 12),
            decay_schedule: DecaySchedule::default_with_base(100),
            seed_agent_count: 0,
            charter_ids: Vec::new(),
            enabled: true,
            surplus_burn_bps: DEFAULT_SURPLUS_BURN_BPS,
            current_month: 0,
            month_drawn_wei: 0,
        };
        mgr.apply_earmark(earmark).unwrap();
        mgr.upsert_charter(Charter {
            charter_id: h(0xC1),
            name: "SunsetCharter".into(),
            purpose: "test".into(),
            operations: vec![OperationKind::InferenceConsumer],
            spend_caps: SpendCaps::default_inference_caps(),
            target_throughput: None,
            counterparty_filter: CounterpartyFilter::default(),
            sunset: charter_sunset,
            enabled: charter_enabled,
        })
        .unwrap();
        for i in 0..n {
            let did = format!("did:tenzro:machine:seed:s{}", i);
            mgr.register_agent(SeedAgentRecord::new(
                did.clone(),
                "did:tenzro:org:treasury:seedagents".into(),
                h(0xC1),
                Timestamp::new(0),
            ))
            .unwrap();
            mgr.set_agent_status(&did, SeedAgentStatus::Paused).unwrap();
        }
        mgr
    }

    #[test]
    fn sweep_paused_to_quarantined_under_sunsetted_charter() {
        // Charter sunset at t=1000; sweep at t=1500.
        let mgr = seeded_manager_for_sweep(2, Timestamp::new(1_000), true);
        let now = Timestamp::new(1_500);
        let report = mgr.sunset_wind_down_sweep(now, DEFAULT_QUARANTINE_GRACE_MS).unwrap();
        assert_eq!(report.quarantined.len(), 2);
        assert_eq!(report.terminated.len(), 0);
        assert!(report.surplus.is_none(), "still inside grace window");
        for a in mgr.list_agents(None) {
            assert!(matches!(a.status, SeedAgentStatus::Quarantined));
        }
    }

    #[test]
    fn sweep_paused_to_quarantined_under_disabled_charter() {
        // Charter sunset in the future, but disabled — still quarantines.
        let mgr = seeded_manager_for_sweep(1, Timestamp::new(10_000_000), false);
        let now = Timestamp::new(1_500);
        let report = mgr.sunset_wind_down_sweep(now, DEFAULT_QUARANTINE_GRACE_MS).unwrap();
        assert_eq!(report.quarantined.len(), 1);
    }

    #[test]
    fn sweep_quarantined_to_terminated_after_grace() {
        let mgr = seeded_manager_for_sweep(1, Timestamp::new(1_000), true);
        // First sweep: Paused → Quarantined at t=1_500.
        let t1 = Timestamp::new(1_500);
        let r1 = mgr.sunset_wind_down_sweep(t1, DEFAULT_QUARANTINE_GRACE_MS).unwrap();
        assert_eq!(r1.quarantined.len(), 1);
        assert_eq!(mgr.earmark().seed_agent_count, 1);

        // Second sweep before grace elapses: still Quarantined.
        let t2 = Timestamp::new(1_500 + DEFAULT_QUARANTINE_GRACE_MS - 1);
        let r2 = mgr.sunset_wind_down_sweep(t2, DEFAULT_QUARANTINE_GRACE_MS).unwrap();
        assert!(r2.terminated.is_empty());

        // Third sweep after grace: Terminated, surplus disposed, earmark frozen.
        let t3 = Timestamp::new(1_500 + DEFAULT_QUARANTINE_GRACE_MS);
        let r3 = mgr.sunset_wind_down_sweep(t3, DEFAULT_QUARANTINE_GRACE_MS).unwrap();
        assert_eq!(r3.terminated.len(), 1);
        assert_eq!(mgr.earmark().seed_agent_count, 0);
        // All charters sunset + no live agents → surplus path triggers.
        let disposition = r3.surplus.expect("surplus disposition must fire");
        // Default 50/50 split on 1_000.
        assert_eq!(disposition.total_wei, 1_000);
        assert_eq!(disposition.burn_wei, 500);
        assert_eq!(disposition.treasury_wei, 500);
        assert_eq!(mgr.earmark().allocation_remaining_wei, 0);
        assert!(!mgr.earmark().enabled);
    }

    #[test]
    fn sweep_idempotent_after_sunset_completes() {
        let mgr = seeded_manager_for_sweep(1, Timestamp::new(1_000), true);
        let t_far = Timestamp::new(1_500 + DEFAULT_QUARANTINE_GRACE_MS);
        // First sweep: Paused → Quarantined.
        mgr.sunset_wind_down_sweep(Timestamp::new(1_500), DEFAULT_QUARANTINE_GRACE_MS)
            .unwrap();
        // Second sweep: Quarantined → Terminated + surplus disposed.
        let r1 = mgr.sunset_wind_down_sweep(t_far, DEFAULT_QUARANTINE_GRACE_MS).unwrap();
        assert!(r1.surplus.is_some());
        // Third sweep: nothing left to do.
        let r2 = mgr.sunset_wind_down_sweep(t_far, DEFAULT_QUARANTINE_GRACE_MS).unwrap();
        assert!(r2.quarantined.is_empty());
        assert!(r2.terminated.is_empty());
        assert!(r2.surplus.is_none(), "surplus already disposed, earmark frozen");
    }

    #[test]
    fn sweep_no_surplus_when_some_charter_still_live() {
        let mgr = seeded_manager_for_sweep(1, Timestamp::new(1_000), true);
        // Add a second charter that is NOT sunsetted.
        mgr.upsert_charter(Charter {
            charter_id: h(0xC2),
            name: "Live".into(),
            purpose: "live charter".into(),
            operations: vec![OperationKind::InferenceConsumer],
            spend_caps: SpendCaps::default_inference_caps(),
            target_throughput: None,
            counterparty_filter: CounterpartyFilter::default(),
            // Well past `now + grace` so C2 remains live during the sweep.
            sunset: Timestamp::new(i64::MAX / 2),
            enabled: true,
        })
        .unwrap();
        // First sweep quarantines the agent under the sunsetted C1 (anchors
        // last_active = sweep-time). Second sweep beyond grace terminates it.
        let t1 = Timestamp::new(1_500);
        let _ = mgr.sunset_wind_down_sweep(t1, DEFAULT_QUARANTINE_GRACE_MS).unwrap();
        let t2 = Timestamp::new(1_500 + DEFAULT_QUARANTINE_GRACE_MS);
        let report = mgr.sunset_wind_down_sweep(t2, DEFAULT_QUARANTINE_GRACE_MS).unwrap();
        assert_eq!(report.terminated.len(), 1);
        // Live charter still around → no surplus disposition.
        assert!(report.surplus.is_none());
        assert_eq!(mgr.earmark().allocation_remaining_wei, 1_000);
        assert!(mgr.earmark().enabled);
    }

    #[test]
    fn sweep_surplus_split_respects_burn_bps() {
        let mgr = SeedAgentEarmarkManager::new();
        // Bias the surplus disposition: 80% burn, 20% treasury.
        let earmark = TreasuryEarmark {
            name: "SeedAgent".into(),
            initial_allocation_wei: 1_000,
            allocation_remaining_wei: 1_000,
            total_drawn_wei: 0,
            bootstrap_start: Timestamp::new(0),
            bootstrap_end: Timestamp::new(MONTH_MILLIS * 12),
            decay_schedule: DecaySchedule::default_with_base(100),
            seed_agent_count: 0,
            charter_ids: Vec::new(),
            enabled: true,
            surplus_burn_bps: 8_000,
            current_month: 0,
            month_drawn_wei: 0,
        };
        mgr.apply_earmark(earmark).unwrap();
        mgr.upsert_charter(Charter {
            charter_id: h(0xC1),
            name: "Sunsets".into(),
            purpose: "p".into(),
            operations: vec![OperationKind::InferenceConsumer],
            spend_caps: SpendCaps::default_inference_caps(),
            target_throughput: None,
            counterparty_filter: CounterpartyFilter::default(),
            sunset: Timestamp::new(1),
            enabled: true,
        })
        .unwrap();
        // No agents → step 1+2 are no-ops, step 3 fires immediately.
        let r = mgr
            .sunset_wind_down_sweep(Timestamp::new(2), DEFAULT_QUARANTINE_GRACE_MS)
            .unwrap();
        let d = r.surplus.expect("must dispose");
        assert_eq!(d.burn_wei, 800);
        assert_eq!(d.treasury_wei, 200);
        assert_eq!(d.surplus_burn_bps, 8_000);
    }
}
