//! SeedAgent treasury allocation primitive (Agent-Swarm Spec 10 — wave 1).
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
//! Wave 1 ships the primitives + hydration + read access. The off-chain
//! daemon, governance executor wiring (charter add/modify/terminate),
//! per-month decay enforcement at refill, sunset wind-down sweep, and
//! the `tenzro_seed_agents/1.0.0` gossipsub topic land in a later wave
//! alongside the governance executor.
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
/// must have `max_draw_tnzo == 0` for the schedule to be valid.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DecayPoint {
    pub month: u8,
    pub max_draw_tnzo: u128,
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
    pub daily_cap_tnzo: u128,
    /// Cumulative monthly cap per agent.
    pub monthly_cap_tnzo: u128,
    /// Maximum amount that can leave on a single transaction.
    pub per_tx_cap_tnzo: u128,
}

impl SpendCaps {
    /// Reasonable C1-class genesis defaults: 10 TNZO/day per agent,
    /// 200 TNZO/month, 1 TNZO/tx. Governance tunes these per charter.
    pub fn default_inference_caps() -> Self {
        Self {
            daily_cap_tnzo: 10_u128 * 1_000_000_000_000_000_000,
            monthly_cap_tnzo: 200_u128 * 1_000_000_000_000_000_000,
            per_tx_cap_tnzo: 1_000_000_000_000_000_000,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.per_tx_cap_tnzo > self.daily_cap_tnzo {
            return Err(TokenError::InvalidParameter(
                "per_tx_cap > daily_cap".into(),
            ));
        }
        if self.daily_cap_tnzo > self.monthly_cap_tnzo {
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
    /// `base_monthly_draw_tnzo` is the cap for months 1-3 (100% rate).
    pub fn default_with_base(base_monthly_draw_tnzo: u128) -> Self {
        let p = base_monthly_draw_tnzo;
        let pct = |bps: u32| -> u128 {
            // (p * bps) / 10_000 with u128 safety
            let prod = p.saturating_mul(bps as u128);
            prod / 10_000
        };
        let points = vec![
            DecayPoint { month: 0, max_draw_tnzo: pct(10_000) },
            DecayPoint { month: 1, max_draw_tnzo: pct(10_000) },
            DecayPoint { month: 2, max_draw_tnzo: pct(10_000) },
            DecayPoint { month: 3, max_draw_tnzo: pct(7_500) },
            DecayPoint { month: 4, max_draw_tnzo: pct(7_500) },
            DecayPoint { month: 5, max_draw_tnzo: pct(7_500) },
            DecayPoint { month: 6, max_draw_tnzo: pct(5_000) },
            DecayPoint { month: 7, max_draw_tnzo: pct(5_000) },
            DecayPoint { month: 8, max_draw_tnzo: pct(5_000) },
            DecayPoint { month: 9, max_draw_tnzo: pct(2_500) },
            DecayPoint { month: 10, max_draw_tnzo: pct(2_500) },
            DecayPoint { month: 11, max_draw_tnzo: pct(2_500) },
            DecayPoint { month: 12, max_draw_tnzo: 0 },
        ];
        Self { points }
    }

    /// Maximum draw permitted in `month` from bootstrap_start.
    /// Months past the schedule end return 0 (hard sunset).
    pub fn cap_for_month(&self, month: u8) -> u128 {
        self.points
            .iter()
            .find(|p| p.month == month)
            .map(|p| p.max_draw_tnzo)
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
        if last.max_draw_tnzo != 0 {
            return Err(TokenError::InvalidParameter(format!(
                "decay schedule does not sunset (final month {} max_draw_tnzo = {})",
                last.month, last.max_draw_tnzo
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
    pub initial_allocation_tnzo: u128,
    /// Remaining unspent allocation.
    pub allocation_remaining_tnzo: u128,
    /// Cumulative TNZO drawn since bootstrap_start (audit-only).
    pub total_drawn_tnzo: u128,
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
}

impl Default for TreasuryEarmark {
    fn default() -> Self {
        Self {
            name: "SeedAgent".to_string(),
            initial_allocation_tnzo: 0,
            allocation_remaining_tnzo: 0,
            total_drawn_tnzo: 0,
            bootstrap_start: Timestamp::default(),
            bootstrap_end: Timestamp::default(),
            decay_schedule: DecaySchedule { points: Vec::new() },
            seed_agent_count: 0,
            charter_ids: Vec::new(),
            enabled: true,
            surplus_burn_bps: DEFAULT_SURPLUS_BURN_BPS,
        }
    }
}

impl TreasuryEarmark {
    pub fn validate(&self) -> Result<()> {
        if self.surplus_burn_bps > 10_000 {
            return Err(TokenError::InvalidParameter(format!(
                "surplus_burn_bps {} > 10000",
                self.surplus_burn_bps
            )));
        }
        if self.allocation_remaining_tnzo > self.initial_allocation_tnzo {
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
        if self.initial_allocation_tnzo > 0 {
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
    pub allocation_used_tnzo: u128,
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
            allocation_used_tnzo: 0,
            bond_id: None,
            provisioned_at,
            last_active: provisioned_at,
        }
    }
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
            initial_allocation = new.initial_allocation_tnzo,
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

    // --- internal: hydration + persistence -------------------------------

    fn hydrate_from_storage(&self) -> Result<()> {
        let storage = self
            .storage
            .as_ref()
            .expect("hydrate_from_storage requires storage");

        // Earmark singleton.
        match storage.get(CF_TOKENS, SEED_EARMARK_KEY)? {
            Some(bytes) => {
                let earmark: TreasuryEarmark = serde_json::from_slice(&bytes)
                    .map_err(|e| TokenError::StorageError(format!(
                        "decode SeedAgent earmark: {}",
                        e
                    )))?;
                *self.earmark.write() = earmark;
            }
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
            let charter: Charter = serde_json::from_slice(&bytes)
                .map_err(|e| TokenError::StorageError(format!(
                    "decode SeedAgent charter: {}",
                    e
                )))?;
            self.charters.insert(charter.charter_id, charter);
        }

        // Agents.
        let agent_keys =
            storage.get_keys_with_prefix(CF_TOKENS, SEED_AGENT_PREFIX)?;
        for key in agent_keys {
            let Some(bytes) = storage.get(CF_TOKENS, &key)? else { continue };
            let record: SeedAgentRecord = serde_json::from_slice(&bytes)
                .map_err(|e| TokenError::StorageError(format!(
                    "decode SeedAgent record: {}",
                    e
                )))?;
            self.agents.insert(record.agent_did.clone(), record);
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
            daily_cap_tnzo: 5,
            monthly_cap_tnzo: 100,
            per_tx_cap_tnzo: 10, // > daily
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
                DecayPoint { month: 0, max_draw_tnzo: 1_000 },
                DecayPoint { month: 1, max_draw_tnzo: 500 }, // doesn't end at zero
            ],
        };
        assert!(s.validate().is_err());
    }

    #[test]
    fn earmark_default_is_consistent() {
        let e = TreasuryEarmark::default();
        assert_eq!(e.surplus_burn_bps, DEFAULT_SURPLUS_BURN_BPS);
        assert_eq!(e.initial_allocation_tnzo, 0);
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
            initial_allocation_tnzo: 100,
            allocation_remaining_tnzo: 200, // > initial
            ..TreasuryEarmark::default()
        };
        assert!(e.validate().is_err());

        e.allocation_remaining_tnzo = 50;
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
}
