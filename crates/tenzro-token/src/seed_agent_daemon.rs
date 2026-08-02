//! SeedAgent provisioning daemon (Agent-Swarm Spec 10, Task #42).
//!
//! Drives the per-month draw against every Active SeedAgent's
//! [`SeedAgentEarmarkManager`], applies charter sunset / disable rules, and
//! broadcasts post-refill snapshots over the
//! [`SEED_AGENTS_TOPIC`](crate::seed_agent_gossip::SEED_AGENTS_TOPIC) gossipsub
//! channel so passive replicas converge on the same earmark state without
//! polling.
//!
//! ## Scope
//!
//! This daemon owns the **treasury accounting tick** — it does NOT drive the
//! charter-operation execution loop (inference calls, bridge probes, 7683
//! intents, dispute filings). Those are per-charter behaviours handled by
//! external agent implementations (template instantiator, task-marketplace
//! consumer, etc.) that consume the refilled wallets the daemon credits.
//!
//! The daemon's responsibilities, in order of execution per tick:
//!
//! 1. **Earmark master switch**: if `earmark.enabled == false`, the tick is a
//!    no-op (governance has frozen the subsystem).
//! 2. **Charter wind-down detection**: any agent whose charter is `disabled`
//!    OR past `sunset` and whose status is `Active` is transitioned to
//!    `Paused`. Charter-level sunset is observed by [`is_charter_past_sunset`].
//!    Sunset *termination* (with wallet drain + surplus burn) is Task #44 and
//!    lives in a dedicated sweep module.
//! 3. **Per-agent monthly refill**: for each remaining `Active` agent under
//!    an enabled non-sunset charter, if the agent's `last_active` is more
//!    than `min_interval_ms` (default `MONTH_MILLIS`) older than `now`, call
//!    [`SeedAgentEarmarkManager::refill_agent_monthly`] with the charter's
//!    `monthly_cap_wei` as the request amount. The manager clamps internally
//!    against schedule, allocation, and per-month global budget.
//! 4. **Broadcast**: every successful refill (granted > 0) fans out a
//!    [`SeedAgentGossipMessage::MonthlyRefillCompleted`] envelope on the
//!    `tenzro/seed-agents` topic carrying the post-refill earmark snapshot.
//!    Receivers refresh their singleton but do NOT replay the refill (would
//!    double-spend).
//!
//! ## Leader election
//!
//! In a multi-validator deployment only one node should drive the tick — the
//! manager state itself is replicated via gossip but the source of the
//! `refill_agent_monthly` mutation must be deterministic to avoid divergent
//! `month_drawn_wei` counters. The daemon is constructed with a
//! [`TickAuthorityFn`] callback the caller (node) uses to gate ticks on
//! "am I the current epoch leader / well-known SeedAgent steward DID". A
//! `None` callback means "always authorised" (single-node / tests).
//!
//! ## Spawn lifecycle
//!
//! [`SeedAgentDaemon::spawn`] returns a `tokio::task::JoinHandle<()>` that
//! lives for the process lifetime. The loop is a no-op when the earmark is
//! disabled or `tick_authority` returns `false`, so it's safe to keep
//! running on every validator.

use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use tokio::sync::mpsc::UnboundedSender;
use tracing::{debug, info, warn};

use crate::error::{Result, TokenError};
use crate::seed_agent::{MONTH_MILLIS, SeedAgentEarmarkManager, SeedAgentStatus};
use crate::seed_agent_gossip::SeedAgentGossipMessage;
use tenzro_types::primitives::Timestamp;

/// Default daemon poll interval: 6 hours. Well under `MONTH_MILLIS` so a
/// drifted-clock validator that misses a tick still catches the per-month
/// rollover well within the same calendar month.
pub const DEFAULT_DAEMON_POLL_INTERVAL_SECS: u64 = 6 * 60 * 60;

/// Minimum interval between refills for the same agent. Set to one
/// `MONTH_MILLIS` window so the daemon never double-refills within a month
/// even if the tick fires more frequently for charter-wind-down reasons.
pub const DEFAULT_MIN_REFILL_INTERVAL_MS: i64 = MONTH_MILLIS;

/// Default quarantine cooldown the daemon passes to
/// [`SeedAgentEarmarkManager::sunset_wind_down_sweep`]. Re-exports
/// [`crate::seed_agent::DEFAULT_QUARANTINE_GRACE_MS`] so callers can tune
/// the daemon and the sweep together.
pub const DEFAULT_DAEMON_QUARANTINE_GRACE_MS: i64 = crate::seed_agent::DEFAULT_QUARANTINE_GRACE_MS;

/// Tick authority callback: returns `true` when this node should drive the
/// next tick (one-leader gate). `None` callback = always authorised.
pub type TickAuthorityFn = Arc<dyn Fn() -> bool + Send + Sync + 'static>;

/// Configuration for [`SeedAgentDaemon`].
#[derive(Clone)]
pub struct SeedAgentDaemonConfig {
    /// How often the background loop wakes up to inspect the manager.
    pub poll_interval_secs: u64,
    /// Minimum age of `last_active` before an agent is eligible for refill.
    /// Defaults to [`DEFAULT_MIN_REFILL_INTERVAL_MS`].
    pub min_refill_interval_ms: i64,
    /// Quarantine cooldown passed to
    /// [`SeedAgentEarmarkManager::sunset_wind_down_sweep`]. Default 7 days
    /// (matches [`DEFAULT_DAEMON_QUARANTINE_GRACE_MS`]).
    pub quarantine_grace_ms: i64,
}

impl Default for SeedAgentDaemonConfig {
    fn default() -> Self {
        Self {
            poll_interval_secs: DEFAULT_DAEMON_POLL_INTERVAL_SECS,
            min_refill_interval_ms: DEFAULT_MIN_REFILL_INTERVAL_MS,
            quarantine_grace_ms: DEFAULT_DAEMON_QUARANTINE_GRACE_MS,
        }
    }
}

/// One iteration's outcome — useful for tests and for the metrics exporter.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TickOutcome {
    /// Number of agents transitioned `Active -> Paused` due to charter
    /// sunset or `enabled == false`.
    pub paused_count: u32,
    /// Number of agents that received a refill with `granted_wei > 0`.
    pub refilled_count: u32,
    /// Sum of `granted_wei` across all refills this tick.
    pub total_granted_wei: u128,
    /// Was the tick skipped because the earmark master switch is off?
    pub master_switch_skipped: bool,
    /// Was the tick skipped because this node is not the current authority?
    pub authority_skipped: bool,
    /// Agents transitioned `Paused -> Quarantined` by the sunset sweep.
    pub quarantined_count: u32,
    /// Agents transitioned `Quarantined -> Terminated` by the sunset sweep.
    pub terminated_count: u32,
    /// Surplus disposed at sunset, in TNZO base units (sum of burn + treasury).
    pub surplus_disposed_wei: u128,
}

/// Callback invoked by the daemon when
/// [`SeedAgentEarmarkManager::sunset_wind_down_sweep`] returns a
/// [`SurplusDisposition`]. Implementations enact the on-chain effect:
/// burn `disposition.burn_wei` from `TnzoToken` and deposit
/// `disposition.treasury_wei` to the general `NetworkTreasury`. Failures
/// are logged but do not abort the tick.
pub type SurplusDispositionFn =
    Arc<dyn Fn(&crate::seed_agent::SurplusDisposition) -> Result<()> + Send + Sync + 'static>;

/// Background daemon that drives the SeedAgent per-month refill loop.
pub struct SeedAgentDaemon {
    manager: Arc<SeedAgentEarmarkManager>,
    gossip_tx: Option<UnboundedSender<SeedAgentGossipMessage>>,
    tick_authority: Option<TickAuthorityFn>,
    surplus_disposition: Option<SurplusDispositionFn>,
    config: SeedAgentDaemonConfig,
    /// Most recent tick outcome, kept for diagnostics / RPC surface.
    last_outcome: Mutex<Option<TickOutcome>>,
}

impl SeedAgentDaemon {
    /// Construct a new daemon with default config and no broadcast channel
    /// (tests / single-node deployments).
    pub fn new(manager: Arc<SeedAgentEarmarkManager>) -> Self {
        Self::with_config(manager, SeedAgentDaemonConfig::default())
    }

    pub fn with_config(
        manager: Arc<SeedAgentEarmarkManager>,
        config: SeedAgentDaemonConfig,
    ) -> Self {
        Self {
            manager,
            gossip_tx: None,
            tick_authority: None,
            surplus_disposition: None,
            config,
            last_outcome: Mutex::new(None),
        }
    }

    /// Attach a surplus-disposition callback. Invoked when the wind-down
    /// sweep produces a [`SurplusDisposition`] (all charters sunsetted +
    /// no live agents). Production wiring: burn + treasury-deposit. `None`
    /// callback is fine for tests — the manager still zeroes the surplus
    /// internally; the callback only enacts the on-chain effect.
    pub fn with_surplus_disposition(mut self, cb: SurplusDispositionFn) -> Self {
        self.surplus_disposition = Some(cb);
        self
    }

    /// Attach a gossip broadcast channel. The channel receiver is drained
    /// by the node-level forwarder task that encodes each message and
    /// publishes it on `SEED_AGENTS_TOPIC`.
    pub fn with_gossip(mut self, gossip_tx: UnboundedSender<SeedAgentGossipMessage>) -> Self {
        self.gossip_tx = Some(gossip_tx);
        self
    }

    /// Attach a tick-authority gate. If the callback returns `false`, the
    /// tick is skipped — used to prevent multi-validator divergent draws.
    pub fn with_tick_authority(mut self, gate: TickAuthorityFn) -> Self {
        self.tick_authority = Some(gate);
        self
    }

    /// Snapshot of the most recent tick outcome (or `None` before the
    /// first iteration).
    pub fn last_outcome(&self) -> Option<TickOutcome> {
        self.last_outcome.lock().clone()
    }

    /// Spawn the background loop. The returned `JoinHandle` lives for the
    /// process lifetime; callers may drop it (the loop is a no-op when the
    /// earmark is disabled or this node lacks tick authority).
    pub fn spawn(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        let poll = Duration::from_secs(self.config.poll_interval_secs);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(poll);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            // Skip the immediate fire — wait one full interval so manager
            // hydration has settled and tick_authority has a stable answer.
            ticker.tick().await;
            loop {
                ticker.tick().await;
                match self.tick_once(Timestamp::now()) {
                    Ok(outcome) => {
                        if outcome.refilled_count > 0 || outcome.paused_count > 0 {
                            info!(
                                refilled = outcome.refilled_count,
                                paused = outcome.paused_count,
                                granted_wei = %outcome.total_granted_wei,
                                "SeedAgentDaemon tick"
                            );
                        }
                    }
                    Err(e) => {
                        warn!(error = %e, "SeedAgentDaemon: tick_once failed");
                    }
                }
            }
        })
    }

    /// One iteration of the daemon loop. Public for tests; also called once
    /// per poll interval by `spawn`. The `now` argument is injectable so
    /// tests can advance synthetic clocks.
    pub fn tick_once(&self, now: Timestamp) -> Result<TickOutcome> {
        let mut outcome = TickOutcome::default();

        // 1. Master-switch gate.
        let earmark = self.manager.earmark();
        if !earmark.enabled {
            debug!("SeedAgentDaemon: earmark disabled, tick is a no-op");
            outcome.master_switch_skipped = true;
            *self.last_outcome.lock() = Some(outcome.clone());
            return Ok(outcome);
        }

        // 2. Tick-authority gate.
        if let Some(gate) = &self.tick_authority
            && !gate()
        {
            debug!("SeedAgentDaemon: not tick authority, skipping");
            outcome.authority_skipped = true;
            *self.last_outcome.lock() = Some(outcome.clone());
            return Ok(outcome);
        }

        // 3. Pause agents under disabled / sunset charters.
        for agent in self.manager.list_agents(None) {
            if !matches!(agent.status, SeedAgentStatus::Active) {
                continue;
            }
            let Some(charter) = self.manager.get_charter(&agent.charter_id) else {
                // Dangling agent — charter was deleted out from under it.
                // Pause defensively so the daemon doesn't keep retrying.
                if let Err(e) = self
                    .manager
                    .set_agent_status(&agent.agent_did, SeedAgentStatus::Paused)
                {
                    warn!(
                        agent = %agent.agent_did,
                        error = %e,
                        "SeedAgentDaemon: failed to pause dangling agent"
                    );
                    continue;
                }
                outcome.paused_count = outcome.paused_count.saturating_add(1);
                self.broadcast_status_change(&agent.agent_did, SeedAgentStatus::Paused);
                continue;
            };
            if !charter.enabled || is_charter_past_sunset(&charter, now) {
                if let Err(e) = self
                    .manager
                    .set_agent_status(&agent.agent_did, SeedAgentStatus::Paused)
                {
                    warn!(
                        agent = %agent.agent_did,
                        error = %e,
                        "SeedAgentDaemon: failed to pause sunsetted agent"
                    );
                    continue;
                }
                outcome.paused_count = outcome.paused_count.saturating_add(1);
                self.broadcast_status_change(&agent.agent_did, SeedAgentStatus::Paused);
            }
        }

        // 4. Refill Active agents whose last_active is older than the
        //    minimum refill interval.
        for agent in self.manager.list_agents(None) {
            if !matches!(agent.status, SeedAgentStatus::Active) {
                continue;
            }
            let Some(charter) = self.manager.get_charter(&agent.charter_id) else {
                continue;
            };
            if !charter.enabled || is_charter_past_sunset(&charter, now) {
                continue;
            }
            let last_ms = agent.last_active.as_millis();
            let now_ms = now.as_millis();
            // Skip if too recent. provisioned_at == last_active at first
            // boot, so an agent provisioned in the same tick won't refill
            // immediately — it waits for `min_refill_interval_ms` to elapse.
            if now_ms.saturating_sub(last_ms) < self.config.min_refill_interval_ms {
                continue;
            }

            // Request the charter's full monthly cap — the manager clamps
            // against schedule + allocation + global monthly budget.
            let requested = charter.spend_caps.monthly_cap_wei;
            if requested == 0 {
                continue;
            }
            match self
                .manager
                .refill_agent_monthly(&agent.agent_did, requested, now)
            {
                Ok(result) if result.granted_wei > 0 => {
                    outcome.refilled_count = outcome.refilled_count.saturating_add(1);
                    outcome.total_granted_wei =
                        outcome.total_granted_wei.saturating_add(result.granted_wei);
                    self.broadcast_refill_completed(
                        &agent.agent_did,
                        result.granted_wei,
                        result.month,
                    );
                }
                Ok(_) => {
                    // granted == 0 — schedule sunsetted or allocation
                    // exhausted. No broadcast; the next sunset sweep
                    // (#44) handles the wind-down.
                    debug!(
                        agent = %agent.agent_did,
                        "SeedAgentDaemon: refill returned 0 granted (sunset/exhausted)"
                    );
                }
                Err(e) => {
                    warn!(
                        agent = %agent.agent_did,
                        error = %e,
                        "SeedAgentDaemon: refill failed"
                    );
                }
            }
        }

        // 5. Sunset wind-down sweep (Spec 10 Task #44).
        //    Advances Paused agents under sunsetted charters through
        //    Quarantined -> Terminated, and disposes the unspent
        //    earmark surplus when all charters are sunsetted and no
        //    live agents remain. The manager zeroes the surplus
        //    internally; the optional `surplus_disposition` callback
        //    enacts the burn + treasury-deposit on-chain.
        match self
            .manager
            .sunset_wind_down_sweep(now, self.config.quarantine_grace_ms)
        {
            Ok(report) => {
                outcome.quarantined_count = report.quarantined.len() as u32;
                outcome.terminated_count = report.terminated.len() as u32;
                for agent_did in &report.quarantined {
                    self.broadcast_status_change(agent_did, SeedAgentStatus::Quarantined);
                }
                for agent_did in &report.terminated {
                    self.broadcast_status_change(agent_did, SeedAgentStatus::Terminated);
                }
                if let Some(disposition) = report.surplus {
                    outcome.surplus_disposed_wei = disposition.total_wei;
                    info!(
                        total = %disposition.total_wei,
                        burn = %disposition.burn_wei,
                        treasury = %disposition.treasury_wei,
                        "SeedAgentDaemon: surplus disposed at sunset"
                    );
                    // Broadcast updated earmark snapshot so passive
                    // replicas converge on the zeroed allocation.
                    if let Some(tx) = &self.gossip_tx {
                        let earmark = self.manager.earmark();
                        let msg = SeedAgentGossipMessage::EarmarkUpdated(earmark);
                        let _ = tx.send(msg);
                    }
                    // Enact the on-chain effect.
                    if let Some(cb) = &self.surplus_disposition
                        && let Err(e) = cb(&disposition)
                    {
                        warn!(
                            error = %e,
                            "SeedAgentDaemon: surplus disposition callback failed"
                        );
                    }
                }
            }
            Err(e) => {
                warn!(error = %e, "SeedAgentDaemon: sunset_wind_down_sweep failed");
            }
        }

        *self.last_outcome.lock() = Some(outcome.clone());
        Ok(outcome)
    }

    /// Best-effort broadcast — drops the message silently if the channel is
    /// closed. The forwarder reattaches on node restart.
    fn broadcast_refill_completed(&self, agent_did: &str, granted_wei: u128, month: u8) {
        let Some(tx) = &self.gossip_tx else { return };
        let snapshot = self.manager.earmark();
        let msg = SeedAgentGossipMessage::MonthlyRefillCompleted {
            agent_did: agent_did.to_string(),
            granted_wei,
            month,
            earmark_snapshot: snapshot,
        };
        if tx.send(msg).is_err() {
            debug!("SeedAgentDaemon: gossip channel closed, dropping refill broadcast");
        }
    }

    fn broadcast_status_change(&self, agent_did: &str, status: SeedAgentStatus) {
        let Some(tx) = &self.gossip_tx else { return };
        let msg = SeedAgentGossipMessage::AgentStatusChanged {
            agent_did: agent_did.to_string(),
            status,
        };
        if tx.send(msg).is_err() {
            debug!("SeedAgentDaemon: gossip channel closed, dropping status broadcast");
        }
    }
}

/// A charter is past sunset if `sunset != 0` AND `now >= sunset`.
/// A `sunset == 0` value means "no sunset configured" (used in tests and
/// indefinite charters).
fn is_charter_past_sunset(charter: &crate::seed_agent::Charter, now: Timestamp) -> bool {
    let sunset_ms = charter.sunset.as_millis();
    sunset_ms != 0 && now.as_millis() >= sunset_ms
}

/// Validate the daemon config — surface obviously-wrong values at startup
/// instead of letting them poison the loop.
impl SeedAgentDaemonConfig {
    pub fn validate(&self) -> Result<()> {
        if self.poll_interval_secs == 0 {
            return Err(TokenError::InvalidParameter(
                "SeedAgentDaemonConfig.poll_interval_secs == 0".into(),
            ));
        }
        if self.min_refill_interval_ms <= 0 {
            return Err(TokenError::InvalidParameter(
                "SeedAgentDaemonConfig.min_refill_interval_ms <= 0".into(),
            ));
        }
        if self.quarantine_grace_ms <= 0 {
            return Err(TokenError::InvalidParameter(
                "SeedAgentDaemonConfig.quarantine_grace_ms <= 0".into(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seed_agent::{
        Charter, CounterpartyFilter, DEFAULT_SURPLUS_BURN_BPS, DecaySchedule, OperationKind,
        SeedAgentRecord, SpendCaps, TreasuryEarmark,
    };
    use tenzro_types::primitives::Hash;
    use tokio::sync::mpsc;

    fn h(byte: u8) -> Hash {
        Hash::new([byte; 32])
    }

    fn seeded_manager(now: Timestamp) -> Arc<SeedAgentEarmarkManager> {
        let mgr = Arc::new(SeedAgentEarmarkManager::new());
        let earmark = TreasuryEarmark {
            name: "SeedAgent".into(),
            initial_allocation_wei: 10_000,
            allocation_remaining_wei: 10_000,
            total_drawn_wei: 0,
            bootstrap_start: now,
            bootstrap_end: Timestamp::new(now.as_millis() + MONTH_MILLIS * 12),
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
            name: "InferenceLoad".into(),
            purpose: "test".into(),
            operations: vec![OperationKind::InferenceConsumer],
            spend_caps: SpendCaps {
                daily_cap_wei: 50,
                monthly_cap_wei: 100,
                per_tx_cap_wei: 10,
            },
            target_throughput: None,
            counterparty_filter: CounterpartyFilter::default(),
            sunset: Timestamp::new(now.as_millis() + MONTH_MILLIS * 12),
            enabled: true,
        };
        mgr.upsert_charter(charter).unwrap();

        // Provision the agent at t=0 so its last_active is the bootstrap.
        mgr.register_agent(SeedAgentRecord::new(
            "did:tenzro:machine:seed:a".into(),
            "did:tenzro:org:treasury:seedagents".into(),
            h(0xC1),
            now,
        ))
        .unwrap();
        mgr
    }

    #[test]
    fn tick_skips_when_master_switch_off() {
        let now = Timestamp::new(0);
        let mgr = seeded_manager(now);
        // Disable the earmark.
        let mut earmark = mgr.earmark();
        earmark.enabled = false;
        mgr.apply_earmark(earmark).unwrap();

        let daemon = SeedAgentDaemon::new(mgr.clone());
        let later = Timestamp::new(MONTH_MILLIS + 1);
        let outcome = daemon.tick_once(later).unwrap();
        assert!(outcome.master_switch_skipped);
        assert_eq!(outcome.refilled_count, 0);
        // Earmark untouched — allocation_remaining still 10_000.
        assert_eq!(mgr.earmark().allocation_remaining_wei, 10_000);
    }

    #[test]
    fn tick_skips_when_authority_returns_false() {
        let now = Timestamp::new(0);
        let mgr = seeded_manager(now);
        let daemon = SeedAgentDaemon::new(mgr.clone()).with_tick_authority(Arc::new(|| false));
        let later = Timestamp::new(MONTH_MILLIS + 1);
        let outcome = daemon.tick_once(later).unwrap();
        assert!(outcome.authority_skipped);
        assert_eq!(outcome.refilled_count, 0);
    }

    #[test]
    fn tick_refills_eligible_agent_and_broadcasts() {
        let now = Timestamp::new(0);
        let mgr = seeded_manager(now);
        let (tx, mut rx) = mpsc::unbounded_channel();
        let daemon = SeedAgentDaemon::new(mgr.clone()).with_gossip(tx);

        let later = Timestamp::new(MONTH_MILLIS + 1);
        let outcome = daemon.tick_once(later).unwrap();
        assert_eq!(outcome.refilled_count, 1);
        // charter.monthly_cap = 100, schedule cap = 100 (month 1), so granted = 100.
        assert_eq!(outcome.total_granted_wei, 100);

        // Broadcast was emitted with the post-refill earmark.
        let msg = rx.try_recv().expect("missing refill broadcast");
        match msg {
            SeedAgentGossipMessage::MonthlyRefillCompleted {
                granted_wei,
                month,
                earmark_snapshot,
                ..
            } => {
                assert_eq!(granted_wei, 100);
                // month_index_for relative to bootstrap_start (which is `now`
                // = 0). `later` is MONTH_MILLIS + 1 → month index 1.
                assert_eq!(month, 1);
                assert_eq!(earmark_snapshot.allocation_remaining_wei, 9_900);
                assert_eq!(earmark_snapshot.total_drawn_wei, 100);
            }
            other => panic!("unexpected gossip: {:?}", other),
        }
    }

    #[test]
    fn tick_skips_recently_active_agent() {
        let now = Timestamp::new(0);
        let mgr = seeded_manager(now);
        let daemon = SeedAgentDaemon::new(mgr.clone());

        // Agent's last_active == 0; advancing by less than the min interval
        // must not trigger a refill.
        let too_soon = Timestamp::new(MONTH_MILLIS - 1);
        let outcome = daemon.tick_once(too_soon).unwrap();
        assert_eq!(outcome.refilled_count, 0);
        assert_eq!(mgr.earmark().total_drawn_wei, 0);
    }

    #[test]
    fn tick_pauses_agent_under_disabled_charter() {
        let now = Timestamp::new(0);
        let mgr = seeded_manager(now);

        // Disable the charter.
        let mut charter = mgr.get_charter(&h(0xC1)).unwrap();
        charter.enabled = false;
        mgr.upsert_charter(charter).unwrap();

        let (tx, mut rx) = mpsc::unbounded_channel();
        let daemon = SeedAgentDaemon::new(mgr.clone()).with_gossip(tx);
        let later = Timestamp::new(MONTH_MILLIS + 1);
        let outcome = daemon.tick_once(later).unwrap();
        assert_eq!(outcome.paused_count, 1);
        assert_eq!(outcome.refilled_count, 0);
        // The sweep step in the same tick picks up the newly-Paused agent
        // under the disabled charter and transitions it to Quarantined.
        assert_eq!(outcome.quarantined_count, 1);

        let updated = mgr.get_agent("did:tenzro:machine:seed:a").unwrap();
        assert_eq!(updated.status, SeedAgentStatus::Quarantined);

        // Two status-change broadcasts emitted in order: Paused, then
        // Quarantined.
        let mut saw_paused = false;
        let mut saw_quarantined = false;
        while let Ok(msg) = rx.try_recv() {
            if let SeedAgentGossipMessage::AgentStatusChanged { agent_did, status } = msg {
                assert_eq!(agent_did, "did:tenzro:machine:seed:a");
                match status {
                    SeedAgentStatus::Paused => saw_paused = true,
                    SeedAgentStatus::Quarantined => saw_quarantined = true,
                    _ => {}
                }
            }
        }
        assert!(saw_paused, "missing Paused broadcast");
        assert!(saw_quarantined, "missing Quarantined broadcast");
    }

    #[test]
    fn tick_pauses_agent_past_sunset() {
        let now = Timestamp::new(0);
        let mgr = seeded_manager(now);

        // Move charter sunset behind `now`.
        let mut charter = mgr.get_charter(&h(0xC1)).unwrap();
        charter.sunset = Timestamp::new(MONTH_MILLIS);
        mgr.upsert_charter(charter).unwrap();

        let daemon = SeedAgentDaemon::new(mgr.clone());
        let later = Timestamp::new(MONTH_MILLIS * 2);
        let outcome = daemon.tick_once(later).unwrap();
        assert_eq!(outcome.paused_count, 1);
        // Same tick's sweep step quarantines the now-Paused agent.
        assert_eq!(outcome.quarantined_count, 1);

        let updated = mgr.get_agent("did:tenzro:machine:seed:a").unwrap();
        assert_eq!(updated.status, SeedAgentStatus::Quarantined);
    }

    #[test]
    fn tick_no_op_for_paused_or_terminated_agents() {
        let now = Timestamp::new(0);
        let mgr = seeded_manager(now);
        mgr.set_agent_status("did:tenzro:machine:seed:a", SeedAgentStatus::Paused)
            .unwrap();

        let daemon = SeedAgentDaemon::new(mgr.clone());
        let later = Timestamp::new(MONTH_MILLIS * 2);
        let outcome = daemon.tick_once(later).unwrap();
        assert_eq!(outcome.refilled_count, 0);
        assert_eq!(outcome.paused_count, 0);
    }

    #[test]
    fn config_validate_rejects_zero_poll() {
        let cfg = SeedAgentDaemonConfig {
            poll_interval_secs: 0,
            min_refill_interval_ms: MONTH_MILLIS,
            quarantine_grace_ms: DEFAULT_DAEMON_QUARANTINE_GRACE_MS,
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn config_validate_rejects_non_positive_grace() {
        let cfg = SeedAgentDaemonConfig {
            poll_interval_secs: DEFAULT_DAEMON_POLL_INTERVAL_SECS,
            min_refill_interval_ms: MONTH_MILLIS,
            quarantine_grace_ms: 0,
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn tick_runs_sunset_sweep_and_broadcasts_quarantined() {
        let now = Timestamp::new(0);
        let mgr = seeded_manager(now);

        // Pause the agent and disable the charter so the sweep should
        // quarantine the agent on the next tick.
        mgr.set_agent_status("did:tenzro:machine:seed:a", SeedAgentStatus::Paused)
            .unwrap();
        let mut charter = mgr.get_charter(&h(0xC1)).unwrap();
        charter.enabled = false;
        mgr.upsert_charter(charter).unwrap();

        let (tx, mut rx) = mpsc::unbounded_channel();
        let daemon = SeedAgentDaemon::new(mgr.clone()).with_gossip(tx);
        let later = Timestamp::new(MONTH_MILLIS + 1);
        let outcome = daemon.tick_once(later).unwrap();
        assert_eq!(outcome.quarantined_count, 1);
        assert_eq!(outcome.terminated_count, 0);

        // First broadcast should be the quarantine status change.
        let mut saw_quarantine = false;
        while let Ok(msg) = rx.try_recv() {
            if let SeedAgentGossipMessage::AgentStatusChanged { status, .. } = msg
                && status == SeedAgentStatus::Quarantined
            {
                saw_quarantine = true;
                break;
            }
        }
        assert!(saw_quarantine, "expected Quarantined status broadcast");
    }

    #[test]
    fn tick_runs_sunset_sweep_and_invokes_surplus_callback() {
        use std::sync::atomic::{AtomicU64, Ordering};

        let now = Timestamp::new(0);
        let mgr = seeded_manager(now);

        // Move the charter sunset before `now+grace` AND disable it.
        let mut charter = mgr.get_charter(&h(0xC1)).unwrap();
        charter.sunset = Timestamp::new(1);
        mgr.upsert_charter(charter).unwrap();
        // Terminate the agent outright so step 3 (surplus) fires.
        mgr.set_agent_status("did:tenzro:machine:seed:a", SeedAgentStatus::Terminated)
            .unwrap();

        let burned = Arc::new(AtomicU64::new(0));
        let burned_cb = burned.clone();
        let cb: SurplusDispositionFn = Arc::new(move |d| {
            burned_cb.store(d.burn_wei as u64, Ordering::SeqCst);
            Ok(())
        });
        let daemon = SeedAgentDaemon::new(mgr.clone()).with_surplus_disposition(cb);

        let later = Timestamp::new(MONTH_MILLIS + 1);
        let outcome = daemon.tick_once(later).unwrap();
        // Surplus = 10_000 * 5000 / 10_000 = 5_000 burned.
        assert_eq!(outcome.surplus_disposed_wei, 10_000);
        assert_eq!(burned.load(Ordering::SeqCst), 5_000);
        // Earmark frozen post-sweep.
        assert_eq!(mgr.earmark().allocation_remaining_wei, 0);
        assert!(!mgr.earmark().enabled);
    }

    #[test]
    fn last_outcome_is_stored_after_tick() {
        let now = Timestamp::new(0);
        let mgr = seeded_manager(now);
        let daemon = SeedAgentDaemon::new(mgr.clone());
        assert!(daemon.last_outcome().is_none());

        let later = Timestamp::new(MONTH_MILLIS + 1);
        let _ = daemon.tick_once(later).unwrap();
        let snap = daemon.last_outcome().unwrap();
        assert_eq!(snap.refilled_count, 1);
    }
}
