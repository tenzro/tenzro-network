//! Agent lifecycle management for Tenzro Network.
//!
//! This module manages the lifecycle states of AI agents, from creation
//! through termination, with proper state transition validation and
//! event emission.

use crate::error::{AgentError, Result};
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::broadcast;
use tenzro_types::primitives::Timestamp;
use tracing::{debug, info, warn};

/// Lifecycle state of an agent
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentState {
    /// Agent has been created but not yet initialized
    Created,
    /// Agent is being initialized
    Initializing,
    /// Agent is active and operational
    Active,
    /// Agent is temporarily suspended
    Suspended,
    /// Agent is permanently terminated
    Terminated,
}

impl AgentState {
    /// Returns the state as a string
    pub fn as_str(&self) -> &str {
        match self {
            AgentState::Created => "created",
            AgentState::Initializing => "initializing",
            AgentState::Active => "active",
            AgentState::Suspended => "suspended",
            AgentState::Terminated => "terminated",
        }
    }

    /// Checks if transition to another state is valid
    pub fn can_transition_to(&self, next: &AgentState) -> bool {
        match (self, next) {
            // From Created
            (AgentState::Created, AgentState::Initializing) => true,
            // From Initializing
            (AgentState::Initializing, AgentState::Active) => true,
            (AgentState::Initializing, AgentState::Terminated) => true,
            // From Active
            (AgentState::Active, AgentState::Suspended) => true,
            (AgentState::Active, AgentState::Terminated) => true,
            // From Suspended
            (AgentState::Suspended, AgentState::Active) => true,
            (AgentState::Suspended, AgentState::Terminated) => true,
            // Cannot transition from Terminated
            (AgentState::Terminated, _) => false,
            // No other transitions allowed
            _ => false,
        }
    }
}

/// Lifecycle event for an agent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AgentLifecycleEvent {
    /// Agent was created
    Created {
        /// Agent ID
        agent_id: String,
        /// Creation timestamp
        timestamp: DateTime<Utc>,
    },
    /// Agent initialization started
    InitializationStarted {
        /// Agent ID
        agent_id: String,
        /// Timestamp
        timestamp: DateTime<Utc>,
    },
    /// Agent was activated
    Activated {
        /// Agent ID
        agent_id: String,
        /// Timestamp
        timestamp: DateTime<Utc>,
    },
    /// Agent was suspended
    Suspended {
        /// Agent ID
        agent_id: String,
        /// Reason for suspension
        reason: String,
        /// Timestamp
        timestamp: DateTime<Utc>,
    },
    /// Agent was resumed
    Resumed {
        /// Agent ID
        agent_id: String,
        /// Timestamp
        timestamp: DateTime<Utc>,
    },
    /// Agent was terminated
    Terminated {
        /// Agent ID
        agent_id: String,
        /// Reason for termination
        reason: String,
        /// Timestamp
        timestamp: DateTime<Utc>,
    },
    /// Heartbeat received from agent
    HeartbeatReceived {
        /// Agent ID
        agent_id: String,
        /// Timestamp
        timestamp: DateTime<Utc>,
    },
}

impl AgentLifecycleEvent {
    /// Gets the agent ID from the event
    pub fn agent_id(&self) -> &str {
        match self {
            AgentLifecycleEvent::Created { agent_id, .. }
            | AgentLifecycleEvent::InitializationStarted { agent_id, .. }
            | AgentLifecycleEvent::Activated { agent_id, .. }
            | AgentLifecycleEvent::Suspended { agent_id, .. }
            | AgentLifecycleEvent::Resumed { agent_id, .. }
            | AgentLifecycleEvent::Terminated { agent_id, .. }
            | AgentLifecycleEvent::HeartbeatReceived { agent_id, .. } => agent_id,
        }
    }

    /// Gets the timestamp of the event
    pub fn timestamp(&self) -> DateTime<Utc> {
        match self {
            AgentLifecycleEvent::Created { timestamp, .. }
            | AgentLifecycleEvent::InitializationStarted { timestamp, .. }
            | AgentLifecycleEvent::Activated { timestamp, .. }
            | AgentLifecycleEvent::Suspended { timestamp, .. }
            | AgentLifecycleEvent::Resumed { timestamp, .. }
            | AgentLifecycleEvent::Terminated { timestamp, .. }
            | AgentLifecycleEvent::HeartbeatReceived { timestamp, .. } => *timestamp,
        }
    }
}

/// Agent lifecycle information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentLifecycleInfo {
    /// Agent ID
    pub agent_id: String,
    /// Current state
    pub state: AgentState,
    /// Last state change timestamp
    pub last_state_change: DateTime<Utc>,
    /// Last heartbeat timestamp
    pub last_heartbeat: Option<DateTime<Utc>>,
    /// State history
    pub state_history: Vec<(AgentState, DateTime<Utc>)>,
}

impl AgentLifecycleInfo {
    /// Creates a new lifecycle info in Created state
    pub fn new(agent_id: String) -> Self {
        let now = Utc::now();
        Self {
            agent_id,
            state: AgentState::Created,
            last_state_change: now,
            last_heartbeat: None,
            state_history: vec![(AgentState::Created, now)],
        }
    }

    /// Transitions to a new state
    pub fn transition(&mut self, new_state: AgentState) -> Result<()> {
        if !self.state.can_transition_to(&new_state) {
            return Err(AgentError::InvalidStateTransition {
                from: self.state.as_str().to_string(),
                to: new_state.as_str().to_string(),
            });
        }

        let now = Utc::now();
        self.state = new_state;
        self.last_state_change = now;
        self.state_history.push((new_state, now));

        Ok(())
    }

    /// Updates the last heartbeat timestamp
    pub fn update_heartbeat(&mut self) {
        self.last_heartbeat = Some(Utc::now());
    }

    /// Checks if the agent is healthy (recent heartbeat)
    pub fn is_healthy(&self, max_heartbeat_age_secs: i64) -> bool {
        if let Some(last_heartbeat) = self.last_heartbeat {
            let age = Utc::now().signed_duration_since(last_heartbeat).num_seconds();
            age < max_heartbeat_age_secs
        } else {
            // No heartbeat received yet, check if recently created
            let age = Utc::now()
                .signed_duration_since(self.last_state_change)
                .num_seconds();
            age < max_heartbeat_age_secs
        }
    }
}

/// Configuration for heartbeat monitoring
#[derive(Debug, Clone)]
pub struct HeartbeatConfig {
    /// Heartbeat interval in seconds (default: 30)
    pub interval_secs: i64,
    /// Heartbeat timeout multiplier (default: 3x interval = 90 seconds)
    pub timeout_multiplier: i64,
}

impl Default for HeartbeatConfig {
    fn default() -> Self {
        Self {
            interval_secs: 30,
            timeout_multiplier: 3,
        }
    }
}

impl HeartbeatConfig {
    /// Gets the total timeout in seconds
    pub fn timeout_secs(&self) -> i64 {
        self.interval_secs * self.timeout_multiplier
    }
}

/// Manages agent lifecycles
pub struct AgentLifecycle {
    /// Lifecycle information for each agent
    lifecycles: Arc<DashMap<String, AgentLifecycleInfo>>,
    /// Event broadcaster
    event_tx: broadcast::Sender<AgentLifecycleEvent>,
    /// Heartbeat configuration
    heartbeat_config: HeartbeatConfig,
}

impl AgentLifecycle {
    /// Creates a new agent lifecycle manager
    pub fn new() -> Self {
        Self::with_heartbeat_config(HeartbeatConfig::default())
    }

    /// Creates a new agent lifecycle manager with custom heartbeat configuration
    pub fn with_heartbeat_config(config: HeartbeatConfig) -> Self {
        let (event_tx, _) = broadcast::channel(1000);
        Self {
            lifecycles: Arc::new(DashMap::new()),
            event_tx,
            heartbeat_config: config,
        }
    }

    /// Creates a new agent lifecycle manager with custom heartbeat timeout
    #[deprecated(note = "Use with_heartbeat_config instead")]
    pub fn with_heartbeat_timeout(heartbeat_timeout: i64) -> Self {
        let config = HeartbeatConfig {
            interval_secs: heartbeat_timeout,
            timeout_multiplier: 1,
        };
        Self::with_heartbeat_config(config)
    }

    /// Subscribes to lifecycle events
    pub fn subscribe(&self) -> broadcast::Receiver<AgentLifecycleEvent> {
        self.event_tx.subscribe()
    }

    /// Emits a lifecycle event
    fn emit_event(&self, event: AgentLifecycleEvent) {
        let _ = self.event_tx.send(event);
    }

    /// Initializes a new agent lifecycle
    pub fn initialize(&self, agent_id: String) -> Result<()> {
        if self.lifecycles.contains_key(&agent_id) {
            return Err(AgentError::AgentAlreadyExists(agent_id));
        }

        let info = AgentLifecycleInfo::new(agent_id.clone());
        self.lifecycles.insert(agent_id.clone(), info);

        self.emit_event(AgentLifecycleEvent::Created {
            agent_id,
            timestamp: Utc::now(),
        });

        Ok(())
    }

    /// Inserts a pre-existing `AgentLifecycleInfo` directly into the in-memory
    /// map without emitting a `Created` event or walking the state machine.
    ///
    /// This is the rehydration entry point used when a node boots and reads
    /// previously persisted lifecycle records from RocksDB (CF_AGENTS). The
    /// persisted state (including terminal states like `Terminated`) is
    /// restored verbatim; emitting a synthetic `Created` event would
    /// corrupt the state history and confuse downstream subscribers, and
    /// driving the state machine forward would reject valid terminal
    /// states.
    ///
    /// Returns `AgentAlreadyExists` if the agent_id is already present, so
    /// callers can safely call this idempotently across restarts.
    pub fn insert_hydrated(&self, info: AgentLifecycleInfo) -> Result<()> {
        let agent_id = info.agent_id.clone();
        if self.lifecycles.contains_key(&agent_id) {
            return Err(AgentError::AgentAlreadyExists(agent_id));
        }
        self.lifecycles.insert(agent_id, info);
        Ok(())
    }

    /// Activates an agent
    pub fn activate(&self, agent_id: &str) -> Result<()> {
        let mut entry = self
            .lifecycles
            .get_mut(agent_id)
            .ok_or_else(|| AgentError::AgentNotFound(agent_id.to_string()))?;

        let info = entry.value_mut();

        // If in Created state, first transition to Initializing
        if info.state == AgentState::Created {
            info.transition(AgentState::Initializing)?;
            self.emit_event(AgentLifecycleEvent::InitializationStarted {
                agent_id: agent_id.to_string(),
                timestamp: Utc::now(),
            });
        }

        // Then transition to Active
        info.transition(AgentState::Active)?;

        info!("Agent {} activated", agent_id);

        self.emit_event(AgentLifecycleEvent::Activated {
            agent_id: agent_id.to_string(),
            timestamp: Utc::now(),
        });

        Ok(())
    }

    /// Suspends an agent
    pub fn suspend(&self, agent_id: &str, reason: String) -> Result<()> {
        let mut entry = self
            .lifecycles
            .get_mut(agent_id)
            .ok_or_else(|| AgentError::AgentNotFound(agent_id.to_string()))?;

        entry.value_mut().transition(AgentState::Suspended)?;

        info!("Agent {} suspended: {}", agent_id, reason);

        self.emit_event(AgentLifecycleEvent::Suspended {
            agent_id: agent_id.to_string(),
            reason,
            timestamp: Utc::now(),
        });

        Ok(())
    }

    /// Resumes a suspended agent
    pub fn resume(&self, agent_id: &str) -> Result<()> {
        let mut entry = self
            .lifecycles
            .get_mut(agent_id)
            .ok_or_else(|| AgentError::AgentNotFound(agent_id.to_string()))?;

        entry.value_mut().transition(AgentState::Active)?;

        info!("Agent {} resumed", agent_id);

        self.emit_event(AgentLifecycleEvent::Resumed {
            agent_id: agent_id.to_string(),
            timestamp: Utc::now(),
        });

        Ok(())
    }

    /// Terminates an agent
    pub fn terminate(&self, agent_id: &str, reason: String) -> Result<()> {
        let mut entry = self
            .lifecycles
            .get_mut(agent_id)
            .ok_or_else(|| AgentError::AgentNotFound(agent_id.to_string()))?;

        entry.value_mut().transition(AgentState::Terminated)?;

        info!("Agent {} terminated: {}", agent_id, reason);

        self.emit_event(AgentLifecycleEvent::Terminated {
            agent_id: agent_id.to_string(),
            reason,
            timestamp: Utc::now(),
        });

        Ok(())
    }

    /// Records a heartbeat from an agent
    pub fn heartbeat(&self, agent_id: &str) -> Result<()> {
        let mut entry = self
            .lifecycles
            .get_mut(agent_id)
            .ok_or_else(|| AgentError::AgentNotFound(agent_id.to_string()))?;

        entry.value_mut().update_heartbeat();

        debug!("Heartbeat received from agent {}", agent_id);

        self.emit_event(AgentLifecycleEvent::HeartbeatReceived {
            agent_id: agent_id.to_string(),
            timestamp: Utc::now(),
        });

        Ok(())
    }

    /// Records a heartbeat with a specific timestamp
    pub fn record_heartbeat(&self, agent_id: &str, timestamp: Timestamp) -> Result<()> {
        let mut entry = self
            .lifecycles
            .get_mut(agent_id)
            .ok_or_else(|| AgentError::AgentNotFound(agent_id.to_string()))?;

        // Update with specific timestamp (from_timestamp expects seconds)
        let datetime = DateTime::<Utc>::from_timestamp(timestamp.as_secs(), 0)
            .unwrap_or_else(Utc::now);
        entry.value_mut().last_heartbeat = Some(datetime);

        debug!("Heartbeat recorded for agent {} at {}", agent_id, datetime);

        self.emit_event(AgentLifecycleEvent::HeartbeatReceived {
            agent_id: agent_id.to_string(),
            timestamp: datetime,
        });

        Ok(())
    }

    /// Checks all agent heartbeats and suspends inactive agents
    pub fn check_heartbeats(&self) -> Result<Vec<String>> {
        let timeout_secs = self.heartbeat_config.timeout_secs();

        // First pass: collect candidate agent IDs without calling back into
        // `self.lifecycles` while a DashMap iterator shard guard is held.
        // `drop(entry)` releases the value `Ref` but the surrounding `for`
        // iterator still owns the shard's read guard, so calling
        // `self.suspend()` (which does `get_mut()`) inside the loop deadlocks
        // whenever the target key hashes to the iterator's current shard.
        let mut candidates: Vec<String> = Vec::new();
        for entry in self.lifecycles.iter() {
            let info = entry.value();
            if info.state == AgentState::Active && !info.is_healthy(timeout_secs) {
                candidates.push(entry.key().clone());
            }
        }

        // Second pass: iterator dropped; safe to mutate.
        let mut suspended_agents = Vec::new();
        for agent_id in candidates {
            warn!(
                "Agent {} missed heartbeat (timeout: {}s), suspending",
                agent_id, timeout_secs
            );
            if let Err(e) = self.suspend(
                &agent_id,
                format!("Heartbeat timeout ({}s)", timeout_secs),
            ) {
                warn!("Failed to suspend agent {}: {}", agent_id, e);
            } else {
                suspended_agents.push(agent_id);
            }
        }

        if !suspended_agents.is_empty() {
            info!("Suspended {} agents due to heartbeat timeout", suspended_agents.len());
        }

        Ok(suspended_agents)
    }

    /// Auto-terminates agents that have been Suspended past `purge_after_secs`.
    /// The companion to [`check_heartbeats`] for the long-horizon sweep:
    /// `check_heartbeats` flips Active → Suspended on missed pings, and this
    /// method flips Suspended → Terminated once the agent has been silent so
    /// long that recovery is no longer expected. Terminated rows stay in
    /// CF_AGENTS for audit (per `AgentRuntime::with_storage()` semantics) —
    /// this method does not delete them.
    ///
    /// Returns the list of agent IDs that were terminated.
    pub fn purge_suspended(&self, purge_after_secs: i64) -> Result<Vec<String>> {
        let now = chrono::Utc::now();
        // First pass: collect candidates without holding shard guards.
        let mut candidates: Vec<String> = Vec::new();
        for entry in self.lifecycles.iter() {
            let info = entry.value();
            if info.state == AgentState::Suspended {
                let age = (now - info.last_state_change).num_seconds();
                if age >= purge_after_secs {
                    candidates.push(entry.key().clone());
                }
            }
        }
        // Second pass: terminate.
        let mut terminated = Vec::new();
        for agent_id in candidates {
            warn!(
                "Agent {} stayed suspended past purge window ({}s), auto-terminating",
                agent_id, purge_after_secs
            );
            if let Err(e) = self.terminate(
                &agent_id,
                format!("Auto-terminated after {}s suspended", purge_after_secs),
            ) {
                warn!("Failed to auto-terminate agent {}: {}", agent_id, e);
            } else {
                terminated.push(agent_id);
            }
        }
        if !terminated.is_empty() {
            info!(
                "Auto-terminated {} agents stuck in Suspended past purge window",
                terminated.len()
            );
        }
        Ok(terminated)
    }

    /// Checks all active agents against a caller-supplied idle TTL (in
    /// seconds) and suspends any whose last heartbeat (or state change, if no
    /// heartbeat has been received) is older than that threshold.
    ///
    /// Unlike [`check_heartbeats`], which uses the configured
    /// `HeartbeatConfig::timeout_secs()` (tuned for tight sub-minute liveness
    /// detection), this method is intended for long-horizon sweeps such as
    /// the registry-wide 1-hour idle TTL reconciliation performed by the
    /// node's event loop.
    ///
    /// Returns the list of agent IDs that were suspended.
    pub fn check_idle_ttl(&self, ttl_secs: i64) -> Result<Vec<String>> {
        // First pass: collect candidate agent IDs without calling back into
        // `self.lifecycles` while a DashMap iterator shard guard is held.
        // Calling `self.suspend()` inside the iterator triggers a re-entrant
        // `get_mut()` on the same map; if the target key hashes to the same
        // shard as the iterator's current shard the task deadlocks
        // permanently. Collect candidate keys first, then mutate after the
        // iterator drops.
        let mut candidates: Vec<String> = Vec::new();
        for entry in self.lifecycles.iter() {
            let info = entry.value();
            if info.state == AgentState::Active && !info.is_healthy(ttl_secs) {
                candidates.push(entry.key().clone());
            }
        }

        // Second pass: iterator dropped; safe to mutate.
        let mut suspended_agents = Vec::new();
        for agent_id in candidates {
            warn!(
                "Agent {} idle beyond TTL ({}s), suspending",
                agent_id, ttl_secs
            );
            if let Err(e) = self.suspend(
                &agent_id,
                format!("Idle TTL exceeded ({}s)", ttl_secs),
            ) {
                warn!("Failed to suspend idle agent {}: {}", agent_id, e);
            } else {
                suspended_agents.push(agent_id);
            }
        }

        if !suspended_agents.is_empty() {
            info!(
                "Suspended {} agents due to idle TTL ({}s)",
                suspended_agents.len(),
                ttl_secs
            );
        }

        Ok(suspended_agents)
    }

    /// Gets the heartbeat configuration
    pub fn heartbeat_config(&self) -> &HeartbeatConfig {
        &self.heartbeat_config
    }

    /// Gets the current state of an agent
    pub fn get_state(&self, agent_id: &str) -> Result<AgentState> {
        self.lifecycles
            .get(agent_id)
            .map(|entry| entry.value().state)
            .ok_or_else(|| AgentError::AgentNotFound(agent_id.to_string()))
    }

    /// Gets lifecycle information for an agent
    pub fn get_lifecycle_info(&self, agent_id: &str) -> Result<AgentLifecycleInfo> {
        self.lifecycles
            .get(agent_id)
            .map(|entry| entry.value().clone())
            .ok_or_else(|| AgentError::AgentNotFound(agent_id.to_string()))
    }

    /// Gets all agents in a specific state
    pub fn get_agents_in_state(&self, state: AgentState) -> Vec<String> {
        self.lifecycles
            .iter()
            .filter(|entry| entry.value().state == state)
            .map(|entry| entry.key().clone())
            .collect()
    }

    /// Gets all unhealthy agents (missing heartbeats)
    pub fn get_unhealthy_agents(&self) -> Vec<String> {
        let timeout_secs = self.heartbeat_config.timeout_secs();
        self.lifecycles
            .iter()
            .filter(|entry| {
                let info = entry.value();
                info.state == AgentState::Active && !info.is_healthy(timeout_secs)
            })
            .map(|entry| entry.key().clone())
            .collect()
    }

    /// Removes an agent's lifecycle information
    pub fn remove(&self, agent_id: &str) -> Result<()> {
        self.lifecycles
            .remove(agent_id)
            .ok_or_else(|| AgentError::AgentNotFound(agent_id.to_string()))?;
        Ok(())
    }
}

impl Default for AgentLifecycle {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_state_transitions() {
        assert!(AgentState::Created.can_transition_to(&AgentState::Initializing));
        assert!(AgentState::Initializing.can_transition_to(&AgentState::Active));
        assert!(AgentState::Active.can_transition_to(&AgentState::Suspended));
        assert!(AgentState::Suspended.can_transition_to(&AgentState::Active));
        assert!(AgentState::Active.can_transition_to(&AgentState::Terminated));
        assert!(!AgentState::Terminated.can_transition_to(&AgentState::Active));
    }

    #[test]
    fn test_lifecycle_creation() {
        let lifecycle = AgentLifecycle::new();
        let agent_id = "test_agent".to_string();

        lifecycle.initialize(agent_id.clone()).unwrap();
        let state = lifecycle.get_state(&agent_id).unwrap();
        assert_eq!(state, AgentState::Created);
    }

    #[test]
    fn test_lifecycle_activation() {
        let lifecycle = AgentLifecycle::new();
        let agent_id = "test_agent".to_string();

        lifecycle.initialize(agent_id.clone()).unwrap();
        lifecycle.activate(&agent_id).unwrap();

        let state = lifecycle.get_state(&agent_id).unwrap();
        assert_eq!(state, AgentState::Active);
    }

    #[test]
    fn test_lifecycle_suspend_resume() {
        let lifecycle = AgentLifecycle::new();
        let agent_id = "test_agent".to_string();

        lifecycle.initialize(agent_id.clone()).unwrap();
        lifecycle.activate(&agent_id).unwrap();
        lifecycle.suspend(&agent_id, "Testing".to_string()).unwrap();

        let state = lifecycle.get_state(&agent_id).unwrap();
        assert_eq!(state, AgentState::Suspended);

        lifecycle.resume(&agent_id).unwrap();
        let state = lifecycle.get_state(&agent_id).unwrap();
        assert_eq!(state, AgentState::Active);
    }

    #[test]
    fn test_lifecycle_termination() {
        let lifecycle = AgentLifecycle::new();
        let agent_id = "test_agent".to_string();

        lifecycle.initialize(agent_id.clone()).unwrap();
        lifecycle.activate(&agent_id).unwrap();
        lifecycle
            .terminate(&agent_id, "Shutdown".to_string())
            .unwrap();

        let state = lifecycle.get_state(&agent_id).unwrap();
        assert_eq!(state, AgentState::Terminated);

        // Cannot resume a terminated agent
        let result = lifecycle.resume(&agent_id);
        assert!(matches!(result, Err(AgentError::InvalidStateTransition { .. })));
    }

    #[test]
    fn test_heartbeat_tracking() {
        let lifecycle = AgentLifecycle::new();
        let agent_id = "test_agent".to_string();

        lifecycle.initialize(agent_id.clone()).unwrap();
        lifecycle.activate(&agent_id).unwrap();

        lifecycle.heartbeat(&agent_id).unwrap();

        let info = lifecycle.get_lifecycle_info(&agent_id).unwrap();
        assert!(info.last_heartbeat.is_some());
        assert!(info.is_healthy(120)); // Within 120 seconds
    }

    #[test]
    fn test_purge_suspended_terminates_old_suspended_agents() {
        let lifecycle = AgentLifecycle::new();
        let agent_id = "stuck_agent".to_string();

        lifecycle.initialize(agent_id.clone()).unwrap();
        lifecycle.activate(&agent_id).unwrap();
        lifecycle.suspend(&agent_id, "test".to_string()).unwrap();

        // Backdate last_state_change so the agent looks like it's been
        // suspended for an hour.
        if let Some(mut entry) = lifecycle.lifecycles.get_mut(&agent_id) {
            entry.last_state_change = Utc::now() - chrono::Duration::seconds(3600);
        }

        let terminated = lifecycle.purge_suspended(60).unwrap();
        assert_eq!(terminated, vec![agent_id.clone()]);
        let state = lifecycle.get_state(&agent_id).unwrap();
        assert_eq!(state, AgentState::Terminated);
    }

    #[test]
    fn test_purge_suspended_leaves_fresh_suspended_alone() {
        let lifecycle = AgentLifecycle::new();
        let agent_id = "recent_agent".to_string();

        lifecycle.initialize(agent_id.clone()).unwrap();
        lifecycle.activate(&agent_id).unwrap();
        lifecycle.suspend(&agent_id, "test".to_string()).unwrap();

        // Just suspended; purge window is 1h.
        let terminated = lifecycle.purge_suspended(3600).unwrap();
        assert!(terminated.is_empty());
        let state = lifecycle.get_state(&agent_id).unwrap();
        assert_eq!(state, AgentState::Suspended);
    }

    #[test]
    fn test_purge_suspended_skips_active_agents() {
        let lifecycle = AgentLifecycle::new();
        let agent_id = "active_agent".to_string();

        lifecycle.initialize(agent_id.clone()).unwrap();
        lifecycle.activate(&agent_id).unwrap();

        // Purge with zero TTL — Active agents must not be touched.
        let terminated = lifecycle.purge_suspended(0).unwrap();
        assert!(terminated.is_empty());
        let state = lifecycle.get_state(&agent_id).unwrap();
        assert_eq!(state, AgentState::Active);
    }
}
