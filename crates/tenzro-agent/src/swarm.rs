//! Swarm orchestration for Tenzro Network agents.
//!
//! This module provides `SwarmManager` — a coordination layer on top of
//! `AgentRuntime` that lets an orchestrator agent spawn a pool of member
//! agents and dispatch tasks to all of them in parallel.

use crate::{
    error::{AgentError, Result},
    runtime::AgentRuntime,
};
use dashmap::DashMap;
use futures::future::join_all;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tenzro_storage::kv::{CF_AGENTS, KvStore};
use tenzro_types::agent::{SwarmConfig, SwarmMember, SwarmMemberStatus};
use tokio::time::timeout;
use tracing::{info, warn};
use uuid::Uuid;

/// Storage key prefix for persisted `SwarmState` records in CF_AGENTS.
const SWARM_KEY_PREFIX: &[u8] = b"swarm:";

/// Internal swarm state, stored per swarm ID.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SwarmState {
    /// Agent ID of the orchestrator that owns this swarm
    pub orchestrator_id: String,
    /// All member agents
    pub members: Vec<SwarmMember>,
    /// Swarm configuration
    pub config: SwarmConfig,
    /// Overall swarm lifecycle status: "idle" | "working" | "completed"
    pub status: String,
}

/// Manages pools of coordinated agents (swarms).
///
/// Each swarm has one orchestrator and N member agents.  Tasks can be
/// broadcast to all members in parallel with `broadcast_task`.
pub struct SwarmManager {
    runtime: Arc<AgentRuntime>,
    swarms: Arc<DashMap<String, SwarmState>>,
    /// Optional durable backing store (RocksDB via CF_AGENTS). When set,
    /// `create_swarm`, `broadcast_task`, and `terminate_swarm` write through
    /// to the store so swarm membership and status survive restarts.
    storage: Option<Arc<dyn KvStore>>,
}

impl SwarmManager {
    /// Creates a new swarm manager backed by the given runtime.
    pub fn new(runtime: Arc<AgentRuntime>) -> Self {
        Self {
            runtime,
            swarms: Arc::new(DashMap::new()),
            storage: None,
        }
    }

    /// Creates a new swarm manager backed by a durable `KvStore` and
    /// hydrates previously-persisted swarms from CF_AGENTS using the
    /// `swarm:` key prefix.
    ///
    /// Hydration failures on individual swarm records are logged and
    /// skipped so that one corrupt entry does not block the whole registry
    /// from coming back up.
    pub fn with_storage(runtime: Arc<AgentRuntime>, storage: Arc<dyn KvStore>) -> Result<Self> {
        let swarms: Arc<DashMap<String, SwarmState>> = Arc::new(DashMap::new());

        let keys = storage
            .get_keys_with_prefix(CF_AGENTS, SWARM_KEY_PREFIX)
            .map_err(|e| AgentError::StorageError(format!("Failed to scan swarm keys: {}", e)))?;

        for key in keys {
            match storage.get(CF_AGENTS, &key) {
                Ok(Some(bytes)) => match serde_json::from_slice::<SwarmState>(&bytes) {
                    Ok(state) => {
                        if let Some(id_bytes) = key.strip_prefix(SWARM_KEY_PREFIX)
                            && let Ok(swarm_id) = std::str::from_utf8(id_bytes)
                        {
                            swarms.insert(swarm_id.to_string(), state);
                        }
                    }
                    Err(e) => warn!(
                        "Corrupt swarm record at key {:?}: {}",
                        String::from_utf8_lossy(&key),
                        e
                    ),
                },
                Ok(None) => {}
                Err(e) => warn!(
                    "Failed to read swarm key {:?}: {}",
                    String::from_utf8_lossy(&key),
                    e
                ),
            }
        }

        info!(
            "SwarmManager hydrated from CF_AGENTS: {} swarms",
            swarms.len()
        );

        Ok(Self {
            runtime,
            swarms,
            storage: Some(storage),
        })
    }

    /// Builds the CF_AGENTS storage key for a swarm record.
    fn swarm_key(swarm_id: &str) -> Vec<u8> {
        let mut k = Vec::with_capacity(SWARM_KEY_PREFIX.len() + swarm_id.len());
        k.extend_from_slice(SWARM_KEY_PREFIX);
        k.extend_from_slice(swarm_id.as_bytes());
        k
    }

    /// Persists a single swarm state. No-op when storage is not configured.
    fn persist_swarm(&self, swarm_id: &str, state: &SwarmState) -> Result<()> {
        if let Some(ref storage) = self.storage {
            let bytes = serde_json::to_vec(state).map_err(|e| {
                AgentError::StorageError(format!("Failed to serialize swarm: {}", e))
            })?;
            let key = Self::swarm_key(swarm_id);
            storage
                .put(CF_AGENTS, &key, &bytes)
                .map_err(|e| AgentError::StorageError(format!("Failed to persist swarm: {}", e)))?;
        }
        Ok(())
    }

    /// Removes a swarm record from storage. No-op when storage is not
    /// configured or the record does not exist.
    fn remove_swarm_from_storage(&self, swarm_id: &str) -> Result<()> {
        if let Some(ref storage) = self.storage {
            let key = Self::swarm_key(swarm_id);
            storage
                .delete(CF_AGENTS, &key)
                .map_err(|e| AgentError::StorageError(format!("Failed to remove swarm: {}", e)))?;
        }
        Ok(())
    }

    /// Creates a new swarm owned by `orchestrator_id`.
    ///
    /// `member_specs` is a list of `(name, capabilities)` pairs.  Each pair
    /// spawns one child agent via `AgentRuntime::spawn_agent`.  Returns the
    /// swarm ID on success.
    pub async fn create_swarm(
        &self,
        orchestrator_id: &str,
        member_specs: Vec<(String, Vec<String>)>,
        config: SwarmConfig,
    ) -> Result<String> {
        if member_specs.len() > config.max_members {
            return Err(AgentError::ProtocolError(format!(
                "member count {} exceeds max_members limit of {}",
                member_specs.len(),
                config.max_members
            )));
        }

        let swarm_id = Uuid::new_v4().to_string();
        let mut members = Vec::new();

        for (name, caps) in member_specs {
            let agent = self
                .runtime
                .spawn_agent(orchestrator_id, &name, caps)
                .await?;
            members.push(SwarmMember {
                agent_id: agent.identity.agent_id.clone(),
                role: name,
                status: SwarmMemberStatus::Idle,
                result: None,
            });
        }

        let state = SwarmState {
            orchestrator_id: orchestrator_id.to_string(),
            members,
            config,
            status: "idle".to_string(),
        };

        // Write-through: the swarm must survive restarts so the orchestrator
        // can reconnect to its members after a node bounce.
        self.persist_swarm(&swarm_id, &state)?;
        self.swarms.insert(swarm_id.clone(), state);

        info!(swarm_id = %swarm_id, orchestrator_id = %orchestrator_id, "Swarm created");
        Ok(swarm_id)
    }

    /// Dispatches `task` to all members of `swarm_id` in parallel.
    ///
    /// Returns a `Vec` with one status string per member.  Individual member
    /// failures are captured as strings rather than propagating — the caller
    /// can inspect them to decide whether to retry.
    pub async fn broadcast_task(&self, swarm_id: &str, task: &str) -> Result<Vec<String>> {
        // Extract config values and member IDs in one scope to avoid holding DashMap guard
        // across the async boundary.
        let (member_ids, task_timeout_secs, parallel, snapshot) = {
            let mut state = self.swarms.get_mut(swarm_id).ok_or_else(|| {
                AgentError::ProtocolError(format!("swarm not found: {}", swarm_id))
            })?;
            state.status = "working".to_string();
            let ids: Vec<String> = state.members.iter().map(|m| m.agent_id.clone()).collect();
            let secs = state.config.task_timeout_secs;
            let par = state.config.parallel;
            let snap = state.clone();
            (ids, secs, par, snap)
        };

        // Write-through: persist the status transition so a crash mid-task
        // leaves the swarm in a recognisable "working" state.
        self.persist_swarm(swarm_id, &snapshot)?;

        let runtime = self.runtime.clone();
        let task_owned = task.to_string();

        /// Dispatch task to a single agent, wrapped in a per-task timeout.
        async fn dispatch_one(
            rt: Arc<AgentRuntime>,
            agent_id: String,
            t: String,
            timeout_secs: u64,
        ) -> String {
            let agent_id_inner = agent_id.clone();
            let fut = async move {
                let sender_result = rt.get_agent("swarm-coordinator");
                let receiver_result = rt.get_agent(&agent_id_inner);

                match (sender_result, receiver_result) {
                    (Ok(sender), Ok(receiver)) => {
                        let mut params = std::collections::HashMap::new();
                        params.insert("task".to_string(), serde_json::json!(t));
                        match rt
                            .delegate_task(
                                sender.identity,
                                receiver.identity,
                                "task_execution".to_string(),
                                params,
                            )
                            .await
                        {
                            Ok(_) => format!("Agent {} accepted task", agent_id_inner),
                            Err(e) => format!("Agent {} error: {}", agent_id_inner, e),
                        }
                    }
                    (_, Err(e)) => format!("Agent {} lookup failed: {}", agent_id_inner, e),
                    (Err(e), _) => format!("Swarm coordinator lookup failed: {}", e),
                }
            };

            match timeout(Duration::from_secs(timeout_secs), fut).await {
                Ok(result) => result,
                Err(_) => format!("Agent {} timed out after {}s", agent_id, timeout_secs),
            }
        }

        let results = if parallel {
            // Dispatch all members concurrently and await together.
            let futures: Vec<_> = member_ids
                .into_iter()
                .map(|agent_id| {
                    let rt = runtime.clone();
                    let t = task_owned.clone();
                    tokio::spawn(
                        async move { dispatch_one(rt, agent_id, t, task_timeout_secs).await },
                    )
                })
                .collect();

            join_all(futures)
                .await
                .into_iter()
                .map(|r| r.unwrap_or_else(|e| format!("join error: {}", e)))
                .collect()
        } else {
            // Dispatch members one at a time (sequential mode).
            let mut results = Vec::with_capacity(member_ids.len());
            for agent_id in member_ids {
                let rt = runtime.clone();
                let t = task_owned.clone();
                results.push(dispatch_one(rt, agent_id, t, task_timeout_secs).await);
            }
            results
        };

        Ok(results)
    }

    /// Returns a JSON snapshot of swarm status, or `None` if the swarm does
    /// not exist.
    pub fn get_swarm_status(&self, swarm_id: &str) -> Option<serde_json::Value> {
        self.swarms.get(swarm_id).map(|s| {
            serde_json::json!({
                "swarm_id": swarm_id,
                "orchestrator_id": s.orchestrator_id,
                "status": s.status,
                "member_count": s.members.len(),
                "config": {
                    "max_members": s.config.max_members,
                    "task_timeout_secs": s.config.task_timeout_secs,
                    "parallel": s.config.parallel,
                },
                "members": s.members.iter().map(|m| serde_json::json!({
                    "agent_id": m.agent_id,
                    "role": m.role,
                    "status": format!("{:?}", m.status),
                    "result": m.result,
                })).collect::<Vec<_>>(),
            })
        })
    }

    /// Terminates all member agents and removes the swarm from the registry.
    pub async fn terminate_swarm(&self, swarm_id: &str) -> Result<()> {
        let state = self
            .swarms
            .remove(swarm_id)
            .ok_or_else(|| AgentError::ProtocolError(format!("swarm not found: {}", swarm_id)))?
            .1;

        // Write-through: drop the swarm record from durable storage so a
        // restart does not rehydrate a terminated swarm.
        if let Err(e) = self.remove_swarm_from_storage(swarm_id) {
            warn!(
                swarm_id = %swarm_id,
                error = %e,
                "Failed to remove swarm from storage"
            );
        }

        for member in &state.members {
            if let Err(e) = self
                .runtime
                .terminate_agent(&member.agent_id, "Swarm terminated".to_string())
                .await
            {
                warn!(
                    agent_id = %member.agent_id,
                    error = %e,
                    "Failed to terminate swarm member"
                );
            }
        }

        info!(swarm_id = %swarm_id, "Swarm terminated");
        Ok(())
    }

    /// Returns the number of active swarms.
    pub fn swarm_count(&self) -> usize {
        self.swarms.len()
    }

    /// Returns a JSON snapshot of every swarm currently registered.
    ///
    /// The returned array matches the shape of `get_swarm_status` and is
    /// suitable for direct exposure via the `tenzro_listSwarms` RPC method.
    /// Because `SwarmManager::with_storage()` hydrates swarm state from
    /// CF_AGENTS on node startup, this iterates over both in-memory swarms
    /// and previously-persisted swarms that survived a restart.
    pub fn list_swarms(&self) -> Vec<serde_json::Value> {
        self.swarms
            .iter()
            .map(|entry| {
                let s = entry.value();
                serde_json::json!({
                    "swarm_id": entry.key(),
                    "orchestrator_id": s.orchestrator_id,
                    "status": s.status,
                    "member_count": s.members.len(),
                    "config": {
                        "max_members": s.config.max_members,
                        "task_timeout_secs": s.config.task_timeout_secs,
                        "parallel": s.config.parallel,
                    },
                    "members": s.members.iter().map(|m| serde_json::json!({
                        "agent_id": m.agent_id,
                        "role": m.role,
                        "status": format!("{:?}", m.status),
                        "result": m.result,
                    })).collect::<Vec<_>>(),
                })
            })
            .collect()
    }

    /// Sweeps all non-completed swarms and auto-completes any swarm whose
    /// members are all in terminal lifecycle state.
    ///
    /// A swarm is considered dead when every member's underlying agent is in
    /// `AgentState::Terminated`. In that case there is no way for the swarm
    /// to do further work, so we transition its status to `"completed"` and
    /// write through to CF_AGENTS. Swarms with even one `Active` or
    /// `Suspended` (resumable) member are left untouched.
    ///
    /// Intended to be driven from the node's periodic reconciliation loop
    /// alongside task/tool/skill reconciles, to prevent permanent accumulation
    /// of stale swarm records after all members have been individually
    /// terminated (either manually or by idle-TTL auto-suspend + operator
    /// termination).
    ///
    /// Returns the list of swarm IDs that were transitioned to `"completed"`
    /// in this sweep.
    pub fn check_swarm_liveness(&self) -> Vec<String> {
        use crate::lifecycle::AgentState;

        let mut completed: Vec<String> = Vec::new();

        // Collect candidate IDs first to avoid holding a DashMap iter guard
        // while we mutate entries below.
        let candidates: Vec<String> = self
            .swarms
            .iter()
            .filter(|e| e.value().status != "completed")
            .map(|e| e.key().clone())
            .collect();

        for swarm_id in candidates {
            // Snapshot member IDs and check liveness outside the write guard.
            let member_ids: Vec<String> = match self.swarms.get(&swarm_id) {
                Some(s) => s.members.iter().map(|m| m.agent_id.clone()).collect(),
                None => continue,
            };

            // Empty-member swarms are degenerate; skip them rather than
            // auto-complete, since that could mask a create_swarm bug.
            if member_ids.is_empty() {
                continue;
            }

            // Swarm is dead iff every member is Terminated.
            let all_terminated = member_ids
                .iter()
                .all(|id| matches!(self.runtime.get_agent_state(id), Ok(AgentState::Terminated)));

            if !all_terminated {
                continue;
            }

            // Transition and persist. Scope the mutable guard.
            let snapshot = {
                let mut entry = match self.swarms.get_mut(&swarm_id) {
                    Some(e) => e,
                    None => continue,
                };
                entry.status = "completed".to_string();
                entry.clone()
            };

            if let Err(e) = self.persist_swarm(&swarm_id, &snapshot) {
                warn!(
                    swarm_id = %swarm_id,
                    error = %e,
                    "Failed to persist auto-completed swarm"
                );
                continue;
            }

            info!(
                swarm_id = %swarm_id,
                "Swarm auto-completed: all members terminated"
            );
            completed.push(swarm_id);
        }

        completed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_types::primitives::Address;

    #[tokio::test]
    async fn test_swarm_create_and_status() {
        let runtime = Arc::new(AgentRuntime::new().expect("runtime"));
        let mgr = SwarmManager::new(runtime.clone());

        // Register the orchestrator agent before creating a swarm.
        // spawn_agent() looks up the parent by agent_id, so we must pre-register it.
        let creator = Address::from([1u8; 32]);
        let orch = runtime
            .register_agent("Orchestrator".to_string(), creator, vec![], false, 0)
            .await
            .expect("register orchestrator");
        let orch_id = &orch.identity.agent_id;

        // Create a tiny swarm with 2 members
        let swarm_id = mgr
            .create_swarm(
                orch_id,
                vec![
                    ("analyst".to_string(), vec!["data_analysis".to_string()]),
                    ("writer".to_string(), vec!["nlp".to_string()]),
                ],
                SwarmConfig::default(),
            )
            .await
            .expect("create_swarm");

        assert_eq!(mgr.swarm_count(), 1);

        let status = mgr.get_swarm_status(&swarm_id).expect("status");
        assert_eq!(status["member_count"], 2);
        assert_eq!(status["status"], "idle");
    }

    #[tokio::test]
    async fn test_swarm_terminate() {
        let runtime = Arc::new(AgentRuntime::new().expect("runtime"));
        let mgr = SwarmManager::new(runtime.clone());

        // Register the orchestrator agent before creating a swarm.
        let creator = Address::from([1u8; 32]);
        let orch = runtime
            .register_agent("Orchestrator2".to_string(), creator, vec![], false, 1)
            .await
            .expect("register orchestrator");
        let orch_id = &orch.identity.agent_id;

        let swarm_id = mgr
            .create_swarm(
                orch_id,
                vec![("worker".to_string(), vec![])],
                SwarmConfig::default(),
            )
            .await
            .expect("create_swarm");

        mgr.terminate_swarm(&swarm_id)
            .await
            .expect("terminate_swarm");

        assert_eq!(mgr.swarm_count(), 0);
        assert!(mgr.get_swarm_status(&swarm_id).is_none());
    }

    #[tokio::test]
    async fn test_swarm_not_found() {
        let runtime = Arc::new(AgentRuntime::new().expect("runtime"));
        let mgr = SwarmManager::new(runtime);

        let result = mgr.terminate_swarm("nonexistent").await;
        assert!(result.is_err());
    }
}
