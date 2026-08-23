//! Cross-cutting liveness sweeper for network registries.
//!
//! Tenzro stores many "live" resources in column families: skills, tools,
//! agent templates, tasks, MPP sessions, model service endpoints, etc.
//! Without a liveness layer these accumulate forever — once written, they
//! show up as "active" indefinitely even when the publisher has gone away.
//!
//! This module provides:
//!
//! 1. [`LivenessConfig`] — per-resource TTL knobs with sane defaults.
//! 2. [`LivenessSweeper`] — a single periodic task that scans every
//!    registered CF + key-prefix combination and applies the policy:
//!    flip status to a stale variant when silent past `stale_after`,
//!    purge the row entirely when silent past `purge_after`.
//! 3. [`spawn_liveness_sweeper`] — wires the sweeper into the node
//!    startup sequence; the returned [`tokio::task::JoinHandle`] is held
//!    by the node so the sweeper shuts down with the rest of the runtime.
//!
//! Resources that are intentionally permanent (identities, tokens,
//! NFTs, governance proposals, validators, escrows) are NOT swept.
//!
//! Concurrency note: each sweep cycle does a single scan per CF, decodes
//! each value, mutates only the rows that need to change, and writes back
//! via `KvStore::put`. The sweeper holds no in-memory locks beyond the
//! duration of a single row's read-modify-write — listing and heartbeat
//! RPCs continue to serve concurrently. Because every registry already
//! treats RocksDB as the source of truth (write-through pattern), the
//! sweeper's mutations propagate to read paths on the next list call.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use chrono::Utc;
use serde::{Deserialize, Serialize};
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use tenzro_agent::AgentLifecycle;
use tenzro_storage::kv::{
    CF_AGENT_TEMPLATES, CF_CHANNELS, CF_MODEL_SERVICES, CF_SKILLS, CF_TASKS, CF_TOOLS, KvStore,
};

/// Default cadence at which the sweeper wakes up.
const DEFAULT_SWEEP_INTERVAL_SECS: u64 = 300; // 5 minutes

/// Per-resource TTL configuration for the liveness sweeper.
///
/// All values are in **seconds**. Charitable defaults — measured in days,
/// not minutes — so a transient network blip never silently nukes the
/// registry. Operators who want stricter cleanup can override via node
/// config.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LivenessConfig {
    /// How often the sweeper task wakes up to scan all registries.
    pub sweep_interval_secs: u64,

    /// Skill goes silent → status::Inactive after this many seconds.
    pub skill_stale_after_secs: u64,
    /// Skill stays Inactive past this → row deleted from CF_SKILLS.
    pub skill_purge_after_secs: u64,

    /// Tool goes silent → status::Inactive after this many seconds.
    pub tool_stale_after_secs: u64,
    /// Tool stays Inactive past this → row deleted from CF_TOOLS.
    pub tool_purge_after_secs: u64,

    /// Template goes silent → status::Deprecated after this many seconds.
    /// Templates are NOT purged — they have audit value as a marketplace
    /// history.
    pub template_stale_after_secs: u64,

    /// Open task whose deadline has passed → status::Expired.
    /// (Tasks without a deadline are never auto-expired.)
    pub task_stale_after_secs_no_deadline: u64,
    /// Terminal task (Completed/Cancelled/Expired) row deleted after this.
    pub task_purge_after_secs: u64,

    /// MPP session goes silent → state::Closing after this many seconds.
    pub mpp_session_stale_after_secs: u64,
    /// Closed MPP session row deleted after this.
    pub mpp_session_purge_after_secs: u64,

    /// Model service endpoint silent past this → marked Inactive.
    pub model_service_stale_after_secs: u64,
    /// Inactive model service endpoint row deleted after this.
    pub model_service_purge_after_secs: u64,

    /// Agent stays Suspended past this → auto-Terminated by lifecycle.
    /// (Wired into [`AgentLifecycle::check_heartbeats`] separately; this
    /// field is the single source of truth so node config can tune it.)
    pub agent_purge_after_secs: u64,
}

impl Default for LivenessConfig {
    fn default() -> Self {
        Self {
            sweep_interval_secs: DEFAULT_SWEEP_INTERVAL_SECS,
            // Skills/tools: 24h silent → Inactive, 30d Inactive → purge.
            skill_stale_after_secs: 24 * 60 * 60,
            skill_purge_after_secs: 30 * 24 * 60 * 60,
            tool_stale_after_secs: 24 * 60 * 60,
            tool_purge_after_secs: 30 * 24 * 60 * 60,
            // Templates: 30d silent → Deprecated, never purged.
            template_stale_after_secs: 30 * 24 * 60 * 60,
            // Tasks without deadline: 7d silent counts as expired.
            // Terminal tasks: 30d → purge.
            task_stale_after_secs_no_deadline: 7 * 24 * 60 * 60,
            task_purge_after_secs: 30 * 24 * 60 * 60,
            // MPP sessions: 1h silent → Closing, 24h Closed → purge.
            mpp_session_stale_after_secs: 60 * 60,
            mpp_session_purge_after_secs: 24 * 60 * 60,
            // Model service endpoints: 5min silent → Inactive, 1h purge.
            model_service_stale_after_secs: 5 * 60,
            model_service_purge_after_secs: 60 * 60,
            // Agents: 7d Suspended → auto-Terminate.
            agent_purge_after_secs: 7 * 24 * 60 * 60,
        }
    }
}

/// A single sweep cycle's results — counted per resource type for
/// observability via the `tenzro_livenessStats` RPC and tracing logs.
#[derive(Debug, Clone, Default, Serialize)]
pub struct SweepStats {
    pub skills_marked_inactive: u64,
    pub skills_purged: u64,
    pub tools_marked_inactive: u64,
    pub tools_purged: u64,
    pub templates_marked_deprecated: u64,
    pub tasks_marked_expired: u64,
    pub tasks_purged: u64,
    pub mpp_sessions_closing: u64,
    pub mpp_sessions_purged: u64,
    pub model_services_marked_inactive: u64,
    pub model_services_purged: u64,
    pub agents_auto_terminated: u64,
}

impl SweepStats {
    fn total_changes(&self) -> u64 {
        self.skills_marked_inactive
            + self.skills_purged
            + self.tools_marked_inactive
            + self.tools_purged
            + self.templates_marked_deprecated
            + self.tasks_marked_expired
            + self.tasks_purged
            + self.mpp_sessions_closing
            + self.mpp_sessions_purged
            + self.model_services_marked_inactive
            + self.model_services_purged
            + self.agents_auto_terminated
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Owns the periodic sweeper task. Drop the handle on shutdown to stop it.
pub struct LivenessSweeper {
    pub config: LivenessConfig,
    handle: Option<JoinHandle<()>>,
}

impl LivenessSweeper {
    /// Stops the background task by aborting the JoinHandle. Idempotent.
    pub fn stop(&mut self) {
        if let Some(h) = self.handle.take() {
            h.abort();
        }
    }
}

impl Drop for LivenessSweeper {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Spawns the sweeper task. The sweeper runs forever until aborted; the
/// returned [`LivenessSweeper`] should be held by the node so shutdown
/// drops it (which aborts the task).
///
/// When `lifecycle` is `Some`, every sweep cycle also drives
/// `AgentLifecycle::purge_suspended()` — Suspended agents that haven't
/// recovered past `agent_purge_after_secs` get auto-Terminated. Pass
/// `None` for nodes that don't host the agent runtime.
pub fn spawn_liveness_sweeper(
    storage: Arc<dyn KvStore>,
    config: LivenessConfig,
    lifecycle: Option<Arc<AgentLifecycle>>,
) -> LivenessSweeper {
    let interval = config.sweep_interval_secs.max(10);
    let cfg = config.clone();

    let handle = tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(interval));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        // Skip the immediate first tick — give the rest of startup a moment
        // before we start scanning.
        ticker.tick().await;
        loop {
            ticker.tick().await;
            match run_sweep(&storage, &cfg, lifecycle.as_ref()) {
                Ok(stats) => {
                    if stats.total_changes() > 0 {
                        info!(
                            target: "liveness",
                            "Sweep complete: {:?}", stats
                        );
                    } else {
                        debug!(target: "liveness", "Sweep clean — no stale resources");
                    }
                }
                Err(e) => warn!(target: "liveness", "Sweep error: {}", e),
            }
        }
    });

    LivenessSweeper {
        config,
        handle: Some(handle),
    }
}

/// Runs one full sweep across every registry. Synchronous because all
/// `KvStore` operations are blocking. Called once per tick from the
/// async task; cheap unless the registry is huge.
pub fn run_sweep(
    storage: &Arc<dyn KvStore>,
    cfg: &LivenessConfig,
    lifecycle: Option<&Arc<AgentLifecycle>>,
) -> Result<SweepStats, String> {
    let now = now_secs();
    let mut stats = SweepStats::default();

    sweep_skills(storage, cfg, now, &mut stats)?;
    sweep_tools(storage, cfg, now, &mut stats)?;
    sweep_templates(storage, cfg, now, &mut stats)?;
    sweep_tasks(storage, cfg, now, &mut stats)?;
    sweep_mpp_sessions(storage, cfg, now, &mut stats)?;
    sweep_model_services(storage, cfg, now, &mut stats)?;

    if let Some(lc) = lifecycle {
        match lc.purge_suspended(cfg.agent_purge_after_secs as i64) {
            Ok(ids) => stats.agents_auto_terminated = ids.len() as u64,
            Err(e) => warn!(target: "liveness", "purge_suspended error: {}", e),
        }
    }

    Ok(stats)
}

// ─────────────────────────── Skills ────────────────────────────

fn sweep_skills(
    storage: &Arc<dyn KvStore>,
    cfg: &LivenessConfig,
    now: u64,
    stats: &mut SweepStats,
) -> Result<(), String> {
    use tenzro_types::skill::{SkillDefinition, SkillStatus};

    let keys = storage
        .get_keys_with_prefix(CF_SKILLS, b"")
        .map_err(|e| format!("CF_SKILLS scan: {}", e))?;
    for key in keys {
        let bytes = match storage.get(CF_SKILLS, &key) {
            Ok(Some(b)) => b,
            _ => continue,
        };
        let mut skill: SkillDefinition = match serde_json::from_slice(&bytes) {
            Ok(s) => s,
            Err(_) => continue,
        };
        // Node-provided builtins never heartbeat — their liveness is the
        // node's liveness. Boot-time reconciliation owns their lifecycle.
        if skill.creator_did == tenzro_types::SYSTEM_CREATOR_DID {
            continue;
        }
        let age = now.saturating_sub(skill.last_seen_at);
        if matches!(skill.status, SkillStatus::Inactive) && age >= cfg.skill_purge_after_secs {
            let _ = storage.delete(CF_SKILLS, &key);
            stats.skills_purged += 1;
            continue;
        }
        if matches!(skill.status, SkillStatus::Active) && age >= cfg.skill_stale_after_secs {
            skill.status = SkillStatus::Inactive;
            if let Ok(updated) = serde_json::to_vec(&skill) {
                let _ = storage.put(CF_SKILLS, &key, &updated);
                stats.skills_marked_inactive += 1;
            }
        }
    }
    Ok(())
}

// ─────────────────────────── Tools ─────────────────────────────

fn sweep_tools(
    storage: &Arc<dyn KvStore>,
    cfg: &LivenessConfig,
    now: u64,
    stats: &mut SweepStats,
) -> Result<(), String> {
    use tenzro_types::tool::{ToolDefinition, ToolStatus};

    let keys = storage
        .get_keys_with_prefix(CF_TOOLS, b"")
        .map_err(|e| format!("CF_TOOLS scan: {}", e))?;
    for key in keys {
        let bytes = match storage.get(CF_TOOLS, &key) {
            Ok(Some(b)) => b,
            _ => continue,
        };
        let mut tool: ToolDefinition = match serde_json::from_slice(&bytes) {
            Ok(s) => s,
            Err(_) => continue,
        };
        // Node-provided builtins never heartbeat — their liveness is the
        // node's liveness. Boot-time reconciliation owns their lifecycle.
        if tool.creator_did.as_deref() == Some(tenzro_types::SYSTEM_CREATOR_DID) {
            continue;
        }
        let age = now.saturating_sub(tool.last_seen_at);
        if matches!(tool.status, ToolStatus::Inactive) && age >= cfg.tool_purge_after_secs {
            let _ = storage.delete(CF_TOOLS, &key);
            stats.tools_purged += 1;
            continue;
        }
        if matches!(tool.status, ToolStatus::Active) && age >= cfg.tool_stale_after_secs {
            tool.status = ToolStatus::Inactive;
            if let Ok(updated) = serde_json::to_vec(&tool) {
                let _ = storage.put(CF_TOOLS, &key, &updated);
                stats.tools_marked_inactive += 1;
            }
        }
    }
    Ok(())
}

// ────────────────────── Agent templates ────────────────────────

fn sweep_templates(
    storage: &Arc<dyn KvStore>,
    cfg: &LivenessConfig,
    now: u64,
    stats: &mut SweepStats,
) -> Result<(), String> {
    use tenzro_types::agent_template::{AgentTemplate, AgentTemplateStatus};

    let keys = storage
        .get_keys_with_prefix(CF_AGENT_TEMPLATES, b"")
        .map_err(|e| format!("CF_AGENT_TEMPLATES scan: {}", e))?;
    for key in keys {
        let bytes = match storage.get(CF_AGENT_TEMPLATES, &key) {
            Ok(Some(b)) => b,
            _ => continue,
        };
        let mut tpl: AgentTemplate = match serde_json::from_slice(&bytes) {
            Ok(s) => s,
            Err(_) => continue,
        };
        // Templates use `Timestamp` (chrono i64 seconds since epoch).
        let last_seen = tpl.last_seen_at.0.max(0) as u64;
        let age = now.saturating_sub(last_seen);
        if matches!(tpl.status, AgentTemplateStatus::Published)
            && age >= cfg.template_stale_after_secs
        {
            tpl.status = AgentTemplateStatus::Deprecated;
            if let Ok(updated) = serde_json::to_vec(&tpl) {
                let _ = storage.put(CF_AGENT_TEMPLATES, &key, &updated);
                stats.templates_marked_deprecated += 1;
            }
        }
    }
    Ok(())
}

// ────────────────────────── Tasks ──────────────────────────────

fn sweep_tasks(
    storage: &Arc<dyn KvStore>,
    cfg: &LivenessConfig,
    now: u64,
    stats: &mut SweepStats,
) -> Result<(), String> {
    use tenzro_types::task::{TaskInfo, TaskStatus};

    // Only the `task:` prefix — the same CF also stores `quote:` entries
    // which have their own expiry stamped on the `TaskQuote` itself.
    let keys = storage
        .get_keys_with_prefix(CF_TASKS, b"task:")
        .map_err(|e| format!("CF_TASKS scan: {}", e))?;
    for key in keys {
        let bytes = match storage.get(CF_TASKS, &key) {
            Ok(Some(b)) => b,
            _ => continue,
        };
        let mut task: TaskInfo = match serde_json::from_slice(&bytes) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let created = task.created_at.0.max(0) as u64;
        let age_since_created = now.saturating_sub(created);

        // Terminal-state purge.
        if task.is_terminal() && age_since_created >= cfg.task_purge_after_secs {
            let _ = storage.delete(CF_TASKS, &key);
            stats.tasks_purged += 1;
            continue;
        }

        // Open/Assigned with deadline past now → Expired.
        let mut should_expire = false;
        if matches!(task.status, TaskStatus::Open | TaskStatus::Assigned)
            && let Some(deadline) = task.deadline
            && deadline <= now
        {
            should_expire = true;
        }
        // Open with no deadline that's been sitting too long → Expired.
        if matches!(task.status, TaskStatus::Open)
            && task.deadline.is_none()
            && age_since_created >= cfg.task_stale_after_secs_no_deadline
        {
            should_expire = true;
        }
        if should_expire {
            task.status = TaskStatus::Expired;
            if let Ok(updated) = serde_json::to_vec(&task) {
                let _ = storage.put(CF_TASKS, &key, &updated);
                stats.tasks_marked_expired += 1;
            }
        }
    }
    Ok(())
}

// ───────────────────── MPP payment sessions ────────────────────

fn sweep_mpp_sessions(
    storage: &Arc<dyn KvStore>,
    cfg: &LivenessConfig,
    now: u64,
    stats: &mut SweepStats,
) -> Result<(), String> {
    // We only need the timestamps and state to sweep — decode just enough.
    // Re-using tenzro_payments types would create a heavy crate edge here;
    // a small mirror struct keeps the sweeper hermetic.
    #[derive(Serialize, Deserialize)]
    struct MppSessionShadow {
        session_id: String,
        payer_did: String,
        recipient: String,
        total_deposit: u128,
        total_spent: u128,
        asset: String,
        state: String,
        last_voucher_nonce: u64,
        created_at: chrono::DateTime<Utc>,
        last_activity: chrono::DateTime<Utc>,
    }

    let prefix = b"mpp-session:";
    let keys = storage
        .get_keys_with_prefix(CF_CHANNELS, prefix)
        .map_err(|e| format!("CF_CHANNELS scan: {}", e))?;
    for key in keys {
        let bytes = match storage.get(CF_CHANNELS, &key) {
            Ok(Some(b)) => b,
            _ => continue,
        };
        let mut sess: MppSessionShadow = match serde_json::from_slice(&bytes) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let last_activity = sess.last_activity.timestamp().max(0) as u64;
        let age = now.saturating_sub(last_activity);

        if sess.state == "Closed" && age >= cfg.mpp_session_purge_after_secs {
            let _ = storage.delete(CF_CHANNELS, &key);
            stats.mpp_sessions_purged += 1;
            continue;
        }
        // Sessions get serialized with serde's default representation; the
        // tenzro-payments enum derives Serialize on a unit variant which
        // produces the bare string "Open"/"Closing"/"Closed".
        if sess.state == "Open" && age >= cfg.mpp_session_stale_after_secs {
            sess.state = "Closing".to_string();
            if let Ok(updated) = serde_json::to_vec(&sess) {
                let _ = storage.put(CF_CHANNELS, &key, &updated);
                stats.mpp_sessions_closing += 1;
            }
        }
    }
    Ok(())
}

// ─────────────────── Model service endpoints ───────────────────

fn sweep_model_services(
    storage: &Arc<dyn KvStore>,
    cfg: &LivenessConfig,
    now: u64,
    stats: &mut SweepStats,
) -> Result<(), String> {
    // Model service rows are written by tenzro_serveModel under
    // CF_MODEL_SERVICES with provider-scoped keys. We treat any row whose
    // last_seen_at is older than stale_after as Inactive, and purge after
    // purge_after. The exact field name varies — try a small struct that
    // captures the common shape; rows that don't decode are left alone.
    #[derive(Serialize, Deserialize)]
    struct ServiceShadow {
        #[serde(default)]
        status: serde_json::Value,
        #[serde(default)]
        last_seen_at: u64,
        #[serde(default)]
        last_heartbeat: Option<u64>,
        #[serde(flatten)]
        _rest: serde_json::Value,
    }

    let keys = storage
        .get_keys_with_prefix(CF_MODEL_SERVICES, b"")
        .map_err(|e| format!("CF_MODEL_SERVICES scan: {}", e))?;
    for key in keys {
        let bytes = match storage.get(CF_MODEL_SERVICES, &key) {
            Ok(Some(b)) => b,
            _ => continue,
        };
        let svc: ServiceShadow = match serde_json::from_slice(&bytes) {
            Ok(s) => s,
            Err(_) => continue,
        };
        // Prefer last_seen_at; fall back to last_heartbeat.
        let last = if svc.last_seen_at > 0 {
            svc.last_seen_at
        } else {
            svc.last_heartbeat.unwrap_or(0)
        };
        if last == 0 {
            // No liveness signal at all — leave alone (charitable).
            continue;
        }
        let age = now.saturating_sub(last);
        let status_str = svc
            .status
            .as_str()
            .map(|s| s.to_string())
            .unwrap_or_else(|| svc.status.to_string());

        if status_str.contains("Inactive") && age >= cfg.model_service_purge_after_secs {
            let _ = storage.delete(CF_MODEL_SERVICES, &key);
            stats.model_services_purged += 1;
            continue;
        }
        if !status_str.contains("Inactive") && age >= cfg.model_service_stale_after_secs {
            // Surgical mutation: re-encode the original JSON with status
            // overridden to "Inactive". Avoids losing fields we don't model.
            if let Ok(mut value) = serde_json::from_slice::<serde_json::Value>(&bytes)
                && let Some(obj) = value.as_object_mut()
            {
                obj.insert(
                    "status".to_string(),
                    serde_json::Value::String("Inactive".to_string()),
                );
                if let Ok(updated) = serde_json::to_vec(&value) {
                    let _ = storage.put(CF_MODEL_SERVICES, &key, &updated);
                    stats.model_services_marked_inactive += 1;
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_storage::kv::MemoryStore;
    use tenzro_types::skill::{SkillDefinition, SkillStatus};
    use tenzro_types::tool::{ToolDefinition, ToolStatus};

    fn fresh_store() -> Arc<dyn KvStore> {
        Arc::new(MemoryStore::new())
    }

    fn fast_config() -> LivenessConfig {
        LivenessConfig {
            sweep_interval_secs: 1,
            skill_stale_after_secs: 10,
            skill_purge_after_secs: 100,
            tool_stale_after_secs: 10,
            tool_purge_after_secs: 100,
            template_stale_after_secs: 10,
            task_stale_after_secs_no_deadline: 10,
            task_purge_after_secs: 100,
            mpp_session_stale_after_secs: 10,
            mpp_session_purge_after_secs: 100,
            model_service_stale_after_secs: 10,
            model_service_purge_after_secs: 100,
            agent_purge_after_secs: 100,
        }
    }

    #[test]
    fn sweeper_marks_silent_skill_inactive_then_purges() {
        let store = fresh_store();
        let cfg = fast_config();

        // Insert a skill with last_seen_at far in the past.
        let mut skill = SkillDefinition::new(
            "old-search".to_string(),
            "1.0.0".to_string(),
            "did:tenzro:human:foo".to_string(),
            "stale".to_string(),
            0,
        );
        skill.last_seen_at = now_secs().saturating_sub(50); // > stale, < purge
        let bytes = serde_json::to_vec(&skill).unwrap();
        store
            .put(CF_SKILLS, skill.skill_id.as_bytes(), &bytes)
            .unwrap();

        let stats = run_sweep(&store, &cfg, None).unwrap();
        assert_eq!(stats.skills_marked_inactive, 1);
        assert_eq!(stats.skills_purged, 0);

        let stored = store
            .get(CF_SKILLS, skill.skill_id.as_bytes())
            .unwrap()
            .unwrap();
        let after: SkillDefinition = serde_json::from_slice(&stored).unwrap();
        assert_eq!(after.status, SkillStatus::Inactive);

        // Now backdate it past purge_after and re-sweep.
        let mut after = after;
        after.last_seen_at = now_secs().saturating_sub(200);
        store
            .put(
                CF_SKILLS,
                after.skill_id.as_bytes(),
                &serde_json::to_vec(&after).unwrap(),
            )
            .unwrap();
        let stats2 = run_sweep(&store, &cfg, None).unwrap();
        assert_eq!(stats2.skills_purged, 1);
        assert!(
            store
                .get(CF_SKILLS, after.skill_id.as_bytes())
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn sweeper_leaves_fresh_skill_alone() {
        let store = fresh_store();
        let cfg = fast_config();
        let skill = SkillDefinition::new(
            "fresh".to_string(),
            "1.0.0".to_string(),
            "did:tenzro:human:foo".to_string(),
            "alive".to_string(),
            0,
        );
        store
            .put(
                CF_SKILLS,
                skill.skill_id.as_bytes(),
                &serde_json::to_vec(&skill).unwrap(),
            )
            .unwrap();

        let stats = run_sweep(&store, &cfg, None).unwrap();
        assert_eq!(stats.total_changes(), 0);
    }

    #[test]
    fn sweeper_exempts_system_builtin_skills_and_tools() {
        let store = fresh_store();
        let cfg = fast_config();

        let mut skill = SkillDefinition::new(
            "web-search".to_string(),
            "1.0.0".to_string(),
            tenzro_types::SYSTEM_CREATOR_DID.to_string(),
            "builtin".to_string(),
            0,
        );
        skill.last_seen_at = now_secs().saturating_sub(500); // way past purge
        store
            .put(
                CF_SKILLS,
                skill.skill_id.as_bytes(),
                &serde_json::to_vec(&skill).unwrap(),
            )
            .unwrap();

        let mut tool = ToolDefinition::new(
            "code-executor".to_string(),
            "1.0.0".to_string(),
            tenzro_types::ToolTransportMode::Mcp,
            "builtin://code-executor".to_string(),
            "builtin".to_string(),
            "code".to_string(),
        );
        tool.creator_did = Some(tenzro_types::SYSTEM_CREATOR_DID.to_string());
        tool.last_seen_at = now_secs().saturating_sub(500);
        store
            .put(
                CF_TOOLS,
                tool.tool_id.as_bytes(),
                &serde_json::to_vec(&tool).unwrap(),
            )
            .unwrap();

        let stats = run_sweep(&store, &cfg, None).unwrap();
        assert_eq!(stats.skills_marked_inactive, 0);
        assert_eq!(stats.skills_purged, 0);
        assert_eq!(stats.tools_marked_inactive, 0);
        assert_eq!(stats.tools_purged, 0);

        let after: SkillDefinition = serde_json::from_slice(
            &store
                .get(CF_SKILLS, skill.skill_id.as_bytes())
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(after.status, SkillStatus::Active);
        let after_tool: ToolDefinition = serde_json::from_slice(
            &store
                .get(CF_TOOLS, tool.tool_id.as_bytes())
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(after_tool.status, ToolStatus::Active);
    }

    #[test]
    fn sweeper_marks_silent_tool_inactive() {
        let store = fresh_store();
        let cfg = fast_config();
        let mut tool = ToolDefinition::new(
            "old-mcp".to_string(),
            "1.0.0".to_string(),
            tenzro_types::ToolTransportMode::Mcp,
            "http://nope".to_string(),
            "gone".to_string(),
            "search".to_string(),
        );
        tool.last_seen_at = now_secs().saturating_sub(50);
        store
            .put(
                CF_TOOLS,
                tool.tool_id.as_bytes(),
                &serde_json::to_vec(&tool).unwrap(),
            )
            .unwrap();

        let stats = run_sweep(&store, &cfg, None).unwrap();
        assert_eq!(stats.tools_marked_inactive, 1);

        let stored = store
            .get(CF_TOOLS, tool.tool_id.as_bytes())
            .unwrap()
            .unwrap();
        let after: ToolDefinition = serde_json::from_slice(&stored).unwrap();
        assert_eq!(after.status, ToolStatus::Inactive);
    }

    #[test]
    fn sweeper_expires_open_task_past_deadline() {
        use tenzro_storage::kv::CF_TASKS;
        use tenzro_types::primitives::{Address, Timestamp};
        use tenzro_types::task::{TaskInfo, TaskStatus, TaskType};

        let store = fresh_store();
        let cfg = fast_config();

        let mut task = TaskInfo::new(
            "test".to_string(),
            "test".to_string(),
            TaskType::Inference,
            Address::zero(),
            0,
            "input".to_string(),
        );
        task.deadline = Some(now_secs().saturating_sub(60)); // past
        let key = format!("task:{}", task.task_id);
        store
            .put(
                CF_TASKS,
                key.as_bytes(),
                &serde_json::to_vec(&task).unwrap(),
            )
            .unwrap();

        let stats = run_sweep(&store, &cfg, None).unwrap();
        assert_eq!(stats.tasks_marked_expired, 1);
        let after: TaskInfo =
            serde_json::from_slice(&store.get(CF_TASKS, key.as_bytes()).unwrap().unwrap()).unwrap();
        assert_eq!(after.status, TaskStatus::Expired);
        let _ = Timestamp::default();
    }

    #[test]
    fn sweeper_purges_terminal_task_after_window() {
        use tenzro_storage::kv::CF_TASKS;
        use tenzro_types::primitives::{Address, Timestamp};
        use tenzro_types::task::{TaskInfo, TaskStatus, TaskType};

        let store = fresh_store();
        let cfg = fast_config();

        let mut task = TaskInfo::new(
            "old-completed".to_string(),
            "x".to_string(),
            TaskType::Inference,
            Address::zero(),
            0,
            "i".to_string(),
        );
        task.status = TaskStatus::Completed;
        // Backdate created_at past the purge window.
        task.created_at = Timestamp((now_secs().saturating_sub(200)) as i64);
        let key = format!("task:{}", task.task_id);
        store
            .put(
                CF_TASKS,
                key.as_bytes(),
                &serde_json::to_vec(&task).unwrap(),
            )
            .unwrap();

        let stats = run_sweep(&store, &cfg, None).unwrap();
        assert_eq!(stats.tasks_purged, 1);
        assert!(store.get(CF_TASKS, key.as_bytes()).unwrap().is_none());
    }
}
