//! Task Manager — A2A 1.0 task state.
//!
//! Wire shapes follow the A2A 1.0 JSON-RPC binding: enum values are the
//! protocol-buffer names (`TASK_STATE_COMPLETED`, `ROLE_USER`), a part is one
//! of `text` / `raw` / `url` / `data`, and timestamps are RFC 3339.
//!
//! Every task records the DID that opened it. Only that DID may read,
//! continue or cancel it; the DID comes from the verified request envelope,
//! never from the request body.
//!
//! A manager bound to a store writes every task through and takes the tasks
//! back when the node starts.
//!
//! Tasks do not accumulate without end ([`TaskLimits`]): a finished task is
//! kept for a retention period and then removed, a task waiting for its
//! sender's input is failed when the input does not arrive by a deadline,
//! and one sender, and all senders together, hold at most a set number of
//! tasks. A sender at its limit makes room by giving up its oldest finished
//! task; when every task it holds is still open, a new one is refused.

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tenzro_storage::KvStore;

/// Task states of the A2A 1.0 `TaskState` enum that this agent reaches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TaskState {
    #[serde(rename = "TASK_STATE_SUBMITTED")]
    Submitted,
    #[serde(rename = "TASK_STATE_WORKING")]
    Working,
    #[serde(rename = "TASK_STATE_INPUT_REQUIRED")]
    InputRequired,
    #[serde(rename = "TASK_STATE_COMPLETED")]
    Completed,
    #[serde(rename = "TASK_STATE_FAILED")]
    Failed,
    #[serde(rename = "TASK_STATE_CANCELED")]
    Canceled,
}

impl TaskState {
    /// Completed, failed and canceled tasks accept no further messages and
    /// cannot be canceled.
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Failed | Self::Canceled)
    }
}

/// Message author.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Role {
    #[serde(rename = "ROLE_USER")]
    User,
    #[serde(rename = "ROLE_AGENT")]
    Agent,
}

/// One unit of message content: exactly one of `text`, `raw` (base64),
/// `url` or `data` (any JSON value).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MessagePart {
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub raw: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub data: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub media_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub filename: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub metadata: Option<serde_json::Value>,
}

impl MessagePart {
    pub fn text(content: impl Into<String>) -> Self {
        Self {
            text: Some(content.into()),
            raw: None,
            url: None,
            data: None,
            media_type: None,
            filename: None,
            metadata: None,
        }
    }

    pub fn data(content: serde_json::Value) -> Self {
        Self {
            text: None,
            raw: None,
            url: None,
            data: Some(content),
            media_type: Some("application/json".to_string()),
            filename: None,
            metadata: None,
        }
    }

    /// A part must carry exactly one content field.
    pub fn content_count(&self) -> usize {
        [
            self.text.is_some(),
            self.raw.is_some(),
            self.url.is_some(),
            self.data.is_some(),
        ]
        .into_iter()
        .filter(|present| *present)
        .count()
    }
}

/// A message in a task conversation
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TaskMessage {
    pub message_id: String,
    pub role: Role,
    pub parts: Vec<MessagePart>,
}

impl TaskMessage {
    /// An agent-authored message with a fresh id.
    pub fn agent(parts: Vec<MessagePart>) -> Self {
        Self {
            message_id: uuid::Uuid::new_v4().to_string(),
            role: Role::Agent,
            parts,
        }
    }
}

/// An artifact produced by task execution
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TaskArtifact {
    pub artifact_id: String,
    pub name: String,
    pub parts: Vec<MessagePart>,
}

/// Task status information
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TaskStatus {
    pub state: TaskState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<TaskMessage>,
    /// RFC 3339 time of the last transition.
    pub timestamp: String,
}

/// A2A Task — the core work unit
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct A2aTask {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context_id: Option<String>,
    pub status: TaskStatus,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub history: Vec<TaskMessage>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub artifacts: Vec<TaskArtifact>,
    /// Additional metadata. Values are arbitrary JSON to allow structured payloads
    /// (e.g. x402 payment requirements / receipts under reserved `x402.*` keys).
    /// See [`crate::a2a::x402_extension`] for the typed accessors.
    #[serde(skip_serializing_if = "std::collections::HashMap::is_empty", default)]
    pub metadata: std::collections::HashMap<String, serde_json::Value>,
    /// DID that opened the task, from its verified envelope. Not part of the
    /// wire shape.
    #[serde(skip)]
    pub principal: String,
}

/// How many tasks this node keeps, and for how long: the `[a2a_tasks]`
/// section of the node's configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TaskLimits {
    /// Seconds a completed, failed or canceled task is kept before it is
    /// removed. From one minute to 30 days.
    pub retention_secs: u64,
    /// Seconds a task may wait for its sender's input (a payment, a missing
    /// part) before it is failed. From one minute to 7 days.
    pub input_deadline_secs: u64,
    /// Most tasks one sender DID holds at a time. From 1 to 100,000, and no
    /// more than `max_total`.
    pub max_per_principal: usize,
    /// Most tasks the node holds at a time. From 1 to 1,000,000.
    pub max_total: usize,
    /// Most messages one task's history holds, the sender's and the node's
    /// together. From 2 to 10,000.
    pub max_history: usize,
    /// Most bytes one task's artifacts hold together, as JSON. From 1 KiB to
    /// 64 MiB.
    pub max_artifact_bytes: u64,
}

impl Default for TaskLimits {
    fn default() -> Self {
        Self {
            retention_secs: 24 * 3600,
            input_deadline_secs: 3600,
            max_per_principal: 256,
            max_total: 16_384,
            max_history: 200,
            max_artifact_bytes: 1 << 20,
        }
    }
}

impl TaskLimits {
    /// Refuse a value outside its bounds, naming the field.
    pub fn validate(&self) -> Result<(), String> {
        let within = |name: &str, value: u64, low: u64, high: u64| {
            if (low..=high).contains(&value) {
                Ok(())
            } else {
                Err(format!(
                    "{name} is {value}; it must be from {low} to {high}"
                ))
            }
        };
        within("retention_secs", self.retention_secs, 60, 30 * 24 * 3600)?;
        within(
            "input_deadline_secs",
            self.input_deadline_secs,
            60,
            7 * 24 * 3600,
        )?;
        within(
            "max_per_principal",
            self.max_per_principal as u64,
            1,
            100_000,
        )?;
        within("max_total", self.max_total as u64, 1, 1_000_000)?;
        within("max_history", self.max_history as u64, 2, 10_000)?;
        within(
            "max_artifact_bytes",
            self.max_artifact_bytes,
            1 << 10,
            64 << 20,
        )?;
        if self.max_per_principal > self.max_total {
            return Err(format!(
                "max_per_principal is {} and max_total is {}; one sender cannot hold more than the node",
                self.max_per_principal, self.max_total
            ));
        }
        Ok(())
    }
}

/// Why a new task was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CreateError {
    /// The sender holds this many tasks and every one is still open.
    PrincipalFull(usize),
    /// The node holds this many tasks and every one is still open.
    NodeFull(usize),
}

impl std::fmt::Display for CreateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PrincipalFull(n) => write!(
                f,
                "this sender already holds {n} open tasks, the most this node keeps for one \
                 sender; finish or cancel one first"
            ),
            Self::NodeFull(n) => write!(
                f,
                "this node already holds {n} open tasks, the most it keeps; try again later"
            ),
        }
    }
}

/// Why an artifact was not added to a task.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArtifactError {
    NotFound,
    /// The task's artifacts would hold `would_hold` bytes, over `max`.
    TooLarge {
        would_hold: u64,
        max: u64,
    },
}

/// Why a cancel was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CancelError {
    NotFound,
    NotCancelable,
    NotOwner,
}

fn rfc3339(at: chrono::DateTime<chrono::Utc>) -> String {
    at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

fn now_rfc3339() -> String {
    rfc3339(chrono::Utc::now())
}

/// Seconds since `task` last changed state, as of `now`. A timestamp that
/// cannot be read counts as just now, so such a task is never aged out by
/// mistake.
fn age_secs(task: &A2aTask, now: chrono::DateTime<chrono::Utc>) -> u64 {
    chrono::DateTime::parse_from_rfc3339(&task.status.timestamp)
        .map(|at| (now - at.with_timezone(&chrono::Utc)).num_seconds().max(0) as u64)
        .unwrap_or(0)
}

/// Key prefix of a stored task in the node's metadata column family.
const TASK_KEY_PREFIX: &str = "a2a_task:";

/// A task as stored: the wire shape plus the DID that opened it.
#[derive(Serialize, Deserialize)]
struct StoredTask {
    principal: String,
    task: A2aTask,
}

/// Manages A2A task lifecycle
pub struct TaskManager {
    tasks: Arc<DashMap<String, A2aTask>>,
    store: Option<Arc<dyn KvStore>>,
    limits: TaskLimits,
    /// Held while a task is admitted, so two senders cannot both take the
    /// last place.
    admitting: parking_lot::Mutex<()>,
    /// Unix seconds of the last sweep a read ran.
    swept_at: std::sync::atomic::AtomicI64,
}

impl Default for TaskManager {
    fn default() -> Self {
        Self::new()
    }
}

impl TaskManager {
    pub fn new() -> Self {
        Self::with_limits(TaskLimits::default())
    }

    /// A manager that keeps its tasks in memory under `limits`.
    pub fn with_limits(limits: TaskLimits) -> Self {
        Self {
            tasks: Arc::new(DashMap::new()),
            store: None,
            limits,
            admitting: parking_lot::Mutex::new(()),
            swept_at: std::sync::atomic::AtomicI64::new(0),
        }
    }

    /// A manager that keeps its tasks in `store`, starting from the tasks a
    /// previous run left there. A task that run left unfinished has nothing
    /// running it any more, so it is failed; one waiting for the caller's
    /// input stays open. An entry that cannot be read is deleted.
    pub fn with_storage(store: Arc<dyn KvStore>, limits: TaskLimits) -> Self {
        let stored = store
            .scan_prefix(tenzro_storage::CF_METADATA, TASK_KEY_PREFIX.as_bytes())
            .unwrap_or_else(|e| {
                tracing::warn!(target: "a2a", error = %e, "stored tasks could not be read");
                Vec::new()
            });
        let mgr = Self {
            store: Some(store.clone()),
            ..Self::with_limits(limits)
        };
        for (key, value) in stored {
            let Ok(StoredTask {
                principal,
                mut task,
            }) = serde_json::from_slice(&value)
            else {
                tracing::warn!(target: "a2a", "unreadable stored task deleted");
                if let Err(e) = store.delete(tenzro_storage::CF_METADATA, &key) {
                    tracing::warn!(
                        target: "a2a",
                        key = %String::from_utf8_lossy(&key),
                        error = %e,
                        "unreadable stored task not removed from the store"
                    );
                }
                continue;
            };
            task.principal = principal;
            if matches!(task.status.state, TaskState::Submitted | TaskState::Working) {
                let message = TaskMessage::agent(vec![MessagePart::text(
                    "the node restarted before the task finished",
                )]);
                task.history.push(message.clone());
                task.status = TaskStatus {
                    state: TaskState::Failed,
                    message: Some(message),
                    timestamp: now_rfc3339(),
                };
                mgr.persist(&task);
            }
            mgr.tasks.insert(task.id.clone(), task);
        }
        // What aged out while the node was down goes before anything is served.
        mgr.sweep(chrono::Utc::now());
        mgr
    }

    /// Removes `task_id` from the table and from the store.
    fn remove(&self, task_id: &str) {
        self.tasks.remove(task_id);
        if let Some(store) = &self.store {
            let key = format!("{TASK_KEY_PREFIX}{task_id}");
            if let Err(e) = store.delete(tenzro_storage::CF_METADATA, key.as_bytes()) {
                tracing::warn!(target: "a2a", task = %task_id, error = %e, "task not removed from the store");
            }
        }
    }

    /// Applies the time limits as of `now`: a finished task past its
    /// retention is removed, and a task that has waited for input past the
    /// deadline is failed (and then kept for the retention like any other
    /// finished task).
    pub fn sweep(&self, now: chrono::DateTime<chrono::Utc>) {
        let mut expired = Vec::new();
        let mut overdue = Vec::new();
        for entry in self.tasks.iter() {
            let task = entry.value();
            let age = age_secs(task, now);
            if task.status.state.is_terminal() {
                if age > self.limits.retention_secs {
                    expired.push(task.id.clone());
                }
            } else if task.status.state == TaskState::InputRequired
                && age > self.limits.input_deadline_secs
            {
                overdue.push(task.id.clone());
            }
        }
        for id in expired {
            self.remove(&id);
        }
        for id in overdue {
            let message = TaskMessage::agent(vec![MessagePart::text(
                "no input arrived before the deadline",
            )]);
            let failed = self.tasks.get_mut(&id).and_then(|mut entry| {
                // Checked again under the entry: the input may have just arrived.
                if entry.status.state != TaskState::InputRequired {
                    return None;
                }
                entry.history.push(message.clone());
                entry.status = TaskStatus {
                    state: TaskState::Failed,
                    message: Some(message),
                    timestamp: rfc3339(now),
                };
                Some(entry.clone())
            });
            if let Some(task) = failed {
                self.persist(&task);
            }
        }
        self.swept_at
            .store(now.timestamp(), std::sync::atomic::Ordering::Relaxed);
    }

    /// [`TaskManager::sweep`] at most once a second, for the read paths.
    fn sweep_if_due(&self) {
        let now = chrono::Utc::now();
        if now.timestamp() != self.swept_at.load(std::sync::atomic::Ordering::Relaxed) {
            self.sweep(now);
        }
    }

    /// The oldest finished task among those `keep` selects, if any.
    fn oldest_finished(&self, keep: impl Fn(&A2aTask) -> bool) -> Option<String> {
        self.tasks
            .iter()
            .filter(|e| e.value().status.state.is_terminal() && keep(e.value()))
            .min_by(|a, b| {
                (a.value().status.timestamp.as_str(), a.value().id.as_str())
                    .cmp(&(b.value().status.timestamp.as_str(), b.value().id.as_str()))
            })
            .map(|e| e.value().id.clone())
    }

    /// Writes `task` to the store, when there is one.
    fn persist(&self, task: &A2aTask) {
        let Some(store) = &self.store else {
            return;
        };
        let key = format!("{TASK_KEY_PREFIX}{}", task.id);
        let stored = StoredTask {
            principal: task.principal.clone(),
            task: task.clone(),
        };
        match serde_json::to_vec(&stored) {
            Ok(bytes) => {
                if let Err(e) = store.put(tenzro_storage::CF_METADATA, key.as_bytes(), &bytes) {
                    tracing::warn!(target: "a2a", task = %task.id, error = %e, "task not stored");
                }
            }
            Err(e) => {
                tracing::warn!(target: "a2a", task = %task.id, error = %e, "task not encoded");
            }
        }
    }

    /// Open a task for `principal` from its first message. A sender, or the
    /// node, at its limit gives up its oldest finished task to make room;
    /// when every task it holds is still open the new one is refused.
    pub fn create_task(
        &self,
        task_id: String,
        context_id: Option<String>,
        message: TaskMessage,
        metadata: std::collections::HashMap<String, serde_json::Value>,
        principal: &str,
    ) -> Result<A2aTask, CreateError> {
        let _admitting = self.admitting.lock();
        self.sweep(chrono::Utc::now());
        let held = self
            .tasks
            .iter()
            .filter(|e| e.value().principal == principal)
            .count();
        if held >= self.limits.max_per_principal {
            match self.oldest_finished(|t| t.principal == principal) {
                Some(id) => self.remove(&id),
                None => return Err(CreateError::PrincipalFull(held)),
            }
        }
        if self.tasks.len() >= self.limits.max_total {
            match self.oldest_finished(|_| true) {
                Some(id) => self.remove(&id),
                None => return Err(CreateError::NodeFull(self.tasks.len())),
            }
        }
        let task = A2aTask {
            id: task_id.clone(),
            context_id,
            status: TaskStatus {
                state: TaskState::Submitted,
                message: None,
                timestamp: now_rfc3339(),
            },
            history: vec![message],
            artifacts: Vec::new(),
            metadata,
            principal: principal.to_string(),
        };
        self.persist(&task);
        self.tasks.insert(task_id, task.clone());
        Ok(task)
    }

    /// Get a task by ID, whoever opened it. For the node's own use: a
    /// caller's read goes through [`TaskManager::task_of`].
    pub fn get_task(&self, task_id: &str) -> Option<A2aTask> {
        self.tasks.get(task_id).map(|t| t.clone())
    }

    /// The task with `task_id` when `principal` opened it. Another DID's
    /// task is `None`, the same as one that does not exist.
    pub fn task_of(&self, task_id: &str, principal: &str) -> Option<A2aTask> {
        self.sweep_if_due();
        self.get_task(task_id).filter(|t| t.principal == principal)
    }

    /// The tasks `principal` opened that match the optional context and
    /// state filters, ordered by id so pagination is stable.
    pub fn list_tasks(
        &self,
        principal: &str,
        context_id: Option<&str>,
        state: Option<TaskState>,
    ) -> Vec<A2aTask> {
        self.sweep_if_due();
        let mut tasks: Vec<A2aTask> = self
            .tasks
            .iter()
            .filter(|entry| {
                let t = entry.value();
                t.principal == principal
                    && context_id.is_none_or(|cid| t.context_id.as_deref() == Some(cid))
                    && state.is_none_or(|s| t.status.state == s)
            })
            .map(|entry| entry.value().clone())
            .collect();
        tasks.sort_by(|a, b| a.id.cmp(&b.id));
        tasks
    }

    /// Update task state
    pub fn update_status(
        &self,
        task_id: &str,
        state: TaskState,
        message: Option<TaskMessage>,
    ) -> Option<A2aTask> {
        let mut entry = self.tasks.get_mut(task_id)?;
        // A final state is final: a run that ends after its task was canceled
        // does not bring it back.
        if entry.status.state.is_terminal() {
            return Some(entry.clone());
        }
        entry.status = TaskStatus {
            state,
            message: message.clone(),
            timestamp: now_rfc3339(),
        };
        if let Some(msg) = message {
            entry.history.push(msg);
        }
        let task = entry.clone();
        drop(entry);
        self.persist(&task);
        Some(task)
    }

    /// Add an artifact to a task, unless the task's artifacts would then
    /// hold more bytes than one task may. A task in a final state keeps the
    /// artifacts it had: a run that ends after its task was canceled adds
    /// nothing to it.
    pub fn add_artifact(
        &self,
        task_id: &str,
        artifact: TaskArtifact,
    ) -> Result<A2aTask, ArtifactError> {
        let size = |a: &TaskArtifact| serde_json::to_vec(a).map_or(0, |b| b.len() as u64);
        let mut entry = self.tasks.get_mut(task_id).ok_or(ArtifactError::NotFound)?;
        if entry.status.state.is_terminal() {
            return Ok(entry.clone());
        }
        let would_hold = entry.artifacts.iter().map(size).sum::<u64>() + size(&artifact);
        if would_hold > self.limits.max_artifact_bytes {
            return Err(ArtifactError::TooLarge {
                would_hold,
                max: self.limits.max_artifact_bytes,
            });
        }
        entry.artifacts.push(artifact);
        let task = entry.clone();
        drop(entry);
        self.persist(&task);
        Ok(task)
    }

    /// Whether `task` has room for one more turn: the sender's message and
    /// the node's answer to it.
    pub fn room_for_turn(&self, task: &A2aTask) -> bool {
        task.history.len() + 2 <= self.limits.max_history
    }

    /// Most messages one task's history holds.
    pub fn max_history(&self) -> usize {
        self.limits.max_history
    }

    /// Mutate the task's metadata via a closure. Used by the x402
    /// dispatcher to merge `x402.payment.*` keys without disturbing
    /// other caller-supplied entries.
    pub fn update_metadata<F>(&self, task_id: &str, f: F) -> Option<A2aTask>
    where
        F: FnOnce(&mut std::collections::HashMap<String, serde_json::Value>),
    {
        let mut entry = self.tasks.get_mut(task_id)?;
        f(&mut entry.metadata);
        let task = entry.clone();
        drop(entry);
        self.persist(&task);
        Some(task)
    }

    /// Cancel a task on behalf of `principal`. Only the DID that opened the
    /// task may cancel it, and a terminal task cannot be canceled.
    pub fn cancel_task(&self, task_id: &str, principal: &str) -> Result<A2aTask, CancelError> {
        {
            let entry = self.tasks.get(task_id).ok_or(CancelError::NotFound)?;
            if entry.principal != principal {
                return Err(CancelError::NotOwner);
            }
            if entry.status.state.is_terminal() {
                return Err(CancelError::NotCancelable);
            }
        }
        self.update_status(
            task_id,
            TaskState::Canceled,
            Some(TaskMessage::agent(vec![MessagePart::text("Task canceled")])),
        )
        .ok_or(CancelError::NotFound)
    }

    /// Count total tasks
    pub fn task_count(&self) -> usize {
        self.tasks.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALICE: &str = "did:tenzro:human:alice";
    const MALLORY: &str = "did:tenzro:human:mallory";

    fn user(text: &str) -> TaskMessage {
        TaskMessage {
            message_id: uuid::Uuid::new_v4().to_string(),
            role: Role::User,
            parts: vec![MessagePart::text(text)],
        }
    }

    fn open(mgr: &TaskManager, id: &str, ctx: Option<&str>) -> A2aTask {
        mgr.create_task(
            id.to_string(),
            ctx.map(str::to_string),
            user("hello"),
            Default::default(),
            ALICE,
        )
        .expect("room")
    }

    #[test]
    fn a_restarted_manager_keeps_its_tasks() {
        let store: Arc<dyn KvStore> = Arc::new(tenzro_storage::MemoryStore::new());
        {
            let mgr = TaskManager::with_storage(store.clone(), TaskLimits::default());
            open(&mgr, "done", Some("ctx"));
            mgr.update_metadata("done", |md| {
                md.insert("k".to_string(), serde_json::json!({"v": 1}));
            });
            mgr.add_artifact(
                "done",
                TaskArtifact {
                    artifact_id: "a1".to_string(),
                    name: "response".to_string(),
                    parts: vec![MessagePart::text("answer")],
                },
            )
            .unwrap();
            mgr.update_status("done", TaskState::Completed, None);
            open(&mgr, "waiting", None);
            mgr.update_status("waiting", TaskState::InputRequired, None);
        }

        let mgr = TaskManager::with_storage(store, TaskLimits::default());
        assert_eq!(mgr.task_count(), 2);
        let done = mgr.get_task("done").unwrap();
        assert_eq!(done.status.state, TaskState::Completed);
        assert_eq!(done.context_id.as_deref(), Some("ctx"));
        assert_eq!(done.principal, ALICE);
        // A task taken back from the store is still read by its owner alone.
        assert!(mgr.task_of("done", ALICE).is_some());
        assert!(mgr.task_of("done", MALLORY).is_none());
        assert!(mgr.list_tasks(MALLORY, None, None).is_empty());
        assert_eq!(done.history.len(), 1);
        assert_eq!(done.artifacts.len(), 1);
        assert_eq!(done.metadata["k"], serde_json::json!({"v": 1}));
        // The owner check still holds on a task taken back from the store.
        assert_eq!(
            mgr.cancel_task("waiting", MALLORY).unwrap_err(),
            CancelError::NotOwner
        );
        assert_eq!(
            mgr.cancel_task("waiting", ALICE).unwrap().status.state,
            TaskState::Canceled
        );
    }

    #[test]
    fn a_task_left_running_is_failed_on_restart() {
        let store: Arc<dyn KvStore> = Arc::new(tenzro_storage::MemoryStore::new());
        {
            let mgr = TaskManager::with_storage(store.clone(), TaskLimits::default());
            open(&mgr, "t1", None);
            mgr.update_status("t1", TaskState::Working, None);
        }
        // Both restarts see the task failed: the failure is itself stored.
        for _ in 0..2 {
            let mgr = TaskManager::with_storage(store.clone(), TaskLimits::default());
            let task = mgr.get_task("t1").unwrap();
            assert_eq!(task.status.state, TaskState::Failed);
            assert_eq!(task.history.len(), 2);
            assert_eq!(task.history[1].role, Role::Agent);
        }
    }

    #[test]
    fn an_unreadable_stored_task_is_deleted() {
        let store: Arc<dyn KvStore> = Arc::new(tenzro_storage::MemoryStore::new());
        let key = format!("{TASK_KEY_PREFIX}bad");
        store
            .put(tenzro_storage::CF_METADATA, key.as_bytes(), b"not a task")
            .unwrap();
        let mgr = TaskManager::with_storage(store.clone(), TaskLimits::default());
        assert_eq!(mgr.task_count(), 0);
        assert!(
            !store
                .contains(tenzro_storage::CF_METADATA, key.as_bytes())
                .unwrap()
        );
    }

    #[test]
    fn task_lifecycle() {
        let mgr = TaskManager::new();
        let task = open(&mgr, "task-1", None);
        assert_eq!(task.status.state, TaskState::Submitted);
        let task = mgr
            .update_status("task-1", TaskState::Working, None)
            .unwrap();
        assert_eq!(task.status.state, TaskState::Working);
        let task = mgr
            .update_status(
                "task-1",
                TaskState::Completed,
                Some(TaskMessage::agent(vec![MessagePart::text("done")])),
            )
            .unwrap();
        assert_eq!(task.status.state, TaskState::Completed);
        assert_eq!(task.history.len(), 2);
    }

    #[test]
    fn owner_cancels_a_running_task() {
        let mgr = TaskManager::new();
        open(&mgr, "task-2", None);
        mgr.update_status("task-2", TaskState::Working, None);
        let task = mgr.cancel_task("task-2", ALICE).unwrap();
        assert_eq!(task.status.state, TaskState::Canceled);
    }

    #[test]
    fn another_did_cannot_cancel_the_task() {
        let mgr = TaskManager::new();
        open(&mgr, "task-3", None);
        assert_eq!(
            mgr.cancel_task("task-3", MALLORY).unwrap_err(),
            CancelError::NotOwner
        );
        assert_eq!(
            mgr.get_task("task-3").unwrap().status.state,
            TaskState::Submitted
        );
    }

    #[test]
    fn terminal_task_is_not_cancelable() {
        let mgr = TaskManager::new();
        open(&mgr, "task-4", None);
        mgr.update_status("task-4", TaskState::Completed, None);
        assert_eq!(
            mgr.cancel_task("task-4", ALICE).unwrap_err(),
            CancelError::NotCancelable
        );
        assert_eq!(
            mgr.cancel_task("missing", ALICE).unwrap_err(),
            CancelError::NotFound
        );
    }

    /// A run that ends after its task was canceled leaves it canceled, and
    /// no later update moves a task out of a final state.
    #[test]
    fn a_canceled_task_stays_canceled_when_its_run_ends() {
        let mgr = TaskManager::new();
        open(&mgr, "task-5", None);
        mgr.update_status("task-5", TaskState::Working, None);
        mgr.cancel_task("task-5", ALICE).unwrap();
        mgr.add_artifact(
            "task-5",
            TaskArtifact {
                artifact_id: "late".to_string(),
                name: "response".to_string(),
                parts: vec![MessagePart::text("late answer")],
            },
        )
        .unwrap();
        let after = mgr
            .update_status(
                "task-5",
                TaskState::Completed,
                Some(TaskMessage::agent(vec![MessagePart::text("late answer")])),
            )
            .unwrap();
        assert_eq!(after.status.state, TaskState::Canceled);
        assert_eq!(
            mgr.get_task("task-5").unwrap().status.state,
            TaskState::Canceled
        );
        let late = |m: &TaskMessage| {
            m.parts
                .iter()
                .any(|p| p.text.as_deref() == Some("late answer"))
        };
        assert!(!after.history.iter().any(late), "the late answer was kept");
        assert!(after.artifacts.is_empty(), "the late artifact was kept");

        open(&mgr, "task-6", None);
        mgr.update_status("task-6", TaskState::Failed, None);
        mgr.update_status("task-6", TaskState::Completed, None);
        assert_eq!(
            mgr.get_task("task-6").unwrap().status.state,
            TaskState::Failed
        );
    }

    #[test]
    fn list_filters_by_context_and_state() {
        let mgr = TaskManager::new();
        open(&mgr, "t1", Some("ctx-a"));
        open(&mgr, "t2", Some("ctx-a"));
        open(&mgr, "t3", Some("ctx-b"));
        mgr.update_status("t2", TaskState::Completed, None);
        assert_eq!(mgr.list_tasks(ALICE, Some("ctx-a"), None).len(), 2);
        assert_eq!(mgr.list_tasks(ALICE, None, None).len(), 3);
        let done = mgr.list_tasks(ALICE, None, Some(TaskState::Completed));
        assert_eq!(done.len(), 1);
        assert_eq!(done[0].id, "t2");
    }

    fn limits(per_principal: usize, total: usize) -> TaskLimits {
        TaskLimits {
            max_per_principal: per_principal,
            max_total: total,
            ..TaskLimits::default()
        }
    }

    fn open_as(mgr: &TaskManager, id: &str, who: &str) -> Result<A2aTask, CreateError> {
        mgr.create_task(id.to_string(), None, user("hello"), Default::default(), who)
    }

    /// Sets when `id` last changed state, as if that long ago.
    fn age(mgr: &TaskManager, id: &str, secs: i64) {
        let mut entry = mgr.tasks.get_mut(id).unwrap();
        entry.status.timestamp = rfc3339(chrono::Utc::now() - chrono::Duration::seconds(secs));
        mgr.persist(&entry);
    }

    #[test]
    fn limits_are_held_to_their_bounds() {
        assert_eq!(TaskLimits::default().validate(), Ok(()));
        let bad = |edit: fn(&mut TaskLimits)| {
            let mut l = TaskLimits::default();
            edit(&mut l);
            l.validate().unwrap_err()
        };
        assert!(bad(|l| l.retention_secs = 59).contains("retention_secs"));
        assert!(bad(|l| l.retention_secs = 30 * 24 * 3600 + 1).contains("retention_secs"));
        assert!(bad(|l| l.input_deadline_secs = 0).contains("input_deadline_secs"));
        assert!(bad(|l| l.input_deadline_secs = 7 * 24 * 3600 + 1).contains("input_deadline_secs"));
        assert!(bad(|l| l.max_per_principal = 0).contains("max_per_principal"));
        assert!(bad(|l| l.max_total = 0).contains("max_total"));
        assert!(bad(|l| l.max_total = 1_000_001).contains("max_total"));
        assert!(bad(|l| l.max_history = 1).contains("max_history"));
        assert!(bad(|l| l.max_history = 10_001).contains("max_history"));
        assert!(bad(|l| l.max_artifact_bytes = 1023).contains("max_artifact_bytes"));
        assert!(bad(|l| l.max_artifact_bytes = (64 << 20) + 1).contains("max_artifact_bytes"));
        assert!(bad(|l| l.max_per_principal = l.max_total + 1).contains("cannot hold more"));
        // The section reads from configuration, and an unknown key is an error.
        let parsed: TaskLimits = serde_json::from_value(serde_json::json!({
            "retention_secs": 600, "max_total": 10, "max_per_principal": 2
        }))
        .unwrap();
        assert_eq!(
            (parsed.retention_secs, parsed.input_deadline_secs),
            (600, 3600)
        );
        assert!(serde_json::from_value::<TaskLimits>(serde_json::json!({"retain": 1})).is_err());
    }

    #[test]
    fn one_task_holds_a_bounded_history_and_bounded_artifact_bytes() {
        let mgr = TaskManager::with_limits(TaskLimits {
            max_history: 4,
            max_artifact_bytes: 2048,
            ..TaskLimits::default()
        });
        let task = open(&mgr, "t", None);
        assert!(mgr.room_for_turn(&task), "1 message held, 2 more fit in 4");
        mgr.update_status("t", TaskState::Working, Some(user("again")));
        let task = mgr
            .update_status("t", TaskState::InputRequired, Some(user("more")))
            .unwrap();
        assert_eq!(task.history.len(), 3);
        assert!(
            !mgr.room_for_turn(&task),
            "a turn adds two and only one fits"
        );

        let artifact = |bytes: usize| TaskArtifact {
            artifact_id: "a".to_string(),
            name: "response".to_string(),
            parts: vec![MessagePart::text("x".repeat(bytes))],
        };
        assert_eq!(
            mgr.add_artifact("t", artifact(500))
                .unwrap()
                .artifacts
                .len(),
            1
        );
        assert_eq!(
            mgr.add_artifact("t", artifact(500))
                .unwrap()
                .artifacts
                .len(),
            2
        );
        match mgr.add_artifact("t", artifact(1500)) {
            Err(ArtifactError::TooLarge { would_hold, max }) => {
                assert!(would_hold > 2048 && max == 2048, "{would_hold} of {max}");
            }
            other => panic!("an artifact over the bound was kept: {other:?}"),
        }
        assert_eq!(
            mgr.get_task("t").unwrap().artifacts.len(),
            2,
            "nothing was added"
        );
        assert_eq!(
            mgr.add_artifact("missing", artifact(1)).unwrap_err(),
            ArtifactError::NotFound
        );
    }

    #[test]
    fn a_finished_task_is_removed_after_its_retention_and_an_open_one_is_not() {
        let store: Arc<dyn KvStore> = Arc::new(tenzro_storage::MemoryStore::new());
        let mgr = TaskManager::with_storage(store.clone(), TaskLimits::default());
        open(&mgr, "done", None);
        mgr.update_status("done", TaskState::Completed, None);
        open(&mgr, "fresh", None);
        mgr.update_status("fresh", TaskState::Canceled, None);
        open(&mgr, "running", None);
        mgr.update_status("running", TaskState::Working, None);
        let retention = TaskLimits::default().retention_secs as i64;
        age(&mgr, "done", retention + 5);
        age(&mgr, "fresh", retention - 60);
        age(&mgr, "running", retention * 10);

        mgr.sweep(chrono::Utc::now());
        assert!(mgr.get_task("done").is_none(), "past its retention");
        assert!(mgr.get_task("fresh").is_some(), "inside its retention");
        assert!(
            mgr.get_task("running").is_some(),
            "never removed while it runs"
        );
        // Gone from the store too: a restart does not bring it back.
        let key = format!("{TASK_KEY_PREFIX}done");
        assert!(
            !store
                .contains(tenzro_storage::CF_METADATA, key.as_bytes())
                .unwrap()
        );
        // A read applies the limits without anyone calling sweep.
        age(&mgr, "fresh", retention + 5);
        mgr.swept_at.store(0, std::sync::atomic::Ordering::Relaxed);
        assert!(mgr.task_of("fresh", ALICE).is_none());
    }

    #[test]
    fn a_task_waiting_for_input_is_failed_at_the_deadline_and_can_no_longer_be_continued() {
        let mgr = TaskManager::new();
        open(&mgr, "waiting", None);
        mgr.update_status("waiting", TaskState::InputRequired, None);
        open(&mgr, "recent", None);
        mgr.update_status("recent", TaskState::InputRequired, None);
        let deadline = TaskLimits::default().input_deadline_secs as i64;
        age(&mgr, "waiting", deadline + 5);
        age(&mgr, "recent", deadline - 60);

        mgr.sweep(chrono::Utc::now());
        let failed = mgr.get_task("waiting").unwrap();
        assert_eq!(failed.status.state, TaskState::Failed);
        assert!(failed.status.state.is_terminal());
        assert_eq!(failed.history.last().unwrap().role, Role::Agent);
        assert_eq!(
            mgr.cancel_task("waiting", ALICE).unwrap_err(),
            CancelError::NotCancelable
        );
        assert_eq!(
            mgr.get_task("recent").unwrap().status.state,
            TaskState::InputRequired
        );
        // Failed now, it is kept for the retention like any finished task.
        mgr.sweep(chrono::Utc::now());
        assert!(mgr.get_task("waiting").is_some());
    }

    #[test]
    fn a_sender_at_its_limit_gives_up_its_oldest_finished_task_or_is_refused() {
        let mgr = TaskManager::with_limits(limits(2, 100));
        open_as(&mgr, "a1", ALICE).unwrap();
        open_as(&mgr, "a2", ALICE).unwrap();
        // Both open: no room, and nothing of Alice's is dropped.
        assert_eq!(
            open_as(&mgr, "a3", ALICE).unwrap_err(),
            CreateError::PrincipalFull(2)
        );
        assert_eq!(mgr.task_count(), 2);
        // Another sender is not held to Alice's count.
        open_as(&mgr, "m1", MALLORY).unwrap();

        mgr.update_status("a1", TaskState::Completed, None);
        mgr.update_status("a2", TaskState::Completed, None);
        age(&mgr, "a2", 120);
        open_as(&mgr, "a3", ALICE).unwrap();
        assert!(
            mgr.get_task("a2").is_none(),
            "the older finished task made room"
        );
        assert!(mgr.get_task("a1").is_some());
        assert!(mgr.get_task("m1").is_some(), "never another sender's task");
        assert_eq!(mgr.list_tasks(ALICE, None, None).len(), 2);
    }

    #[test]
    fn the_node_at_its_limit_gives_up_the_oldest_finished_task_or_refuses() {
        let mgr = TaskManager::with_limits(limits(2, 3));
        open_as(&mgr, "a1", ALICE).unwrap();
        open_as(&mgr, "a2", ALICE).unwrap();
        open_as(&mgr, "m1", MALLORY).unwrap();
        let err = open_as(&mgr, "m2", MALLORY).unwrap_err();
        assert_eq!(err, CreateError::NodeFull(3));
        assert!(err.to_string().contains("3 open tasks"));
        assert_eq!(mgr.task_count(), 3);

        mgr.update_status("a1", TaskState::Failed, None);
        open_as(&mgr, "m2", MALLORY).unwrap();
        assert!(mgr.get_task("a1").is_none());
        assert_eq!(mgr.task_count(), 3);
    }

    #[test]
    fn what_aged_out_while_the_node_was_down_is_gone_when_it_starts() {
        let store: Arc<dyn KvStore> = Arc::new(tenzro_storage::MemoryStore::new());
        {
            let mgr = TaskManager::with_storage(store.clone(), TaskLimits::default());
            open(&mgr, "old", None);
            mgr.update_status("old", TaskState::Completed, None);
            age(&mgr, "old", TaskLimits::default().retention_secs as i64 + 5);
            open(&mgr, "stale-wait", None);
            mgr.update_status("stale-wait", TaskState::InputRequired, None);
            age(
                &mgr,
                "stale-wait",
                TaskLimits::default().input_deadline_secs as i64 + 5,
            );
        }
        let mgr = TaskManager::with_storage(store, TaskLimits::default());
        assert!(mgr.get_task("old").is_none());
        assert_eq!(
            mgr.get_task("stale-wait").unwrap().status.state,
            TaskState::Failed
        );
    }

    #[test]
    fn a_did_reads_only_the_tasks_it_opened() {
        let mgr = TaskManager::new();
        open(&mgr, "t1", Some("ctx-a"));
        mgr.create_task(
            "t2".to_string(),
            Some("ctx-a".to_string()),
            user("mallory's own"),
            Default::default(),
            MALLORY,
        )
        .unwrap();
        let ids = |who: &str, ctx: Option<&str>| -> Vec<String> {
            mgr.list_tasks(who, ctx, None)
                .into_iter()
                .map(|t| t.id)
                .collect()
        };
        assert_eq!(ids(ALICE, None), ["t1"]);
        assert_eq!(ids(MALLORY, None), ["t2"]);
        // Naming the other DID's context does not widen the list.
        assert_eq!(ids(MALLORY, Some("ctx-a")), ["t2"]);
        assert!(ids("did:tenzro:human:nobody", None).is_empty());
        assert!(mgr.task_of("t1", ALICE).is_some());
        assert!(mgr.task_of("t1", MALLORY).is_none());
        assert!(mgr.task_of("t2", ALICE).is_none());
        assert!(mgr.task_of("missing", ALICE).is_none());
    }

    #[test]
    fn wire_shape_uses_protocol_buffer_enum_names() {
        let mgr = TaskManager::new();
        let task = open(&mgr, "t-wire", Some("ctx-1"));
        mgr.add_artifact(
            "t-wire",
            TaskArtifact {
                artifact_id: "a-1".to_string(),
                name: "result".to_string(),
                parts: vec![MessagePart::data(serde_json::json!({"k": 1}))],
            },
        )
        .unwrap();
        let json = serde_json::to_value(mgr.get_task("t-wire").unwrap()).unwrap();
        assert_eq!(json["status"]["state"], "TASK_STATE_SUBMITTED");
        assert_eq!(json["history"][0]["role"], "ROLE_USER");
        assert_eq!(json["contextId"], "ctx-1");
        assert_eq!(json["artifacts"][0]["artifactId"], "a-1");
        assert_eq!(
            json["artifacts"][0]["parts"][0]["mediaType"],
            "application/json"
        );
        // The owning DID is server state, not wire content.
        assert!(json.get("principal").is_none());
        assert!(!task.status.timestamp.is_empty());
    }

    #[test]
    fn part_content_count() {
        assert_eq!(MessagePart::text("x").content_count(), 1);
        let mut p = MessagePart::text("x");
        p.url = Some("https://example.com".to_string());
        assert_eq!(p.content_count(), 2);
    }
}
