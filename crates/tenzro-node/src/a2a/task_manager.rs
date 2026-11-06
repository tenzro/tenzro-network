//! Task Manager — A2A 1.0 task state.
//!
//! Wire shapes follow the A2A 1.0 JSON-RPC binding: enum values are the
//! protocol-buffer names (`TASK_STATE_COMPLETED`, `ROLE_USER`), a part is one
//! of `text` / `raw` / `url` / `data`, and timestamps are RFC 3339.
//!
//! Every task records the DID that opened it. Only that DID may continue or
//! cancel it; the DID comes from the verified request envelope, never from
//! the request body.

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

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

/// Why a cancel was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CancelError {
    NotFound,
    NotCancelable,
    NotOwner,
}

fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

/// Manages A2A task lifecycle
pub struct TaskManager {
    tasks: Arc<DashMap<String, A2aTask>>,
}

impl Default for TaskManager {
    fn default() -> Self {
        Self::new()
    }
}

impl TaskManager {
    pub fn new() -> Self {
        Self {
            tasks: Arc::new(DashMap::new()),
        }
    }

    /// Open a task for `principal` from its first message.
    pub fn create_task(
        &self,
        task_id: String,
        context_id: Option<String>,
        message: TaskMessage,
        metadata: std::collections::HashMap<String, serde_json::Value>,
        principal: &str,
    ) -> A2aTask {
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
        self.tasks.insert(task_id, task.clone());
        task
    }

    /// Get a task by ID
    pub fn get_task(&self, task_id: &str) -> Option<A2aTask> {
        self.tasks.get(task_id).map(|t| t.clone())
    }

    /// Tasks matching the optional context and state filters, ordered by id
    /// so pagination is stable.
    pub fn list_tasks(&self, context_id: Option<&str>, state: Option<TaskState>) -> Vec<A2aTask> {
        let mut tasks: Vec<A2aTask> = self
            .tasks
            .iter()
            .filter(|entry| {
                let t = entry.value();
                context_id.is_none_or(|cid| t.context_id.as_deref() == Some(cid))
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
        entry.status = TaskStatus {
            state,
            message: message.clone(),
            timestamp: now_rfc3339(),
        };
        if let Some(msg) = message {
            entry.history.push(msg);
        }
        Some(entry.clone())
    }

    /// Add an artifact to a task
    pub fn add_artifact(&self, task_id: &str, artifact: TaskArtifact) -> Option<A2aTask> {
        let mut entry = self.tasks.get_mut(task_id)?;
        entry.artifacts.push(artifact);
        Some(entry.clone())
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
        Some(entry.clone())
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

    #[test]
    fn list_filters_by_context_and_state() {
        let mgr = TaskManager::new();
        open(&mgr, "t1", Some("ctx-a"));
        open(&mgr, "t2", Some("ctx-a"));
        open(&mgr, "t3", Some("ctx-b"));
        mgr.update_status("t2", TaskState::Completed, None);
        assert_eq!(mgr.list_tasks(Some("ctx-a"), None).len(), 2);
        assert_eq!(mgr.list_tasks(None, None).len(), 3);
        let done = mgr.list_tasks(None, Some(TaskState::Completed));
        assert_eq!(done.len(), 1);
        assert_eq!(done[0].id, "t2");
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
        );
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
