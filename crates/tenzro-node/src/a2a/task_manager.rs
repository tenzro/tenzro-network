//! Task Manager — A2A protocol task state management

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// Task states per A2A protocol specification
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TaskState {
    Submitted,
    Working,
    InputRequired,
    Completed,
    Failed,
    Canceled,
}

/// A message part (text or data)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MessagePart {
    /// Content type
    #[serde(rename = "type")]
    pub part_type: String,
    /// Text content (for type="text")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    /// Data content (for type="data")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
    /// MIME type for data parts
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
}

impl MessagePart {
    pub fn text(content: impl Into<String>) -> Self {
        Self {
            part_type: "text".to_string(),
            text: Some(content.into()),
            data: None,
            mime_type: None,
        }
    }

    pub fn data(content: serde_json::Value, mime: impl Into<String>) -> Self {
        Self {
            part_type: "data".to_string(),
            text: None,
            data: Some(content),
            mime_type: Some(mime.into()),
        }
    }
}

/// A message in a task conversation
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TaskMessage {
    /// Role: "user" or "agent"
    pub role: String,
    /// Message parts
    pub parts: Vec<MessagePart>,
}

/// An artifact produced by task execution
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TaskArtifact {
    /// Artifact name
    pub name: String,
    /// Artifact parts
    pub parts: Vec<MessagePart>,
    /// Index for ordering
    #[serde(skip_serializing_if = "Option::is_none")]
    pub index: Option<u32>,
}

/// Task status information
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TaskStatus {
    /// Current state
    pub state: TaskState,
    /// Status message
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<TaskMessage>,
    /// Timestamp (Unix seconds)
    pub timestamp: u64,
}

/// A2A Task — the core work unit
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct A2aTask {
    /// Unique task identifier
    pub id: String,
    /// Context ID for multi-turn conversations
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context_id: Option<String>,
    /// Current status
    pub status: TaskStatus,
    /// Conversation history
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub history: Vec<TaskMessage>,
    /// Produced artifacts
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub artifacts: Vec<TaskArtifact>,
    /// Additional metadata. Values are arbitrary JSON to allow structured payloads
    /// (e.g. x402 payment requirements / receipts under reserved `x402.*` keys).
    /// See [`crate::a2a::x402_extension`] for the typed accessors.
    #[serde(skip_serializing_if = "std::collections::HashMap::is_empty", default)]
    pub metadata: std::collections::HashMap<String, serde_json::Value>,
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

    /// Create a new task from a user message
    pub fn create_task(
        &self,
        task_id: String,
        context_id: Option<String>,
        message: TaskMessage,
    ) -> A2aTask {
        self.create_task_with_metadata(task_id, context_id, message, std::collections::HashMap::new())
    }

    /// Create a new task from a user message with caller metadata
    pub fn create_task_with_metadata(
        &self,
        task_id: String,
        context_id: Option<String>,
        message: TaskMessage,
        metadata: std::collections::HashMap<String, serde_json::Value>,
    ) -> A2aTask {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let task = A2aTask {
            id: task_id.clone(),
            context_id,
            status: TaskStatus {
                state: TaskState::Submitted,
                message: None,
                timestamp: now,
            },
            history: vec![message],
            artifacts: Vec::new(),
            metadata,
        };

        self.tasks.insert(task_id, task.clone());
        task
    }

    /// Get a task by ID
    pub fn get_task(&self, task_id: &str) -> Option<A2aTask> {
        self.tasks.get(task_id).map(|t| t.clone())
    }

    /// List tasks, optionally filtered by context_id
    pub fn list_tasks(&self, context_id: Option<&str>) -> Vec<A2aTask> {
        self.tasks
            .iter()
            .filter(|entry| match context_id {
                Some(cid) => entry.value().context_id.as_deref() == Some(cid),
                None => true,
            })
            .map(|entry| entry.value().clone())
            .collect()
    }

    /// Update task state
    pub fn update_status(
        &self,
        task_id: &str,
        state: TaskState,
        message: Option<TaskMessage>,
    ) -> Option<A2aTask> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut entry = self.tasks.get_mut(task_id)?;
        entry.status = TaskStatus {
            state,
            message: message.clone(),
            timestamp: now,
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
    /// other caller-supplied entries (`agent_id`, `wallet_address`, …).
    /// Returns the updated task.
    pub fn update_metadata<F>(&self, task_id: &str, f: F) -> Option<A2aTask>
    where
        F: FnOnce(&mut std::collections::HashMap<String, serde_json::Value>),
    {
        let mut entry = self.tasks.get_mut(task_id)?;
        f(&mut entry.metadata);
        Some(entry.clone())
    }

    /// Cancel a task
    pub fn cancel_task(&self, task_id: &str) -> Option<A2aTask> {
        self.update_status(
            task_id,
            TaskState::Canceled,
            Some(TaskMessage {
                role: "agent".to_string(),
                parts: vec![MessagePart::text("Task canceled")],
            }),
        )
    }

    /// Count total tasks
    pub fn task_count(&self) -> usize {
        self.tasks.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_task_lifecycle() {
        let mgr = TaskManager::new();

        // Create
        let msg = TaskMessage {
            role: "user".to_string(),
            parts: vec![MessagePart::text("Check my balance")],
        };
        let task = mgr.create_task("task-1".to_string(), None, msg);
        assert_eq!(task.status.state, TaskState::Submitted);
        assert_eq!(task.history.len(), 1);

        // Update to working
        let task = mgr
            .update_status("task-1", TaskState::Working, None)
            .unwrap();
        assert_eq!(task.status.state, TaskState::Working);

        // Complete with response
        let response = TaskMessage {
            role: "agent".to_string(),
            parts: vec![MessagePart::text("Your balance is 100 TNZO")],
        };
        let task = mgr
            .update_status("task-1", TaskState::Completed, Some(response))
            .unwrap();
        assert_eq!(task.status.state, TaskState::Completed);
        assert_eq!(task.history.len(), 2);
    }

    #[test]
    fn test_task_cancel() {
        let mgr = TaskManager::new();

        let msg = TaskMessage {
            role: "user".to_string(),
            parts: vec![MessagePart::text("Run inference")],
        };
        mgr.create_task("task-2".to_string(), None, msg);

        let task = mgr.cancel_task("task-2").unwrap();
        assert_eq!(task.status.state, TaskState::Canceled);
    }

    #[test]
    fn test_task_list_by_context() {
        let mgr = TaskManager::new();

        let msg1 = TaskMessage {
            role: "user".to_string(),
            parts: vec![MessagePart::text("msg1")],
        };
        let msg2 = TaskMessage {
            role: "user".to_string(),
            parts: vec![MessagePart::text("msg2")],
        };
        let msg3 = TaskMessage {
            role: "user".to_string(),
            parts: vec![MessagePart::text("msg3")],
        };

        mgr.create_task("t1".to_string(), Some("ctx-a".to_string()), msg1);
        mgr.create_task("t2".to_string(), Some("ctx-a".to_string()), msg2);
        mgr.create_task("t3".to_string(), Some("ctx-b".to_string()), msg3);

        let ctx_a = mgr.list_tasks(Some("ctx-a"));
        assert_eq!(ctx_a.len(), 2);

        let all = mgr.list_tasks(None);
        assert_eq!(all.len(), 3);
    }

    #[test]
    fn test_task_artifact() {
        let mgr = TaskManager::new();

        let msg = TaskMessage {
            role: "user".to_string(),
            parts: vec![MessagePart::text("generate data")],
        };
        mgr.create_task("t-art".to_string(), None, msg);

        let artifact = TaskArtifact {
            name: "result.json".to_string(),
            parts: vec![MessagePart::data(
                serde_json::json!({"balance": 100}),
                "application/json",
            )],
            index: Some(0),
        };
        let task = mgr.add_artifact("t-art", artifact).unwrap();
        assert_eq!(task.artifacts.len(), 1);
        assert_eq!(task.artifacts[0].name, "result.json");
    }

    #[test]
    fn test_task_serialization() {
        let task = A2aTask {
            id: "test-id".to_string(),
            context_id: Some("ctx-1".to_string()),
            status: TaskStatus {
                state: TaskState::Completed,
                message: None,
                timestamp: 1234567890,
            },
            history: vec![],
            artifacts: vec![],
            metadata: std::collections::HashMap::new(),
        };

        let json = serde_json::to_string(&task).unwrap();
        assert!(json.contains("\"contextId\""));
        assert!(json.contains("\"completed\""));

        let parsed: A2aTask = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.id, "test-id");
        assert_eq!(parsed.status.state, TaskState::Completed);
    }

    #[test]
    fn test_message_part_constructors() {
        let mgr = TaskManager::new();
        let msg = TaskMessage {
            role: "user".to_string(),
            parts: vec![MessagePart::text("hello")],
        };
        let task = mgr.create_task("t1".to_string(), None, msg);
        assert_eq!(task.id, "t1");
        assert_eq!(task.status.state, TaskState::Submitted);

        // Test data message part
        let data_part = MessagePart::data(serde_json::json!({"key": "value"}), "application/json");
        assert_eq!(data_part.part_type, "data");
        assert!(data_part.data.is_some());

        // Test add_artifact
        let artifact = TaskArtifact {
            name: "result".to_string(),
            parts: vec![data_part],
            index: Some(0),
        };
        let updated = mgr.add_artifact("t1", artifact);
        assert!(updated.is_some());
        assert_eq!(updated.unwrap().artifacts.len(), 1);
    }
}
