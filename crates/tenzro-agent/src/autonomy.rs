//! Autonomous agent execution and scheduling capabilities.
//!
//! This module provides infrastructure for agents to autonomously execute tasks,
//! make payments, run scheduled operations, and enforce spending policies.

use crate::{
    a2a_protocol::{TaskRequest, TaskResponse},
    error::{AgentError, Result},
    runtime::AgentRuntime,
};
use async_trait::async_trait;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

/// Result of task execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskResult {
    /// Task ID
    pub task_id: String,
    /// Success status
    pub success: bool,
    /// Result data (JSON)
    pub result: Option<serde_json::Value>,
    /// Error message if failed
    pub error: Option<String>,
    /// Execution time in milliseconds
    pub execution_time_ms: u64,
}

impl TaskResult {
    /// Creates a successful task result
    pub fn success(task_id: String, result: serde_json::Value, execution_time_ms: u64) -> Self {
        Self {
            task_id,
            success: true,
            result: Some(result),
            error: None,
            execution_time_ms,
        }
    }

    /// Creates an error task result
    pub fn error(task_id: String, error: String, execution_time_ms: u64) -> Self {
        Self {
            task_id,
            success: false,
            result: None,
            error: Some(error),
            execution_time_ms,
        }
    }

    /// Converts to TaskResponse
    pub fn to_task_response(&self) -> TaskResponse {
        if self.success {
            TaskResponse::success(
                self.task_id.clone(),
                self.result.clone().unwrap_or(serde_json::Value::Null),
                self.execution_time_ms,
            )
        } else {
            TaskResponse::error(
                self.task_id.clone(),
                self.error
                    .clone()
                    .unwrap_or_else(|| "Unknown error".to_string()),
                self.execution_time_ms,
            )
        }
    }
}

/// Trait for handlers that execute specific task types
#[async_trait]
pub trait TaskHandler: Send + Sync {
    /// Handles a task and returns the result
    async fn handle(&self, task: &TaskRequest) -> Result<TaskResult>;

    /// Returns the capability name this handler supports
    fn capability(&self) -> &str;
}

/// Task executor that processes tasks from a queue
pub struct TaskExecutor {
    /// Registered task handlers by capability
    handlers: DashMap<String, Arc<dyn TaskHandler>>,
    /// Maximum concurrent tasks
    max_concurrent_tasks: usize,
    /// Active task count
    active_tasks: Arc<RwLock<usize>>,
    /// Execution history
    history: DashMap<String, TaskResult>,
}

impl TaskExecutor {
    /// Creates a new task executor
    pub fn new(max_concurrent_tasks: usize) -> Self {
        Self {
            handlers: DashMap::new(),
            max_concurrent_tasks,
            active_tasks: Arc::new(RwLock::new(0)),
            history: DashMap::new(),
        }
    }

    /// Registers a task handler for a specific capability
    pub fn register_handler(&self, handler: Arc<dyn TaskHandler>) -> Result<()> {
        let capability = handler.capability().to_string();
        if self.handlers.contains_key(&capability) {
            return Err(AgentError::InvalidCapability(format!(
                "Handler for capability {} already registered",
                capability
            )));
        }
        self.handlers.insert(capability.clone(), handler);
        debug!("Registered handler for capability: {}", capability);
        Ok(())
    }

    /// Unregisters a task handler
    pub fn unregister_handler(&self, capability: &str) -> Result<()> {
        self.handlers.remove(capability).ok_or_else(|| {
            AgentError::CapabilityNotFound(format!("No handler for capability: {}", capability))
        })?;
        debug!("Unregistered handler for capability: {}", capability);
        Ok(())
    }

    /// Executes a task if a matching handler is registered
    pub async fn execute_task(&self, task: TaskRequest) -> Result<TaskResult> {
        // Check concurrent task limit
        let active = *self.active_tasks.read().await;
        if active >= self.max_concurrent_tasks {
            return Err(AgentError::ResourceLimitExceeded(format!(
                "Maximum concurrent tasks reached: {}",
                self.max_concurrent_tasks
            )));
        }

        // Find the appropriate handler
        let handler = if !task.required_capabilities.is_empty() {
            // Use the first required capability
            let capability = &task.required_capabilities[0];
            self.handlers.get(capability).map(|h| h.clone())
        } else {
            // Fallback to task_type as capability name
            self.handlers.get(&task.task_type).map(|h| h.clone())
        };

        let handler = handler.ok_or_else(|| {
            AgentError::CapabilityNotFound(format!("No handler for task type: {}", task.task_type))
        })?;

        // Increment active task count
        {
            let mut active = self.active_tasks.write().await;
            *active += 1;
        }

        // Execute the task
        let task_id = task.task_id.clone();
        let start_time = std::time::Instant::now();

        let result = match handler.handle(&task).await {
            Ok(result) => result,
            Err(e) => {
                let execution_time_ms = start_time.elapsed().as_millis() as u64;
                TaskResult::error(task_id.clone(), e.to_string(), execution_time_ms)
            }
        };

        // Decrement active task count
        {
            let mut active = self.active_tasks.write().await;
            *active = active.saturating_sub(1);
        }

        // Store in history
        self.history.insert(task_id.clone(), result.clone());

        if result.success {
            info!(
                "Task {} completed successfully in {}ms",
                task_id, result.execution_time_ms
            );
        } else {
            warn!(
                "Task {} failed: {}",
                task_id,
                result
                    .error
                    .as_ref()
                    .unwrap_or(&"Unknown error".to_string())
            );
        }

        Ok(result)
    }

    /// Gets task execution result from history
    pub fn get_task_result(&self, task_id: &str) -> Option<TaskResult> {
        self.history.get(task_id).map(|r| r.clone())
    }

    /// Gets current active task count
    pub async fn active_task_count(&self) -> usize {
        *self.active_tasks.read().await
    }

    /// Clears execution history
    pub fn clear_history(&self) {
        self.history.clear();
        debug!("Task execution history cleared");
    }
}

/// Scheduled task configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduledTask {
    /// Unique schedule ID
    pub schedule_id: String,
    /// Task request to execute
    pub task: TaskRequest,
    /// Interval in seconds
    pub interval_secs: u64,
    /// Last execution timestamp (Unix seconds)
    pub last_execution: Option<i64>,
    /// Is active
    pub active: bool,
}

impl ScheduledTask {
    /// Creates a new scheduled task
    pub fn new(task: TaskRequest, interval_secs: u64) -> Self {
        Self {
            schedule_id: uuid::Uuid::new_v4().to_string(),
            task,
            interval_secs,
            last_execution: None,
            active: true,
        }
    }

    /// Checks if the task is due for execution
    pub fn is_due(&self) -> bool {
        if !self.active {
            return false;
        }

        match self.last_execution {
            None => true, // Never executed
            Some(last) => {
                let now = chrono::Utc::now().timestamp();
                let elapsed = (now - last) as u64;
                elapsed >= self.interval_secs
            }
        }
    }

    /// Marks as executed now
    pub fn mark_executed(&mut self) {
        self.last_execution = Some(chrono::Utc::now().timestamp());
    }
}

/// Scheduler for periodic task execution
pub struct AutonomousScheduler {
    /// Scheduled tasks
    tasks: DashMap<String, ScheduledTask>,
    /// Shutdown signal
    shutdown_tx: tokio::sync::broadcast::Sender<()>,
    shutdown_rx: Arc<std::sync::Mutex<Option<tokio::sync::broadcast::Receiver<()>>>>,
    /// Handle to the spawned scheduler task (for abort on stop)
    task_handle: Arc<std::sync::Mutex<Option<tokio::task::JoinHandle<()>>>>,
}

impl AutonomousScheduler {
    /// Creates a new scheduler
    pub fn new() -> Self {
        let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel(1);
        Self {
            tasks: DashMap::new(),
            shutdown_tx,
            shutdown_rx: Arc::new(std::sync::Mutex::new(Some(shutdown_rx))),
            task_handle: Arc::new(std::sync::Mutex::new(None)),
        }
    }

    /// Adds a scheduled task
    pub fn add_task(&self, task: ScheduledTask) -> Result<String> {
        let schedule_id = task.schedule_id.clone();
        self.tasks.insert(schedule_id.clone(), task);
        info!("Added scheduled task: {}", schedule_id);
        Ok(schedule_id)
    }

    /// Removes a scheduled task
    pub fn remove_task(&self, schedule_id: &str) -> Result<()> {
        self.tasks.remove(schedule_id).ok_or_else(|| {
            AgentError::AgentNotFound(format!("Scheduled task not found: {}", schedule_id))
        })?;
        info!("Removed scheduled task: {}", schedule_id);
        Ok(())
    }

    /// Pauses a scheduled task
    pub fn pause_task(&self, schedule_id: &str) -> Result<()> {
        let mut task = self.tasks.get_mut(schedule_id).ok_or_else(|| {
            AgentError::AgentNotFound(format!("Scheduled task not found: {}", schedule_id))
        })?;
        task.active = false;
        debug!("Paused scheduled task: {}", schedule_id);
        Ok(())
    }

    /// Resumes a scheduled task
    pub fn resume_task(&self, schedule_id: &str) -> Result<()> {
        let mut task = self.tasks.get_mut(schedule_id).ok_or_else(|| {
            AgentError::AgentNotFound(format!("Scheduled task not found: {}", schedule_id))
        })?;
        task.active = true;
        debug!("Resumed scheduled task: {}", schedule_id);
        Ok(())
    }

    /// Gets due tasks
    pub fn get_due_tasks(&self) -> Vec<ScheduledTask> {
        self.tasks
            .iter()
            .filter_map(|entry| {
                let task = entry.value().clone();
                if task.is_due() { Some(task) } else { None }
            })
            .collect()
    }

    /// Marks a task as executed
    pub fn mark_executed(&self, schedule_id: &str) {
        if let Some(mut task) = self.tasks.get_mut(schedule_id) {
            task.mark_executed();
        }
    }

    /// Starts the scheduler loop
    pub async fn start(&self, executor: Arc<TaskExecutor>) {
        let mut shutdown_rx = {
            let mut rx = self.shutdown_rx.lock().unwrap();
            rx.take().expect("Scheduler already started")
        };

        let tasks = self.tasks.clone();
        let handle_store = self.task_handle.clone();

        let handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(1));

            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        // Check for due tasks
                        let due_tasks: Vec<ScheduledTask> = tasks
                            .iter()
                            .filter_map(|entry| {
                                let task = entry.value().clone();
                                if task.is_due() {
                                    Some(task)
                                } else {
                                    None
                                }
                            })
                            .collect();

                        for task in due_tasks {
                            let schedule_id = task.schedule_id.clone();
                            let task_req = task.task.clone();

                            // Mark as executed first
                            if let Some(mut task) = tasks.get_mut(&schedule_id) {
                                task.mark_executed();
                            }

                            // Execute task
                            let executor = executor.clone();
                            let sid = schedule_id.clone();
                            tokio::spawn(async move {
                                match executor.execute_task(task_req).await {
                                    Ok(_) => {
                                        debug!("Scheduled task {} executed successfully", sid);
                                    }
                                    Err(e) => {
                                        error!("Scheduled task {} failed: {}", sid, e);
                                    }
                                }
                            });
                        }
                    }
                    _ = shutdown_rx.recv() => {
                        info!("Scheduler shutting down");
                        break;
                    }
                }
            }
        });

        *handle_store.lock().unwrap() = Some(handle);
    }

    /// Stops the scheduler
    pub async fn stop(&self) {
        let _ = self.shutdown_tx.send(());
        // Take the handle while holding the lock, then drop the lock before awaiting
        let handle = self.task_handle.lock().unwrap().take();
        if let Some(handle) = handle {
            handle.abort();
            // Wait for the abort to take effect
            let _ = handle.await;
        }
    }
}

impl Default for AutonomousScheduler {
    fn default() -> Self {
        Self::new()
    }
}

/// Spending policy for autonomous payments
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpendingPolicy {
    /// Maximum amount per transaction (in smallest TNZO unit)
    pub max_per_transaction: u64,
    /// Maximum daily spend (in smallest TNZO unit)
    pub max_daily_spend: u64,
    /// Current daily spend (resets daily)
    pub current_daily_spend: u64,
    /// Last reset timestamp (Unix seconds)
    pub last_reset: i64,
    /// Is policy enabled
    pub enabled: bool,
}

impl SpendingPolicy {
    /// Creates a new spending policy
    pub fn new(max_per_transaction: u64, max_daily_spend: u64) -> Self {
        Self {
            max_per_transaction,
            max_daily_spend,
            current_daily_spend: 0,
            last_reset: chrono::Utc::now().timestamp(),
            enabled: true,
        }
    }

    /// Checks if a transaction amount is allowed
    pub fn is_allowed(&mut self, amount: u64) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }

        // Check daily reset
        self.check_daily_reset();

        // Check per-transaction limit
        if amount > self.max_per_transaction {
            return Err(AgentError::ResourceLimitExceeded(format!(
                "Transaction amount {} exceeds per-transaction limit {}",
                amount, self.max_per_transaction
            )));
        }

        // Check daily limit
        if self.current_daily_spend.saturating_add(amount) > self.max_daily_spend {
            return Err(AgentError::ResourceLimitExceeded(format!(
                "Transaction would exceed daily spend limit (current: {}, limit: {})",
                self.current_daily_spend, self.max_daily_spend
            )));
        }

        Ok(())
    }

    /// Records a transaction
    pub fn record_transaction(&mut self, amount: u64) -> Result<()> {
        self.is_allowed(amount)?;
        self.current_daily_spend = self.current_daily_spend.saturating_add(amount);
        debug!(
            "Recorded transaction: {} (daily total: {})",
            amount, self.current_daily_spend
        );
        Ok(())
    }

    /// Checks and performs daily reset if needed
    fn check_daily_reset(&mut self) {
        let now = chrono::Utc::now().timestamp();
        let elapsed_days = (now - self.last_reset) / 86400;

        if elapsed_days >= 1 {
            self.current_daily_spend = 0;
            self.last_reset = now;
            debug!("Daily spending counter reset");
        }
    }

    /// Gets remaining daily spend allowance
    pub fn remaining_daily_allowance(&mut self) -> u64 {
        self.check_daily_reset();
        self.max_daily_spend
            .saturating_sub(self.current_daily_spend)
    }

    /// Enables the policy
    pub fn enable(&mut self) {
        self.enabled = true;
        info!("Spending policy enabled");
    }

    /// Disables the policy
    pub fn disable(&mut self) {
        self.enabled = false;
        warn!("Spending policy disabled");
    }
}

impl Default for SpendingPolicy {
    fn default() -> Self {
        Self::new(
            1_000_000_000,  // 1 TNZO per transaction
            10_000_000_000, // 10 TNZO per day
        )
    }
}

/// Main autonomy system that coordinates all autonomous capabilities
pub struct AgentAutonomy {
    /// Task executor
    executor: Arc<TaskExecutor>,
    /// Autonomous scheduler
    scheduler: Arc<AutonomousScheduler>,
    /// Spending policy
    spending_policy: Arc<RwLock<SpendingPolicy>>,
    /// Is running
    running: Arc<RwLock<bool>>,
}

impl AgentAutonomy {
    /// Creates a new agent autonomy system
    pub fn new(max_concurrent_tasks: usize, spending_policy: SpendingPolicy) -> Self {
        Self {
            executor: Arc::new(TaskExecutor::new(max_concurrent_tasks)),
            scheduler: Arc::new(AutonomousScheduler::new()),
            spending_policy: Arc::new(RwLock::new(spending_policy)),
            running: Arc::new(RwLock::new(false)),
        }
    }

    /// Creates with default configuration
    pub fn with_defaults() -> Self {
        Self::new(10, SpendingPolicy::default())
    }

    /// Gets the task executor
    pub fn executor(&self) -> Arc<TaskExecutor> {
        self.executor.clone()
    }

    /// Gets the scheduler
    pub fn scheduler(&self) -> Arc<AutonomousScheduler> {
        self.scheduler.clone()
    }

    /// Gets the spending policy
    pub async fn spending_policy(&self) -> SpendingPolicy {
        self.spending_policy.read().await.clone()
    }

    /// Updates the spending policy
    pub async fn update_spending_policy<F>(&self, f: F)
    where
        F: FnOnce(&mut SpendingPolicy),
    {
        let mut policy = self.spending_policy.write().await;
        f(&mut policy);
    }

    /// Checks if a payment is allowed
    pub async fn check_payment(&self, amount: u64) -> Result<()> {
        let mut policy = self.spending_policy.write().await;
        policy.is_allowed(amount)
    }

    /// Records a payment
    pub async fn record_payment(&self, amount: u64) -> Result<()> {
        let mut policy = self.spending_policy.write().await;
        policy.record_transaction(amount)
    }

    /// Starts all autonomous subsystems
    pub async fn start(&self) -> Result<()> {
        let mut running = self.running.write().await;
        if *running {
            return Err(AgentError::InvalidConfiguration(
                "Autonomy already running".to_string(),
            ));
        }

        // Start scheduler
        self.scheduler.start(self.executor.clone()).await;

        *running = true;
        info!("Agent autonomy started");
        Ok(())
    }

    /// Stops all autonomous subsystems
    pub async fn stop(&self) -> Result<()> {
        let mut running = self.running.write().await;
        if !*running {
            return Ok(());
        }

        // Stop scheduler
        self.scheduler.stop().await;

        *running = false;
        info!("Agent autonomy stopped");
        Ok(())
    }

    /// Checks if the autonomy system is running
    pub async fn is_running(&self) -> bool {
        *self.running.read().await
    }
}

/// Internal enum for tool execution results
enum ToolResult {
    /// Intermediate output to feed back to the LLM
    Output(String),
    /// Final result — task is complete
    Complete(String),
}

/// Agentic execution loop: LLM → parse tool_calls → execute built-in tools → repeat
///
/// Calls an inference endpoint with built-in tool definitions (OpenAI tool_calls format),
/// executes each tool call (spawn_agent, delegate_task, collect_results, complete),
/// feeds results back to the LLM, and repeats until `complete` is called or `max_steps`
/// is reached.
pub struct AgentExecutionLoop {
    runtime: Arc<AgentRuntime>,
    /// URL of the LLM inference endpoint (OpenAI-compatible chat completions)
    inference_url: String,
    /// Maximum number of LLM ↔ tool round-trips (default: 10)
    max_steps: usize,
}

impl AgentExecutionLoop {
    /// Creates a new execution loop backed by the given runtime and inference URL
    pub fn new(runtime: Arc<AgentRuntime>, inference_url: String) -> Self {
        Self {
            runtime,
            inference_url,
            max_steps: 10,
        }
    }

    /// Overrides the default max steps (10)
    pub fn with_max_steps(mut self, max_steps: usize) -> Self {
        self.max_steps = max_steps;
        self
    }

    /// Runs the agentic loop for `agent_id` on `task`. Returns the final result string.
    pub async fn run(&self, agent_id: &str, task: &str) -> Result<String> {
        let tools = self.built_in_tools();
        let mut messages = vec![
            serde_json::json!({
                "role": "system",
                "content": "You are an autonomous agent. Use the provided tools to accomplish the task. Call `complete` when finished."
            }),
            serde_json::json!({"role": "user", "content": task}),
        ];
        let mut final_result = String::new();

        let client = reqwest::Client::new();

        for step in 0..self.max_steps {
            let body = serde_json::json!({
                "model": "default",
                "messages": messages,
                "tools": tools,
                "tool_choice": "auto",
                "max_tokens": 1024,
            });

            let resp = client
                .post(&self.inference_url)
                .json(&body)
                .send()
                .await
                .map_err(|e| AgentError::ProtocolError(format!("LLM request failed: {}", e)))?;

            let resp_json: serde_json::Value = resp.json().await.map_err(|e| {
                AgentError::ProtocolError(format!("LLM response parse failed: {}", e))
            })?;

            let content = resp_json["choices"][0]["message"]["content"]
                .as_str()
                .unwrap_or("")
                .to_string();
            let tool_calls = resp_json["choices"][0]["message"]["tool_calls"].clone();

            // Record assistant turn in history
            messages.push(serde_json::json!({
                "role": "assistant",
                "content": content,
                "tool_calls": tool_calls
            }));

            let tool_calls_arr = tool_calls.as_array();
            if tool_calls_arr.map(|a| a.is_empty()).unwrap_or(true) {
                // No tool calls — treat assistant content as final answer
                final_result = content;
                info!(agent_id = %agent_id, step = step, "Execution loop complete (no tool calls)");
                break;
            }

            let calls = tool_calls_arr.unwrap();
            let mut done = false;

            for call in calls {
                let tool_name = call["function"]["name"].as_str().unwrap_or("");
                let args: serde_json::Value =
                    serde_json::from_str(call["function"]["arguments"].as_str().unwrap_or("{}"))
                        .unwrap_or_default();
                let call_id = call["id"].as_str().unwrap_or("call_0");

                let result = self.execute_tool(agent_id, tool_name, &args).await;

                match result {
                    Ok(ToolResult::Complete(msg)) => {
                        final_result = msg;
                        done = true;
                        info!(agent_id = %agent_id, step = step, "Execution loop complete via complete() tool");
                        break;
                    }
                    Ok(ToolResult::Output(out)) => {
                        messages.push(serde_json::json!({
                            "role": "tool",
                            "tool_call_id": call_id,
                            "content": out,
                        }));
                    }
                    Err(e) => {
                        warn!(agent_id = %agent_id, tool = %tool_name, error = %e, "Tool call failed");
                        messages.push(serde_json::json!({
                            "role": "tool",
                            "tool_call_id": call_id,
                            "content": format!("Error: {}", e),
                        }));
                    }
                }
            }

            if done {
                break;
            }
        }

        Ok(final_result)
    }

    async fn execute_tool(
        &self,
        agent_id: &str,
        tool_name: &str,
        args: &serde_json::Value,
    ) -> Result<ToolResult> {
        match tool_name {
            "spawn_agent" => {
                let name = args["name"].as_str().unwrap_or("sub-agent");
                let caps: Vec<String> = args["capabilities"]
                    .as_array()
                    .unwrap_or(&vec![])
                    .iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect();
                let child = self.runtime.spawn_agent(agent_id, name, caps).await?;
                Ok(ToolResult::Output(format!(
                    "Spawned agent: {}",
                    child.identity.agent_id
                )))
            }
            "delegate_task" => {
                let target_id = args["agent_id"].as_str().ok_or_else(|| {
                    AgentError::InvalidConfiguration("missing agent_id".to_string())
                })?;
                let task_text = args["task"]
                    .as_str()
                    .ok_or_else(|| AgentError::InvalidConfiguration("missing task".to_string()))?;
                let sender = self.runtime.get_agent(agent_id)?.identity;
                let receiver = self.runtime.get_agent(target_id)?.identity;
                let mut parameters = std::collections::HashMap::new();
                parameters.insert("task".to_string(), serde_json::json!(task_text));
                self.runtime
                    .delegate_task(sender, receiver, "task_execution".to_string(), parameters)
                    .await?;
                Ok(ToolResult::Output(format!(
                    "Task delegated to {}",
                    target_id
                )))
            }
            "collect_results" => {
                let children = self.runtime.get_children(agent_id);
                Ok(ToolResult::Output(format!("Child agents: {:?}", children)))
            }
            "complete" => {
                let result = args["result"].as_str().unwrap_or("").to_string();
                Ok(ToolResult::Complete(result))
            }
            _ => Err(AgentError::CapabilityNotFound(format!(
                "Unknown tool: {}",
                tool_name
            ))),
        }
    }

    fn built_in_tools(&self) -> serde_json::Value {
        serde_json::json!([
            {
                "type": "function",
                "function": {
                    "name": "spawn_agent",
                    "description": "Spawn a new sub-agent with specified capabilities",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "name": { "type": "string", "description": "Name for the new agent" },
                            "capabilities": {
                                "type": "array",
                                "items": { "type": "string" },
                                "description": "List of capability names for the new agent"
                            }
                        },
                        "required": ["name", "capabilities"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "delegate_task",
                    "description": "Delegate a task to an existing agent by ID",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "agent_id": { "type": "string", "description": "ID of the target agent" },
                            "task": { "type": "string", "description": "Task description to send" }
                        },
                        "required": ["agent_id", "task"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "collect_results",
                    "description": "Collect the list of spawned sub-agent IDs",
                    "parameters": { "type": "object", "properties": {} }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "complete",
                    "description": "Mark the task as complete and return the final result",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "result": { "type": "string", "description": "Final result text" }
                        },
                        "required": ["result"]
                    }
                }
            }
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    struct TestTaskHandler {
        capability: String,
    }

    #[async_trait]
    impl TaskHandler for TestTaskHandler {
        async fn handle(&self, task: &TaskRequest) -> Result<TaskResult> {
            let execution_time_ms = 100;
            Ok(TaskResult::success(
                task.task_id.clone(),
                serde_json::json!({"status": "completed"}),
                execution_time_ms,
            ))
        }

        fn capability(&self) -> &str {
            &self.capability
        }
    }

    #[tokio::test]
    async fn test_task_executor() {
        let executor = TaskExecutor::new(5);
        let handler = Arc::new(TestTaskHandler {
            capability: "test".to_string(),
        });

        executor.register_handler(handler).unwrap();

        let task = TaskRequest::new("test".to_string(), HashMap::new());
        let result = executor.execute_task(task).await.unwrap();

        assert!(result.success);
        assert_eq!(result.execution_time_ms, 100);
    }

    #[tokio::test]
    async fn test_concurrent_task_limit() {
        let executor = TaskExecutor::new(1);
        let handler = Arc::new(TestTaskHandler {
            capability: "test".to_string(),
        });

        executor.register_handler(handler).unwrap();

        // First task should succeed
        let task1 = TaskRequest::new("test".to_string(), HashMap::new());
        let _result1 = executor.execute_task(task1).await.unwrap();

        // Active count should be 0 after execution
        assert_eq!(executor.active_task_count().await, 0);
    }

    #[test]
    fn test_scheduled_task_is_due() {
        let task = TaskRequest::new("test".to_string(), HashMap::new());
        let mut scheduled = ScheduledTask::new(task, 60);

        // Should be due initially (never executed)
        assert!(scheduled.is_due());

        // Mark as executed
        scheduled.mark_executed();

        // Should not be due immediately after execution
        assert!(!scheduled.is_due());

        // Pause task
        scheduled.active = false;
        assert!(!scheduled.is_due());
    }

    #[test]
    fn test_spending_policy() {
        let mut policy = SpendingPolicy::new(1000, 5000);

        // Should allow transaction within limits
        assert!(policy.is_allowed(500).is_ok());

        // Record transaction
        policy.record_transaction(500).unwrap();
        assert_eq!(policy.current_daily_spend, 500);

        // Should allow another transaction
        assert!(policy.is_allowed(1000).is_ok());
        policy.record_transaction(1000).unwrap();
        assert_eq!(policy.current_daily_spend, 1500);

        // Should reject transaction exceeding per-transaction limit
        assert!(policy.is_allowed(1500).is_err());

        // Should reject transaction exceeding daily limit
        assert!(policy.is_allowed(4000).is_err());

        // Remaining allowance
        assert_eq!(policy.remaining_daily_allowance(), 3500);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_agent_autonomy() {
        let autonomy = AgentAutonomy::with_defaults();

        assert!(!autonomy.is_running().await);

        // Start autonomy
        autonomy.start().await.unwrap();
        assert!(autonomy.is_running().await);

        // Check payment
        assert!(autonomy.check_payment(500_000_000).await.is_ok());

        // Record payment
        autonomy.record_payment(500_000_000).await.unwrap();

        // Stop autonomy
        autonomy.stop().await.unwrap();
        assert!(!autonomy.is_running().await);
    }

    #[tokio::test]
    async fn test_scheduler_add_remove_task() {
        let scheduler = AutonomousScheduler::new();
        let task = TaskRequest::new("test".to_string(), HashMap::new());
        let scheduled = ScheduledTask::new(task, 60);

        let schedule_id = scheduler.add_task(scheduled).unwrap();
        assert!(scheduler.tasks.contains_key(&schedule_id));

        scheduler.remove_task(&schedule_id).unwrap();
        assert!(!scheduler.tasks.contains_key(&schedule_id));
    }

    #[test]
    fn test_scheduler_pause_resume() {
        let scheduler = AutonomousScheduler::new();
        let task = TaskRequest::new("test".to_string(), HashMap::new());
        let scheduled = ScheduledTask::new(task, 60);

        let schedule_id = scheduler.add_task(scheduled).unwrap();

        scheduler.pause_task(&schedule_id).unwrap();
        let paused_task = scheduler.tasks.get(&schedule_id).unwrap();
        assert!(!paused_task.active);
        drop(paused_task);

        scheduler.resume_task(&schedule_id).unwrap();
        let resumed_task = scheduler.tasks.get(&schedule_id).unwrap();
        assert!(resumed_task.active);
    }
}
