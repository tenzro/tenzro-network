# Agent Autonomy Module

The autonomy module provides infrastructure for agents to operate autonomously on the Tenzro Network with task execution, scheduling, and spending policies.

## Features

### 1. Task Execution (`TaskExecutor`)

The `TaskExecutor` processes incoming tasks from message queues and executes registered handlers.

```rust
use tenzro_agent::{TaskExecutor, TaskHandler};
use std::sync::Arc;

// Create executor with max 10 concurrent tasks
let executor = Arc::new(TaskExecutor::new(10));

// Register a handler
executor.register_handler(Arc::new(MyTaskHandler))?;

// Execute a task
let result = executor.execute_task(task_request).await?;
```

**Features:**
- Configurable concurrency limits
- Task handler registry by capability
- Execution history tracking
- Automatic error handling

### 2. Autonomous Scheduling (`AutonomousScheduler`)

The `AutonomousScheduler` runs tasks at specified intervals.

```rust
use tenzro_agent::{AutonomousScheduler, ScheduledTask};
use std::sync::Arc;

let scheduler = Arc::new(AutonomousScheduler::new());

// Create a task that runs every 60 seconds
let scheduled = ScheduledTask::new(task_request, 60);
let schedule_id = scheduler.add_task(scheduled)?;

// Start the scheduler
scheduler.start(executor.clone()).await;

// Pause/resume tasks
scheduler.pause_task(&schedule_id)?;
scheduler.resume_task(&schedule_id)?;

// Stop the scheduler
scheduler.stop();
```

**Features:**
- Interval-based scheduling (simple cron)
- Pause/resume individual tasks
- Execution history per task
- Graceful shutdown

### 3. Spending Policy (`SpendingPolicy`)

The `SpendingPolicy` controls autonomous spending limits.

```rust
use tenzro_agent::SpendingPolicy;

// Create policy: max 1 TNZO per tx, 10 TNZO per day
let mut policy = SpendingPolicy::new(
    1_000_000_000_000_000_000,   // max per transaction (18 decimals)
    10_000_000_000_000_000_000,  // max daily spend (18 decimals)
);

// Check if payment is allowed
policy.is_allowed(500_000_000_000_000_000)?;

// Record a payment
policy.record_transaction(500_000_000_000_000_000)?;

// Check remaining allowance
let remaining = policy.remaining_daily_allowance();
```

**Features:**
- Per-transaction limits
- Daily spending caps
- Automatic daily reset at midnight UTC
- Enable/disable policy

### 4. Agent Autonomy (`AgentAutonomy`)

The `AgentAutonomy` struct ties everything together.

```rust
use tenzro_agent::{AgentAutonomy, SpendingPolicy};

// Create with custom policy
let spending_policy = SpendingPolicy::new(
    1_000_000_000_000_000_000,
    10_000_000_000_000_000_000,
);
let autonomy = AgentAutonomy::new(10, spending_policy);

// Or use defaults
let autonomy = AgentAutonomy::with_defaults();

// Register handlers
autonomy.executor().register_handler(handler)?;

// Schedule tasks
autonomy.scheduler().add_task(scheduled_task)?;

// Start autonomous operation
autonomy.start().await?;

// Check/record payments
autonomy.check_payment(amount).await?;
autonomy.record_payment(amount).await?;

// Stop when done
autonomy.stop().await?;
```

## Architecture

```
┌─────────────────────────────────────────┐
│         AgentAutonomy                   │
│  - Coordinates all subsystems           │
│  - Manages lifecycle                    │
└───────────┬─────────────────────────────┘
            │
    ┌───────┼───────┬────────────────┐
    │       │       │                │
┌───▼───┐ ┌─▼──────▼─┐  ┌───────────▼──┐
│Task   │ │Autonomous│  │  Spending    │
│Executor│ │Scheduler │  │  Policy      │
└────┬───┘ └────┬─────┘  └──────────────┘
     │          │
┌────▼──────┐ ┌─▼──────────┐
│ Handler   │ │ Scheduled  │
│ Registry  │ │ Tasks      │
└───────────┘ └────────────┘
```

## Task Handler Trait

Implement the `TaskHandler` trait to handle specific task types:

```rust
use async_trait::async_trait;
use tenzro_agent::{TaskHandler, TaskRequest, TaskResult, Result};

struct DataAnalysisHandler;

#[async_trait]
impl TaskHandler for DataAnalysisHandler {
    async fn handle(&self, task: &TaskRequest) -> Result<TaskResult> {
        let start = std::time::Instant::now();

        // Execute task logic here
        let result = process_data(&task.parameters)?;

        let execution_time_ms = start.elapsed().as_millis() as u64;

        Ok(TaskResult::success(
            task.task_id.clone(),
            serde_json::json!({ "result": result }),
            execution_time_ms,
        ))
    }

    fn capability(&self) -> &str {
        "data_analysis"
    }
}
```

## Integration with AgentRuntime

The autonomy module integrates seamlessly with the existing `AgentRuntime`:

```rust
use tenzro_agent::{AgentRuntime, AgentAutonomy};
use std::sync::Arc;

// Create runtime
let runtime = Arc::new(AgentRuntime::new()?);

// Register and activate agent
let agent = runtime.register_agent(
    "AutoAgent".to_string(),
    creator,
    capabilities,
    false,
    0
).await?;

runtime.activate_agent(&agent.identity.agent_id).await?;

// Create autonomy system for the agent
let autonomy = AgentAutonomy::with_defaults();

// Register task handlers
autonomy.executor().register_handler(handler)?;

// Start autonomous operation
autonomy.start().await?;

// The agent can now:
// - Process incoming tasks from its message queue
// - Execute scheduled tasks
// - Make autonomous payments within policy limits
```

## Delegation Scopes

Agent autonomy respects TDIP delegation scopes inherited from human controllers:

- **max_transaction_value** — Maximum amount per transaction
- **max_daily_spend** — Daily spending cap (tracked by SpendingPolicy)
- **allowed_operations** — Permitted operation types (e.g., "transfer", "inference")
- **allowed_contracts** — Whitelisted smart contracts
- **time_bound** — Temporal validity (start/end timestamps)
- **allowed_payment_protocols** — Permitted protocols (MPP, x402, Direct, Channel, Custom)
- **allowed_chains** — Whitelisted destination chains for cross-chain operations

The `SpendingPolicy` enforces transaction-level and daily limits. TDIP delegation enforcement happens at the identity layer via `tenzro-identity`.

## Example Usage

See `examples/autonomy_example.rs` for a complete working example:

```bash
cargo run --example autonomy_example
```

## Constraints

### Concurrency
- Default: 10 concurrent tasks
- Configurable via `TaskExecutor::new(max_concurrent_tasks)`
- Tasks exceeding limit return `ResourceLimitExceeded` error

### Scheduling
- Simple interval-based (not full cron syntax)
- Minimum interval: 1 second
- Tasks execute at most once per interval

### Spending
- Default: 1 TNZO per transaction, 10 TNZO per day (18-decimal precision)
- Daily counter resets at midnight UTC
- Policy can be disabled if needed

## Thread Safety

All components are thread-safe and use:
- `Arc` for shared ownership
- `DashMap` for concurrent access to registries
- `RwLock` for state that needs occasional writes
- `async_trait` for async trait methods

## Error Handling

All methods return `Result<T, AgentError>` where:
- `ResourceLimitExceeded`: Concurrent task limit or spending limit reached
- `CapabilityNotFound`: No handler registered for capability
- `InvalidConfiguration`: Autonomy already running or other config error
- `AgentNotFound`: Scheduled task not found

## Testing

The module includes comprehensive unit tests:

```bash
cargo test -p tenzro-agent autonomy
```

Tests cover:
- Task execution and handler registration
- Concurrent task limits
- Scheduled task due checking
- Spending policy enforcement
- Daily spending reset
- Scheduler pause/resume
- Full autonomy lifecycle
