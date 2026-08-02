//! Example demonstrating autonomous agent capabilities
//!
//! Run with: cargo run --example autonomy_example

use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use tenzro_agent::{
    AgentAutonomy, Result, ScheduledTask, SpendingPolicy, TaskHandler, TaskResult,
    a2a_protocol::TaskRequest,
};
/// Example task handler that processes data analysis tasks
struct DataAnalysisHandler;

#[async_trait]
impl TaskHandler for DataAnalysisHandler {
    async fn handle(&self, task: &TaskRequest) -> Result<TaskResult> {
        let start = std::time::Instant::now();

        println!("Processing data analysis task: {}", task.task_id);
        println!("Parameters: {:?}", task.parameters);

        // Simulate some work
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

        let execution_time_ms = start.elapsed().as_millis() as u64;

        Ok(TaskResult::success(
            task.task_id.clone(),
            serde_json::json!({
                "analysis": "Data processed successfully",
                "records_analyzed": 1000,
                "patterns_found": 15
            }),
            execution_time_ms,
        ))
    }

    fn capability(&self) -> &str {
        "data_analysis"
    }
}

/// Example task handler for blockchain interactions
struct BlockchainHandler;

#[async_trait]
impl TaskHandler for BlockchainHandler {
    async fn handle(&self, task: &TaskRequest) -> Result<TaskResult> {
        let start = std::time::Instant::now();

        println!("Processing blockchain task: {}", task.task_id);

        // Simulate blockchain interaction
        tokio::time::sleep(tokio::time::Duration::from_millis(300)).await;

        let execution_time_ms = start.elapsed().as_millis() as u64;

        Ok(TaskResult::success(
            task.task_id.clone(),
            serde_json::json!({
                "transaction_hash": "0x1234567890abcdef",
                "block_number": 12345,
                "status": "confirmed"
            }),
            execution_time_ms,
        ))
    }

    fn capability(&self) -> &str {
        "blockchain_interaction"
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    println!("=== Tenzro Agent Autonomy Example ===\n");

    // Create spending policy
    let spending_policy = SpendingPolicy::new(
        1_000_000_000,  // 1 TNZO per transaction
        10_000_000_000, // 10 TNZO per day
    );

    // Create autonomy system
    let autonomy = AgentAutonomy::new(10, spending_policy);

    // Register task handlers
    println!("1. Registering task handlers...");
    autonomy
        .executor()
        .register_handler(Arc::new(DataAnalysisHandler))
        .unwrap();
    autonomy
        .executor()
        .register_handler(Arc::new(BlockchainHandler))
        .unwrap();
    println!("   ✓ Handlers registered\n");

    // Execute immediate tasks
    println!("2. Executing immediate tasks...");

    let mut params = HashMap::new();
    params.insert(
        "dataset".to_string(),
        serde_json::json!("sales_data_2024.csv"),
    );

    let task1 = TaskRequest::new("data_analysis".to_string(), params.clone())
        .require_capability("data_analysis".to_string());

    let result1 = autonomy.executor().execute_task(task1).await?;
    println!("   Task 1 result: {:?}\n", result1);

    let task2 = TaskRequest::new("blockchain_interaction".to_string(), HashMap::new())
        .require_capability("blockchain_interaction".to_string());

    let result2 = autonomy.executor().execute_task(task2).await?;
    println!("   Task 2 result: {:?}\n", result2);

    // Schedule recurring tasks
    println!("3. Scheduling recurring tasks...");

    let scheduled_task = ScheduledTask::new(
        TaskRequest::new("data_analysis".to_string(), params),
        5, // Every 5 seconds
    );

    autonomy.scheduler().add_task(scheduled_task)?;
    println!("   ✓ Scheduled task added\n");

    // Test spending policy
    println!("4. Testing spending policy...");

    // Check payment allowance
    match autonomy.check_payment(500_000_000).await {
        Ok(_) => println!("   ✓ Payment of 0.5 TNZO allowed"),
        Err(e) => println!("   ✗ Payment rejected: {}", e),
    }

    // Record payment
    autonomy.record_payment(500_000_000).await?;
    println!("   ✓ Payment recorded\n");

    // Check remaining allowance
    let policy = autonomy.spending_policy().await;
    println!(
        "   Remaining daily allowance: {} TNZO\n",
        policy.current_daily_spend as f64 / 1_000_000_000.0
    );

    // Start autonomous operation
    println!("5. Starting autonomous operation...");
    autonomy.start().await?;
    println!("   ✓ Autonomy system running\n");

    // Let it run for a bit
    println!("   Running for 15 seconds...\n");
    tokio::time::sleep(tokio::time::Duration::from_secs(15)).await;

    // Stop autonomous operation
    println!("6. Stopping autonomous operation...");
    autonomy.stop().await?;
    println!("   ✓ Autonomy system stopped\n");

    println!("=== Example completed successfully ===");

    Ok(())
}
