//! Task marketplace commands

use anyhow::Result;
use clap::{Parser, Subcommand};

use crate::{output, rpc};

#[derive(Debug, Subcommand)]
pub enum TaskCommand {
    /// List open tasks in the marketplace
    List(ListTasksCmd),
    /// Post a new task to the marketplace
    Post(PostTaskCmd),
    /// Get details of a specific task
    Get(GetTaskCmd),
    /// Cancel a task you posted
    Cancel(CancelTaskCmd),
    /// Submit a quote for a task (as a provider)
    Quote(SubmitQuoteCmd),
    /// Assign a task to a provider (accept a quote)
    Assign(AssignTaskCmd),
    /// Mark a task as completed with result
    Complete(CompleteTaskCmd),
    /// Update a task
    Update(UpdateTaskCmd),
    /// Reconcile the task registry — expire overdue tasks + purge terminal tasks
    Prune(PruneTasksCmd),
}

impl TaskCommand {
    pub async fn execute(self) -> Result<()> {
        match self {
            Self::List(cmd) => cmd.execute().await,
            Self::Post(cmd) => cmd.execute().await,
            Self::Get(cmd) => cmd.execute().await,
            Self::Cancel(cmd) => cmd.execute().await,
            Self::Quote(cmd) => cmd.execute().await,
            Self::Assign(cmd) => cmd.execute().await,
            Self::Complete(cmd) => cmd.execute().await,
            Self::Update(cmd) => cmd.execute().await,
            Self::Prune(cmd) => cmd.execute().await,
        }
    }
}

/// Reconcile the node's task registry — transition non-terminal tasks past
/// their deadline to `Expired`, and purge terminal tasks
/// (Completed/Cancelled/Expired) older than `purge_after_secs`. Disputed
/// tasks are always retained.
#[derive(Debug, Parser)]
pub struct PruneTasksCmd {
    /// Purge terminal tasks older than this many seconds (default: 30 days)
    #[arg(long)]
    purge_after_secs: Option<u64>,

    /// RPC endpoint (default: http://127.0.0.1:8545)
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,

    /// Output format (text, json)
    #[arg(long, default_value = "text")]
    format: String,
}

impl PruneTasksCmd {
    pub async fn execute(self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Reconciling Task Registry");

        let rpc = RpcClient::new(&self.rpc);
        let spinner = output::create_spinner("Running task reconcile on node...");
        let params = match self.purge_after_secs {
            Some(s) => serde_json::json!({ "purge_after_secs": s }),
            None => serde_json::Value::Null,
        };
        let result: serde_json::Value = rpc
            .call("tenzro_pruneTaskRegistry", params)
            .await?;
        spinner.finish_and_clear();

        if self.format == "json" {
            output::print_json(&result)?;
            return Ok(());
        }

        let expired = result.get("expired").and_then(|v| v.as_u64()).unwrap_or(0);
        let purged = result.get("purged").and_then(|v| v.as_u64()).unwrap_or(0);
        output::print_success(&format!(
            "Task reconcile complete: {} expired, {} purged",
            expired, purged,
        ));
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct ListTasksCmd {
    /// Filter by status (open, assigned, in_progress, completed)
    #[arg(long)]
    status: Option<String>,
    /// Filter by task type (inference, code_review, data_analysis, etc.)
    #[arg(long)]
    task_type: Option<String>,
    /// Maximum number to show
    #[arg(long, default_value = "20")]
    limit: u32,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ListTasksCmd {
    pub async fn execute(self) -> Result<()> {
        output::print_header("Task Marketplace");

        let spinner = output::create_spinner("Fetching tasks...");
        let rpc = rpc::RpcClient::new(&self.rpc);

        let mut filter = serde_json::json!({ "limit": self.limit });
        if let Some(ref s) = self.status {
            filter["status"] = serde_json::json!(s);
        }
        if let Some(ref t) = self.task_type {
            filter["task_type"] = serde_json::json!(t);
        }

        let result: Result<serde_json::Value> = rpc.call("tenzro_listTasks", serde_json::json!([filter])).await;
        spinner.finish_and_clear();

        match result {
            Ok(tasks) => {
                let arr = tasks.as_array().cloned().unwrap_or_default();
                println!();
                output::print_field("Total Tasks", &arr.len().to_string());
                println!();
                for task in &arr {
                    let task_id = task["task_id"].as_str().unwrap_or("?");
                    let title = task["title"].as_str().unwrap_or("Untitled");
                    let status = task["status"].as_str().unwrap_or("unknown");
                    let max_price = task["max_price"].as_str()
                        .or_else(|| task["max_price"].as_u64().map(|_| "?"))
                        .unwrap_or("?");
                    let task_type = task["task_type"].as_str().unwrap_or("?");
                    output::print_field("ID", &format!("{:.16}...", task_id));
                    output::print_field("Title", title);
                    output::print_field("Type", task_type);
                    output::print_field("Status", status);
                    output::print_field("Max Price", &format!("{} TNZO-units", max_price));
                    println!();
                }
                if arr.is_empty() {
                    output::print_info("No tasks found");
                }
            }
            Err(e) => output::print_error(&format!("Failed to list tasks: {}", e)),
        }

        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct PostTaskCmd {
    /// Task title
    #[arg(long)]
    title: String,
    /// Task description
    #[arg(long)]
    description: String,
    /// Task type (inference, code_review, data_analysis, content_generation, translation, research)
    #[arg(long, default_value = "inference")]
    task_type: String,
    /// Maximum price you will pay (in TNZO micro-units)
    #[arg(long)]
    max_price: u128,
    /// Task input/prompt
    #[arg(long)]
    input: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl PostTaskCmd {
    pub async fn execute(self) -> Result<()> {
        output::print_header("Post Task");

        let spinner = output::create_spinner("Posting task to marketplace...");
        let rpc = rpc::RpcClient::new(&self.rpc);

        let params = serde_json::json!({
            "title": self.title,
            "description": self.description,
            "task_type": self.task_type,
            "max_price": self.max_price,
            "input": self.input,
        });

        let result: Result<serde_json::Value> = rpc.call("tenzro_postTask", serde_json::json!([params])).await;
        spinner.finish_and_clear();

        match result {
            Ok(task) => {
                println!();
                output::print_success("Task posted successfully!");
                if let Some(id) = task["task_id"].as_str() {
                    output::print_field("Task ID", id);
                }
                if let Some(status) = task["status"].as_str() {
                    output::print_field("Status", status);
                }
            }
            Err(e) => output::print_error(&format!("Failed to post task: {}", e)),
        }

        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct GetTaskCmd {
    /// Task ID to look up
    task_id: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl GetTaskCmd {
    pub async fn execute(self) -> Result<()> {
        output::print_header("Task Details");

        let spinner = output::create_spinner("Fetching task...");
        let rpc = rpc::RpcClient::new(&self.rpc);

        let result: Result<serde_json::Value> = rpc.call(
            "tenzro_getTask",
            serde_json::json!([{ "task_id": self.task_id }]),
        ).await;
        spinner.finish_and_clear();

        match result {
            Ok(task) => {
                println!();
                for (key, val) in task.as_object().unwrap_or(&serde_json::Map::new()) {
                    output::print_field(key, val.to_string().trim_matches('"'));
                }
            }
            Err(e) => output::print_error(&format!("Task not found: {}", e)),
        }

        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct CancelTaskCmd {
    /// Task ID to cancel
    task_id: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl CancelTaskCmd {
    pub async fn execute(self) -> Result<()> {
        output::print_header("Cancel Task");

        let spinner = output::create_spinner("Cancelling task...");
        let rpc = rpc::RpcClient::new(&self.rpc);

        let result: Result<serde_json::Value> = rpc.call(
            "tenzro_cancelTask",
            serde_json::json!([{ "task_id": self.task_id }]),
        ).await;
        spinner.finish_and_clear();

        match result {
            Ok(_) => {
                println!();
                output::print_success(&format!("Task {} cancelled", self.task_id));
            }
            Err(e) => output::print_error(&format!("Failed to cancel task: {}", e)),
        }

        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct SubmitQuoteCmd {
    /// Task ID to quote for
    task_id: String,
    /// Price you will charge (in TNZO micro-units)
    #[arg(long)]
    price: u128,
    /// Model ID you will use
    #[arg(long)]
    model_id: String,
    /// Estimated time to complete (seconds)
    #[arg(long, default_value = "60")]
    estimated_secs: u64,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl SubmitQuoteCmd {
    pub async fn execute(self) -> Result<()> {
        output::print_header("Submit Quote");

        let spinner = output::create_spinner("Submitting quote...");
        let rpc = rpc::RpcClient::new(&self.rpc);

        let params = serde_json::json!({
            "task_id": self.task_id,
            "price": self.price,
            "model_id": self.model_id,
            "estimated_duration_secs": self.estimated_secs,
        });

        let result: Result<serde_json::Value> = rpc.call("tenzro_quoteTask", serde_json::json!([params])).await;
        spinner.finish_and_clear();

        match result {
            Ok(quote) => {
                println!();
                output::print_success("Quote submitted!");
                if let Some(id) = quote["task_id"].as_str() {
                    output::print_field("Task ID", id);
                }
                output::print_field("Price", &format!("{} TNZO-units", self.price));
                output::print_field("Model", &self.model_id);
            }
            Err(e) => output::print_error(&format!("Failed to submit quote: {}", e)),
        }

        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct AssignTaskCmd {
    /// Task ID to assign
    task_id: String,
    /// Provider address to assign to
    #[arg(long)]
    provider: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl AssignTaskCmd {
    pub async fn execute(self) -> Result<()> {
        output::print_header("Assign Task");

        let spinner = output::create_spinner("Assigning task...");
        let rpc = rpc::RpcClient::new(&self.rpc);

        let result: Result<serde_json::Value> = rpc.call(
            "tenzro_assignTask",
            serde_json::json!([{
                "task_id": self.task_id,
                "provider": self.provider
            }]),
        ).await;
        spinner.finish_and_clear();

        match result {
            Ok(task) => {
                println!();
                output::print_success("Task assigned!");
                output::print_field("Task ID", &self.task_id);
                output::print_field("Provider", &self.provider);
                if let Some(status) = task["status"].as_str() {
                    output::print_field("Status", status);
                }
            }
            Err(e) => output::print_error(&format!("Failed to assign task: {}", e)),
        }

        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct CompleteTaskCmd {
    /// Task ID to complete
    task_id: String,
    /// Result/output of the completed task
    #[arg(long)]
    result: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl CompleteTaskCmd {
    pub async fn execute(self) -> Result<()> {
        output::print_header("Complete Task");

        let spinner = output::create_spinner("Submitting task result...");
        let rpc = rpc::RpcClient::new(&self.rpc);

        let result: Result<serde_json::Value> = rpc.call(
            "tenzro_completeTask",
            serde_json::json!([{
                "task_id": self.task_id,
                "result": self.result
            }]),
        ).await;
        spinner.finish_and_clear();

        match result {
            Ok(task) => {
                println!();
                output::print_success("Task completed!");
                output::print_field("Task ID", &self.task_id);
                if let Some(status) = task["status"].as_str() {
                    output::print_field("Status", status);
                }
                if let Some(settlement) = task["settlement_id"].as_str() {
                    output::print_field("Settlement ID", settlement);
                }
            }
            Err(e) => output::print_error(&format!("Failed to complete task: {}", e)),
        }

        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct UpdateTaskCmd {
    /// Task ID to update
    task_id: String,
    /// New status
    #[arg(long)]
    status: Option<String>,
    /// Updated description
    #[arg(long)]
    description: Option<String>,
    /// Updated max price
    #[arg(long)]
    max_price: Option<u128>,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl UpdateTaskCmd {
    pub async fn execute(self) -> Result<()> {
        output::print_header("Update Task");
        let spinner = output::create_spinner("Updating...");
        let rpc = rpc::RpcClient::new(&self.rpc);
        let mut params = serde_json::json!({ "task_id": self.task_id });
        if let Some(ref s) = self.status { params["status"] = serde_json::json!(s); }
        if let Some(ref d) = self.description { params["description"] = serde_json::json!(d); }
        if let Some(p) = self.max_price { params["max_price"] = serde_json::json!(p); }
        let _result: serde_json::Value = rpc.call("tenzro_updateTask", serde_json::json!([params])).await?;
        spinner.finish_and_clear();
        output::print_success("Task updated!");
        output::print_field("Task ID", &self.task_id);
        Ok(())
    }
}
