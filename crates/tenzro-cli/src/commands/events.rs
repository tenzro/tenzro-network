//! Event streaming commands for the Tenzro CLI
//!
//! Subscribe to real-time events, query event history, and manage webhooks.

use clap::{Parser, Subcommand};
use anyhow::Result;
use crate::output;

/// Event streaming commands
#[derive(Debug, Subcommand)]
pub enum EventsCommand {
    /// Subscribe to real-time events (prints events to stdout)
    Subscribe(EventSubscribeCmd),
    /// Query historical events
    History(EventHistoryCmd),
    /// Get event logs (eth_getLogs compatible)
    Logs(EventLogsCmd),
    /// Register a webhook for event notifications
    RegisterWebhook(RegisterWebhookCmd),
    /// List registered webhooks
    ListWebhooks(ListWebhooksCmd),
    /// Delete a webhook
    DeleteWebhook(DeleteWebhookCmd),
    /// Show event streaming server info
    Info(EventInfoCmd),
}

impl EventsCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Subscribe(cmd) => cmd.execute().await,
            Self::History(cmd) => cmd.execute().await,
            Self::Logs(cmd) => cmd.execute().await,
            Self::RegisterWebhook(cmd) => cmd.execute().await,
            Self::ListWebhooks(cmd) => cmd.execute().await,
            Self::DeleteWebhook(cmd) => cmd.execute().await,
            Self::Info(cmd) => cmd.execute().await,
        }
    }
}

/// Subscribe to real-time events
#[derive(Debug, Parser)]
pub struct EventSubscribeCmd {
    /// Event types to subscribe to (comma-separated: newHeads,logs,transfers,all)
    #[arg(long, default_value = "all")]
    types: String,
    /// Filter by contract address (hex)
    #[arg(long)]
    address: Option<String>,
    /// Filter by topic[0] (event signature hash, hex)
    #[arg(long)]
    topic: Option<String>,
    /// Filter by VM type: evm, svm, daml
    #[arg(long)]
    vm: Option<String>,
    /// Maximum events to receive (0 = unlimited)
    #[arg(long, default_value = "0")]
    limit: u64,
    /// Output format: json, compact
    #[arg(long, default_value = "compact")]
    format: String,
    /// RPC endpoint (WebSocket will be derived)
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl EventSubscribeCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Event Subscription");
        let rpc = RpcClient::new(&self.rpc);

        let mut filter = serde_json::Map::new();
        if self.types != "all" {
            let types: Vec<&str> = self.types.split(',').collect();
            filter.insert("event_types".into(), serde_json::json!(types));
        }
        if let Some(ref addr) = self.address {
            filter.insert("addresses".into(), serde_json::json!([addr]));
        }
        if let Some(ref topic) = self.topic {
            filter.insert("topics".into(), serde_json::json!([[topic]]));
        }
        if let Some(ref vm) = self.vm {
            filter.insert("vm_types".into(), serde_json::json!([vm]));
        }

        // Subscribe via RPC (this would normally use WebSocket, but we use
        // the polling-based tenzro_getEvents for CLI compatibility)
        output::print_info(&format!("Subscribing to events (types: {})...", self.types));
        output::print_info("Press Ctrl+C to stop");

        let mut from_sequence: u64 = 0;
        let mut count: u64 = 0;

        // First, get the current sequence to start from
        let status: serde_json::Value = rpc.call("tenzro_eventStatus", serde_json::json!({})).await?;
        if let Some(seq) = status.get("current_sequence").and_then(|v| v.as_u64()) {
            from_sequence = seq;
        }

        loop {
            let params = serde_json::json!({
                "filter": serde_json::Value::Object(filter.clone()),
                "from_sequence": from_sequence,
                "limit": 50,
            });

            let result: serde_json::Value = rpc.call("tenzro_getEvents", params).await?;

            if let Some(events) = result.get("events").and_then(|v| v.as_array()) {
                for event in events {
                    count += 1;
                    let seq = event.get("sequence").and_then(|v| v.as_u64()).unwrap_or(0);
                    let event_type = event.get("event_type").and_then(|v| v.as_str()).unwrap_or("unknown");
                    let block = event.get("block_height").and_then(|v| v.as_u64()).map(|h| h.to_string()).unwrap_or("-".to_string());

                    if self.format == "json" {
                        println!("{}", serde_json::to_string(event).unwrap_or_default());
                    } else {
                        println!("  #{:<8} block={:<8} {}", seq, block, event_type);
                        // Print key details based on event type
                        if let Some(details) = event.get("details") {
                            if let Some(hash) = details.get("tx_hash").and_then(|v| v.as_str()) {
                                println!("           tx={}", &hash[..18.min(hash.len())]);
                            }
                            if let Some(amount) = details.get("amount").and_then(|v| v.as_str()) {
                                println!("           amount={}", amount);
                            }
                        }
                    }

                    from_sequence = seq + 1;

                    if self.limit > 0 && count >= self.limit {
                        output::print_info(&format!("Reached limit of {} events", self.limit));
                        return Ok(());
                    }
                }
            }

            // If no events, wait a bit before polling again
            if result.get("events").and_then(|v| v.as_array()).map(|a| a.is_empty()).unwrap_or(true) {
                tokio::time::sleep(std::time::Duration::from_millis(1000)).await;
            }
        }
    }
}

/// Query historical events
#[derive(Debug, Parser)]
pub struct EventHistoryCmd {
    /// Starting block height
    #[arg(long)]
    from_block: Option<u64>,
    /// Ending block height
    #[arg(long)]
    to_block: Option<u64>,
    /// Starting sequence number
    #[arg(long)]
    from_sequence: Option<u64>,
    /// Event types to filter (comma-separated)
    #[arg(long)]
    types: Option<String>,
    /// Maximum events to return
    #[arg(long, default_value = "100")]
    limit: u32,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl EventHistoryCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Event History");
        let spinner = output::create_spinner("Querying events...");
        let rpc = RpcClient::new(&self.rpc);

        let mut filter = serde_json::Map::new();
        if let Some(from) = self.from_block { filter.insert("from_block".into(), serde_json::json!(from)); }
        if let Some(to) = self.to_block { filter.insert("to_block".into(), serde_json::json!(to)); }
        if let Some(seq) = self.from_sequence { filter.insert("from_sequence".into(), serde_json::json!(seq)); }
        if let Some(ref types) = self.types {
            let types: Vec<&str> = types.split(',').collect();
            filter.insert("event_types".into(), serde_json::json!(types));
        }

        let result: serde_json::Value = rpc.call("tenzro_getEvents", serde_json::json!({
            "filter": serde_json::Value::Object(filter),
            "limit": self.limit,
        })).await?;

        spinner.finish_and_clear();

        if let Some(events) = result.get("events").and_then(|v| v.as_array()) {
            if events.is_empty() {
                output::print_info("No events found.");
            } else {
                output::print_info(&format!("Found {} events", events.len()));
                let headers = vec!["Seq", "Block", "Type", "Details"];
                let mut rows = Vec::new();
                for e in events {
                    let seq = e.get("sequence").and_then(|v| v.as_u64()).unwrap_or(0).to_string();
                    let block = e.get("block_height").and_then(|v| v.as_u64()).map(|h| h.to_string()).unwrap_or("-".to_string());
                    let etype = e.get("event_type").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    let details = e.get("summary").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    rows.push(vec![seq, block, etype, details]);
                }
                output::print_table(&headers, &rows);
            }
        }

        if let Some(cursor) = result.get("next_cursor").and_then(|v| v.as_u64()) {
            output::print_info(&format!("Next cursor: {} (use --from-sequence {})", cursor, cursor));
        }

        Ok(())
    }
}

/// Get event logs (eth_getLogs compatible)
#[derive(Debug, Parser)]
pub struct EventLogsCmd {
    /// Contract address to filter (hex)
    #[arg(long)]
    address: Option<String>,
    /// Topic[0] filter (event signature hash, hex)
    #[arg(long)]
    topic0: Option<String>,
    /// From block
    #[arg(long)]
    from_block: Option<u64>,
    /// To block
    #[arg(long)]
    to_block: Option<u64>,
    /// Maximum logs to return
    #[arg(long, default_value = "100")]
    limit: u32,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl EventLogsCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Event Logs (eth_getLogs)");
        let spinner = output::create_spinner("Querying logs...");
        let rpc = RpcClient::new(&self.rpc);

        let mut filter = serde_json::Map::new();
        if let Some(ref addr) = self.address { filter.insert("address".into(), serde_json::json!(addr)); }
        if let Some(ref t0) = self.topic0 { filter.insert("topics".into(), serde_json::json!([[t0]])); }
        if let Some(from) = self.from_block {
            filter.insert("fromBlock".into(), serde_json::json!(format!("0x{:x}", from)));
        }
        if let Some(to) = self.to_block {
            filter.insert("toBlock".into(), serde_json::json!(format!("0x{:x}", to)));
        }

        let result: serde_json::Value = rpc.call("eth_getLogs", serde_json::Value::Object(filter)).await?;

        spinner.finish_and_clear();

        if let Some(logs) = result.as_array() {
            if logs.is_empty() {
                output::print_info("No logs found.");
            } else {
                output::print_info(&format!("Found {} logs", logs.len()));
                let headers = vec!["Block", "TxHash", "Address", "Topic0", "Data"];
                let mut rows = Vec::new();
                for log in logs.iter().take(self.limit as usize) {
                    let block = log.get("blockNumber").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    let tx = log.get("transactionHash").and_then(|v| v.as_str()).map(|s| {
                        if s.len() > 18 { format!("{}...", &s[..18]) } else { s.to_string() }
                    }).unwrap_or_default();
                    let addr = log.get("address").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    let topic0 = log.get("topics").and_then(|v| v.as_array()).and_then(|a| a.first())
                        .and_then(|v| v.as_str()).map(|s| {
                            if s.len() > 18 { format!("{}...", &s[..18]) } else { s.to_string() }
                        }).unwrap_or_default();
                    let data_len = log.get("data").and_then(|v| v.as_str()).map(|s| {
                        format!("{} bytes", (s.len() - 2) / 2)
                    }).unwrap_or_default();
                    rows.push(vec![block, tx, addr, topic0, data_len]);
                }
                output::print_table(&headers, &rows);
            }
        }

        Ok(())
    }
}

/// Register a webhook for event notifications
#[derive(Debug, Parser)]
pub struct RegisterWebhookCmd {
    /// Webhook URL (HTTPS recommended)
    #[arg(long)]
    url: String,
    /// Event types to filter (comma-separated, or "all")
    #[arg(long, default_value = "all")]
    types: String,
    /// Contract address to filter (hex)
    #[arg(long)]
    address: Option<String>,
    /// Secret for HMAC-SHA256 signature verification
    #[arg(long)]
    secret: String,
    /// Enable dual delivery (unconfirmed + confirmed)
    #[arg(long)]
    confirmed_delivery: bool,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl RegisterWebhookCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Register Webhook");
        let spinner = output::create_spinner("Registering...");
        let rpc = RpcClient::new(&self.rpc);

        let mut filter = serde_json::Map::new();
        if self.types != "all" {
            let types: Vec<&str> = self.types.split(',').collect();
            filter.insert("event_types".into(), serde_json::json!(types));
        }
        if let Some(ref addr) = self.address {
            filter.insert("addresses".into(), serde_json::json!([addr]));
        }

        let result: serde_json::Value = rpc.call("tenzro_registerWebhook", serde_json::json!({
            "url": self.url,
            "filter": serde_json::Value::Object(filter),
            "secret": self.secret,
            "confirmed_delivery": self.confirmed_delivery,
        })).await?;

        spinner.finish_and_clear();

        output::print_success("Webhook registered!");
        output::print_field("Webhook ID", result.get("webhook_id").and_then(|v| v.as_str()).unwrap_or(""));
        output::print_field("URL", &self.url);
        output::print_field("Confirmed Delivery", &self.confirmed_delivery.to_string());
        output::print_info("Payloads will include X-Tenzro-Signature header (HMAC-SHA256)");

        Ok(())
    }
}

/// List registered webhooks
#[derive(Debug, Parser)]
pub struct ListWebhooksCmd {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ListWebhooksCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Registered Webhooks");
        let spinner = output::create_spinner("Loading...");
        let rpc = RpcClient::new(&self.rpc);

        let result: serde_json::Value = rpc.call("tenzro_listWebhooks", serde_json::json!({})).await?;

        spinner.finish_and_clear();

        if let Some(webhooks) = result.get("webhooks").and_then(|v| v.as_array()) {
            if webhooks.is_empty() {
                output::print_info("No webhooks registered.");
            } else {
                let headers = vec!["ID", "URL", "Active", "Deliveries", "Failures"];
                let mut rows = Vec::new();
                for wh in webhooks {
                    rows.push(vec![
                        wh.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                        wh.get("url").and_then(|v| v.as_str()).map(|u| {
                            if u.len() > 40 { format!("{}...", &u[..40]) } else { u.to_string() }
                        }).unwrap_or_default(),
                        wh.get("active").and_then(|v| v.as_bool()).map(|b| if b { "yes" } else { "no" }).unwrap_or("?").to_string(),
                        wh.get("total_deliveries").and_then(|v| v.as_u64()).unwrap_or(0).to_string(),
                        wh.get("failed_deliveries").and_then(|v| v.as_u64()).unwrap_or(0).to_string(),
                    ]);
                }
                output::print_table(&headers, &rows);
            }
        }

        Ok(())
    }
}

/// Delete a webhook
#[derive(Debug, Parser)]
pub struct DeleteWebhookCmd {
    /// Webhook ID to delete
    webhook_id: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl DeleteWebhookCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Delete Webhook");
        let spinner = output::create_spinner("Deleting...");
        let rpc = RpcClient::new(&self.rpc);

        let _result: serde_json::Value = rpc.call("tenzro_deleteWebhook", serde_json::json!({
            "webhook_id": self.webhook_id,
        })).await?;

        spinner.finish_and_clear();

        output::print_success(&format!("Webhook {} deleted", self.webhook_id));

        Ok(())
    }
}

/// Show event streaming server info
#[derive(Debug, Parser)]
pub struct EventInfoCmd {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl EventInfoCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Event Streaming Info");
        let spinner = output::create_spinner("Loading...");
        let rpc = RpcClient::new(&self.rpc);

        let result: serde_json::Value = rpc.call("tenzro_eventStatus", serde_json::json!({})).await?;

        spinner.finish_and_clear();

        output::print_field("Current Sequence", &result.get("current_sequence").and_then(|v| v.as_u64()).unwrap_or(0).to_string());
        output::print_field("Total Events", &result.get("total_events").and_then(|v| v.as_u64()).unwrap_or(0).to_string());
        output::print_field("Active Subscribers", &result.get("active_subscribers").and_then(|v| v.as_u64()).unwrap_or(0).to_string());
        output::print_field("Active Webhooks", &result.get("active_webhooks").and_then(|v| v.as_u64()).unwrap_or(0).to_string());

        println!();
        output::print_field("WebSocket", &format!("ws://{}/ws", self.rpc.trim_start_matches("http://").trim_start_matches("https://")));
        output::print_field("gRPC Stream", &format!("{}:3008", self.rpc.split(':').take(2).collect::<Vec<_>>().join(":")));

        println!();
        output::print_info("Subscription types: newHeads, logs, newPendingTransactions, syncing, tenzroEvents");
        output::print_info("Use 'tenzro events subscribe' for real-time event streaming");

        Ok(())
    }
}
