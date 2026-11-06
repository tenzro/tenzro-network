//! Event streaming commands for the Tenzro CLI
//!
//! Subscribe to real-time events, query event history, and manage webhooks.

use crate::output;
use anyhow::Result;
use clap::{Parser, Subcommand};

/// Event streaming commands
#[derive(Debug, Subcommand)]
pub enum EventsCommand {
    /// Follow the chain's events from a cursor
    Subscribe(EventSubscribeCmd),
    /// Query a range of the chain's events, with proofs
    History(EventHistoryCmd),
    /// Verify an event from genesis, as a light client
    Verify(EventVerifyCmd),
    /// Query a range and verify from genesis that it left nothing out
    Complete(EventCompleteCmd),
    /// Get event logs (eth_getLogs compatible)
    Logs(EventLogsCmd),
    /// Show event streaming server info
    Info(EventInfoCmd),
}

impl EventsCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Subscribe(cmd) => cmd.execute().await,
            Self::History(cmd) => cmd.execute().await,
            Self::Verify(cmd) => cmd.execute().await,
            Self::Complete(cmd) => cmd.execute().await,
            Self::Logs(cmd) => cmd.execute().await,
            Self::Info(cmd) => cmd.execute().await,
        }
    }
}

/// The JSON filter the event methods take, from the command line.
fn chain_filter(
    types: Option<&str>,
    address: Option<&str>,
    topic: Option<&str>,
) -> serde_json::Value {
    let mut filter = serde_json::Map::new();
    if let Some(types) = types {
        let types: Vec<&str> = types.split(',').map(str::trim).collect();
        filter.insert("event_types".into(), serde_json::json!(types));
    }
    if let Some(addr) = address {
        filter.insert("addresses".into(), serde_json::json!([addr]));
    }
    if let Some(topic) = topic {
        filter.insert("topics".into(), serde_json::json!([[topic]]));
    }
    serde_json::Value::Object(filter)
}

fn print_event(entry: &serde_json::Value, format: &str) {
    if format == "json" {
        println!("{}", serde_json::to_string(entry).unwrap_or_default());
        return;
    }
    let e = &entry["event"];
    let c = &e["cursor"];
    let cursor = format!("{}:{}:{}", c["height"], c["tx_index"], c["event_index"]);
    let kind = e["kind"].as_str().unwrap_or("?");
    let detail = match kind {
        "tx_outcome" => format!("success={} gas={}", e["success"], e["gas_used"]),
        "log" => format!("topics={}", e["topics"].as_array().map_or(0, Vec::len)),
        _ => String::new(),
    };
    println!("  {cursor:<16} {kind:<11} {detail}");
}

/// Follow the chain's events from a cursor, resuming with no gap
#[derive(Debug, Parser)]
pub struct EventSubscribeCmd {
    /// Event types (comma-separated): log, transaction_included
    #[arg(long)]
    types: Option<String>,
    /// Filter logs by contract address (20-byte hex)
    #[arg(long)]
    address: Option<String>,
    /// Filter logs by topic[0] (32-byte hex)
    #[arg(long)]
    topic: Option<String>,
    /// Resume after this cursor (height:tx_index:event_index)
    #[arg(long, conflicts_with = "from_height")]
    from_cursor: Option<String>,
    /// Start at this height (default: the current tip)
    #[arg(long)]
    from_height: Option<u64>,
    /// Stop after this many events (0 = follow until interrupted)
    #[arg(long, default_value = "0")]
    limit: u64,
    /// Output format: json, compact
    #[arg(long, default_value = "compact")]
    format: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl EventSubscribeCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Event Subscription");
        let rpc = RpcClient::new(&self.rpc);
        let filter = chain_filter(
            self.types.as_deref(),
            self.address.as_deref(),
            self.topic.as_deref(),
        );
        output::print_info(
            "Press Ctrl+C to stop; resume with --from-cursor and the last cursor printed",
        );

        let mut cursor = self.from_cursor.clone();
        let mut count: u64 = 0;
        loop {
            let mut params =
                serde_json::json!({ "filter": filter, "wait_ms": 20_000, "limit": 100 });
            match (&cursor, self.from_height) {
                (Some(c), _) => params["from_cursor"] = serde_json::json!(c),
                (None, Some(h)) => params["from_height"] = serde_json::json!(h),
                (None, None) => {}
            }
            let result: serde_json::Value = rpc.call("tenzro_subscribe", params).await?;
            for entry in result["events"].as_array().into_iter().flatten() {
                print_event(entry, &self.format);
                count += 1;
                if self.limit > 0 && count >= self.limit {
                    let c = &entry["event"]["cursor"];
                    output::print_info(&format!(
                        "Reached {count} events; resume with --from-cursor {}:{}:{}",
                        c["height"], c["tx_index"], c["event_index"]
                    ));
                    return Ok(());
                }
            }
            if let Some(c) = result["cursor"].as_str() {
                cursor = Some(c.to_string());
            }
        }
    }
}

/// Query a range of the chain's events, each with its proof
#[derive(Debug, Parser)]
pub struct EventHistoryCmd {
    /// Start at this height
    #[arg(long, conflicts_with = "from_cursor")]
    from_height: Option<u64>,
    /// Resume after this cursor (height:tx_index:event_index)
    #[arg(long)]
    from_cursor: Option<String>,
    /// Stop at this cursor, inclusive
    #[arg(long)]
    to_cursor: Option<String>,
    /// Event types (comma-separated): log, transaction_included
    #[arg(long)]
    types: Option<String>,
    /// Filter logs by contract address (20-byte hex)
    #[arg(long)]
    address: Option<String>,
    /// Maximum events to return
    #[arg(long, default_value = "100")]
    limit: u32,
    /// Output format: json, compact
    #[arg(long, default_value = "compact")]
    format: String,
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
        let mut params = serde_json::json!({
            "filter": chain_filter(self.types.as_deref(), self.address.as_deref(), None),
            "limit": self.limit,
        });
        if let Some(h) = self.from_height {
            params["from_height"] = serde_json::json!(h);
        }
        if let Some(c) = &self.from_cursor {
            params["from_cursor"] = serde_json::json!(c);
        }
        if let Some(c) = &self.to_cursor {
            params["to_cursor"] = serde_json::json!(c);
        }
        let result: serde_json::Value = rpc.call("tenzro_queryEvents", params).await?;
        spinner.finish_and_clear();

        let events = result["events"].as_array().cloned().unwrap_or_default();
        if events.is_empty() {
            output::print_info("No events found.");
        }
        for entry in &events {
            print_event(entry, &self.format);
        }
        if let Some(c) = result["cursor"].as_str() {
            output::print_info(&format!("Next page: --from-cursor {c}"));
        }
        Ok(())
    }
}

/// Fetch an event's proof and verify it from genesis, as a light client
#[derive(Debug, Parser)]
pub struct EventVerifyCmd {
    /// The event's cursor (height:tx_index:event_index)
    cursor: String,
    #[command(flatten)]
    genesis: crate::commands::finality::GenesisArgs,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl EventVerifyCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Verify Event From Genesis");
        let rpc = RpcClient::new(&self.rpc);
        let (client, compact) = crate::commands::finality::follow(&rpc, &self.genesis).await?;
        let anchor = compact.checkpoint.index;
        let result: serde_json::Value = rpc
            .call(
                "tenzro_getEventProof",
                serde_json::json!({ "cursor": self.cursor, "anchor_index": anchor }),
            )
            .await?;
        let proof: tenzro_consensus::event_proof::EventProof =
            serde_json::from_value(result["proof"].clone())
                .map_err(|e| anyhow::anyhow!("the node's proof does not decode: {e}"))?;
        if proof.event.cursor.to_string() != self.cursor {
            anyhow::bail!(
                "the node proved {} instead of {}",
                proof.event.cursor,
                self.cursor
            );
        }
        client
            .verify_event(&proof)
            .map_err(|e| anyhow::anyhow!("the proof does not verify: {e}"))?;
        output::print_success("Event verified against a certified checkpoint");
        output::print_field("Cursor", &self.cursor);
        output::print_field("Anchor checkpoint", &anchor.to_string());
        output::print_json(&proof.event)?;
        Ok(())
    }
}

/// Query a range of events with proofs and verify, as a light client from
/// genesis, every event and that the page left out nothing the filter
/// selects
#[derive(Debug, Parser)]
pub struct EventCompleteCmd {
    /// Start at this height
    #[arg(long, conflicts_with = "from_cursor")]
    from_height: Option<u64>,
    /// Resume after this cursor (height:tx_index:event_index)
    #[arg(long)]
    from_cursor: Option<String>,
    /// Stop at this cursor, inclusive
    #[arg(long)]
    to_cursor: Option<String>,
    /// Event types (comma-separated): log, transaction_included
    #[arg(long)]
    types: Option<String>,
    /// Filter logs by contract address (20-byte hex)
    #[arg(long)]
    address: Option<String>,
    /// Filter logs by their first topic (32-byte hex)
    #[arg(long)]
    topic: Option<String>,
    /// Maximum events to return
    #[arg(long, default_value = "100")]
    limit: u32,
    #[command(flatten)]
    genesis: crate::commands::finality::GenesisArgs,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl EventCompleteCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        use tenzro_consensus::event_proof::{CompletenessProof, EventProof};

        output::print_header("Complete Event Range");
        let rpc = RpcClient::new(&self.rpc);
        let (client, compact) = crate::commands::finality::follow(&rpc, &self.genesis).await?;
        let filter_json = chain_filter(
            self.types.as_deref(),
            self.address.as_deref(),
            self.topic.as_deref(),
        );
        let filter = tenzro_events::EventFilter::from_json(&filter_json)
            .map_err(|e| anyhow::anyhow!("filter: {e}"))?;
        let mut params = serde_json::json!({
            "filter": filter_json,
            "limit": self.limit,
            "completeness": true,
            "anchor_index": compact.checkpoint.index,
        });
        if let Some(h) = self.from_height {
            params["from_height"] = serde_json::json!(h);
        }
        if let Some(c) = &self.from_cursor {
            params["from_cursor"] = serde_json::json!(c);
        }
        if let Some(c) = &self.to_cursor {
            params["to_cursor"] = serde_json::json!(c);
        }
        let result: serde_json::Value = rpc.call("tenzro_queryEvents", params).await?;
        let mut answer = Vec::new();
        for entry in result["events"].as_array().cloned().unwrap_or_default() {
            let proof: EventProof = serde_json::from_value(entry["proof"].clone())
                .map_err(|e| anyhow::anyhow!("an event proof does not decode: {e}"))?;
            client
                .verify_event(&proof)
                .map_err(|e| anyhow::anyhow!("event {}: {e}", proof.event.cursor))?;
            answer.push(proof.event);
        }
        let completeness: CompletenessProof =
            serde_json::from_value(result["completeness"].clone())
                .map_err(|e| anyhow::anyhow!("the completeness proof does not decode: {e}"))?;
        let certified = client
            .latest()
            .ok_or_else(|| anyhow::anyhow!("the light client accepted no checkpoint"))?;
        completeness
            .verify(certified, &filter.index_keys(), &answer, &|e| {
                filter.matches_chain(e)
            })
            .map_err(|e| anyhow::anyhow!("the page is not proven complete: {e}"))?;
        output::print_success("Every event verified, and the range proven complete");
        output::print_field("First height", &completeness.first_height.to_string());
        output::print_field("Through", &completeness.through.to_string());
        output::print_field("Events", &answer.len().to_string());
        output::print_field(
            "Excluded candidates",
            &completeness.excluded.len().to_string(),
        );
        if let Some(c) = result["cursor"].as_str() {
            output::print_info(&format!("Next page: --from-cursor {c}"));
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
        if let Some(ref addr) = self.address {
            filter.insert("address".into(), serde_json::json!(addr));
        }
        if let Some(ref t0) = self.topic0 {
            filter.insert("topics".into(), serde_json::json!([[t0]]));
        }
        if let Some(from) = self.from_block {
            filter.insert(
                "fromBlock".into(),
                serde_json::json!(format!("0x{:x}", from)),
            );
        }
        if let Some(to) = self.to_block {
            filter.insert("toBlock".into(), serde_json::json!(format!("0x{:x}", to)));
        }

        let result: serde_json::Value = rpc
            .call("eth_getLogs", serde_json::Value::Object(filter))
            .await?;

        spinner.finish_and_clear();

        if let Some(logs) = result.as_array() {
            if logs.is_empty() {
                output::print_info("No logs found.");
            } else {
                output::print_info(&format!("Found {} logs", logs.len()));
                let headers = vec!["Block", "TxHash", "Address", "Topic0", "Data"];
                let mut rows = Vec::new();
                for log in logs.iter().take(self.limit as usize) {
                    let block = log
                        .get("blockNumber")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let tx = log
                        .get("transactionHash")
                        .and_then(|v| v.as_str())
                        .map(|s| {
                            if s.len() > 18 {
                                format!("{}...", &s[..18])
                            } else {
                                s.to_string()
                            }
                        })
                        .unwrap_or_default();
                    let addr = log
                        .get("address")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let topic0 = log
                        .get("topics")
                        .and_then(|v| v.as_array())
                        .and_then(|a| a.first())
                        .and_then(|v| v.as_str())
                        .map(|s| {
                            if s.len() > 18 {
                                format!("{}...", &s[..18])
                            } else {
                                s.to_string()
                            }
                        })
                        .unwrap_or_default();
                    let data_len = log
                        .get("data")
                        .and_then(|v| v.as_str())
                        .map(|s| format!("{} bytes", (s.len() - 2) / 2))
                        .unwrap_or_default();
                    rows.push(vec![block, tx, addr, topic0, data_len]);
                }
                output::print_table(&headers, &rows);
            }
        }

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

        let result: serde_json::Value = rpc
            .call("tenzro_eventStatus", serde_json::json!({}))
            .await?;

        spinner.finish_and_clear();

        output::print_field(
            "Current Sequence",
            &result
                .get("current_sequence")
                .and_then(|v| v.as_u64())
                .unwrap_or(0)
                .to_string(),
        );
        output::print_field(
            "Total Events",
            &result
                .get("total_events")
                .and_then(|v| v.as_u64())
                .unwrap_or(0)
                .to_string(),
        );
        output::print_field(
            "Active Subscribers",
            &result
                .get("active_subscribers")
                .and_then(|v| v.as_u64())
                .unwrap_or(0)
                .to_string(),
        );

        println!();
        output::print_field(
            "WebSocket",
            &format!(
                "ws://{}/ws",
                self.rpc
                    .trim_start_matches("http://")
                    .trim_start_matches("https://")
            ),
        );
        output::print_field(
            "gRPC Stream",
            &format!(
                "{}:3008",
                self.rpc.split(':').take(2).collect::<Vec<_>>().join(":")
            ),
        );

        println!();
        output::print_info(
            "Subscription types: newHeads, logs, newPendingTransactions, syncing, tenzroEvents",
        );
        output::print_info("Use 'tenzro events subscribe' for real-time event streaming");

        Ok(())
    }
}
