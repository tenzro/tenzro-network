//! WebSocket subscription server for real-time event streaming
//!
//! Implements eth_subscribe/eth_unsubscribe JSON-RPC over WebSocket for
//! Ethereum compatibility, plus tenzro_subscribe for unified event streaming.
//! Designed for wallets, dApps, and browser clients.

use crate::bus::EventBus;
use crate::types::{EventEnvelope, EventFilter, EventType, SubscriptionId, TenzroEvent, VmType};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::{debug, error, info, warn};

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for the WebSocket subscription server.
#[derive(Debug, Clone)]
pub struct WebSocketConfig {
    /// Maximum number of active subscriptions per connection.
    pub max_subscriptions_per_connection: usize,
    /// Interval between WebSocket ping frames (seconds).
    pub ping_interval_secs: u64,
    /// Maximum incoming message size (bytes).
    pub max_message_size: usize,
    /// Rate limit: maximum messages processed per second per connection.
    pub rate_limit_per_second: u32,
}

impl Default for WebSocketConfig {
    fn default() -> Self {
        Self {
            max_subscriptions_per_connection: 100,
            ping_interval_secs: 30,
            max_message_size: 1_048_576, // 1 MB
            rate_limit_per_second: 100,
        }
    }
}

impl WebSocketConfig {
    /// Builder: set max subscriptions per connection.
    pub fn with_max_subscriptions(mut self, max: usize) -> Self {
        self.max_subscriptions_per_connection = max;
        self
    }

    /// Builder: set ping interval.
    pub fn with_ping_interval_secs(mut self, secs: u64) -> Self {
        self.ping_interval_secs = secs;
        self
    }

    /// Builder: set max message size.
    pub fn with_max_message_size(mut self, size: usize) -> Self {
        self.max_message_size = size;
        self
    }

    /// Builder: set rate limit.
    pub fn with_rate_limit(mut self, rate: u32) -> Self {
        self.rate_limit_per_second = rate;
        self
    }
}

// ---------------------------------------------------------------------------
// Statistics
// ---------------------------------------------------------------------------

/// Atomic counters for WebSocket server observability.
#[derive(Debug)]
pub struct WebSocketStats {
    /// Number of currently connected WebSocket clients.
    pub active_connections: AtomicU64,
    /// Total active subscriptions across all connections.
    pub total_subscriptions: AtomicU64,
    /// Total events sent to clients since startup.
    pub total_events_sent: AtomicU64,
    /// Total errors encountered.
    pub total_errors: AtomicU64,
}

impl WebSocketStats {
    fn new() -> Self {
        Self {
            active_connections: AtomicU64::new(0),
            total_subscriptions: AtomicU64::new(0),
            total_events_sent: AtomicU64::new(0),
            total_errors: AtomicU64::new(0),
        }
    }

    /// Returns a plain-data snapshot of all counters.
    pub fn snapshot(&self) -> WebSocketStatsSnapshot {
        WebSocketStatsSnapshot {
            active_connections: self.active_connections.load(Ordering::Relaxed),
            total_subscriptions: self.total_subscriptions.load(Ordering::Relaxed),
            total_events_sent: self.total_events_sent.load(Ordering::Relaxed),
            total_errors: self.total_errors.load(Ordering::Relaxed),
        }
    }
}

impl Default for WebSocketStats {
    fn default() -> Self {
        Self::new()
    }
}

/// Plain-data snapshot of [`WebSocketStats`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebSocketStatsSnapshot {
    pub active_connections: u64,
    pub total_subscriptions: u64,
    pub total_events_sent: u64,
    pub total_errors: u64,
}

// ---------------------------------------------------------------------------
// Subscription types
// ---------------------------------------------------------------------------

/// The kind of subscription requested by the client.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SubscriptionType {
    /// `eth_subscribe("newHeads")` -- new block headers.
    NewHeads,
    /// `eth_subscribe("logs", {filter})` -- filtered EVM log events.
    Logs,
    /// `eth_subscribe("newPendingTransactions")` -- mempool transactions.
    NewPendingTransactions,
    /// `eth_subscribe("syncing")` -- sync status changes.
    Syncing,
    /// `tenzro_subscribe` -- unified Tenzro event stream (all event types).
    TenzroEvents,
}

impl SubscriptionType {
    /// Parse a subscription type from the string sent in `eth_subscribe` params.
    pub fn from_str_param(s: &str) -> Option<Self> {
        match s {
            "newHeads" => Some(SubscriptionType::NewHeads),
            "logs" => Some(SubscriptionType::Logs),
            "newPendingTransactions" => Some(SubscriptionType::NewPendingTransactions),
            "syncing" => Some(SubscriptionType::Syncing),
            "tenzroEvents" => Some(SubscriptionType::TenzroEvents),
            _ => None,
        }
    }

    /// Returns the corresponding event types that this subscription matches.
    fn matching_event_types(&self) -> Vec<EventType> {
        match self {
            SubscriptionType::NewHeads => vec![EventType::NewBlock],
            SubscriptionType::Logs => vec![EventType::Log],
            SubscriptionType::NewPendingTransactions => vec![EventType::NewPendingTransaction],
            SubscriptionType::Syncing => vec![EventType::SyncProgress],
            SubscriptionType::TenzroEvents => vec![], // matches everything
        }
    }
}

/// Metadata about an active subscription.
#[derive(Debug, Clone)]
pub struct SubscriptionInfo {
    /// Unique subscription ID.
    pub id: u64,
    /// The type of subscription.
    pub subscription_type: SubscriptionType,
    /// Filter applied to incoming events.
    pub filter: EventFilter,
    /// Unix timestamp (millis) when the subscription was created.
    pub created_at: i64,
}

// ---------------------------------------------------------------------------
// WebSocketServer
// ---------------------------------------------------------------------------

/// WebSocket subscription server implementing `eth_subscribe`/`eth_unsubscribe`
/// and `tenzro_subscribe` JSON-RPC methods.
///
/// This struct manages subscription lifecycle and event formatting. The actual
/// WebSocket transport (accept, read, write frames) is handled by the caller
/// (typically axum/tungstenite in tenzro-node). This server provides the
/// JSON-RPC message processing and subscription matching logic.
pub struct WebSocketServer {
    event_bus: Arc<EventBus>,
    subscriptions: Arc<DashMap<u64, SubscriptionInfo>>,
    next_subscription_id: AtomicU64,
    config: WebSocketConfig,
    stats: Arc<WebSocketStats>,
}

impl WebSocketServer {
    /// Create a new WebSocket server.
    pub fn new(event_bus: Arc<EventBus>, config: WebSocketConfig) -> Self {
        Self {
            event_bus,
            subscriptions: Arc::new(DashMap::new()),
            next_subscription_id: AtomicU64::new(1),
            config,
            stats: Arc::new(WebSocketStats::new()),
        }
    }

    /// Returns a reference to the server statistics.
    pub fn stats(&self) -> &Arc<WebSocketStats> {
        &self.stats
    }

    /// Returns the number of active subscriptions.
    pub fn subscription_count(&self) -> usize {
        self.subscriptions.len()
    }

    /// Returns a reference to the event bus.
    pub fn event_bus(&self) -> &Arc<EventBus> {
        &self.event_bus
    }

    // -----------------------------------------------------------------------
    // Subscribe / Unsubscribe
    // -----------------------------------------------------------------------

    /// Handle a subscribe request.
    ///
    /// Parses the subscription type and optional filter from the JSON-RPC params,
    /// creates a subscription, and returns the subscription ID, type, and filter.
    pub fn handle_subscribe(
        &self,
        params: &serde_json::Value,
    ) -> Result<(u64, SubscriptionType, EventFilter), String> {
        // Check subscription limit
        if self.subscriptions.len() >= self.config.max_subscriptions_per_connection {
            return Err(format!(
                "maximum subscriptions ({}) reached",
                self.config.max_subscriptions_per_connection
            ));
        }

        // First param: subscription type string
        let type_str = params
            .get(0)
            .and_then(|v| v.as_str())
            .or_else(|| params.get("type").and_then(|v| v.as_str()))
            .ok_or_else(|| "missing subscription type parameter".to_string())?;

        let sub_type = SubscriptionType::from_str_param(type_str)
            .ok_or_else(|| format!("unknown subscription type: {}", type_str))?;

        // Second param: optional filter object
        let filter = match &sub_type {
            SubscriptionType::Logs => {
                let filter_param = params.get(1).or_else(|| params.get("filter"));
                match filter_param {
                    Some(fp) => parse_log_filter(fp),
                    None => EventFilter::new().with_event_types(vec![EventType::Log]),
                }
            }
            SubscriptionType::TenzroEvents => {
                let filter_param = params.get(1).or_else(|| params.get("filter"));
                match filter_param {
                    Some(fp) => parse_tenzro_filter(fp),
                    None => EventFilter::new(),
                }
            }
            _ => {
                let types = sub_type.matching_event_types();
                if types.is_empty() {
                    EventFilter::new()
                } else {
                    EventFilter::new().with_event_types(types)
                }
            }
        };

        let id = self.next_subscription_id.fetch_add(1, Ordering::SeqCst);
        let info = SubscriptionInfo {
            id,
            subscription_type: sub_type.clone(),
            filter: filter.clone(),
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as i64,
        };

        self.subscriptions.insert(id, info);
        self.stats.total_subscriptions.fetch_add(1, Ordering::Relaxed);
        info!(subscription_id = id, sub_type = ?sub_type, "subscription created");

        Ok((id, sub_type, filter))
    }

    /// Handle an unsubscribe request. Returns `true` if the subscription existed.
    pub fn handle_unsubscribe(&self, subscription_id: u64) -> bool {
        let removed = self.subscriptions.remove(&subscription_id).is_some();
        if removed {
            self.stats.total_subscriptions.fetch_sub(1, Ordering::Relaxed);
            info!(subscription_id, "subscription removed");
        } else {
            warn!(subscription_id, "unsubscribe: subscription not found");
        }
        removed
    }

    // -----------------------------------------------------------------------
    // Event formatting
    // -----------------------------------------------------------------------

    /// Format an event envelope for delivery to a specific subscription type.
    ///
    /// Returns `Some(json)` if the event is relevant to the subscription type,
    /// or `None` if it should be skipped.
    pub fn format_event_for_subscription(
        envelope: &EventEnvelope,
        sub_type: &SubscriptionType,
        sub_id: u64,
    ) -> Option<serde_json::Value> {
        match sub_type {
            SubscriptionType::NewHeads => {
                if let TenzroEvent::NewBlock {
                    block_hash,
                    parent_hash,
                    height,
                    tx_count,
                    proposer,
                } = &envelope.event
                {
                    let result = json!({
                        "number": format!("0x{:x}", height),
                        "hash": format!("0x{}", hex::encode(block_hash)),
                        "parentHash": format!("0x{}", hex::encode(parent_hash)),
                        "timestamp": format!("0x{:x}", envelope.timestamp / 1000),
                        "gasUsed": "0x0",
                        "gasLimit": "0x1c9c380",
                        "baseFeePerGas": "0x0",
                        "miner": format!("0x{}", hex::encode(proposer)),
                        "transactionsRoot": "0x0000000000000000000000000000000000000000000000000000000000000000",
                        "stateRoot": "0x0000000000000000000000000000000000000000000000000000000000000000",
                        "receiptsRoot": "0x0000000000000000000000000000000000000000000000000000000000000000",
                    });
                    Some(wrap_subscription_notification(sub_id, result))
                } else {
                    None
                }
            }

            SubscriptionType::Logs => {
                if let TenzroEvent::Log {
                    address,
                    topics,
                    data,
                    block_height,
                    tx_hash,
                    log_index,
                    removed,
                } = &envelope.event
                {
                    let topics_hex: Vec<String> = topics
                        .iter()
                        .map(|t| format!("0x{}", hex::encode(t)))
                        .collect();
                    let result = json!({
                        "address": format!("0x{}", hex::encode(address)),
                        "topics": topics_hex,
                        "data": format!("0x{}", hex::encode(data)),
                        "blockNumber": format!("0x{:x}", block_height),
                        "transactionHash": format!("0x{}", hex::encode(tx_hash)),
                        "logIndex": format!("0x{:x}", log_index),
                        "blockHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
                        "transactionIndex": "0x0",
                        "removed": removed,
                    });
                    Some(wrap_subscription_notification(sub_id, result))
                } else {
                    None
                }
            }

            SubscriptionType::NewPendingTransactions => {
                if let TenzroEvent::NewPendingTransaction { tx_hash, .. } = &envelope.event {
                    let hash_hex = format!("0x{}", hex::encode(tx_hash));
                    Some(wrap_subscription_notification(sub_id, json!(hash_hex)))
                } else {
                    None
                }
            }

            SubscriptionType::Syncing => {
                if let TenzroEvent::SyncProgress {
                    current_block,
                    highest_block,
                    percent,
                } = &envelope.event
                {
                    if *current_block < *highest_block {
                        let result = json!({
                            "syncing": true,
                            "status": {
                                "startingBlock": "0x0",
                                "currentBlock": format!("0x{:x}", current_block),
                                "highestBlock": format!("0x{:x}", highest_block),
                            }
                        });
                        Some(wrap_subscription_notification(sub_id, result))
                    } else {
                        Some(wrap_subscription_notification(sub_id, json!(false)))
                    }
                } else {
                    None
                }
            }

            SubscriptionType::TenzroEvents => {
                // Return the full event envelope as JSON
                let result = match serde_json::to_value(envelope) {
                    Ok(v) => v,
                    Err(_) => return None,
                };
                Some(wrap_subscription_notification(sub_id, result))
            }
        }
    }

    // -----------------------------------------------------------------------
    // Message processing
    // -----------------------------------------------------------------------

    /// Process an incoming JSON-RPC message from a WebSocket client.
    ///
    /// Handles:
    /// - `eth_subscribe` -- creates subscription, returns subscription ID
    /// - `eth_unsubscribe` -- removes subscription, returns bool
    /// - `tenzro_subscribe` -- creates TenzroEvents subscription
    ///
    /// Returns the JSON-RPC response to send back to the client.
    pub fn process_message(&self, message: &str) -> serde_json::Value {
        let parsed: serde_json::Value = match serde_json::from_str(message) {
            Ok(v) => v,
            Err(e) => {
                self.stats.total_errors.fetch_add(1, Ordering::Relaxed);
                return json!({
                    "jsonrpc": "2.0",
                    "id": null,
                    "error": {
                        "code": -32700,
                        "message": format!("Parse error: {}", e)
                    }
                });
            }
        };

        let id = parsed.get("id").cloned().unwrap_or(json!(null));
        let method = parsed.get("method").and_then(|v| v.as_str()).unwrap_or("");
        let params = parsed.get("params").cloned().unwrap_or(json!([]));

        match method {
            "eth_subscribe" => match self.handle_subscribe(&params) {
                Ok((sub_id, sub_type, _filter)) => {
                    debug!(subscription_id = sub_id, sub_type = ?sub_type, "eth_subscribe");
                    json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": format!("0x{:x}", sub_id)
                    })
                }
                Err(err) => {
                    self.stats.total_errors.fetch_add(1, Ordering::Relaxed);
                    json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": {
                            "code": -32602,
                            "message": err
                        }
                    })
                }
            },

            "eth_unsubscribe" => {
                let sub_id = params
                    .get(0)
                    .and_then(|v| {
                        if let Some(s) = v.as_str() {
                            let s = s.strip_prefix("0x").unwrap_or(s);
                            u64::from_str_radix(s, 16).ok()
                        } else {
                            v.as_u64()
                        }
                    })
                    .unwrap_or(0);

                let result = self.handle_unsubscribe(sub_id);
                json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": result
                })
            }

            "tenzro_subscribe" => {
                // Force subscription type to TenzroEvents
                let mut effective_params = vec![json!("tenzroEvents")];
                if let Some(filter) = params.get(0) {
                    effective_params.push(filter.clone());
                }
                let effective_params = serde_json::Value::Array(effective_params);

                match self.handle_subscribe(&effective_params) {
                    Ok((sub_id, sub_type, _filter)) => {
                        debug!(subscription_id = sub_id, sub_type = ?sub_type, "tenzro_subscribe");
                        json!({
                            "jsonrpc": "2.0",
                            "id": id,
                            "result": format!("0x{:x}", sub_id)
                        })
                    }
                    Err(err) => {
                        self.stats.total_errors.fetch_add(1, Ordering::Relaxed);
                        json!({
                            "jsonrpc": "2.0",
                            "id": id,
                            "error": {
                                "code": -32602,
                                "message": err
                            }
                        })
                    }
                }
            }

            _ => {
                self.stats.total_errors.fetch_add(1, Ordering::Relaxed);
                json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": {
                        "code": -32601,
                        "message": format!("Method not found: {}", method)
                    }
                })
            }
        }
    }

    /// Check if an event envelope matches any active subscription.
    /// Returns a list of (subscription_id, formatted_event) pairs for delivery.
    pub fn match_event(&self, envelope: &EventEnvelope) -> Vec<(u64, serde_json::Value)> {
        let mut results = Vec::new();
        for entry in self.subscriptions.iter() {
            let info = entry.value();
            // First check the filter
            if !info.filter.matches(envelope) {
                continue;
            }
            // Then format for the subscription type
            if let Some(formatted) = Self::format_event_for_subscription(
                envelope,
                &info.subscription_type,
                info.id,
            ) {
                results.push((info.id, formatted));
                self.stats.total_events_sent.fetch_add(1, Ordering::Relaxed);
            }
        }
        results
    }
}

// ---------------------------------------------------------------------------
// Filter parsing
// ---------------------------------------------------------------------------

/// Parse an `eth_subscribe("logs", { ... })` filter object.
///
/// Supports:
/// - `address`: single hex string or array of hex strings (decoded to 20-byte arrays)
/// - `topics`: array of (null | hex-string | array-of-hex-strings) for positional matching
/// - `fromBlock` / `toBlock`: block height range
pub fn parse_log_filter(params: &serde_json::Value) -> EventFilter {
    let mut filter = EventFilter::new().with_event_types(vec![EventType::Log]);

    // Parse address(es) into 20-byte arrays
    if let Some(addr) = params.get("address") {
        let mut addrs = Vec::new();
        if let Some(s) = addr.as_str() {
            if let Some(a) = parse_hex_address(s) {
                addrs.push(a);
            }
        } else if let Some(arr) = addr.as_array() {
            for v in arr {
                if let Some(s) = v.as_str() {
                    if let Some(a) = parse_hex_address(s) {
                        addrs.push(a);
                    }
                }
            }
        }
        if !addrs.is_empty() {
            filter = filter.with_addresses(addrs);
        }
    }

    // Parse topics
    if let Some(topics_val) = params.get("topics").and_then(|v| v.as_array()) {
        let mut parsed_topics: Vec<Option<Vec<[u8; 32]>>> = Vec::new();
        for slot in topics_val {
            if slot.is_null() {
                parsed_topics.push(None);
            } else if let Some(s) = slot.as_str() {
                if let Some(h) = parse_hex_hash(s) {
                    parsed_topics.push(Some(vec![h]));
                } else {
                    parsed_topics.push(None);
                }
            } else if let Some(arr) = slot.as_array() {
                let hashes: Vec<[u8; 32]> = arr
                    .iter()
                    .filter_map(|v| v.as_str().and_then(parse_hex_hash))
                    .collect();
                if hashes.is_empty() {
                    parsed_topics.push(None);
                } else {
                    parsed_topics.push(Some(hashes));
                }
            } else {
                parsed_topics.push(None);
            }
        }
        filter.topics = parsed_topics;
    }

    // Parse block range
    if let Some(from) = params.get("fromBlock") {
        filter.from_block = parse_block_number(from);
    }
    if let Some(to) = params.get("toBlock") {
        filter.to_block = parse_block_number(to);
    }

    filter
}

/// Parse a `tenzro_subscribe` filter object.
///
/// Supports:
/// - `eventTypes`: array of event type strings
/// - `addresses`: array of hex address strings
/// - `fromBlock` / `toBlock`: block height range
/// - `vmTypes`: array of VM type strings
pub fn parse_tenzro_filter(params: &serde_json::Value) -> EventFilter {
    let mut filter = EventFilter::new();

    // Parse event types
    if let Some(types) = params.get("eventTypes").and_then(|v| v.as_array()) {
        let mut event_types = Vec::new();
        for t in types {
            if let Some(s) = t.as_str() {
                if let Some(et) = parse_event_type_name(s) {
                    event_types.push(et);
                }
            }
        }
        if !event_types.is_empty() {
            filter = filter.with_event_types(event_types);
        }
    }

    // Parse addresses
    if let Some(addrs) = params.get("addresses").and_then(|v| v.as_array()) {
        let parsed: Vec<[u8; 20]> = addrs
            .iter()
            .filter_map(|v| v.as_str().and_then(parse_hex_address))
            .collect();
        if !parsed.is_empty() {
            filter = filter.with_addresses(parsed);
        }
    }

    // Parse VM types
    if let Some(vms) = params.get("vmTypes").and_then(|v| v.as_array()) {
        let mut vm_types = Vec::new();
        for v in vms {
            if let Some(s) = v.as_str() {
                match s {
                    "native" | "Native" => vm_types.push(VmType::Native),
                    "evm" | "Evm" | "EVM" => vm_types.push(VmType::Evm),
                    "svm" | "Svm" | "SVM" => vm_types.push(VmType::Svm),
                    "daml" | "Daml" | "DAML" => vm_types.push(VmType::Daml),
                    _ => {}
                }
            }
        }
        filter.vm_types = vm_types;
    }

    // Parse block range
    if let Some(from) = params.get("fromBlock") {
        filter.from_block = parse_block_number(from);
    }
    if let Some(to) = params.get("toBlock") {
        filter.to_block = parse_block_number(to);
    }

    filter
}

/// Parse a hex address string ("0x...") into a 20-byte array.
fn parse_hex_address(s: &str) -> Option<[u8; 20]> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(s).ok()?;
    if bytes.len() == 20 {
        let mut arr = [0u8; 20];
        arr.copy_from_slice(&bytes);
        Some(arr)
    } else {
        None
    }
}

/// Parse a hex hash string ("0x...") into a 32-byte array.
fn parse_hex_hash(s: &str) -> Option<[u8; 32]> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(s).ok()?;
    if bytes.len() == 32 {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Some(arr)
    } else {
        None
    }
}

/// Parse a block number from hex string ("0x...") or decimal integer.
fn parse_block_number(value: &serde_json::Value) -> Option<u64> {
    if let Some(s) = value.as_str() {
        let s = s.strip_prefix("0x").unwrap_or(s);
        u64::from_str_radix(s, 16).ok()
    } else {
        value.as_u64()
    }
}

/// Parse an event type name string into an [`EventType`].
fn parse_event_type_name(name: &str) -> Option<EventType> {
    match name {
        "NewBlock" | "newBlock" | "newHeads" => Some(EventType::NewBlock),
        "BlockFinalized" | "blockFinalized" => Some(EventType::BlockFinalized),
        "BlockReorged" | "blockReorged" => Some(EventType::BlockReorged),
        "NewPendingTransaction" | "newPendingTransactions" => {
            Some(EventType::NewPendingTransaction)
        }
        "TransactionIncluded" | "transactionIncluded" => Some(EventType::TransactionIncluded),
        "TransactionFinalized" | "transactionFinalized" => Some(EventType::TransactionFinalized),
        "Log" | "log" | "logs" => Some(EventType::Log),
        "Transfer" | "transfer" => Some(EventType::Transfer),
        "NftTransfer" | "nftTransfer" => Some(EventType::NftTransfer),
        "CrosschainMint" | "crosschainMint" => Some(EventType::CrosschainMint),
        "CrosschainBurn" | "crosschainBurn" => Some(EventType::CrosschainBurn),
        "IdentityRegistered" | "identityRegistered" => Some(EventType::IdentityRegistered),
        "CredentialIssued" | "credentialIssued" => Some(EventType::CredentialIssued),
        "ComplianceViolation" | "complianceViolation" => Some(EventType::ComplianceViolation),
        "ModelRegistered" | "modelRegistered" => Some(EventType::ModelRegistered),
        "InferenceCompleted" | "inferenceCompleted" => Some(EventType::InferenceCompleted),
        "AgentMessage" | "agentMessage" => Some(EventType::AgentMessage),
        "SettlementCompleted" | "settlementCompleted" => Some(EventType::SettlementCompleted),
        "PaymentChannelUpdate" | "paymentChannelUpdate" => Some(EventType::PaymentChannelUpdate),
        "StakeDeposited" | "stakeDeposited" => Some(EventType::StakeDeposited),
        "StakeWithdrawn" | "stakeWithdrawn" => Some(EventType::StakeWithdrawn),
        "ValidatorSlashed" | "validatorSlashed" => Some(EventType::ValidatorSlashed),
        "ProposalCreated" | "proposalCreated" => Some(EventType::ProposalCreated),
        "VoteCast" | "voteCast" => Some(EventType::VoteCast),
        "BridgeTransferInitiated" | "bridgeTransferInitiated" => {
            Some(EventType::BridgeTransferInitiated)
        }
        "BridgeTransferCompleted" | "bridgeTransferCompleted" => {
            Some(EventType::BridgeTransferCompleted)
        }
        "SyncProgress" | "syncProgress" | "syncing" => Some(EventType::SyncProgress),
        _ => None,
    }
}

/// Wrap a result in a JSON-RPC subscription notification envelope.
fn wrap_subscription_notification(sub_id: u64, result: serde_json::Value) -> serde_json::Value {
    json!({
        "jsonrpc": "2.0",
        "method": "eth_subscription",
        "params": {
            "subscription": format!("0x{:x}", sub_id),
            "result": result
        }
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bus::{EventBus, EventBusConfig};
    use crate::types::{EventEnvelope, EventType, TenzroEvent, VmType};
    use std::sync::Arc;

    fn make_bus() -> Arc<EventBus> {
        Arc::new(EventBus::new(EventBusConfig::default()))
    }

    fn make_server() -> WebSocketServer {
        WebSocketServer::new(make_bus(), WebSocketConfig::default())
    }

    fn make_server_with_config(config: WebSocketConfig) -> WebSocketServer {
        WebSocketServer::new(make_bus(), config)
    }

    fn make_block_envelope(height: u64) -> EventEnvelope {
        EventEnvelope {
            sequence: 0,
            timestamp: 1700000000,
            block_height: Some(height),
            vm_type: Some(VmType::Native),
            event: TenzroEvent::NewBlock {
                block_hash: [0xAA; 32],
                parent_hash: [0xBB; 32],
                height,
                tx_count: 5,
                proposer: [0x01; 20],
            },
        }
    }

    fn make_log_envelope() -> EventEnvelope {
        EventEnvelope {
            sequence: 1,
            timestamp: 1700000001,
            block_height: Some(100),
            vm_type: Some(VmType::Evm),
            event: TenzroEvent::Log {
                address: [0x42; 20],
                topics: vec![[0xDD; 32]],
                data: vec![0x01, 0x02, 0x03],
                block_height: 100,
                tx_hash: [0xCC; 32],
                log_index: 0,
                removed: false,
            },
        }
    }

    fn make_pending_tx_envelope() -> EventEnvelope {
        EventEnvelope {
            sequence: 2,
            timestamp: 1700000002,
            block_height: None,
            vm_type: None,
            event: TenzroEvent::NewPendingTransaction {
                tx_hash: [0xEE; 32],
                from: [0x01; 20],
                to: Some([0x02; 20]),
                value: 1000,
                nonce: 42,
            },
        }
    }

    fn make_transfer_envelope() -> EventEnvelope {
        EventEnvelope {
            sequence: 3,
            timestamp: 1700000003,
            block_height: Some(50),
            vm_type: Some(VmType::Native),
            event: TenzroEvent::Transfer {
                from: [0x01; 20],
                to: [0x02; 20],
                amount: 1_000_000_000_000_000_000,
                token_id: "TNZO".into(),
                tx_hash: [0xFF; 32],
            },
        }
    }

    // -- Subscribe tests ---------------------------------------------------

    #[test]
    fn test_subscribe_new_heads() {
        let server = make_server();
        let params = json!(["newHeads"]);
        let (id, sub_type, filter) = server.handle_subscribe(&params).unwrap();
        assert!(id > 0);
        assert_eq!(sub_type, SubscriptionType::NewHeads);
        assert_eq!(filter.event_types, vec![EventType::NewBlock]);
        assert_eq!(server.subscription_count(), 1);
    }

    #[test]
    fn test_subscribe_logs_with_filter() {
        let server = make_server();
        let params = json!(["logs", {
            "address": "0x4242424242424242424242424242424242424242",
            "fromBlock": "0xa"
        }]);
        let (id, sub_type, filter) = server.handle_subscribe(&params).unwrap();
        assert!(id > 0);
        assert_eq!(sub_type, SubscriptionType::Logs);
        assert_eq!(filter.event_types, vec![EventType::Log]);
        assert_eq!(filter.addresses.len(), 1);
        assert_eq!(filter.addresses[0], [0x42; 20]);
        assert_eq!(filter.from_block, Some(10));
    }

    #[test]
    fn test_subscribe_logs_with_address_array() {
        let server = make_server();
        let params = json!(["logs", {
            "address": [
                "0x0101010101010101010101010101010101010101",
                "0x0202020202020202020202020202020202020202"
            ]
        }]);
        let (_id, _sub_type, filter) = server.handle_subscribe(&params).unwrap();
        assert_eq!(filter.addresses.len(), 2);
    }

    #[test]
    fn test_subscribe_pending_transactions() {
        let server = make_server();
        let params = json!(["newPendingTransactions"]);
        let (_id, sub_type, filter) = server.handle_subscribe(&params).unwrap();
        assert_eq!(sub_type, SubscriptionType::NewPendingTransactions);
        assert_eq!(filter.event_types, vec![EventType::NewPendingTransaction]);
    }

    #[test]
    fn test_subscribe_syncing() {
        let server = make_server();
        let params = json!(["syncing"]);
        let (_id, sub_type, _filter) = server.handle_subscribe(&params).unwrap();
        assert_eq!(sub_type, SubscriptionType::Syncing);
    }

    #[test]
    fn test_tenzro_subscribe() {
        let server = make_server();
        let params = json!(["tenzroEvents", {
            "eventTypes": ["NewBlock", "Transfer"]
        }]);
        let (_id, sub_type, filter) = server.handle_subscribe(&params).unwrap();
        assert_eq!(sub_type, SubscriptionType::TenzroEvents);
        assert_eq!(filter.event_types.len(), 2);
    }

    #[test]
    fn test_subscribe_unknown_type_fails() {
        let server = make_server();
        let params = json!(["unknownType"]);
        let result = server.handle_subscribe(&params);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("unknown subscription type"));
    }

    // -- Unsubscribe tests -------------------------------------------------

    #[test]
    fn test_unsubscribe() {
        let server = make_server();
        let (id, _, _) = server.handle_subscribe(&json!(["newHeads"])).unwrap();
        assert_eq!(server.subscription_count(), 1);
        let removed = server.handle_unsubscribe(id);
        assert!(removed);
        assert_eq!(server.subscription_count(), 0);
    }

    #[test]
    fn test_unsubscribe_nonexistent() {
        let server = make_server();
        let removed = server.handle_unsubscribe(9999);
        assert!(!removed);
    }

    // -- Format tests ------------------------------------------------------

    #[test]
    fn test_format_block_header() {
        let envelope = make_block_envelope(42);
        let formatted = WebSocketServer::format_event_for_subscription(
            &envelope,
            &SubscriptionType::NewHeads,
            1,
        );
        assert!(formatted.is_some());
        let value = formatted.unwrap();
        let result = &value["params"]["result"];
        assert_eq!(result["number"], "0x2a"); // 42 in hex
        assert!(result["hash"].as_str().unwrap().starts_with("0x"));
        assert!(result["miner"].as_str().unwrap().starts_with("0x"));
    }

    #[test]
    fn test_format_block_header_skips_non_block() {
        let envelope = make_transfer_envelope();
        let formatted = WebSocketServer::format_event_for_subscription(
            &envelope,
            &SubscriptionType::NewHeads,
            1,
        );
        assert!(formatted.is_none());
    }

    #[test]
    fn test_format_log() {
        let envelope = make_log_envelope();
        let formatted = WebSocketServer::format_event_for_subscription(
            &envelope,
            &SubscriptionType::Logs,
            1,
        );
        assert!(formatted.is_some());
        let value = formatted.unwrap();
        let result = &value["params"]["result"];
        assert_eq!(result["blockNumber"], "0x64"); // 100 in hex
        assert_eq!(result["logIndex"], "0x0");
        assert_eq!(result["removed"], false);
        assert!(result["address"].as_str().unwrap().starts_with("0x"));
        assert!(result["topics"].as_array().unwrap().len() == 1);
    }

    #[test]
    fn test_format_pending_tx() {
        let envelope = make_pending_tx_envelope();
        let formatted = WebSocketServer::format_event_for_subscription(
            &envelope,
            &SubscriptionType::NewPendingTransactions,
            1,
        );
        assert!(formatted.is_some());
        let value = formatted.unwrap();
        let result = &value["params"]["result"];
        assert!(result.as_str().unwrap().starts_with("0x"));
    }

    #[test]
    fn test_format_tenzro_event() {
        let envelope = make_transfer_envelope();
        let formatted = WebSocketServer::format_event_for_subscription(
            &envelope,
            &SubscriptionType::TenzroEvents,
            1,
        );
        assert!(formatted.is_some());
        let value = formatted.unwrap();
        let result = &value["params"]["result"];
        assert_eq!(result["sequence"], 3);
        assert_eq!(result["block_height"], 50);
    }

    // -- Parse log filter tests --------------------------------------------

    #[test]
    fn test_parse_log_filter_single_address() {
        let params = json!({
            "address": "0x4242424242424242424242424242424242424242",
            "fromBlock": "0x10",
            "toBlock": 256
        });
        let filter = parse_log_filter(&params);
        assert_eq!(filter.addresses, vec![[0x42; 20]]);
        assert_eq!(filter.from_block, Some(16));
        assert_eq!(filter.to_block, Some(256));
    }

    #[test]
    fn test_parse_log_filter_topics() {
        let topic_hex = format!("0x{}", hex::encode([0xDD; 32]));
        let params = json!({
            "topics": [topic_hex, null]
        });
        let filter = parse_log_filter(&params);
        assert_eq!(filter.topics.len(), 2);
        assert!(filter.topics[0].is_some());
        assert!(filter.topics[1].is_none());
    }

    #[test]
    fn test_parse_tenzro_filter() {
        let params = json!({
            "eventTypes": ["NewBlock", "Transfer"],
            "vmTypes": ["evm"]
        });
        let filter = parse_tenzro_filter(&params);
        assert_eq!(filter.event_types.len(), 2);
        assert_eq!(filter.vm_types, vec![VmType::Evm]);
    }

    // -- Max subscriptions limit -------------------------------------------

    #[test]
    fn test_max_subscriptions_limit() {
        let config = WebSocketConfig::default().with_max_subscriptions(3);
        let server = make_server_with_config(config);

        for _ in 0..3 {
            let result = server.handle_subscribe(&json!(["newHeads"]));
            assert!(result.is_ok());
        }

        let result = server.handle_subscribe(&json!(["newHeads"]));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("maximum subscriptions"));
    }

    // -- Stats tracking ----------------------------------------------------

    #[test]
    fn test_stats_tracking() {
        let server = make_server();
        let snap = server.stats().snapshot();
        assert_eq!(snap.total_subscriptions, 0);
        assert_eq!(snap.total_events_sent, 0);

        let (id, _, _) = server.handle_subscribe(&json!(["newHeads"])).unwrap();
        assert_eq!(server.stats().snapshot().total_subscriptions, 1);

        let envelope = make_block_envelope(1);
        let matches = server.match_event(&envelope);
        assert_eq!(matches.len(), 1);
        assert_eq!(server.stats().snapshot().total_events_sent, 1);

        server.handle_unsubscribe(id);
        assert_eq!(server.stats().snapshot().total_subscriptions, 0);
    }

    // -- process_message integration tests ---------------------------------

    #[test]
    fn test_process_message_eth_subscribe() {
        let server = make_server();
        let msg = r#"{"jsonrpc":"2.0","id":1,"method":"eth_subscribe","params":["newHeads"]}"#;
        let response = server.process_message(msg);
        assert_eq!(response["jsonrpc"], "2.0");
        assert_eq!(response["id"], 1);
        assert!(response["result"].as_str().unwrap().starts_with("0x"));
        assert_eq!(server.subscription_count(), 1);
    }

    #[test]
    fn test_process_message_eth_unsubscribe() {
        let server = make_server();
        let sub_resp = server.process_message(
            r#"{"jsonrpc":"2.0","id":1,"method":"eth_subscribe","params":["newHeads"]}"#,
        );
        let sub_id_hex = sub_resp["result"].as_str().unwrap();

        let unsub_msg = format!(
            r#"{{"jsonrpc":"2.0","id":2,"method":"eth_unsubscribe","params":["{}"]}}"#,
            sub_id_hex
        );
        let response = server.process_message(&unsub_msg);
        assert_eq!(response["result"], true);
        assert_eq!(server.subscription_count(), 0);
    }

    #[test]
    fn test_process_message_tenzro_subscribe() {
        let server = make_server();
        let msg = r#"{"jsonrpc":"2.0","id":1,"method":"tenzro_subscribe","params":[{"eventTypes":["NewBlock"]}]}"#;
        let response = server.process_message(msg);
        assert_eq!(response["jsonrpc"], "2.0");
        assert!(response["result"].as_str().unwrap().starts_with("0x"));
        assert_eq!(server.subscription_count(), 1);

        let sub_id_hex = response["result"].as_str().unwrap();
        let sub_id_str = sub_id_hex.strip_prefix("0x").unwrap();
        let sub_id = u64::from_str_radix(sub_id_str, 16).unwrap();
        let info = server.subscriptions.get(&sub_id).unwrap();
        assert_eq!(info.subscription_type, SubscriptionType::TenzroEvents);
    }

    #[test]
    fn test_process_message_unknown_method() {
        let server = make_server();
        let msg = r#"{"jsonrpc":"2.0","id":1,"method":"eth_badMethod","params":[]}"#;
        let response = server.process_message(msg);
        assert!(response["error"]["message"]
            .as_str()
            .unwrap()
            .contains("Method not found"));
        assert_eq!(server.stats().snapshot().total_errors, 1);
    }

    #[test]
    fn test_process_message_parse_error() {
        let server = make_server();
        let response = server.process_message("not json");
        assert!(response["error"]["message"]
            .as_str()
            .unwrap()
            .contains("Parse error"));
    }

    // -- match_event integration test --------------------------------------

    #[test]
    fn test_match_event_multiple_subscriptions() {
        let server = make_server();

        // newHeads subscription
        server.handle_subscribe(&json!(["newHeads"])).unwrap();
        // tenzroEvents subscription (matches everything)
        server.handle_subscribe(&json!(["tenzroEvents"])).unwrap();
        // logs subscription (won't match block events)
        server.handle_subscribe(&json!(["logs"])).unwrap();

        let envelope = make_block_envelope(10);
        let matches = server.match_event(&envelope);

        // newHeads and tenzroEvents should match; logs should not
        assert_eq!(matches.len(), 2);
    }

    #[test]
    fn test_parse_event_type_name() {
        assert_eq!(parse_event_type_name("NewBlock"), Some(EventType::NewBlock));
        assert_eq!(parse_event_type_name("newHeads"), Some(EventType::NewBlock));
        assert_eq!(parse_event_type_name("Transfer"), Some(EventType::Transfer));
        assert_eq!(parse_event_type_name("logs"), Some(EventType::Log));
        assert_eq!(parse_event_type_name("syncing"), Some(EventType::SyncProgress));
        assert_eq!(parse_event_type_name("nonexistent"), None);
    }

    #[test]
    fn test_subscription_notification_format() {
        let notif = wrap_subscription_notification(42, json!("hello"));
        assert_eq!(notif["jsonrpc"], "2.0");
        assert_eq!(notif["method"], "eth_subscription");
        assert_eq!(notif["params"]["subscription"], "0x2a");
        assert_eq!(notif["params"]["result"], "hello");
    }
}
