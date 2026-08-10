//! Webhook registry and delivery engine
//!
//! Register HTTP callback URLs with event filters. When matching events occur,
//! the engine delivers JSON payloads via HTTP POST with HMAC-SHA256 signatures.
//! Supports retry with exponential backoff and dual confirmed/unconfirmed delivery.

use crate::types::{EventEnvelope, EventFilter};
use dashmap::DashMap;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::{debug, error, info, warn};

type HmacSha256 = Hmac<Sha256>;

// ---------------------------------------------------------------------------
// WebhookEngineConfig
// ---------------------------------------------------------------------------

/// Configuration for the webhook delivery engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookEngineConfig {
    /// Maximum number of registered webhooks.
    pub max_webhooks: usize,
    /// Maximum retries per delivery attempt.
    pub max_retries: u32,
    /// Initial retry delay in milliseconds.
    pub initial_retry_delay_ms: u64,
    /// Maximum retry delay in milliseconds (caps exponential backoff).
    pub max_retry_delay_ms: u64,
    /// HTTP delivery timeout in seconds.
    pub delivery_timeout_secs: u64,
    /// Disable webhook after this many consecutive failures.
    pub disable_after_failures: u64,
}

impl Default for WebhookEngineConfig {
    fn default() -> Self {
        Self {
            max_webhooks: 1000,
            max_retries: 5,
            initial_retry_delay_ms: 1000,
            max_retry_delay_ms: 30000,
            delivery_timeout_secs: 10,
            disable_after_failures: 50,
        }
    }
}

// ---------------------------------------------------------------------------
// WebhookConfig
// ---------------------------------------------------------------------------

/// Registered webhook configuration.
#[derive(Debug, Serialize, Deserialize)]
pub struct WebhookConfig {
    /// Unique webhook identifier.
    pub id: String,
    /// Callback URL to POST events to.
    pub url: String,
    /// Event filter determining which events trigger delivery.
    pub filter: EventFilter,
    /// Shared secret for HMAC-SHA256 payload signing.
    #[serde(skip_serializing)]
    pub secret: String,
    /// Maximum retries per delivery.
    pub max_retries: u32,
    /// Whether this webhook is active.
    pub active: bool,
    /// Creation timestamp (unix millis).
    pub created_at: i64,
    /// If true, deliver both on inclusion and on finalization.
    pub confirmed_delivery: bool,
    /// Consecutive delivery failures (for auto-disable).
    #[serde(skip)]
    pub consecutive_failures: AtomicU64,
}

// ---------------------------------------------------------------------------
// WebhookStats
// ---------------------------------------------------------------------------

/// Delivery statistics for a webhook.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WebhookStats {
    pub total_deliveries: u64,
    pub successful_deliveries: u64,
    pub failed_deliveries: u64,
    pub last_delivery_at: Option<i64>,
    pub last_error: Option<String>,
}

// ---------------------------------------------------------------------------
// WebhookInfo
// ---------------------------------------------------------------------------

/// Public-facing webhook information (excludes secret).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookInfo {
    pub id: String,
    pub url: String,
    pub filter: EventFilter,
    pub active: bool,
    pub created_at: i64,
    pub confirmed_delivery: bool,
    pub stats: WebhookStats,
}

// ---------------------------------------------------------------------------
// WebhookPayload
// ---------------------------------------------------------------------------

/// Payload sent to webhook endpoints via HTTP POST.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookPayload {
    /// Webhook ID that matched the event.
    pub webhook_id: String,
    /// Serialized event envelope.
    pub event: serde_json::Value,
    /// Whether this delivery represents a finalized (confirmed) event.
    pub confirmed: bool,
    /// Delivery timestamp (unix millis).
    pub timestamp: i64,
    /// Event sequence number.
    pub sequence: u64,
}

// ---------------------------------------------------------------------------
// WebhookRegistry
// ---------------------------------------------------------------------------

/// Webhook registry and delivery engine.
///
/// Manages registered webhooks, evaluates filters, and delivers matching
/// events via HTTP POST with HMAC-SHA256 signatures and exponential backoff.
pub struct WebhookRegistry {
    webhooks: DashMap<String, WebhookConfig>,
    delivery_stats: DashMap<String, WebhookStats>,
    http_client: reqwest::Client,
    config: WebhookEngineConfig,
    next_id: AtomicU64,
}

impl WebhookRegistry {
    /// Create a new webhook registry with default configuration.
    pub fn new() -> Self {
        Self::with_config(WebhookEngineConfig::default())
    }

    /// Create a new webhook registry with the given configuration.
    pub fn with_config(config: WebhookEngineConfig) -> Self {
        let http_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(config.delivery_timeout_secs))
            .build()
            .unwrap_or_default();
        Self {
            webhooks: DashMap::new(),
            delivery_stats: DashMap::new(),
            http_client,
            config,
            next_id: AtomicU64::new(1),
        }
    }

    /// Register a new webhook. Returns the webhook ID.
    pub fn register(
        &self,
        url: String,
        filter: EventFilter,
        secret: String,
        confirmed_delivery: bool,
    ) -> Result<String, String> {
        if self.webhooks.len() >= self.config.max_webhooks {
            return Err(format!(
                "maximum webhook capacity reached ({})",
                self.config.max_webhooks
            ));
        }

        let id = format!("wh_{}", self.next_id.fetch_add(1, Ordering::SeqCst));
        let webhook = WebhookConfig {
            id: id.clone(),
            url,
            filter,
            secret,
            max_retries: self.config.max_retries,
            active: true,
            created_at: chrono::Utc::now().timestamp_millis(),
            confirmed_delivery,
            consecutive_failures: AtomicU64::new(0),
        };

        self.delivery_stats.insert(id.clone(), WebhookStats::default());
        self.webhooks.insert(id.clone(), webhook);
        info!(webhook_id = %id, "webhook registered");
        Ok(id)
    }

    /// Unregister a webhook by ID. Returns true if found and removed.
    pub fn unregister(&self, webhook_id: &str) -> bool {
        let removed = self.webhooks.remove(webhook_id).is_some();
        if removed {
            self.delivery_stats.remove(webhook_id);
            info!(webhook_id = %webhook_id, "webhook unregistered");
        }
        removed
    }

    /// List all registered webhooks (public info only).
    pub fn list(&self) -> Vec<WebhookInfo> {
        self.webhooks
            .iter()
            .map(|entry| {
                let wh = entry.value();
                let stats = self
                    .delivery_stats
                    .get(&wh.id)
                    .map(|s| s.clone())
                    .unwrap_or_default();
                WebhookInfo {
                    id: wh.id.clone(),
                    url: wh.url.clone(),
                    filter: wh.filter.clone(),
                    active: wh.active,
                    created_at: wh.created_at,
                    confirmed_delivery: wh.confirmed_delivery,
                    stats,
                }
            })
            .collect()
    }

    /// Get a specific webhook's info.
    pub fn get(&self, webhook_id: &str) -> Option<WebhookInfo> {
        self.webhooks.get(webhook_id).map(|entry| {
            let wh = entry.value();
            let stats = self
                .delivery_stats
                .get(&wh.id)
                .map(|s| s.clone())
                .unwrap_or_default();
            WebhookInfo {
                id: wh.id.clone(),
                url: wh.url.clone(),
                filter: wh.filter.clone(),
                active: wh.active,
                created_at: wh.created_at,
                confirmed_delivery: wh.confirmed_delivery,
                stats,
            }
        })
    }

    /// Update the filter for a webhook.
    pub fn update_filter(&self, webhook_id: &str, new_filter: EventFilter) -> bool {
        if let Some(mut entry) = self.webhooks.get_mut(webhook_id) {
            entry.value_mut().filter = new_filter;
            true
        } else {
            false
        }
    }

    /// Enable a webhook.
    pub fn enable(&self, webhook_id: &str) -> bool {
        if let Some(mut entry) = self.webhooks.get_mut(webhook_id) {
            entry.value_mut().active = true;
            entry.value_mut().consecutive_failures = AtomicU64::new(0);
            info!(webhook_id = %webhook_id, "webhook enabled");
            true
        } else {
            false
        }
    }

    /// Disable a webhook.
    pub fn disable(&self, webhook_id: &str) -> bool {
        if let Some(mut entry) = self.webhooks.get_mut(webhook_id) {
            entry.value_mut().active = false;
            info!(webhook_id = %webhook_id, "webhook disabled");
            true
        } else {
            false
        }
    }

    /// Deliver an event to all matching active webhooks.
    ///
    /// For each matching webhook, spawns an async delivery task that sends
    /// the event via HTTP POST with HMAC-SHA256 signature. On failure,
    /// retries with exponential backoff (1s, 2s, 4s, 8s, ...) up to
    /// `max_retries`. Tracks consecutive failures and auto-disables the
    /// webhook after the configured threshold.
    pub fn deliver(&self, envelope: &EventEnvelope) {
        let envelope_arc = Arc::new(envelope.clone());

        for entry in self.webhooks.iter() {
            let wh = entry.value();

            if !wh.active {
                continue;
            }

            if !wh.filter.matches(&envelope_arc) {
                continue;
            }

            let webhook_id = wh.id.clone();
            let url = wh.url.clone();
            let secret = wh.secret.clone();
            let max_retries = wh.max_retries;
            let client = self.http_client.clone();
            let stats_map = self.delivery_stats.clone();
            let webhooks_map = self.webhooks.clone();
            let initial_delay = self.config.initial_retry_delay_ms;
            let max_delay = self.config.max_retry_delay_ms;
            let disable_threshold = self.config.disable_after_failures;

            let payload = WebhookPayload {
                webhook_id: webhook_id.clone(),
                event: serde_json::to_value(&*envelope_arc).unwrap_or_default(),
                confirmed: false,
                timestamp: chrono::Utc::now().timestamp_millis(),
                sequence: envelope_arc.sequence,
            };

            tokio::spawn(async move {
                let payload_json = match serde_json::to_vec(&payload) {
                    Ok(v) => v,
                    Err(e) => {
                        error!(webhook_id = %webhook_id, error = %e, "failed to serialize payload");
                        return;
                    }
                };

                let signature = compute_signature(&secret, &payload_json);
                let mut attempt = 0u32;
                let mut delay_ms = initial_delay;

                loop {
                    let result = client
                        .post(&url)
                        .header("Content-Type", "application/json")
                        .header("X-Tenzro-Signature", &signature)
                        .header("X-Tenzro-Webhook-Id", &webhook_id)
                        .body(payload_json.clone())
                        .send()
                        .await;

                    match result {
                        Ok(response) if response.status().is_success() => {
                            debug!(
                                webhook_id = %webhook_id,
                                status = %response.status(),
                                "webhook delivery successful"
                            );
                            if let Some(mut stats) = stats_map.get_mut(&webhook_id) {
                                stats.total_deliveries += 1;
                                stats.successful_deliveries += 1;
                                stats.last_delivery_at =
                                    Some(chrono::Utc::now().timestamp_millis());
                                stats.last_error = None;
                            }
                            if let Some(wh) = webhooks_map.get(&webhook_id) {
                                wh.consecutive_failures.store(0, Ordering::Relaxed);
                            }
                            return;
                        }
                        Ok(response) => {
                            let err_msg = format!("HTTP {}", response.status());
                            warn!(
                                webhook_id = %webhook_id,
                                attempt = attempt,
                                status = %response.status(),
                                "webhook delivery failed"
                            );
                            record_failure(
                                &stats_map,
                                &webhooks_map,
                                &webhook_id,
                                &err_msg,
                                disable_threshold,
                            );
                        }
                        Err(e) => {
                            let err_msg = e.to_string();
                            warn!(
                                webhook_id = %webhook_id,
                                attempt = attempt,
                                error = %e,
                                "webhook delivery network error"
                            );
                            record_failure(
                                &stats_map,
                                &webhooks_map,
                                &webhook_id,
                                &err_msg,
                                disable_threshold,
                            );
                        }
                    }

                    attempt += 1;
                    if attempt > max_retries {
                        error!(
                            webhook_id = %webhook_id,
                            attempts = attempt,
                            "webhook delivery exhausted all retries"
                        );
                        return;
                    }

                    tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
                    delay_ms = (delay_ms * 2).min(max_delay);
                }
            });
        }
    }
}

/// Record a delivery failure and check auto-disable threshold.
fn record_failure(
    stats_map: &DashMap<String, WebhookStats>,
    webhooks_map: &DashMap<String, WebhookConfig>,
    webhook_id: &str,
    error: &str,
    disable_threshold: u64,
) {
    if let Some(mut stats) = stats_map.get_mut(webhook_id) {
        stats.total_deliveries += 1;
        stats.failed_deliveries += 1;
        stats.last_delivery_at = Some(chrono::Utc::now().timestamp_millis());
        stats.last_error = Some(error.to_string());
    }
    if let Some(wh) = webhooks_map.get(webhook_id) {
        let failures = wh.consecutive_failures.fetch_add(1, Ordering::Relaxed) + 1;
        if failures >= disable_threshold {
            drop(wh);
            if let Some(mut wh_mut) = webhooks_map.get_mut(webhook_id) {
                wh_mut.active = false;
                warn!(
                    webhook_id = %webhook_id,
                    failures = failures,
                    "webhook auto-disabled after consecutive failures"
                );
            }
        }
    }
}

/// Compute HMAC-SHA256 signature of payload using the given secret.
/// Returns the hex-encoded signature string.
pub fn compute_signature(secret: &str, payload: &[u8]) -> String {
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC can take key of any size");
    mac.update(payload);
    let result = mac.finalize();
    hex::encode(result.into_bytes())
}

/// Verify an HMAC-SHA256 signature against expected.
/// Uses constant-time comparison to prevent timing attacks.
pub fn verify_signature(secret: &str, payload: &[u8], signature: &str) -> bool {
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC can take key of any size");
    mac.update(payload);
    match hex::decode(signature) {
        Ok(sig_bytes) => mac.verify_slice(&sig_bytes).is_ok(),
        Err(_) => false,
    }
}

impl Default for WebhookRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{EventFilter, EventType, TenzroEvent, VmType};

    fn make_envelope(seq: u64, event: TenzroEvent) -> EventEnvelope {
        EventEnvelope {
            sequence: seq,
            timestamp: 1_700_000_000_000,
            block_height: Some(100),
            vm_type: Some(VmType::Native),
            event,
        }
    }

    fn make_block() -> TenzroEvent {
        TenzroEvent::NewBlock {
            block_hash: [0xAA; 32],
            parent_hash: [0; 32],
            height: 100,
            tx_count: 5,
            proposer: [0x01; 20],
        }
    }

    fn make_transfer() -> TenzroEvent {
        TenzroEvent::Transfer {
            from: [0x01; 20],
            to: [0x02; 20],
            amount: 1_000_000,
            token_id: "TNZO".into(),
            tx_hash: [0xBB; 32],
        }
    }

    #[test]
    fn test_register_webhook() {
        let registry = WebhookRegistry::new();
        let id = registry
            .register(
                "https://example.com/hook".into(),
                EventFilter::new(),
                "secret123".into(),
                false,
            )
            .unwrap();
        assert!(id.starts_with("wh_"));
        assert_eq!(registry.webhooks.len(), 1);
    }

    #[test]
    fn test_unregister_webhook() {
        let registry = WebhookRegistry::new();
        let id = registry
            .register(
                "https://example.com/hook".into(),
                EventFilter::new(),
                "secret123".into(),
                false,
            )
            .unwrap();
        assert!(registry.unregister(&id));
        assert_eq!(registry.webhooks.len(), 0);
        assert!(!registry.unregister("nonexistent"));
    }

    #[test]
    fn test_list_webhooks() {
        let registry = WebhookRegistry::new();
        registry
            .register("https://a.com/hook".into(), EventFilter::new(), "s1".into(), false)
            .unwrap();
        registry
            .register(
                "https://b.com/hook".into(),
                EventFilter::new().with_event_types(vec![EventType::NewBlock]),
                "s2".into(),
                true,
            )
            .unwrap();
        let list = registry.list();
        assert_eq!(list.len(), 2);
    }

    #[test]
    fn test_get_webhook() {
        let registry = WebhookRegistry::new();
        let id = registry
            .register(
                "https://example.com/hook".into(),
                EventFilter::new(),
                "secret".into(),
                true,
            )
            .unwrap();
        let info = registry.get(&id).unwrap();
        assert_eq!(info.url, "https://example.com/hook");
        assert!(info.confirmed_delivery);
        assert!(info.active);
    }

    #[test]
    fn test_update_filter() {
        let registry = WebhookRegistry::new();
        let id = registry
            .register(
                "https://example.com/hook".into(),
                EventFilter::new(),
                "secret".into(),
                false,
            )
            .unwrap();

        let new_filter = EventFilter::new().with_event_types(vec![EventType::Transfer]);
        assert!(registry.update_filter(&id, new_filter));

        let info = registry.get(&id).unwrap();
        assert_eq!(info.filter.event_types, vec![EventType::Transfer]);
    }

    #[test]
    fn test_enable_disable() {
        let registry = WebhookRegistry::new();
        let id = registry
            .register(
                "https://example.com/hook".into(),
                EventFilter::new(),
                "secret".into(),
                false,
            )
            .unwrap();

        assert!(registry.disable(&id));
        assert!(!registry.get(&id).unwrap().active);

        assert!(registry.enable(&id));
        assert!(registry.get(&id).unwrap().active);
    }

    #[test]
    fn test_hmac_signature_compute_and_verify() {
        let secret = "my_webhook_secret";
        let payload = b"test payload data";

        let sig = compute_signature(secret, payload);
        assert!(!sig.is_empty());
        assert_eq!(sig.len(), 64); // 32 bytes = 64 hex chars

        assert!(verify_signature(secret, payload, &sig));
        assert!(!verify_signature("wrong_secret", payload, &sig));
        assert!(!verify_signature(secret, b"different payload", &sig));
        assert!(!verify_signature(secret, payload, "not_valid_hex_zzz"));
    }

    #[test]
    fn test_hmac_signature_deterministic() {
        let secret = "deterministic_test";
        let payload = b"same payload";
        let sig1 = compute_signature(secret, payload);
        let sig2 = compute_signature(secret, payload);
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn test_max_webhooks_capacity() {
        let config = WebhookEngineConfig {
            max_webhooks: 2,
            ..Default::default()
        };
        let registry = WebhookRegistry::with_config(config);
        registry
            .register("https://a.com".into(), EventFilter::new(), "s".into(), false)
            .unwrap();
        registry
            .register("https://b.com".into(), EventFilter::new(), "s".into(), false)
            .unwrap();
        let result = registry.register(
            "https://c.com".into(),
            EventFilter::new(),
            "s".into(),
            false,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_webhook_payload_serialization() {
        let payload = WebhookPayload {
            webhook_id: "wh_1".into(),
            event: serde_json::json!({"type": "block"}),
            confirmed: false,
            timestamp: 1234567890,
            sequence: 42,
        };
        let json = serde_json::to_string(&payload).unwrap();
        let deser: WebhookPayload = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.webhook_id, "wh_1");
        assert_eq!(deser.sequence, 42);
        assert!(!deser.confirmed);
    }

    #[test]
    fn test_filter_matching_for_delivery() {
        let registry = WebhookRegistry::new();
        let _id = registry
            .register(
                "https://example.com/hook".into(),
                EventFilter::new().with_event_types(vec![EventType::Transfer]),
                "secret".into(),
                false,
            )
            .unwrap();

        let block_env = make_envelope(1, make_block());
        let transfer_env = make_envelope(2, make_transfer());

        let wh = registry.webhooks.iter().next().unwrap();
        assert!(!wh.filter.matches(&block_env));
        assert!(wh.filter.matches(&transfer_env));
    }

    #[test]
    fn test_stats_default() {
        let stats = WebhookStats::default();
        assert_eq!(stats.total_deliveries, 0);
        assert_eq!(stats.successful_deliveries, 0);
        assert_eq!(stats.failed_deliveries, 0);
        assert!(stats.last_delivery_at.is_none());
        assert!(stats.last_error.is_none());
    }

    #[test]
    fn test_auto_disable_after_failures() {
        let config = WebhookEngineConfig {
            disable_after_failures: 3,
            ..Default::default()
        };
        let registry = WebhookRegistry::with_config(config);
        let id = registry
            .register(
                "https://example.com/hook".into(),
                EventFilter::new(),
                "secret".into(),
                false,
            )
            .unwrap();

        for _ in 0..3 {
            record_failure(
                &registry.delivery_stats,
                &registry.webhooks,
                &id,
                "connection refused",
                registry.config.disable_after_failures,
            );
        }

        let info = registry.get(&id).unwrap();
        assert!(!info.active);
        assert_eq!(info.stats.failed_deliveries, 3);
        assert_eq!(info.stats.last_error.as_deref(), Some("connection refused"));
    }
}
