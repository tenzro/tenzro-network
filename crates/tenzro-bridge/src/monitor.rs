//! Cross-chain transfer monitoring
//!
//! Provides a background polling service that tracks the status of pending
//! cross-chain transfers across all registered bridge adapters and emits
//! status update events.

use crate::traits::{BridgeAdapter, TransferStatus};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, mpsc, RwLock};
use tracing::{debug, info, warn};

/// Event emitted when a transfer status changes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferStatusEvent {
    /// Transfer ID
    pub transfer_id: String,
    /// Adapter that reported the status
    pub adapter_name: String,
    /// Previous status (None if first observation)
    pub previous_status: Option<TransferStatus>,
    /// New status
    pub new_status: TransferStatus,
    /// Timestamp of the status change (Unix millis)
    pub timestamp: i64,
    /// Source chain
    pub source_chain: String,
    /// Destination chain
    pub dest_chain: String,
}

/// A transfer being monitored
#[derive(Debug, Clone)]
struct MonitoredTransfer {
    /// Transfer ID (used by Debug formatting and status events)
    #[allow(dead_code)]
    transfer_id: String,
    /// Name of the adapter that initiated the transfer
    adapter_name: String,
    /// Current known status
    current_status: TransferStatus,
    /// Source chain
    source_chain: String,
    /// Destination chain
    dest_chain: String,
    /// Number of consecutive poll failures
    failure_count: u32,
    /// Maximum poll failures before giving up
    max_failures: u32,
}

/// Configuration for the transfer monitor
#[derive(Debug, Clone)]
pub struct MonitorConfig {
    /// Base polling interval
    pub poll_interval: Duration,
    /// Maximum polling interval (used with exponential backoff on errors)
    pub max_poll_interval: Duration,
    /// Maximum number of consecutive failures before marking a transfer as failed
    pub max_failures: u32,
    /// Channel buffer size for status events
    pub event_buffer_size: usize,
}

impl Default for MonitorConfig {
    fn default() -> Self {
        Self {
            poll_interval: Duration::from_secs(15),
            max_poll_interval: Duration::from_secs(120),
            max_failures: 20,
            event_buffer_size: 256,
        }
    }
}

/// Cross-chain transfer monitor
///
/// Runs a background task that periodically polls adapter `get_transfer_status()`
/// for all pending transfers and emits status change events via a broadcast channel.
///
/// # Usage
///
/// ```ignore
/// let monitor = TransferMonitor::new(MonitorConfig::default());
///
/// // Subscribe to status events
/// let mut rx = monitor.subscribe();
///
/// // Register adapters
/// monitor.register_adapter("layerzero", adapter).await;
///
/// // Start monitoring a transfer
/// monitor.track_transfer("lz-tx-123", "layerzero", "ethereum", "arbitrum").await;
///
/// // Start the background polling task
/// let handle = monitor.start();
///
/// // Listen for events
/// while let Ok(event) = rx.recv().await {
///     println!("Transfer {} is now {:?}", event.transfer_id, event.new_status);
/// }
///
/// // Stop monitoring
/// monitor.stop();
/// ```
pub struct TransferMonitor {
    /// Registered adapters
    adapters: Arc<RwLock<Vec<(String, Arc<dyn BridgeAdapter>)>>>,
    /// Transfers being monitored
    transfers: Arc<DashMap<String, MonitoredTransfer>>,
    /// Broadcast channel for status events
    event_tx: broadcast::Sender<TransferStatusEvent>,
    /// Configuration
    config: MonitorConfig,
    /// Shutdown signal
    shutdown_tx: mpsc::Sender<()>,
    /// Shutdown receiver (moved into the polling task)
    shutdown_rx: Arc<tokio::sync::Mutex<Option<mpsc::Receiver<()>>>>,
}

impl TransferMonitor {
    /// Creates a new transfer monitor
    pub fn new(config: MonitorConfig) -> Self {
        let (event_tx, _) = broadcast::channel(config.event_buffer_size);
        let (shutdown_tx, shutdown_rx) = mpsc::channel(1);

        Self {
            adapters: Arc::new(RwLock::new(Vec::new())),
            transfers: Arc::new(DashMap::new()),
            event_tx,
            config,
            shutdown_tx,
            shutdown_rx: Arc::new(tokio::sync::Mutex::new(Some(shutdown_rx))),
        }
    }

    /// Registers an adapter for monitoring
    pub async fn register_adapter(&self, name: impl Into<String>, adapter: Arc<dyn BridgeAdapter>) {
        let name = name.into();
        info!("Monitor: Registered adapter '{}'", name);
        self.adapters.write().await.push((name, adapter));
    }

    /// Starts tracking a transfer
    pub async fn track_transfer(
        &self,
        transfer_id: impl Into<String>,
        adapter_name: impl Into<String>,
        source_chain: impl Into<String>,
        dest_chain: impl Into<String>,
    ) {
        let transfer_id = transfer_id.into();
        let adapter_name = adapter_name.into();
        let source_chain = source_chain.into();
        let dest_chain = dest_chain.into();

        info!(
            "Monitor: Tracking transfer {} via {} ({} -> {})",
            transfer_id, adapter_name, source_chain, dest_chain
        );

        self.transfers.insert(
            transfer_id.clone(),
            MonitoredTransfer {
                transfer_id,
                adapter_name,
                current_status: TransferStatus::Pending,
                source_chain,
                dest_chain,
                failure_count: 0,
                max_failures: self.config.max_failures,
            },
        );
    }

    /// Stops tracking a transfer
    pub fn untrack_transfer(&self, transfer_id: &str) {
        if self.transfers.remove(transfer_id).is_some() {
            info!("Monitor: Untracked transfer {}", transfer_id);
        }
    }

    /// Subscribes to transfer status events
    pub fn subscribe(&self) -> broadcast::Receiver<TransferStatusEvent> {
        self.event_tx.subscribe()
    }

    /// Returns the current status of a monitored transfer
    pub fn get_status(&self, transfer_id: &str) -> Option<TransferStatus> {
        self.transfers
            .get(transfer_id)
            .map(|t| t.current_status)
    }

    /// Returns the number of actively monitored transfers
    pub fn active_transfer_count(&self) -> usize {
        self.transfers
            .iter()
            .filter(|t| t.current_status.is_in_progress())
            .count()
    }

    /// Returns all monitored transfer IDs
    pub fn transfer_ids(&self) -> Vec<String> {
        self.transfers.iter().map(|t| t.key().clone()).collect()
    }

    /// Starts the background polling task
    ///
    /// Returns a `JoinHandle` that can be awaited for the polling task.
    pub fn start(&self) -> tokio::task::JoinHandle<()> {
        let adapters = self.adapters.clone();
        let transfers = self.transfers.clone();
        let event_tx = self.event_tx.clone();
        let config = self.config.clone();
        let shutdown_rx = self.shutdown_rx.clone();

        tokio::spawn(async move {
            // Take the shutdown receiver
            let mut shutdown = match shutdown_rx.lock().await.take() {
                Some(rx) => rx,
                None => {
                    warn!("Monitor: Already started, cannot start again");
                    return;
                }
            };

            info!(
                "Monitor: Started with poll interval {:?}",
                config.poll_interval
            );

            loop {
                // Check for shutdown
                tokio::select! {
                    _ = shutdown.recv() => {
                        info!("Monitor: Received shutdown signal");
                        break;
                    }
                    _ = tokio::time::sleep(config.poll_interval) => {
                        // Poll all pending transfers
                        Self::poll_transfers(&adapters, &transfers, &event_tx, &config).await;
                    }
                }
            }

            info!("Monitor: Stopped");
        })
    }

    /// Signals the monitor to stop
    pub fn stop(&self) {
        let _ = self.shutdown_tx.try_send(());
    }

    /// Polls all pending transfers for status updates
    async fn poll_transfers(
        adapters: &Arc<RwLock<Vec<(String, Arc<dyn BridgeAdapter>)>>>,
        transfers: &Arc<DashMap<String, MonitoredTransfer>>,
        event_tx: &broadcast::Sender<TransferStatusEvent>,
        _config: &MonitorConfig,
    ) {
        let adapter_list = adapters.read().await;

        // Collect transfer IDs to poll (only in-progress ones)
        let pending_ids: Vec<String> = transfers
            .iter()
            .filter(|t| t.current_status.is_in_progress())
            .map(|t| t.key().clone())
            .collect();

        if pending_ids.is_empty() {
            return;
        }

        debug!("Monitor: Polling {} pending transfers", pending_ids.len());

        for transfer_id in &pending_ids {
            let transfer = match transfers.get(transfer_id) {
                Some(t) => t.clone(),
                None => continue,
            };

            // Find the adapter for this transfer
            let adapter = adapter_list
                .iter()
                .find(|(name, _)| *name == transfer.adapter_name)
                .map(|(_, adapter)| adapter.clone());

            let adapter = match adapter {
                Some(a) => a,
                None => {
                    warn!(
                        "Monitor: Adapter '{}' not found for transfer {}",
                        transfer.adapter_name, transfer_id
                    );
                    continue;
                }
            };

            // Query status
            match adapter.get_transfer_status(transfer_id).await {
                Ok(new_status) => {
                    if new_status != transfer.current_status {
                        info!(
                            "Monitor: Transfer {} status changed: {:?} -> {:?}",
                            transfer_id, transfer.current_status, new_status
                        );

                        let event = TransferStatusEvent {
                            transfer_id: transfer_id.clone(),
                            adapter_name: transfer.adapter_name.clone(),
                            previous_status: Some(transfer.current_status),
                            new_status,
                            timestamp: chrono::Utc::now().timestamp_millis(),
                            source_chain: transfer.source_chain.clone(),
                            dest_chain: transfer.dest_chain.clone(),
                        };

                        // Update status in map
                        if let Some(mut entry) = transfers.get_mut(transfer_id) {
                            entry.current_status = new_status;
                            entry.failure_count = 0; // Reset failure count on success
                        }

                        // Emit event (ignore send errors — no subscribers is OK)
                        let _ = event_tx.send(event);
                    }
                }
                Err(e) => {
                    debug!(
                        "Monitor: Failed to get status for {}: {}",
                        transfer_id, e
                    );

                    // Increment failure count
                    if let Some(mut entry) = transfers.get_mut(transfer_id) {
                        entry.failure_count += 1;

                        if entry.failure_count >= entry.max_failures {
                            warn!(
                                "Monitor: Transfer {} exceeded max failures ({}), marking as failed",
                                transfer_id, entry.max_failures
                            );

                            let event = TransferStatusEvent {
                                transfer_id: transfer_id.clone(),
                                adapter_name: entry.adapter_name.clone(),
                                previous_status: Some(entry.current_status),
                                new_status: TransferStatus::Failed,
                                timestamp: chrono::Utc::now().timestamp_millis(),
                                source_chain: entry.source_chain.clone(),
                                dest_chain: entry.dest_chain.clone(),
                            };

                            entry.current_status = TransferStatus::Failed;
                            let _ = event_tx.send(event);
                        }
                    }
                }
            }
        }

        // Clean up finalized transfers older than the replay window
        // Keep them around for a bit so clients can query final status
        // but don't actively poll them
    }
}

impl Default for TransferMonitor {
    fn default() -> Self {
        Self::new(MonitorConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layerzero::{LayerZeroAdapter, LayerZeroConfig};

    #[tokio::test]
    async fn test_monitor_creation() {
        let monitor = TransferMonitor::new(MonitorConfig::default());
        assert_eq!(monitor.active_transfer_count(), 0);
        assert!(monitor.transfer_ids().is_empty());
    }

    #[tokio::test]
    async fn test_track_transfer() {
        let monitor = TransferMonitor::new(MonitorConfig::default());

        monitor
            .track_transfer("tx-123", "layerzero", "ethereum", "arbitrum")
            .await;

        assert_eq!(monitor.active_transfer_count(), 1);
        assert_eq!(
            monitor.get_status("tx-123"),
            Some(TransferStatus::Pending)
        );
    }

    #[tokio::test]
    async fn test_untrack_transfer() {
        let monitor = TransferMonitor::new(MonitorConfig::default());

        monitor
            .track_transfer("tx-123", "layerzero", "ethereum", "arbitrum")
            .await;
        assert_eq!(monitor.active_transfer_count(), 1);

        monitor.untrack_transfer("tx-123");
        assert_eq!(monitor.active_transfer_count(), 0);
    }

    #[tokio::test]
    async fn test_subscribe_and_poll() {
        let config = MonitorConfig {
            poll_interval: Duration::from_millis(50),
            max_failures: 3,
            ..Default::default()
        };
        let monitor = TransferMonitor::new(config);

        // Register a LayerZero adapter (no signer — status polling still works)
        let lz_config = LayerZeroConfig::new(
            "0x1a44076050125825900e736c501f859c50fE728c",
            30101,
            "0x0000000000000000000000000000000000000001",
            "0x0000000000000000000000000000000000000002",
        );
        let lz_adapter = Arc::new(LayerZeroAdapter::new(lz_config));

        // Track a synthetic transfer ID directly — bridge_tokens() requires a
        // real EVM signer, but the monitor's poll loop only needs an adapter
        // registered for status queries.
        let transfer_id = "lz-oft-ethereum-arbitrum-test-1";

        monitor
            .register_adapter("layerzero", lz_adapter)
            .await;
        monitor
            .track_transfer(
                transfer_id,
                "layerzero",
                "ethereum",
                "arbitrum",
            )
            .await;

        assert_eq!(monitor.active_transfer_count(), 1);
        assert_eq!(
            monitor.get_status(transfer_id),
            Some(TransferStatus::Pending)
        );

        // Start monitor and let it poll once
        let handle = monitor.start();

        // Give it time to poll
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Stop the monitor
        monitor.stop();

        // Wait for the task to finish
        let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;
    }

    #[tokio::test]
    async fn test_monitor_multiple_transfers() {
        let monitor = TransferMonitor::new(MonitorConfig::default());

        monitor
            .track_transfer("tx-1", "layerzero", "ethereum", "arbitrum")
            .await;
        monitor
            .track_transfer("tx-2", "chainlink", "ethereum", "polygon")
            .await;
        monitor
            .track_transfer("tx-3", "debridge", "arbitrum", "bsc")
            .await;

        assert_eq!(monitor.active_transfer_count(), 3);

        let ids = monitor.transfer_ids();
        assert_eq!(ids.len(), 3);
        assert!(ids.contains(&"tx-1".to_string()));
        assert!(ids.contains(&"tx-2".to_string()));
        assert!(ids.contains(&"tx-3".to_string()));
    }

    #[tokio::test]
    async fn test_monitor_nonexistent_transfer() {
        let monitor = TransferMonitor::new(MonitorConfig::default());
        assert_eq!(monitor.get_status("nonexistent"), None);
    }
}
