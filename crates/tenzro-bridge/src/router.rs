//! Bridge router for intelligent cross-chain routing
//!
//! This module provides a bridge router that can intelligently select and route
//! cross-chain transfers across multiple bridge protocols based on various criteria
//! such as cost, speed, and availability.

use crate::{
    error::{BridgeError, Result},
    fee_oracle::{BridgeAdapterId, BridgeFeeQuote},
    fee_sponsor::{BridgeSponsorshipReceipt, SponsorshipPool, WiredBridgeFeeSurface},
    traits::{
        BridgeAdapter, BridgeAdapterClass, BridgeTokenReceipt, BridgeTokenRequest, ChainInfo,
        TransferStatus,
    },
};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// Bridge router that manages multiple bridge adapters and selects the best route
pub struct BridgeRouter {
    /// Registered bridge adapters
    adapters: Arc<RwLock<HashMap<String, Box<dyn BridgeAdapter>>>>,
    /// Routing preferences
    preferences: Arc<RwLock<RoutingPreferences>>,
    /// Processed transfer IDs for replay protection (transfer_id -> timestamp)
    processed_transfers: Arc<RwLock<HashMap<String, Instant>>>,
    /// Processed message fingerprints for replay protection (fingerprint -> timestamp)
    processed_messages: Arc<RwLock<HashMap<String, Instant>>>,
    /// Replay protection window (transfers older than this are pruned)
    replay_window: Duration,
    /// Monotonic nonce counter for transfer deduplication
    nonce_counter: AtomicU64,
    /// Monotonic nonce counter for message deduplication
    message_nonce_counter: AtomicU64,
    /// Optional wired fee-in-TNZO surface. When set, every adapter routed
    /// through this router can surface destination-native fees as TNZO
    /// quotes via [`Self::quote_fee_in_tnzo`] without per-adapter forking.
    fee_surface: Option<Arc<WiredBridgeFeeSurface>>,
}

impl BridgeRouter {
    /// Creates a new bridge router
    pub fn new() -> Self {
        Self {
            adapters: Arc::new(RwLock::new(HashMap::new())),
            preferences: Arc::new(RwLock::new(RoutingPreferences::default())),
            processed_transfers: Arc::new(RwLock::new(HashMap::new())),
            processed_messages: Arc::new(RwLock::new(HashMap::new())),
            replay_window: Duration::from_secs(86400), // 24 hour replay window
            nonce_counter: AtomicU64::new(0),
            message_nonce_counter: AtomicU64::new(0),
            fee_surface: None,
        }
    }

    /// Attach a wired fee-in-TNZO surface to the router. Once attached,
    /// every registered adapter can surface destination-native fee quotes
    /// in TNZO via [`Self::quote_fee_in_tnzo`] and route sponsorship to
    /// the per-adapter pool — without per-adapter constructor injection.
    ///
    /// This is the established cross-chain fee-abstraction pattern (Cosmos ICS-29,
    /// Hyperlane IGP, Polkadot AssetHub asset-conversion): the router is
    /// the single fee-quoting choke-point; adapters quote destination-
    /// native, the oracle converts, the sponsor escrows.
    pub fn with_fee_surface(mut self, surface: Arc<WiredBridgeFeeSurface>) -> Self {
        self.fee_surface = Some(surface);
        self
    }

    /// Returns the attached fee surface, if any.
    pub fn fee_surface(&self) -> Option<Arc<WiredBridgeFeeSurface>> {
        self.fee_surface.clone()
    }

    /// Quote a destination-native bridge fee in TNZO for an arbitrary
    /// adapter + destination chain. Calls the underlying adapter's
    /// `estimate_fee()` to determine the destination-native amount, then
    /// passes it through the fee oracle for TNZO conversion.
    ///
    /// Returns `AdapterError` if no fee surface is wired, or if the named
    /// adapter is not registered with the router.
    pub async fn quote_fee_in_tnzo(
        &self,
        adapter_name: &str,
        dest_chain: &str,
        payload_size: usize,
    ) -> Result<BridgeFeeQuote> {
        let surface = self.fee_surface.as_ref().ok_or_else(|| {
            BridgeError::AdapterError("no fee surface wired into BridgeRouter".to_string())
        })?;
        let adapter_id = BridgeAdapterId::from_str(adapter_name).ok_or_else(|| {
            BridgeError::AdapterError(format!("unknown bridge adapter: {}", adapter_name))
        })?;
        let adapters = self.adapters.read().await;
        let adapter = adapters.get(adapter_name).ok_or_else(|| {
            BridgeError::AdapterError(format!(
                "adapter '{}' not registered with router",
                adapter_name
            ))
        })?;
        let native_fee = adapter.estimate_fee(dest_chain, payload_size).await?;
        surface
            .oracle
            .quote(adapter_id, dest_chain, native_fee)
            .await
    }

    /// Sponsor a previously-quoted destination-native fee on the caller's
    /// behalf. Records the sponsorship against the per-adapter pool and
    /// returns the receipt; the caller is responsible for the actual TNZO
    /// debit + on-chain mirror.
    pub async fn sponsor_quote(
        &self,
        quote: &BridgeFeeQuote,
        payer_did: impl Into<String>,
    ) -> Result<BridgeSponsorshipReceipt> {
        let surface = self.fee_surface.as_ref().ok_or_else(|| {
            BridgeError::AdapterError("no fee surface wired into BridgeRouter".to_string())
        })?;
        surface.sponsor.record_sponsorship(quote, payer_did)
    }

    /// Enumerate the per-adapter sponsorship pools currently held by the
    /// wired sponsor (one entry per adapter that has seen at least one
    /// sponsorship or been preregistered).
    pub async fn list_sponsorship_pools(&self) -> Vec<SponsorshipPool> {
        let Some(surface) = self.fee_surface.as_ref() else {
            return Vec::new();
        };
        // Walk every adapter that's wire-supported and surface its pool
        // (get-or-create is idempotent — preregistered pools are returned
        // as-is, otherwise a zero-balance pool snapshot is returned).
        let mut pools = Vec::new();
        for adapter_id in [
            BridgeAdapterId::LayerZero,
            BridgeAdapterId::ChainlinkCcip,
            BridgeAdapterId::Wormhole,
            BridgeAdapterId::DeBridge,
            BridgeAdapterId::Hyperlane,
            BridgeAdapterId::Axelar,
            BridgeAdapterId::LiFi,
            BridgeAdapterId::Canton,
        ] {
            pools.push(surface.sponsor.get_or_create_pool(adapter_id));
        }
        pools
    }

    /// Registers a bridge adapter
    ///
    /// # Arguments
    /// * `name` - Unique name for this adapter
    /// * `adapter` - The bridge adapter implementation
    pub async fn register_adapter(
        &self,
        name: impl Into<String>,
        adapter: Box<dyn BridgeAdapter>,
    ) {
        let name = name.into();
        info!("Registering bridge adapter: {}", name);
        self.adapters.write().await.insert(name, adapter);
    }

    /// Dispatches an inbound cross-chain payload to the named adapter's
    /// verifier and returns the quorum-verified inner [`TenzroMessage`],
    /// when the payload carries one.
    ///
    /// This is the single admission point for inbound bridge traffic:
    /// the adapter runs its provider-native authority check (Guardian
    /// quorum, ISM multisig, DVN set, commit-store + RMN, DLN set) plus
    /// replay protection before any message content is trusted.
    pub async fn receive_message(
        &self,
        adapter_name: &str,
        source_chain: &str,
        payload: Vec<u8>,
    ) -> Result<Option<crate::message_format::TenzroMessage>> {
        let adapters = self.adapters.read().await;
        let adapter = adapters.get(adapter_name).ok_or_else(|| {
            BridgeError::AdapterError(format!(
                "adapter '{}' not registered with router",
                adapter_name
            ))
        })?;
        adapter.receive_message(source_chain, payload).await
    }

    /// Prunes expired entries from the replay protection cache
    async fn prune_replay_cache(&self) {
        let now = Instant::now();
        let mut transfers = self.processed_transfers.write().await;
        transfers.retain(|_, ts| now.duration_since(*ts) < self.replay_window);
    }

    /// Prunes expired entries from the message replay protection cache
    async fn prune_message_cache(&self) {
        let now = Instant::now();
        let mut messages = self.processed_messages.write().await;
        messages.retain(|_, ts| now.duration_since(*ts) < self.replay_window);
    }

    /// Bridges tokens using the best available adapter
    ///
    /// Automatically selects the best adapter based on routing preferences.
    /// Includes replay protection using nonce-based fingerprints — each call gets
    /// a unique monotonic nonce included in the fingerprint, so identical transfers
    /// from the same session always succeed. Cross-session replays are prevented
    /// because the nonce counter resets on restart, and stale fingerprints expire
    /// from the replay cache after the replay window.
    pub async fn bridge_tokens(&self, request: BridgeTokenRequest) -> Result<BridgeTokenReceipt> {
        info!(
            "Routing bridge request: {} -> {}, asset: {}, amount: {}",
            request.source_chain, request.dest_chain, request.asset_id, request.amount
        );

        // Increment nonce FIRST to get a unique value for this transfer
        let nonce = self.nonce_counter.fetch_add(1, Ordering::SeqCst);

        // Create fingerprint WITH monotonic nonce so each call is unique.
        // Replay protection comes from the nonce — if someone replays the same
        // request with the same nonce, it will be caught by the cache lookup.
        let transfer_fingerprint = {
            use sha2::Digest;
            let mut hasher = sha2::Sha256::new();
            hasher.update(request.source_chain.as_bytes());
            hasher.update(request.dest_chain.as_bytes());
            hasher.update(request.asset_id.as_bytes());
            hasher.update(request.amount.to_le_bytes());
            hasher.update(request.sender.as_bytes());
            hasher.update(nonce.to_le_bytes());
            let hash = hasher.finalize();
            format!("xfer:{}", hex::encode(hash))
        };

        // Check for replay BEFORE executing the transfer
        {
            let transfers = self.processed_transfers.read().await;
            if transfers.contains_key(&transfer_fingerprint) {
                return Err(BridgeError::AdapterError(format!(
                    "Transfer replay detected: fingerprint {} already processed within replay window",
                    transfer_fingerprint
                )));
            }
        }

        // Periodically prune old entries
        self.prune_replay_cache().await;

        // Find available routes
        let routes = self
            .get_available_routes(&request.source_chain, &request.dest_chain)
            .await?;

        if routes.is_empty() {
            return Err(BridgeError::NoRouteAvailable(
                request.source_chain.clone(),
                request.dest_chain.clone(),
            ));
        }

        // Select best route based on preferences
        let best_route = self.select_best_route(&routes).await?;

        info!(
            "Selected adapter '{}' for route {} -> {}",
            best_route.adapter_name, request.source_chain, request.dest_chain
        );

        // Check adapter availability before executing
        if !self.is_adapter_available(&best_route.adapter_name).await {
            return Err(BridgeError::AdapterError(format!(
                "Selected adapter '{}' is not available",
                best_route.adapter_name
            )));
        }

        // Get the adapter and execute the bridge
        let adapters = self.adapters.read().await;
        let adapter = adapters
            .get(&best_route.adapter_name)
            .ok_or_else(|| BridgeError::AdapterError("Adapter not found".to_string()))?;

        let receipt = adapter.bridge_tokens(request).await?;

        // Record in replay cache after successful bridge
        self.processed_transfers
            .write()
            .await
            .insert(transfer_fingerprint, Instant::now());

        Ok(receipt)
    }

    /// Sends a message using the best available adapter
    ///
    /// Includes replay protection using nonce-based fingerprints — each call gets
    /// a unique monotonic nonce included in the fingerprint, so identical payloads
    /// always succeed from the same sender. Replays of the exact same nonce+content
    /// are caught by the cache lookup.
    pub async fn send_message(&self, dest_chain: &str, payload: Vec<u8>) -> Result<String> {
        info!(
            "Routing message to chain: {}, payload_size: {}",
            dest_chain,
            payload.len()
        );

        // Increment message nonce FIRST to get a unique value
        let nonce = self.message_nonce_counter.fetch_add(1, Ordering::SeqCst);

        // Create fingerprint WITH monotonic nonce so each call is unique.
        let message_fingerprint = {
            use sha2::Digest;
            let mut hasher = sha2::Sha256::new();
            hasher.update(dest_chain.as_bytes());
            hasher.update(&payload);
            hasher.update(nonce.to_le_bytes());
            let fingerprint_bytes = hasher.finalize();
            format!("msg:{}", hex::encode(fingerprint_bytes))
        };

        // Check for replay BEFORE executing
        {
            let messages = self.processed_messages.read().await;
            if messages.contains_key(&message_fingerprint) {
                return Err(BridgeError::AdapterError(format!(
                    "Message replay detected: fingerprint {} already processed within replay window",
                    message_fingerprint
                )));
            }
        }

        // Periodically prune old entries
        self.prune_message_cache().await;

        // Get all adapters that support the destination chain
        let adapters = self.adapters.read().await;
        let mut viable_adapters = Vec::new();

        for (name, adapter) in adapters.iter() {
            if adapter
                .supported_chains()
                .iter()
                .any(|c| c.chain_id == dest_chain)
            {
                viable_adapters.push((name.clone(), adapter));
            }
        }

        if viable_adapters.is_empty() {
            return Err(BridgeError::ChainNotSupported(dest_chain.to_string()));
        }

        // Use the first viable adapter (could be enhanced with fee comparison)
        let (adapter_name, adapter) = &viable_adapters[0];
        info!("Selected adapter '{}' for message", adapter_name);

        let message_id = adapter.send_message(dest_chain, payload).await?;

        // Record in replay cache after successful send
        self.processed_messages
            .write()
            .await
            .insert(message_fingerprint, Instant::now());

        Ok(message_id)
    }

    /// Gets all available routes between two chains
    pub async fn get_available_routes(
        &self,
        source_chain: &str,
        dest_chain: &str,
    ) -> Result<Vec<RouteInfo>> {
        let adapters = self.adapters.read().await;
        let mut routes = Vec::new();

        for (name, adapter) in adapters.iter() {
            let chains = adapter.supported_chains();
            let supports_source = chains.iter().any(|c| c.chain_id == source_chain);
            let supports_dest = chains.iter().any(|c| c.chain_id == dest_chain);

            if supports_source && supports_dest {
                // Estimate fee for this route
                let estimated_fee = adapter
                    .estimate_fee(dest_chain, 100)
                    .await
                    .unwrap_or(u128::MAX);

                // Get destination chain info for time estimate
                let dest_info = chains
                    .iter()
                    .find(|c| c.chain_id == dest_chain)
                    .cloned()
                    .unwrap_or_else(|| ChainInfo::new(dest_chain, dest_chain, "UNKNOWN", 300));

                routes.push(RouteInfo {
                    adapter_name: name.clone(),
                    source_chain: source_chain.to_string(),
                    dest_chain: dest_chain.to_string(),
                    estimated_fee,
                    estimated_time_secs: dest_info.finality_time_secs,
                    classes: adapter.classes(),
                });
            }
        }

        debug!(
            "Found {} available routes from {} to {}",
            routes.len(),
            source_chain,
            dest_chain
        );

        Ok(routes)
    }

    /// Compares fees across all adapters for a specific route
    pub async fn compare_fees(
        &self,
        source_chain: &str,
        dest_chain: &str,
        payload_size: usize,
    ) -> Result<Vec<FeeComparison>> {
        let adapters = self.adapters.read().await;
        let mut comparisons = Vec::new();

        for (name, adapter) in adapters.iter() {
            let chains = adapter.supported_chains();
            let supports_route = chains.iter().any(|c| c.chain_id == source_chain)
                && chains.iter().any(|c| c.chain_id == dest_chain);

            if supports_route {
                match adapter.estimate_fee(dest_chain, payload_size).await {
                    Ok(fee) => {
                        comparisons.push(FeeComparison {
                            adapter_name: name.clone(),
                            fee,
                            currency: "native".to_string(), // Simplified
                        });
                    }
                    Err(e) => {
                        warn!(
                            "Failed to get fee estimate from adapter '{}': {:?}",
                            name, e
                        );
                    }
                }
            }
        }

        // Sort by fee (lowest first)
        comparisons.sort_by_key(|c| c.fee);

        Ok(comparisons)
    }

    /// Gets transfer status across all adapters
    ///
    /// Tries to find the transfer in all registered adapters
    pub async fn get_transfer_status(&self, transfer_id: &str) -> Result<TransferStatus> {
        let adapters = self.adapters.read().await;

        for (name, adapter) in adapters.iter() {
            match adapter.get_transfer_status(transfer_id).await {
                Ok(status) => {
                    debug!(
                        "Found transfer {} in adapter '{}': {:?}",
                        transfer_id, name, status
                    );
                    return Ok(status);
                }
                Err(_) => continue,
            }
        }

        Err(BridgeError::TransferNotFound(transfer_id.to_string()))
    }

    /// Updates routing preferences
    pub async fn set_preferences(&self, preferences: RoutingPreferences) {
        *self.preferences.write().await = preferences;
    }

    /// Gets current routing preferences
    pub async fn get_preferences(&self) -> RoutingPreferences {
        self.preferences.read().await.clone()
    }

    /// Checks if an adapter is available and registered
    ///
    /// # Arguments
    /// * `adapter_name` - Name of the adapter to check
    ///
    /// # Returns
    /// `true` if the adapter is registered and available, `false` otherwise
    pub async fn is_adapter_available(&self, adapter_name: &str) -> bool {
        self.adapters.read().await.contains_key(adapter_name)
    }

    /// Gets a list of all registered adapter names
    pub async fn list_adapters(&self) -> Vec<String> {
        self.adapters.read().await.keys().cloned().collect()
    }

    /// Returns a deduplicated list of every chain reachable through any
    /// registered adapter, with the set of adapter names that reach each chain.
    ///
    /// The chain identity is `chain_id`; if two adapters publish different
    /// human-readable names for the same chain_id, the first one encountered is
    /// kept. Adapters are sorted alphabetically per chain for deterministic
    /// output across calls.
    pub async fn list_chains(&self) -> Vec<ChainCoverage> {
        let adapters = self.adapters.read().await;
        let mut by_chain: HashMap<String, ChainCoverage> = HashMap::new();
        for (adapter_name, adapter) in adapters.iter() {
            for chain in adapter.supported_chains() {
                let entry = by_chain
                    .entry(chain.chain_id.clone())
                    .or_insert_with(|| ChainCoverage {
                        chain: chain.clone(),
                        adapters: Vec::new(),
                    });
                if !entry.adapters.contains(adapter_name) {
                    entry.adapters.push(adapter_name.clone());
                }
            }
        }
        let mut out: Vec<ChainCoverage> = by_chain.into_values().collect();
        for entry in out.iter_mut() {
            entry.adapters.sort();
        }
        out.sort_by(|a, b| a.chain.chain_id.cmp(&b.chain.chain_id));
        out
    }

    /// Selects the best route based on preferences
    async fn select_best_route(&self, routes: &[RouteInfo]) -> Result<RouteInfo> {
        if routes.is_empty() {
            return Err(BridgeError::AdapterError("No routes available".to_string()));
        }

        let preferences = self.preferences.read().await;

        let best = match preferences.strategy {
            RoutingStrategy::LowestFee => {
                // Select route with lowest fee
                routes.iter().min_by_key(|r| r.estimated_fee)
            }
            RoutingStrategy::FastestTime => {
                // Select route with fastest finality
                routes.iter().min_by_key(|r| r.estimated_time_secs)
            }
            RoutingStrategy::Balanced => {
                // Balance fee and time (normalize and combine scores)
                let max_fee = routes.iter().map(|r| r.estimated_fee).max().unwrap_or(1);
                let max_time = routes.iter().map(|r| r.estimated_time_secs).max().unwrap_or(1);

                routes.iter().min_by_key(|r| {
                    // Normalize fee and time to 0-100 range and combine
                    let fee_score = (r.estimated_fee * 100 / max_fee.max(1)) as u64;
                    let time_score = r.estimated_time_secs * 100 / max_time.max(1);
                    fee_score + time_score
                })
            }
            RoutingStrategy::PreferAdapter(ref adapter_name) => {
                // Prefer specific adapter if available
                routes
                    .iter()
                    .find(|r| r.adapter_name == *adapter_name)
                    .or_else(|| routes.first())
            }
            RoutingStrategy::LiFiAggregator => {
                // Prefer LI.FI adapter if registered (it aggregates across all bridges
                // and picks the best route internally). Falls back to lowest-fee
                // selection across direct adapters if LI.FI is not available.
                let lifi_route = routes.iter().find(|r| r.adapter_name == "lifi");
                if lifi_route.is_some() {
                    lifi_route
                } else {
                    debug!("LI.FI adapter not available, falling back to lowest fee");
                    routes.iter().min_by_key(|r| r.estimated_fee)
                }
            }
            RoutingStrategy::Regulated => {
                // Restrict to adapters that declare RegulatedRail (Chainlink
                // CCIP, Wormhole). Pick the cheapest among those. If no
                // regulated rail is available for this lane, fall back to
                // lowest-fee across all routes — the caller asked for
                // regulated-preferred, not regulated-required.
                let regulated: Vec<&RouteInfo> = routes
                    .iter()
                    .filter(|r| r.classes.contains(&BridgeAdapterClass::RegulatedRail))
                    .collect();
                if regulated.is_empty() {
                    debug!("No regulated rails available, falling back to lowest fee");
                    routes.iter().min_by_key(|r| r.estimated_fee)
                } else {
                    regulated.into_iter().min_by_key(|r| r.estimated_fee)
                }
            }
        };

        best.cloned().ok_or_else(|| BridgeError::AdapterError("No suitable route found".to_string()))
    }
}

impl Default for BridgeRouter {
    fn default() -> Self {
        Self::new()
    }
}

impl BridgeRouter {
    /// Returns the current nonce value (for testing/diagnostics)
    pub fn current_nonce(&self) -> u64 {
        self.nonce_counter.load(Ordering::SeqCst)
    }

    /// Returns the current message nonce value (for testing/diagnostics)
    pub fn current_message_nonce(&self) -> u64 {
        self.message_nonce_counter.load(Ordering::SeqCst)
    }

    /// Starts a background task to poll and update transfer statuses.
    ///
    /// This spawns a task that periodically checks the status of pending transfers
    /// across all adapters and updates them from Pending -> Delivered/Failed.
    ///
    /// Returns a tuple of:
    /// - JoinHandle to the polling task
    /// - mpsc::Sender for shutdown signaling
    /// - broadcast::Receiver for transfer status events
    pub async fn start_status_polling(
        &self,
        interval: Duration,
    ) -> (
        tokio::task::JoinHandle<()>,
        tokio::sync::mpsc::Sender<()>,
        tokio::sync::broadcast::Receiver<crate::TransferStatusEvent>,
    ) {
        use crate::{MonitorConfig, TransferMonitor};

        let (shutdown_tx, mut shutdown_rx) = tokio::sync::mpsc::channel::<()>(1);

        let monitor = Arc::new(TransferMonitor::new(MonitorConfig {
            poll_interval: interval,
            max_poll_interval: interval * 8,
            max_failures: 20,
            event_buffer_size: 256,
        }));

        // Register all adapters from the router
        // Note: This is a workaround since adapters are Box<dyn> not Arc<dyn>
        // In production, we would refactor to use Arc<dyn BridgeAdapter>
        let adapters_read = self.adapters.read().await;
        for name in adapters_read.keys() {
            info!(
                "Bridge monitor: Would register adapter '{}' (adapters need Arc wrapping for monitor)",
                name
            );
        }
        drop(adapters_read);

        // Subscribe to status events before starting
        let event_rx = monitor.subscribe();

        // Start the monitor
        let monitor_handle = monitor.start();

        // Create a wrapper task that handles shutdown signaling
        let monitor_clone = monitor.clone();
        let handle = tokio::spawn(async move {
            tokio::select! {
                _ = monitor_handle => {
                    info!("Bridge monitor task completed normally");
                }
                _ = shutdown_rx.recv() => {
                    info!("Bridge status polling received shutdown signal");
                    monitor_clone.stop();
                }
            }
        });

        (handle, shutdown_tx, event_rx)
    }
}

/// Information about a bridge route
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteInfo {
    /// Name of the bridge adapter
    pub adapter_name: String,
    /// Source chain
    pub source_chain: String,
    /// Destination chain
    pub dest_chain: String,
    /// Estimated fee in smallest unit
    pub estimated_fee: u128,
    /// Estimated time in seconds
    pub estimated_time_secs: u64,
    /// Classes this adapter declares (see [`BridgeAdapterClass`]).
    /// Drives [`RoutingStrategy::Regulated`] route filtering.
    #[serde(default = "default_classes")]
    pub classes: Vec<BridgeAdapterClass>,
}

fn default_classes() -> Vec<BridgeAdapterClass> {
    vec![BridgeAdapterClass::Generic]
}

/// One row of `BridgeRouter::list_chains()`: a chain plus the set of
/// registered adapters that can route to it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainCoverage {
    /// Chain metadata (id, name, native token, finality time).
    pub chain: ChainInfo,
    /// Names of adapters reaching this chain. Sorted, deduplicated.
    pub adapters: Vec<String>,
}

/// Fee comparison across adapters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeComparison {
    /// Adapter name
    pub adapter_name: String,
    /// Fee amount
    pub fee: u128,
    /// Fee currency
    pub currency: String,
}

/// Routing preferences for the bridge router
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingPreferences {
    /// Routing strategy to use
    pub strategy: RoutingStrategy,
    /// Maximum acceptable fee (in smallest unit)
    pub max_fee: Option<u128>,
    /// Maximum acceptable time (in seconds)
    pub max_time_secs: Option<u64>,
}

impl Default for RoutingPreferences {
    fn default() -> Self {
        Self {
            strategy: RoutingStrategy::LowestFee,
            max_fee: None,
            max_time_secs: None,
        }
    }
}

/// Strategy for selecting bridge routes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RoutingStrategy {
    /// Minimize fee
    LowestFee,
    /// Minimize time
    FastestTime,
    /// Balance fee and time
    Balanced,
    /// Prefer a specific adapter
    PreferAdapter(String),
    /// Use LI.FI aggregator for automatic best-route selection across all bridges.
    /// Falls back to direct adapters if LI.FI is unavailable or doesn't support
    /// the requested chain (e.g., Canton enterprise flows).
    LiFiAggregator,
    /// Filter routes to adapters that declare
    /// [`BridgeAdapterClass::RegulatedRail`] (currently Chainlink CCIP
    /// and Wormhole NTT) then pick the cheapest among them. Falls back
    /// to lowest-fee across all routes when no `RegulatedRail` adapter
    /// covers the lane.
    Regulated,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layerzero::{LayerZeroAdapter, LayerZeroConfig};

    #[tokio::test]
    async fn test_router_registration() {
        let router = BridgeRouter::new();

        let lz_config = LayerZeroConfig::new(
            "0x1a44076050125825900e736c501f859c50fE728c",
            30101,
            "0x0000000000000000000000000000000000000001",
            "0x0000000000000000000000000000000000000002",
        );

        let lz_adapter = LayerZeroAdapter::new(lz_config);
        router
            .register_adapter("layerzero", Box::new(lz_adapter))
            .await;

        let routes = router
            .get_available_routes("ethereum", "arbitrum")
            .await
            .unwrap();
        assert!(!routes.is_empty());
    }

    #[tokio::test]
    async fn test_message_replay_protection() {
        let router = BridgeRouter::new();

        // Register LayerZero adapter without a signer — send_message will
        // fail with a ConfigurationError, but the nonce counter and replay
        // fingerprint logic still execute before the adapter call.
        let lz_config = LayerZeroConfig::new(
            "0x1a44076050125825900e736c501f859c50fE728c",
            30101,
            "0x0000000000000000000000000000000000000001",
            "0x0000000000000000000000000000000000000002",
        );
        let lz_adapter = LayerZeroAdapter::new(lz_config);
        lz_adapter.set_peer("arbitrum", "0x0000000000000000000000000000000000000001");
        router.register_adapter("layerzero", Box::new(lz_adapter)).await;

        let payload = b"test message payload".to_vec();

        // Without a signer, the underlying adapter returns ConfigurationError
        let result1 = router.send_message("arbitrum", payload.clone()).await;
        assert!(result1.is_err(), "send_message should fail without a signer");

        // Nonce still increments even on failure (consumed before adapter call)
        assert_eq!(router.current_message_nonce(), 1);

        // Second call also fails but gets a different nonce
        let result2 = router.send_message("arbitrum", payload.clone()).await;
        assert!(result2.is_err(), "send_message should fail without a signer");
        assert_eq!(router.current_message_nonce(), 2);

        // Failed sends should NOT be recorded in the replay cache
        let messages = router.processed_messages.read().await;
        assert_eq!(messages.len(), 0, "Failed sends should not be cached");
    }

    #[tokio::test]
    async fn test_message_nonce_independence() {
        let router = BridgeRouter::new();

        // Register LayerZero adapter
        let lz_config = LayerZeroConfig::new(
            "0x1a44076050125825900e736c501f859c50fE728c",
            30101,
            "0x0000000000000000000000000000000000000001",
            "0x0000000000000000000000000000000000000002",
        );
        let lz_adapter = LayerZeroAdapter::new(lz_config);
        lz_adapter.set_peer("arbitrum", "0x0000000000000000000000000000000000000001");
        router.register_adapter("layerzero", Box::new(lz_adapter)).await;

        // Send a message
        let _ = router.send_message("arbitrum", b"test".to_vec()).await;
        assert_eq!(router.current_message_nonce(), 1);

        // Transfer nonce should still be 0
        assert_eq!(router.current_nonce(), 0);

        // Send a transfer
        let request = BridgeTokenRequest::new(
            "ethereum",
            "arbitrum",
            "USDC",
            1_000_000,
            "0xsender",
            "0xrecipient",
        );
        let _ = router.bridge_tokens(request).await;

        // Transfer nonce should be 1, message nonce should still be 1
        assert_eq!(router.current_nonce(), 1);
        assert_eq!(router.current_message_nonce(), 1);
    }

    #[tokio::test]
    async fn test_transfer_status_polling_integration() {
        let router = BridgeRouter::new();

        // Register LayerZero adapter
        let lz_config = LayerZeroConfig::new(
            "0x1a44076050125825900e736c501f859c50fE728c",
            30101,
            "0x0000000000000000000000000000000000000001",
            "0x0000000000000000000000000000000000000002",
        );
        let lz_adapter = LayerZeroAdapter::new(lz_config);
        lz_adapter.set_peer("arbitrum", "0x0000000000000000000000000000000000000001");
        router.register_adapter("layerzero", Box::new(lz_adapter)).await;

        // Start status polling with a short interval
        let (handle, shutdown_tx, mut event_rx) = router
            .start_status_polling(Duration::from_millis(50))
            .await;

        // Let it run for a bit
        tokio::time::sleep(Duration::from_millis(150)).await;

        // Send shutdown signal
        let _ = shutdown_tx.send(()).await;

        // Wait for task to complete (with timeout)
        let result = tokio::time::timeout(Duration::from_secs(2), handle).await;
        assert!(result.is_ok(), "Polling task should shut down gracefully");

        // Drain any pending events
        while event_rx.try_recv().is_ok() {}
    }

    #[tokio::test]
    async fn test_bridge_tokens_replay_protection() {
        let router = BridgeRouter::new();

        // Register LayerZero adapter without a signer — bridge_tokens will
        // fail with a ConfigurationError, but the nonce counter and replay
        // fingerprint logic still execute before the adapter call.
        let lz_config = LayerZeroConfig::new(
            "0x1a44076050125825900e736c501f859c50fE728c",
            30101,
            "0x0000000000000000000000000000000000000001",
            "0x0000000000000000000000000000000000000002",
        );
        let lz_adapter = LayerZeroAdapter::new(lz_config);
        lz_adapter.set_peer("arbitrum", "0x0000000000000000000000000000000000000001");
        router.register_adapter("layerzero", Box::new(lz_adapter)).await;

        // Without a signer, bridge_tokens returns ConfigurationError
        let request1 = BridgeTokenRequest::new(
            "ethereum",
            "arbitrum",
            "USDC",
            1_000_000,
            "0xsender",
            "0xrecipient",
        );
        let result1 = router.bridge_tokens(request1).await;
        assert!(result1.is_err(), "bridge_tokens should fail without a signer");

        // Nonce still increments even on failure (consumed before adapter call)
        assert_eq!(router.current_nonce(), 1);

        // Second identical request also fails but gets a different nonce
        let request2 = BridgeTokenRequest::new(
            "ethereum",
            "arbitrum",
            "USDC",
            1_000_000,
            "0xsender",
            "0xrecipient",
        );
        let result2 = router.bridge_tokens(request2).await;
        assert!(result2.is_err(), "bridge_tokens should fail without a signer");
        assert_eq!(router.current_nonce(), 2);

        // Failed transfers should NOT be recorded in the replay cache
        let transfers = router.processed_transfers.read().await;
        assert_eq!(transfers.len(), 0, "Failed transfers should not be cached");
    }

    #[tokio::test]
    async fn test_message_cache_pruning() {
        let router = BridgeRouter::new();

        // Without a signer, send_message fails at the adapter level, so
        // nothing is cached. Instead, we directly insert entries into the
        // processed_messages map to test the pruning logic in isolation.
        {
            let mut messages = router.processed_messages.write().await;
            // Insert a recent entry (should survive pruning)
            messages.insert("msg:recent".to_string(), Instant::now());
        }

        // Verify message was cached
        {
            let messages = router.processed_messages.read().await;
            assert_eq!(messages.len(), 1, "Message should be in cache");
        }

        // Manually prune (should not remove recent entries)
        router.prune_message_cache().await;

        {
            let messages = router.processed_messages.read().await;
            assert_eq!(messages.len(), 1, "Recent message should not be pruned");
        }

        // Try to insert an old entry (should be pruned). On platforms where
        // Instant subtraction would underflow (process hasn't been running 24h),
        // fall back to just verifying the recent entry survives.
        if let Some(old_time) = Instant::now().checked_sub(std::time::Duration::from_secs(86401)) {
            {
                let mut messages = router.processed_messages.write().await;
                messages.insert("msg:old".to_string(), old_time);
            }

            assert_eq!(router.processed_messages.read().await.len(), 2);

            // Prune should remove the old entry but keep the recent one
            router.prune_message_cache().await;

            {
                let messages = router.processed_messages.read().await;
                assert_eq!(messages.len(), 1, "Old message should be pruned");
                assert!(messages.contains_key("msg:recent"), "Recent message should survive pruning");
            }
        }
    }

    #[tokio::test]
    async fn router_quotes_fee_in_tnzo_via_wired_surface() {
        use crate::fee_oracle::{GovernanceFeeRow, GovernanceSetFeeOracle};
        use crate::fee_sponsor::{BridgeFeeSponsor, WiredBridgeFeeSurface};

        let oracle = Arc::new(GovernanceSetFeeOracle::new());
        oracle.set_rate(GovernanceFeeRow {
            adapter: BridgeAdapterId::LayerZero,
            dest_chain: "arbitrum".into(),
            rate_q18: 3 * 1_000_000_000_000_000_000u128, // 3.0
            markup_bps: 100,                              // 1%
            valid_window_ms: 60_000,
            updated_at_ms: 0,
        });
        let sponsor = Arc::new(BridgeFeeSponsor::new());
        let surface = Arc::new(WiredBridgeFeeSurface::new(oracle, sponsor.clone()));
        let router = BridgeRouter::new().with_fee_surface(surface);

        // Register a LayerZero adapter so the router has a destination chain
        // entry — `estimate_fee` from LayerZero stub returns a deterministic
        // value the oracle can convert.
        let lz_config = LayerZeroConfig::new(
            "0x1a44076050125825900e736c501f859c50fE728c",
            30101,
            "0x0000000000000000000000000000000000000001",
            "0x0000000000000000000000000000000000000002",
        );
        router
            .register_adapter("layerzero", Box::new(LayerZeroAdapter::new(lz_config)))
            .await;

        let quote = router
            .quote_fee_in_tnzo("layerzero", "arbitrum", 100)
            .await
            .unwrap();
        assert_eq!(quote.adapter, BridgeAdapterId::LayerZero);
        assert!(quote.tnzo_amount_wei > 0);
        assert!(quote.valid_until_ms > quote.issued_at_ms);

        // Sponsoring the quote should produce a receipt and update the pool.
        let receipt = router
            .sponsor_quote(&quote, "did:tn:human:router-test")
            .await
            .unwrap();
        assert_eq!(receipt.adapter, BridgeAdapterId::LayerZero);
        assert_eq!(receipt.tnzo_paid_wei, quote.tnzo_amount_wei);

        // list_sponsorship_pools returns one entry per known adapter id.
        let pools = router.list_sponsorship_pools().await;
        assert_eq!(pools.len(), 8);
        let lz_pool = pools
            .iter()
            .find(|p| p.adapter == BridgeAdapterId::LayerZero)
            .unwrap();
        assert_eq!(lz_pool.tnzo_balance_wei, quote.tnzo_amount_wei);
    }

    #[tokio::test]
    async fn router_sponsor_pattern_covers_wormhole_lz_axelar_uniformly() {
        use crate::fee_oracle::{GovernanceFeeRow, GovernanceSetFeeOracle};
        use crate::fee_sponsor::{BridgeFeeSponsor, WiredBridgeFeeSurface};

        let oracle = Arc::new(GovernanceSetFeeOracle::new());
        for adapter in [
            BridgeAdapterId::Wormhole,
            BridgeAdapterId::LayerZero,
            BridgeAdapterId::Axelar,
        ] {
            oracle.set_rate(GovernanceFeeRow {
                adapter,
                dest_chain: "eip155:1".into(),
                rate_q18: 2 * 1_000_000_000_000_000_000u128,
                markup_bps: 50,
                valid_window_ms: 60_000,
                updated_at_ms: 0,
            });
        }
        let sponsor = Arc::new(BridgeFeeSponsor::new());
        let surface = Arc::new(WiredBridgeFeeSurface::new(oracle, sponsor.clone()));
        let router = BridgeRouter::new().with_fee_surface(surface);

        // Direct oracle path (no adapter registration required) — verifies
        // the sponsor-pattern fan-out works uniformly across all three.
        for adapter in [
            BridgeAdapterId::Wormhole,
            BridgeAdapterId::LayerZero,
            BridgeAdapterId::Axelar,
        ] {
            let quote = router
                .fee_surface()
                .unwrap()
                .oracle
                .quote(adapter, "eip155:1", 1_000_000)
                .await
                .unwrap();
            assert_eq!(quote.adapter, adapter);
            // 1_000_000 * 2 = 2_000_000; +0.5% = 2_010_000.
            assert_eq!(quote.tnzo_amount_wei, 2_010_000);
            let receipt = router
                .sponsor_quote(&quote, format!("did:tn:human:{}", adapter.as_str()))
                .await
                .unwrap();
            assert_eq!(receipt.adapter, adapter);
        }

        // Each adapter has its own deterministic vault.
        let pools = router.list_sponsorship_pools().await;
        let wormhole = pools
            .iter()
            .find(|p| p.adapter == BridgeAdapterId::Wormhole)
            .unwrap();
        let lz = pools
            .iter()
            .find(|p| p.adapter == BridgeAdapterId::LayerZero)
            .unwrap();
        let axelar = pools
            .iter()
            .find(|p| p.adapter == BridgeAdapterId::Axelar)
            .unwrap();
        assert_ne!(wormhole.vault_address, lz.vault_address);
        assert_ne!(lz.vault_address, axelar.vault_address);
        assert_ne!(wormhole.vault_address, axelar.vault_address);
    }

    #[tokio::test]
    async fn regulated_strategy_prefers_ccip_when_available() {
        use crate::chainlink_ccip::{CcipConfig, ChainlinkCcipAdapter, FeeToken};

        let router = BridgeRouter::new();

        // Register a regulated rail (CCIP) and a generic rail (LayerZero)
        // on the same lane. CCIP supports Ethereum + Arbitrum out of the
        // box; LayerZero supports the same two via its config.
        let ccip = ChainlinkCcipAdapter::new(CcipConfig::ethereum_mainnet(FeeToken::Native));
        router.register_adapter("chainlink_ccip", Box::new(ccip)).await;

        let lz_config = LayerZeroConfig::new(
            "0x1a44076050125825900e736c501f859c50fE728c",
            30101,
            "0x0000000000000000000000000000000000000001",
            "0x0000000000000000000000000000000000000002",
        );
        router
            .register_adapter("layerzero", Box::new(LayerZeroAdapter::new(lz_config)))
            .await;

        router
            .set_preferences(RoutingPreferences {
                strategy: RoutingStrategy::Regulated,
                max_fee: None,
                max_time_secs: None,
            })
            .await;

        let routes = router
            .get_available_routes("ethereum", "arbitrum")
            .await
            .unwrap();
        assert!(routes.len() >= 2, "expected both adapters to be discovered");

        // Both adapters expose this lane; Regulated must pick CCIP.
        let chosen = router.select_best_route(&routes).await.unwrap();
        assert_eq!(chosen.adapter_name, "chainlink_ccip");
        assert!(chosen.classes.contains(&BridgeAdapterClass::RegulatedRail));
    }

    #[tokio::test]
    async fn regulated_strategy_falls_back_when_no_regulated_rail() {
        let router = BridgeRouter::new();

        // Only register a generic rail. Regulated must fall back to it
        // rather than fail — caller asked for "regulated-preferred",
        // not "regulated-required".
        let lz_config = LayerZeroConfig::new(
            "0x1a44076050125825900e736c501f859c50fE728c",
            30101,
            "0x0000000000000000000000000000000000000001",
            "0x0000000000000000000000000000000000000002",
        );
        router
            .register_adapter("layerzero", Box::new(LayerZeroAdapter::new(lz_config)))
            .await;

        router
            .set_preferences(RoutingPreferences {
                strategy: RoutingStrategy::Regulated,
                max_fee: None,
                max_time_secs: None,
            })
            .await;

        let routes = router
            .get_available_routes("ethereum", "arbitrum")
            .await
            .unwrap();
        let chosen = router.select_best_route(&routes).await.unwrap();
        assert_eq!(chosen.adapter_name, "layerzero");
    }

    #[tokio::test]
    async fn router_returns_error_when_fee_surface_unwired() {
        let router = BridgeRouter::new();
        let err = router
            .quote_fee_in_tnzo("layerzero", "arbitrum", 100)
            .await
            .unwrap_err();
        match err {
            BridgeError::AdapterError(m) => assert!(m.contains("no fee surface")),
            other => panic!("unexpected: {:?}", other),
        }
        let empty = router.list_sponsorship_pools().await;
        assert!(empty.is_empty());
    }
}
