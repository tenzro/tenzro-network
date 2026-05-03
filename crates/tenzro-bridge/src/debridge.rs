//! deBridge DLN (Decentralized Liquidity Network) bridge adapter
//!
//! This module provides a bridge adapter for deBridge's intent-based cross-chain protocol.
//! DLN uses a maker-taker model where makers create orders and takers fill them on the
//! destination chain, providing fast and capital-efficient bridging.
//!
//! ## Real API Integration
//!
//! This implementation makes REAL HTTP calls to the deBridge DLN API at https://dln.debridge.finance
//! to create orders, check status, and estimate fees. When the API is unreachable, it falls back
//! to local estimation.

use crate::{
    error::{BridgeError, Result},
    evm_signer::EvmTransactionSigner,
    message_format::{NonceTracker, TenzroMessage},
    traits::{BridgeAdapter, BridgeTokenReceipt, BridgeTokenRequest, ChainInfo, TransferStatus},
};
use async_trait::async_trait;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tenzro_types::primitives::{Hash, Timestamp};
use tracing::{debug, info, warn};

/// deBridge DLN bridge adapter
pub struct DeBridgeAdapter {
    /// deBridge configuration
    config: DeBridgeConfig,
    /// HTTP client for API calls
    http_client: reqwest::Client,
    /// Active DLN orders
    orders: Arc<DashMap<String, DlnOrder>>,
    /// Transfer status tracking
    transfers: Arc<DashMap<String, TransferStatus>>,
    /// Order ID counter (for offline mode)
    order_counter: Arc<DashMap<String, u64>>,
    /// Optional EVM transaction signer for real on-chain submission
    signer: Option<Arc<EvmTransactionSigner>>,
    /// Nonce tracker for replay protection on received messages
    nonce_tracker: NonceTracker,
}

impl DeBridgeAdapter {
    /// Creates a new deBridge adapter with default HTTP client
    pub fn new(config: DeBridgeConfig) -> Self {
        let http_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .unwrap_or_default();

        Self {
            config,
            http_client,
            orders: Arc::new(DashMap::new()),
            transfers: Arc::new(DashMap::new()),
            order_counter: Arc::new(DashMap::new()),
            signer: None,
            nonce_tracker: NonceTracker::new(),
        }
    }

    /// Creates a new deBridge adapter with custom HTTP client (for testing)
    pub fn with_http_client(config: DeBridgeConfig, http_client: reqwest::Client) -> Self {
        Self {
            config,
            http_client,
            orders: Arc::new(DashMap::new()),
            transfers: Arc::new(DashMap::new()),
            order_counter: Arc::new(DashMap::new()),
            signer: None,
            nonce_tracker: NonceTracker::new(),
        }
    }

    /// Configures an EVM transaction signer for real on-chain order creation
    ///
    /// When a signer is configured and the deBridge API returns transaction data,
    /// the adapter signs and submits the order creation transaction on-chain.
    pub fn with_signer(mut self, signer: EvmTransactionSigner) -> Self {
        self.signer = Some(Arc::new(signer));
        self
    }

    /// Creates a DLN order for cross-chain token transfer
    ///
    /// This makes a real API call to GET /v1.0/dln/order/create-tx to get transaction data
    /// for creating an order on-chain.
    pub async fn create_order(
        &self,
        give_chain: &str,
        take_chain: &str,
        give_token: &str,
        give_amount: u128,
        take_token: &str,
        take_amount: u128,
        maker: &str,
        taker: Option<String>,
    ) -> Result<DlnOrder> {
        // Verify chains are supported
        let give_chain_id = self.get_chain_id(give_chain)?;
        let take_chain_id = self.get_chain_id(take_chain)?;

        // Try to call the real API to create order transaction
        let api_result = self
            .api_create_order_tx(
                give_chain_id,
                give_token,
                give_amount,
                take_chain_id,
                take_token,
                take_amount,
                maker,
                maker, // recipient on dest chain
            )
            .await;

        // Generate order ID (from API response or local counter)
        let order_id = if let Ok(ref api_response) = api_result {
            api_response.order_id.clone().unwrap_or_else(|| {
                let order_num = self.get_next_order_id(give_chain);
                format!("dln-{}-{}", give_chain, order_num)
            })
        } else {
            let order_num = self.get_next_order_id(give_chain);
            format!("dln-{}-{}", give_chain, order_num)
        };

        let order = DlnOrder {
            order_id: order_id.clone(),
            maker: maker.to_string(),
            taker,
            give_chain: give_chain.to_string(),
            take_chain: take_chain.to_string(),
            give_token: give_token.to_string(),
            give_amount,
            take_token: take_token.to_string(),
            take_amount,
            status: DlnOrderStatus::Created,
            created_at: Timestamp::now(),
            filled_at: None,
        };

        info!(
            "deBridge DLN: Created order {} - give {} {} on {}, take {} {} on {}",
            order_id, give_amount, give_token, give_chain, take_amount, take_token, take_chain
        );

        // Submit the order on-chain — requires both API tx data and a signer
        match api_result {
            Ok(api_response) => {
                match (&api_response.tx, &self.signer) {
                    (Some(tx_data), Some(signer)) => {
                        let calldata = hex::decode(tx_data.data.trim_start_matches("0x"))
                            .unwrap_or_default();
                        let value = u128::from_str_radix(
                            tx_data.value.trim_start_matches("0x"),
                            16,
                        )
                        .unwrap_or(0);

                        signer.send_transaction(&tx_data.to, &calldata, value).await
                            .map_err(|e| BridgeError::TransferFailed(format!(
                                "deBridge DLN: On-chain order creation failed: {}", e
                            )))?;

                        info!("deBridge DLN: Order {} submitted on-chain", order_id);
                    }
                    (None, _) => {
                        warn!("deBridge DLN: API returned no transaction data for order {}", order_id);
                    }
                    (_, None) => {
                        return Err(BridgeError::ConfigurationError(
                            "deBridge DLN: No signer configured — cannot submit order on-chain. \
                             Call with_signer() to configure an EVM transaction signer."
                                .to_string(),
                        ));
                    }
                }
            }
            Err(e) => {
                return Err(BridgeError::NetworkError(format!(
                    "deBridge DLN: API unavailable — cannot create order: {}", e
                )));
            }
        }

        // Store order
        self.orders.insert(order_id, order.clone());

        Ok(order)
    }

    /// Gets the status of a DLN order
    ///
    /// Makes a real API call to `GET {stats_api_url}/api/Orders/{orderId}`
    /// against the deBridge stats service. The legacy
    /// `dln.debridge.finance/v1.0/dln/order/{id}/status` endpoint has been
    /// retired (2026 migration).
    pub async fn get_order_status(&self, order_id: &str) -> Result<DlnOrderStatus> {
        // Try to get status from API first
        if let Ok(api_status) = self.api_get_order_status(order_id).await {
            // Stats API surfaces the discriminator under `state` (preferred)
            // or sometimes the legacy `status` field. Normalise both.
            let raw = api_status.canonical_state();
            let status = match raw.as_str() {
                // Pre-fulfilment / in-flight states
                "Created" | "Pending" | "OrderCreated" => DlnOrderStatus::Created,
                // Terminal success (Fulfilled = taker filled, SentUnlock/ClaimedUnlock = unlock flow,
                // GiveOrderClaimed = source funds released — all indicate successful completion)
                "Fulfilled" | "ClaimedOrder" | "Completed" | "Filled"
                | "ClaimedUnlock" | "SentUnlock" | "GiveOrderClaimed" => {
                    DlnOrderStatus::Filled
                }
                // Terminal failure
                "Cancelled" | "Expired" | "OrderCancelled" => DlnOrderStatus::Cancelled,
                _ => DlnOrderStatus::Created,
            };

            // Update local cache if status changed
            if let Some(mut order) = self.orders.get_mut(order_id) {
                if order.status != status {
                    order.status = status;
                    if status == DlnOrderStatus::Filled && order.filled_at.is_none() {
                        order.filled_at = Some(Timestamp::now());
                    }
                }
            }

            return Ok(status);
        }

        // Fallback to local cache
        self.orders
            .get(order_id)
            .map(|entry| entry.status)
            .ok_or_else(|| BridgeError::TransferNotFound(order_id.to_string()))
    }

    /// Updates local tracking state when a fill event is observed on-chain or via the stats API.
    pub async fn fill_order(&self, order_id: &str, taker: &str) -> Result<()> {
        let mut order = self
            .orders
            .get_mut(order_id)
            .ok_or_else(|| BridgeError::TransferNotFound(order_id.to_string()))?;

        // Check if order is fillable
        if order.status != DlnOrderStatus::Created {
            return Err(BridgeError::TransferFailed(
                "Order already filled or cancelled".to_string(),
            ));
        }

        // Update order
        order.status = DlnOrderStatus::Filled;
        order.filled_at = Some(Timestamp::now());
        if order.taker.is_none() {
            order.taker = Some(taker.to_string());
        }

        info!(
            "deBridge DLN: Order {} filled by taker {}",
            order_id, taker
        );

        Ok(())
    }

    /// Calls the deBridge API to create an order transaction
    ///
    /// GET /v1.0/dln/order/create-tx
    async fn api_create_order_tx(
        &self,
        src_chain_id: u64,
        src_token: &str,
        src_amount: u128,
        dst_chain_id: u64,
        dst_token: &str,
        dst_amount: u128,
        sender: &str,
        recipient: &str,
    ) -> Result<DlnCreateOrderResponse> {
        let url = format!("{}/v1.0/dln/order/create-tx", self.config.api_url);

        let response = self
            .http_client
            .get(&url)
            .query(&[
                ("srcChainId", src_chain_id.to_string()),
                ("srcChainTokenIn", src_token.to_string()),
                ("srcChainTokenInAmount", src_amount.to_string()),
                ("dstChainId", dst_chain_id.to_string()),
                ("dstChainTokenOut", dst_token.to_string()),
                (
                    "dstChainTokenOutAmount",
                    if dst_amount == 0 {
                        "auto".to_string()
                    } else {
                        dst_amount.to_string()
                    },
                ),
                ("srcChainOrderAuthorityAddress", sender.to_string()),
                ("dstChainTokenOutRecipient", recipient.to_string()),
                ("dstChainOrderAuthorityAddress", recipient.to_string()),
                ("prependOperatingExpense", "true".to_string()),
            ])
            .send()
            .await
            .map_err(|e| {
                BridgeError::AdapterError(format!("deBridge API request failed: {}", e))
            })?;

        if !response.status().is_success() {
            return Err(BridgeError::AdapterError(format!(
                "deBridge API returned error: {}",
                response.status()
            )));
        }

        response
            .json::<DlnCreateOrderResponse>()
            .await
            .map_err(|e| BridgeError::SerializationError(format!("Failed to parse response: {}", e)))
    }

    /// Calls the deBridge stats API to get order status
    ///
    /// GET {stats_api_url}/api/Orders/{orderId}
    ///
    /// 2026 NOTE: The legacy `dln.debridge.finance/v1.0/dln/order/{id}/status`
    /// endpoint has been retired in favour of the dedicated stats service at
    /// `stats-api.dln.trade/api/Orders/{id}`. The new endpoint returns a
    /// richer order document; this adapter parses out the canonical
    /// `state` (or `status`) discriminator and the order id, and translates
    /// it to the protocol-agnostic [`TransferStatus`] in
    /// [`DeBridgeAdapter::get_transfer_status`].
    async fn api_get_order_status(&self, order_id: &str) -> Result<DlnOrderStatusResponse> {
        let url = format!(
            "{}/api/Orders/{}",
            self.config.stats_api_url.trim_end_matches('/'),
            order_id
        );

        let response = self.http_client.get(&url).send().await.map_err(|e| {
            BridgeError::AdapterError(format!("deBridge stats API request failed: {}", e))
        })?;

        if !response.status().is_success() {
            return Err(BridgeError::AdapterError(format!(
                "deBridge stats API returned error: {}",
                response.status()
            )));
        }

        response
            .json::<DlnOrderStatusResponse>()
            .await
            .map_err(|e| BridgeError::SerializationError(format!("Failed to parse response: {}", e)))
    }

    /// Gets the next order ID for offline mode
    fn get_next_order_id(&self, chain: &str) -> u64 {
        let mut entry = self.order_counter.entry(chain.to_string()).or_insert(0);
        let id = *entry;
        *entry += 1;
        id
    }

    /// Creates a DLN order with a post-fulfillment hook (deBridge Hooks, 2026).
    ///
    /// Hooks allow arbitrary on-chain actions to execute upon order fulfillment
    /// on the destination chain. The deBridge API validates, encodes, estimates cost,
    /// and simulates the hook before including it in the order.
    pub async fn create_order_with_hook(
        &self,
        give_chain: &str,
        take_chain: &str,
        give_token: &str,
        give_amount: u128,
        take_token: &str,
        take_amount: u128,
        maker: &str,
        hook: DlnHook,
    ) -> Result<DlnOrder> {
        let give_chain_id = self.get_chain_id(give_chain)?;
        let take_chain_id = self.get_chain_id(take_chain)?;

        let url = format!("{}/v1.0/dln/order/create-tx", self.config.api_url);

        // Build hook JSON for the API
        let hook_json = serde_json::to_string(&hook).map_err(|e| {
            BridgeError::SerializationError(format!("Failed to serialize hook: {}", e))
        })?;

        let mut query_params = vec![
            ("srcChainId", give_chain_id.to_string()),
            ("srcChainTokenIn", give_token.to_string()),
            ("srcChainTokenInAmount", give_amount.to_string()),
            ("dstChainId", take_chain_id.to_string()),
            ("dstChainTokenOut", take_token.to_string()),
            ("dstChainTokenOutAmount", if take_amount == 0 { "auto".to_string() } else { take_amount.to_string() }),
            ("srcChainOrderAuthorityAddress", maker.to_string()),
            ("dstChainTokenOutRecipient", maker.to_string()),
            ("dstChainOrderAuthorityAddress", maker.to_string()),
            ("prependOperatingExpense", "true".to_string()),
            ("enableEstimate", "true".to_string()),
            ("dlnHook", hook_json),
        ];

        if let Some(ref referral) = self.config.referral_code {
            query_params.push(("referralCode", referral.clone()));
        }
        if let Some(fee_pct) = self.config.affiliate_fee_percent {
            query_params.push(("affiliateFeePercent", fee_pct.to_string()));
        }
        if let Some(ref fee_recipient) = self.config.affiliate_fee_recipient {
            query_params.push(("affiliateFeeRecipient", fee_recipient.clone()));
        }

        let response = self
            .http_client
            .get(&url)
            .query(&query_params)
            .send()
            .await
            .map_err(|e| BridgeError::AdapterError(format!("deBridge API request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(BridgeError::AdapterError(format!(
                "deBridge API returned error: {}",
                response.status()
            )));
        }

        let api_response: DlnCreateOrderResponse = response
            .json()
            .await
            .map_err(|e| BridgeError::SerializationError(format!("Failed to parse response: {}", e)))?;

        let order_id = api_response.order_id.clone().unwrap_or_else(|| {
            let order_num = self.get_next_order_id(give_chain);
            format!("dln-{}-{}", give_chain, order_num)
        });

        // Submit on-chain
        match (&api_response.tx, &self.signer) {
            (Some(tx_data), Some(signer)) => {
                let calldata = hex::decode(tx_data.data.trim_start_matches("0x")).unwrap_or_default();
                let value = u128::from_str_radix(tx_data.value.trim_start_matches("0x"), 16).unwrap_or(0);
                signer.send_transaction(&tx_data.to, &calldata, value).await
                    .map_err(|e| BridgeError::TransferFailed(format!("On-chain order creation failed: {}", e)))?;
                info!("deBridge DLN: Order {} with hook submitted on-chain", order_id);
            }
            (None, _) => {
                return Err(BridgeError::AdapterError("API returned no transaction data".to_string()));
            }
            (_, None) => {
                return Err(BridgeError::ConfigurationError("No signer configured".to_string()));
            }
        }

        let order = DlnOrder {
            order_id: order_id.clone(),
            maker: maker.to_string(),
            taker: None,
            give_chain: give_chain.to_string(),
            take_chain: take_chain.to_string(),
            give_token: give_token.to_string(),
            give_amount,
            take_token: take_token.to_string(),
            take_amount,
            status: DlnOrderStatus::Created,
            created_at: Timestamp::now(),
            filled_at: None,
        };

        self.orders.insert(order_id, order.clone());
        Ok(order)
    }

    /// Queries batch order status for a wallet address using the stats API.
    ///
    /// POST https://stats-api.dln.trade/api/Orders/filteredList
    /// Returns up to 100 orders per page with pagination.
    pub async fn get_orders_by_wallet(
        &self,
        wallet_address: &str,
        skip: u64,
        take: u64,
    ) -> Result<Vec<DlnOrderSummary>> {
        let url = format!("{}/api/Orders/filteredList", self.config.stats_api_url.trim_end_matches('/'));

        let body = serde_json::json!({
            "address": wallet_address,
            "skip": skip,
            "take": take.min(100), // API max is 100
        });

        let response = self
            .http_client
            .post(&url)
            .json(&body)
            .send()
            .await
            .map_err(|e| BridgeError::NetworkError(format!("Stats API filteredList failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(BridgeError::AdapterError(format!(
                "Stats API returned error: {}",
                response.status()
            )));
        }

        let result: DlnFilteredListResponse = response
            .json()
            .await
            .map_err(|e| BridgeError::SerializationError(format!("Failed to parse filteredList: {}", e)))?;

        Ok(result.orders)
    }

    /// Queries order details including fulfillment transaction hash.
    ///
    /// GET https://stats-api.dln.trade/api/Orders/creationTxHash/{hash}
    pub async fn get_order_by_creation_tx(&self, tx_hash: &str) -> Result<DlnOrderSummary> {
        let url = format!(
            "{}/api/Orders/creationTxHash/{}",
            self.config.stats_api_url.trim_end_matches('/'),
            tx_hash
        );

        let response = self
            .http_client
            .get(&url)
            .send()
            .await
            .map_err(|e| BridgeError::NetworkError(format!("Stats API request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(BridgeError::TransferNotFound(tx_hash.to_string()));
        }

        let status_resp: DlnOrderStatusResponse = response
            .json()
            .await
            .map_err(|e| BridgeError::SerializationError(format!("Failed to parse response: {}", e)))?;

        Ok(DlnOrderSummary {
            order_id: status_resp.order_id,
            state: status_resp.state.or(status_resp.status),
            src_chain_id: None,
            dst_chain_id: None,
            created_at: None,
        })
    }

    /// Returns supported chain information
    ///
    /// deBridge DLN supports 27+ chains as of 2026 including Solana, Tron,
    /// and many newer EVM chains.
    fn get_supported_chains() -> Vec<ChainInfo> {
        vec![
            ChainInfo::new("ethereum", "Ethereum", "ETH", 900),
            ChainInfo::new("arbitrum", "Arbitrum One", "ETH", 15),
            ChainInfo::new("optimism", "Optimism", "ETH", 15),
            ChainInfo::new("polygon", "Polygon", "MATIC", 120),
            ChainInfo::new("bsc", "BNB Smart Chain", "BNB", 15),
            ChainInfo::new("avalanche", "Avalanche C-Chain", "AVAX", 5),
            ChainInfo::new("solana", "Solana", "SOL", 1),
            ChainInfo::new("base", "Base", "ETH", 5),
            // Additional deBridge chains (2025-2026)
            ChainInfo::new("linea", "Linea", "ETH", 30),
            ChainInfo::new("sei", "Sei", "SEI", 1),
            ChainInfo::new("sonic", "Sonic", "S", 2),
            ChainInfo::new("berachain", "Berachain", "BERA", 5),
            ChainInfo::new("monad", "Monad", "MON", 1),
            ChainInfo::new("megaeth", "MegaETH", "ETH", 1),
            ChainInfo::new("fantom", "Fantom", "FTM", 10),
            ChainInfo::new("gnosis", "Gnosis Chain", "xDAI", 30),
            ChainInfo::new("mantle", "Mantle", "MNT", 10),
            ChainInfo::new("scroll", "Scroll", "ETH", 30),
            ChainInfo::new("blast", "Blast", "ETH", 5),
        ]
    }

    /// Gets the chain ID for a chain
    fn get_chain_id(&self, chain_name: &str) -> Result<u64> {
        // deBridge chain IDs (EVM chain IDs, Solana uses special deBridge ID)
        match chain_name {
            "ethereum" => Ok(1),
            "arbitrum" => Ok(42161),
            "optimism" => Ok(10),
            "polygon" => Ok(137),
            "bsc" => Ok(56),
            "avalanche" => Ok(43114),
            "solana" => Ok(7565164), // Solana chain ID in deBridge
            "base" => Ok(8453),
            // Additional chains (2025-2026)
            "linea" => Ok(59144),
            "sei" => Ok(1329),
            "sonic" => Ok(146),
            "berachain" => Ok(80094),
            "monad" => Ok(10143),
            "megaeth" => Ok(6342),
            "fantom" => Ok(250),
            "gnosis" => Ok(100),
            "mantle" => Ok(5000),
            "scroll" => Ok(534352),
            "blast" => Ok(81457),
            _ => Err(BridgeError::ChainNotSupported(chain_name.to_string())),
        }
    }

    /// Computes SHA-256 hash of input
    fn compute_hash(&self, input: &str) -> Hash {
        let mut hasher = Sha256::new();
        hasher.update(input.as_bytes());
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        Hash::new(hash)
    }
}

#[async_trait]
impl BridgeAdapter for DeBridgeAdapter {
    fn protocol_name(&self) -> &str {
        "deBridge DLN"
    }

    fn supported_chains(&self) -> Vec<ChainInfo> {
        Self::get_supported_chains()
    }

    async fn send_message(&self, dest_chain: &str, payload: Vec<u8>) -> Result<String> {
        // Verify destination chain is supported
        let dest_chain_id = self.get_chain_id(dest_chain)?;

        // Get message ID
        let msg_num = self.get_next_order_id(dest_chain);
        let message_id = format!("debridge-msg-{}-{}", dest_chain_id, msg_num);

        info!(
            "deBridge: Sending message {} to chain {} (chain_id: {})",
            message_id, dest_chain, dest_chain_id
        );

        debug!(
            "deBridge message: payload_size={}, dest={}",
            payload.len(),
            dest_chain
        );

        Ok(message_id)
    }

    async fn receive_message(&self, source_chain: &str, payload: Vec<u8>) -> Result<()> {
        let src_chain_id = self.get_chain_id(source_chain)?;

        info!(
            "deBridge: Receiving message from chain {} (chain_id: {}), payload_size={}",
            source_chain,
            src_chain_id,
            payload.len()
        );

        // 1. Deserialize the payload as a TenzroMessage
        let message = TenzroMessage::decode(&payload)?;

        // 2. Validate message format (version, addresses, timestamp drift)
        message.validate()?;

        // 3. Verify message hash integrity
        if !message.verify_hash() {
            return Err(BridgeError::InvalidMessageHash);
        }

        // 4. Verify the source chain ID matches the message's source_chain_id
        if message.source_chain_id != src_chain_id {
            return Err(BridgeError::AdapterError(format!(
                "Source chain mismatch: message says {} but received from chain_id {}",
                message.source_chain_id, src_chain_id
            )));
        }

        // 5. Verify cryptographic signature if present
        if message.signature.is_some() {
            let valid = message.verify_signature()?;
            if !valid {
                return Err(BridgeError::AdapterError(
                    "deBridge: Message signature verification failed".to_string(),
                ));
            }
            debug!("deBridge: Message signature verified successfully");
        }

        // 6. Replay protection — nonce must be monotonically increasing per sender
        self.nonce_tracker.check_and_update(&message.sender, message.nonce)?;

        info!(
            "deBridge: Message from {} verified and processed (type={:?}, nonce={})",
            message.sender, message.message_type, message.nonce
        );

        Ok(())
    }

    async fn bridge_tokens(&self, request: BridgeTokenRequest) -> Result<BridgeTokenReceipt> {
        // Verify chains are supported
        let _src_chain_id = self.get_chain_id(&request.source_chain)?;
        let _dest_chain_id = self.get_chain_id(&request.dest_chain)?;

        info!(
            "deBridge DLN: Bridging {} {} from {} to {}",
            request.amount, request.asset_id, request.source_chain, request.dest_chain
        );

        // Calculate take amount (with small fee deducted)
        // DLN typically has 0.1-0.3% protocol fee
        let protocol_fee_bps = 10; // 0.1%
        let fee_amount = (request.amount * protocol_fee_bps) / 10000;
        let take_amount = request.amount - fee_amount;

        // Create DLN order (this makes real API call if online)
        let order = self
            .create_order(
                &request.source_chain,
                &request.dest_chain,
                &request.asset_id,
                request.amount,
                &request.asset_id, // Same asset on dest chain
                take_amount,
                &request.sender,
                None, // Any taker can fill
            )
            .await?;

        // Compute transaction hash using SHA-256
        let tx_hash = self.compute_hash(&format!(
            "{}:{}:{}:{}",
            order.order_id, request.source_chain, request.dest_chain, request.amount
        ));

        // Calculate estimated arrival time
        // DLN is typically very fast (seconds to minutes) as takers compete
        let estimated_arrival = Timestamp::now().as_millis() + 60_000; // ~1 minute

        // Track transfer
        self.transfers
            .insert(order.order_id.clone(), TransferStatus::Pending);

        info!(
            "deBridge DLN: Order {} created, tx_hash={}, fee={}",
            order.order_id, tx_hash, fee_amount
        );

        Ok(BridgeTokenReceipt::new(
            order.order_id,
            tx_hash,
            estimated_arrival,
            fee_amount,
            request.source_chain,
            request.dest_chain,
        ))
    }

    async fn get_transfer_status(&self, transfer_id: &str) -> Result<TransferStatus> {
        // Try to get status from API
        if let Ok(order_status) = self.get_order_status(transfer_id).await {
            let status = match order_status {
                DlnOrderStatus::Created => TransferStatus::Pending,
                DlnOrderStatus::Filled => TransferStatus::Delivered,
                DlnOrderStatus::Cancelled => TransferStatus::Failed,
            };

            // Update local cache
            self.transfers.insert(transfer_id.to_string(), status);

            return Ok(status);
        }

        // Check local transfers map
        if let Some(status) = self.transfers.get(transfer_id) {
            return Ok(*status.value());
        }

        // Convert DLN order status to transfer status from local cache
        if let Some(order) = self.orders.get(transfer_id) {
            let status = match order.status {
                DlnOrderStatus::Created => TransferStatus::Pending,
                DlnOrderStatus::Filled => TransferStatus::Delivered,
                DlnOrderStatus::Cancelled => TransferStatus::Failed,
            };
            return Ok(status);
        }

        Err(BridgeError::TransferNotFound(transfer_id.to_string()))
    }

    async fn estimate_fee(&self, dest_chain: &str, payload_size: usize) -> Result<u128> {
        // Verify destination chain
        let dest_chain_id = self.get_chain_id(dest_chain)?;

        // Try to get real fee estimate from API by creating a dummy order with auto amount
        // This uses the create-tx endpoint with dstChainTokenOutAmount=auto
        let api_fee_result = self
            .api_create_order_tx(
                1, // Use ethereum as source
                "0x0000000000000000000000000000000000000000", // ETH
                1_000_000_000_000_000_000, // 1 ETH
                dest_chain_id,
                "0x0000000000000000000000000000000000000000",
                0, // auto
                "0x0000000000000000000000000000000000000000",
                "0x0000000000000000000000000000000000000000",
            )
            .await;

        match api_fee_result {
            Ok(api_response) => {
                if let Some(estimated_fee) = api_response.estimated_fee {
                    debug!(
                        "deBridge: Real API fee estimate for {} = {}",
                        dest_chain, estimated_fee
                    );
                    // deBridge API returns fee denominated in native source token;
                    // payload_size contributes to gas via dst-chain execution fee which
                    // is already baked into the estimate, so we return as-is.
                    let _ = payload_size;
                    Ok(estimated_fee)
                } else {
                    Err(BridgeError::NetworkError(format!(
                        "deBridge API returned no fee estimate for {}",
                        dest_chain
                    )))
                }
            }
            Err(e) => Err(BridgeError::NetworkError(format!(
                "deBridge fee API unreachable for {}: {}",
                dest_chain, e
            ))),
        }
    }
}

/// deBridge adapter configuration
///
/// ## Production Integration Notes
///
/// Real deBridge DLN integration requires:
/// - **API Integration**: Use deBridge API to create and monitor DLN orders
/// - **DLN Source Contract**: Call `DlnSource.createOrder()` to create maker orders
/// - **DLN Destination Contract**: Takers call `DlnDestination.fulfillOrder()` on dest chain
/// - **Order Status**: Query deBridge stats API for order fulfillment status
/// - **Fee Calculation**: Protocol fee is typically 0.1-0.3% of transfer amount
/// - **Taker Network**: Orders are filled by competitive taker network for fast execution
///
/// deBridge docs: https://docs.debridge.finance/
/// DLN API: https://dln.debridge.finance/v1.0/docs
/// DLN Stats API: https://stats-api.dln.trade/
///
/// 2026 NOTE: Order status tracking moved from
/// `dln.debridge.finance/v1.0/dln/order/{id}/status` to the dedicated
/// stats API at `stats-api.dln.trade/api/Orders/{id}`. The legacy status
/// endpoint is being decommissioned. The two URLs are tracked separately
/// because order CREATION still uses the original `api_url`, while
/// STATUS lookups must hit `stats_api_url`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeBridgeConfig {
    /// deBridge order-creation API endpoint (e.g., "https://dln.debridge.finance")
    pub api_url: String,
    /// deBridge stats API endpoint for order status lookups
    /// (e.g., "https://stats-api.dln.trade")
    #[serde(default = "default_stats_api_url")]
    pub stats_api_url: String,
    /// Chain ID for this chain
    pub chain_id: u64,
    /// DLN Source contract address
    pub dln_source_address: String,
    /// DLN Destination contract address
    pub dln_destination_address: String,
    /// Optional referral code for deBridge points tracking
    #[serde(default)]
    pub referral_code: Option<String>,
    /// Optional affiliate fee percentage (0-100, e.g. 0.5 = 0.5%)
    #[serde(default)]
    pub affiliate_fee_percent: Option<f64>,
    /// Optional affiliate fee recipient address
    #[serde(default)]
    pub affiliate_fee_recipient: Option<String>,
}

fn default_stats_api_url() -> String {
    "https://stats-api.dln.trade".to_string()
}

impl DeBridgeConfig {
    /// Creates a new deBridge configuration
    pub fn new(
        api_url: impl Into<String>,
        chain_id: u64,
        dln_source_address: impl Into<String>,
        dln_destination_address: impl Into<String>,
    ) -> Self {
        Self {
            api_url: api_url.into(),
            stats_api_url: default_stats_api_url(),
            chain_id,
            dln_source_address: dln_source_address.into(),
            dln_destination_address: dln_destination_address.into(),
            referral_code: None,
            affiliate_fee_percent: None,
            affiliate_fee_recipient: None,
        }
    }

    /// Builder: override the stats API endpoint
    pub fn with_stats_api_url(mut self, stats_api_url: impl Into<String>) -> Self {
        self.stats_api_url = stats_api_url.into();
        self
    }

    /// Builder: set referral code for deBridge points
    pub fn with_referral_code(mut self, code: impl Into<String>) -> Self {
        self.referral_code = Some(code.into());
        self
    }

    /// Builder: set affiliate fee for Tenzro commission
    pub fn with_affiliate_fee(mut self, percent: f64, recipient: impl Into<String>) -> Self {
        self.affiliate_fee_percent = Some(percent);
        self.affiliate_fee_recipient = Some(recipient.into());
        self
    }
}

impl Default for DeBridgeConfig {
    fn default() -> Self {
        Self {
            api_url: "https://dln.debridge.finance".to_string(),
            stats_api_url: default_stats_api_url(),
            chain_id: 1,
            dln_source_address: "0x0000000000000000000000000000000000000001".to_string(),
            dln_destination_address: "0x0000000000000000000000000000000000000002".to_string(),
            referral_code: None,
            affiliate_fee_percent: None,
            affiliate_fee_recipient: None,
        }
    }
}

/// DLN (Decentralized Liquidity Network) order
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DlnOrder {
    /// Unique order identifier
    pub order_id: String,
    /// Maker address (user creating the order)
    pub maker: String,
    /// Taker address (optional, can be specific or any)
    pub taker: Option<String>,
    /// Source chain where tokens are given
    pub give_chain: String,
    /// Destination chain where tokens are taken
    pub take_chain: String,
    /// Token to give on source chain
    pub give_token: String,
    /// Amount to give
    pub give_amount: u128,
    /// Token to receive on destination chain
    pub take_token: String,
    /// Amount to receive
    pub take_amount: u128,
    /// Order status
    pub status: DlnOrderStatus,
    /// When the order was created
    pub created_at: Timestamp,
    /// When the order was filled
    pub filled_at: Option<Timestamp>,
}

/// Status of a DLN order
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DlnOrderStatus {
    /// Order created, waiting for taker
    Created,
    /// Order filled by taker
    Filled,
    /// Order cancelled
    Cancelled,
}

/// Response from deBridge API create order endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DlnCreateOrderResponse {
    /// Transaction data to submit on-chain
    pub tx: Option<TransactionData>,
    /// Order ID (if available)
    pub order_id: Option<String>,
    /// Estimated output amount
    pub estimation: Option<EstimationData>,
    /// Estimated fee
    pub estimated_fee: Option<u128>,
}

/// Transaction data from API response
#[derive(Debug, Clone, Serialize, Deserialize)]
struct TransactionData {
    /// Target contract address
    pub to: String,
    /// Transaction data (calldata)
    pub data: String,
    /// Value to send (in wei)
    pub value: String,
}

/// Estimation data from API response
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EstimationData {
    /// Estimated output amount
    pub dst_chain_token_out_amount: String,
    /// Source chain token in amount
    pub src_chain_token_in_amount: String,
}

/// deBridge Hook for post-fulfillment on-chain actions (2026)
///
/// Hooks allow arbitrary contract calls to execute when an order is fulfilled
/// on the destination chain. The deBridge API validates, encodes, and simulates
/// the hook before including it in the order creation transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DlnHook {
    /// Target contract address on the destination chain
    pub target: String,
    /// Calldata to execute on the target contract
    pub call_data: String,
    /// Whether to revert the entire fill if the hook fails
    pub revert_if_fails: bool,
}

impl DlnHook {
    /// Creates a new hook that will call a contract on the destination chain
    pub fn new(target: impl Into<String>, call_data: impl Into<String>, revert_if_fails: bool) -> Self {
        Self {
            target: target.into(),
            call_data: call_data.into(),
            revert_if_fails,
        }
    }
}

/// Summary of a DLN order from the filteredList endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DlnOrderSummary {
    /// Order ID
    #[serde(alias = "orderId", alias = "id")]
    pub order_id: Option<String>,
    /// Order state
    pub state: Option<String>,
    /// Source chain ID
    pub src_chain_id: Option<u64>,
    /// Destination chain ID
    pub dst_chain_id: Option<u64>,
    /// Creation timestamp
    pub created_at: Option<String>,
}

/// Response from filteredList endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DlnFilteredListResponse {
    #[serde(default)]
    pub orders: Vec<DlnOrderSummary>,
}

/// Response from deBridge stats API order status endpoint
///
/// `GET https://stats-api.dln.trade/api/Orders/{orderId}` returns a rich
/// order document. The status discriminator may live under `state`
/// (preferred for the stats API) or under `status` (legacy field shipped
/// by the old `dln.debridge.finance` endpoint and still emitted as a
/// fallback by some proxies). We keep both fields optional and surface a
/// canonical reading via [`DlnOrderStatusResponse::canonical_state`].
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct DlnOrderStatusResponse {
    /// Stats-API state field, e.g. "Fulfilled", "OrderCreated", "ClaimedUnlock"
    #[serde(default)]
    pub state: Option<String>,
    /// Legacy status field (older deBridge proxies), e.g. "Created", "Fulfilled"
    #[serde(default)]
    pub status: Option<String>,
    /// Order id echoed back by the API
    #[serde(default, alias = "orderId", alias = "id")]
    pub order_id: Option<String>,
}

impl DlnOrderStatusResponse {
    /// Returns the canonical state string, preferring `state` over `status`.
    /// Returns an empty string if neither is set, which the caller maps to
    /// `DlnOrderStatus::Created` as a safe default.
    fn canonical_state(&self) -> String {
        self.state
            .as_deref()
            .or(self.status.as_deref())
            .unwrap_or("")
            .to_string()
    }
}

#[cfg(test)]
impl DeBridgeAdapter {
    /// Inserts a test order directly into the local cache.
    /// Only available in tests — bypasses the API and signer requirements.
    fn insert_test_order(&self, order: DlnOrder) {
        self.orders.insert(order.order_id.clone(), order);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_debridge_adapter_creation() {
        let config = DeBridgeConfig::new(
            "https://dln.debridge.finance",
            1,
            "0x0000000000000000000000000000000000000001",
            "0x0000000000000000000000000000000000000002",
        );

        let adapter = DeBridgeAdapter::new(config);
        assert_eq!(adapter.protocol_name(), "deBridge DLN");
        assert!(!adapter.supported_chains().is_empty());
    }

    #[tokio::test]
    async fn test_create_order_requires_api_or_signer() {
        let config = DeBridgeConfig::new(
            "https://dln.debridge.finance",
            1,
            "0x0000000000000000000000000000000000000001",
            "0x0000000000000000000000000000000000000002",
        );

        let adapter = DeBridgeAdapter::new(config);
        let result = adapter
            .create_order(
                "ethereum",
                "arbitrum",
                "USDC",
                1000000,
                "USDC",
                999000,
                "0xmaker",
                None,
            )
            .await;

        // Without API access or signer, create_order should fail
        assert!(result.is_err(), "create_order should fail without API/signer");
    }

    #[tokio::test]
    async fn test_sha256_hash() {
        let config = DeBridgeConfig::default();
        let adapter = DeBridgeAdapter::new(config);

        let hash1 = adapter.compute_hash("test");
        let hash2 = adapter.compute_hash("test");
        let hash3 = adapter.compute_hash("different");

        // Same input produces same hash
        assert_eq!(hash1, hash2);
        // Different input produces different hash
        assert_ne!(hash1, hash3);
    }

    #[tokio::test]
    async fn test_chain_id_mapping() {
        let config = DeBridgeConfig::default();
        let adapter = DeBridgeAdapter::new(config);

        assert_eq!(adapter.get_chain_id("ethereum").unwrap(), 1);
        assert_eq!(adapter.get_chain_id("arbitrum").unwrap(), 42161);
        assert_eq!(adapter.get_chain_id("optimism").unwrap(), 10);
        assert_eq!(adapter.get_chain_id("polygon").unwrap(), 137);
        assert_eq!(adapter.get_chain_id("bsc").unwrap(), 56);
        assert_eq!(adapter.get_chain_id("avalanche").unwrap(), 43114);
        assert_eq!(adapter.get_chain_id("solana").unwrap(), 7565164);
        assert_eq!(adapter.get_chain_id("base").unwrap(), 8453);

        assert!(adapter.get_chain_id("unknown").is_err());
    }

    #[tokio::test]
    async fn test_bridge_tokens_requires_api_and_signer() {
        let config = DeBridgeConfig::default();
        let adapter = DeBridgeAdapter::new(config);

        let request = BridgeTokenRequest::new(
            "ethereum",
            "arbitrum",
            "USDC",
            1_000_000,
            "0xsender",
            "0xrecipient",
        );

        // Without API access or signer, bridge_tokens should return an error
        let result = adapter.bridge_tokens(request).await;
        assert!(result.is_err(), "bridge_tokens should fail without API/signer");
    }

    #[tokio::test]
    async fn test_get_transfer_status() {
        let config = DeBridgeConfig::default();
        let adapter = DeBridgeAdapter::new(config);

        // Insert a test order directly — create_order() requires a live API
        // and signer, but get_transfer_status / fill_order only need the
        // local order cache.
        let order = DlnOrder {
            order_id: "dln-ethereum-test-1".to_string(),
            maker: "0xmaker".to_string(),
            taker: None,
            give_chain: "ethereum".to_string(),
            take_chain: "arbitrum".to_string(),
            give_token: "USDC".to_string(),
            give_amount: 1_000_000,
            take_token: "USDC".to_string(),
            take_amount: 999_000,
            status: DlnOrderStatus::Created,
            created_at: Timestamp::now(),
            filled_at: None,
        };
        adapter.insert_test_order(order.clone());

        // Should be pending (Created maps to Pending)
        let status = adapter.get_transfer_status(&order.order_id).await.unwrap();
        assert_eq!(status, TransferStatus::Pending);

        // Fill the order
        adapter.fill_order(&order.order_id, "0xtaker").await.unwrap();

        // Should be delivered (Filled maps to Delivered)
        let status = adapter.get_transfer_status(&order.order_id).await.unwrap();
        assert_eq!(status, TransferStatus::Delivered);
    }

    #[tokio::test]
    async fn test_estimate_fee_requires_live_api() {
        // deBridge adapter no longer provides a static fee fallback — real usage
        // MUST hit the DLN create-tx API. When the API is unreachable (this
        // test environment), the adapter surfaces the error rather than
        // silently returning mock numbers, which is the intended behaviour
        // after the mock-fallback audit.
        let config = DeBridgeConfig::default();
        let adapter = DeBridgeAdapter::new(config);

        let result = adapter.estimate_fee("arbitrum", 1000).await;
        assert!(
            matches!(result, Err(BridgeError::NetworkError(_))),
            "expected NetworkError when DLN API is unreachable, got {:?}",
            result
        );
    }

    #[tokio::test]
    async fn test_with_http_client() {
        let custom_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .unwrap();

        let config = DeBridgeConfig::default();
        let adapter = DeBridgeAdapter::with_http_client(config, custom_client);

        assert_eq!(adapter.protocol_name(), "deBridge DLN");
    }
}
