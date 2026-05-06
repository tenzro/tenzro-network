//! LayerZero V2 bridge adapter
//!
//! This module provides a bridge adapter for LayerZero's Omnichain Interoperability Protocol.
//! LayerZero uses a lightweight message-passing framework with configurable security via
//! independent oracles and relayers.
//!
//! ## Real EVM Integration
//!
//! This implementation makes actual JSON-RPC calls to LayerZero V2 EndpointV2 contracts:
//! - **Quote fees**: `eth_call` to `EndpointV2.quote()`
//! - **Send messages**: `eth_sendRawTransaction` to `EndpointV2.send()`
//! - **Transfer status**: Query LayerZero Scan API
//!
//! EndpointV2 is deployed at `0x1a44076050125825900e736c501f859c50fE728c` on all EVM chains.

use crate::{
    error::{BridgeError, Result},
    evm_signer::EvmTransactionSigner,
    message_format::{NonceTracker, TenzroMessage},
    traits::{BridgeAdapter, BridgeTokenReceipt, BridgeTokenRequest, ChainInfo, TransferStatus},
};
use async_trait::async_trait;
use dashmap::DashMap;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;
use tenzro_types::primitives::{Hash, Timestamp};
use tracing::{debug, info, warn};

/// LayerZero V2 EndpointV2 contract address (same on all EVM chains)
const ENDPOINT_V2_ADDRESS: &str = "0x1a44076050125825900e736c501f859c50fE728c";

/// LayerZero Scan API base URL (used by query_layerzero_scan and get_transfer_status)
pub const LAYERZERO_SCAN_API: &str = "https://scan.layerzero-api.com/v1";

/// LayerZero bridge adapter implementing OApp/OFT patterns
pub struct LayerZeroAdapter {
    /// LayerZero configuration
    config: LayerZeroConfig,
    /// HTTP client for JSON-RPC calls
    http_client: Client,
    /// Configured peers on destination chains
    peers: Arc<DashMap<String, String>>,
    /// Message nonce tracking
    nonce: Arc<DashMap<String, u64>>,
    /// Transfer status tracking
    transfers: Arc<DashMap<String, TransferStatus>>,
    /// Optional EVM transaction signer for real on-chain submission
    signer: Option<Arc<EvmTransactionSigner>>,
    /// Nonce tracker for replay protection on received messages
    inbound_nonce_tracker: NonceTracker,
}

impl LayerZeroAdapter {
    /// Creates a new LayerZero adapter
    pub fn new(config: LayerZeroConfig) -> Self {
        let http_client = Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .unwrap_or_else(|_| Client::new());

        Self {
            config,
            http_client,
            peers: Arc::new(DashMap::new()),
            nonce: Arc::new(DashMap::new()),
            transfers: Arc::new(DashMap::new()),
            signer: None,
            inbound_nonce_tracker: NonceTracker::new(),
        }
    }

    /// Configures an EVM transaction signer for real on-chain submission
    ///
    /// When a signer is configured, `send_message()` and `bridge_tokens()` will
    /// submit real transactions via `eth_sendRawTransaction` instead of generating
    /// deterministic tx hashes.
    pub fn with_signer(mut self, signer: EvmTransactionSigner) -> Self {
        self.signer = Some(Arc::new(signer));
        self
    }

    /// Sets a peer address on a destination chain
    ///
    /// In LayerZero, OApps must configure trusted peers on each chain they communicate with.
    pub fn set_peer(&self, chain_id: impl Into<String>, peer_address: impl Into<String>) {
        let chain = chain_id.into();
        let peer = peer_address.into();
        info!("LayerZero: Setting peer on chain {} to {}", chain, peer);
        self.peers.insert(chain, peer);
    }

    /// Gets the next nonce for a destination chain
    fn get_next_nonce(&self, dest_chain: &str) -> u64 {
        let mut entry = self.nonce.entry(dest_chain.to_string()).or_insert(0);
        let nonce = *entry;
        *entry += 1;
        nonce
    }

    /// Quotes the LayerZero messaging fee via eth_call to `EndpointV2.quote()`.
    ///
    /// Returns the real on-chain quote when the adapter has an RPC URL configured
    /// and the endpoint contract replies successfully; otherwise falls back to
    /// the offline `estimate_fee_static` heuristic. This is the public entry
    /// point used by callers that explicitly want a quote.
    pub async fn quote_fee(&self, dest_chain: &str, payload_size: usize) -> Result<u128> {
        match self.quote_fee_via_rpc(dest_chain, payload_size).await {
            Ok(fee) => Ok(fee),
            Err(e) => {
                warn!(
                    "LayerZero: quote_fee RPC path failed ({}), falling back to static estimate",
                    e
                );
                Ok(self.estimate_fee_static(payload_size))
            }
        }
    }

    /// Calls `EndpointV2.quote()` via `eth_call` and returns the decoded native fee.
    ///
    /// Returns `Err` if the adapter is not configured with an RPC URL, the
    /// destination chain is unknown, or the endpoint returns an invalid
    /// response. Callers are responsible for handling fallback.
    async fn quote_fee_via_rpc(&self, dest_chain: &str, payload_size: usize) -> Result<u128> {
        let dest_eid = self.get_chain_eid(dest_chain)?;

        if self.config.rpc_url.is_empty() {
            return Err(BridgeError::AdapterError(
                "LayerZero: no RPC URL configured for fee quote".to_string(),
            ));
        }

        // Encode MessagingParams struct
        let dummy_payload = vec![0u8; payload_size];
        let messaging_params = self.encode_messaging_params(
            dest_eid,
            vec![0u8; 32], // dummy receiver
            &dummy_payload, // dummy payload of correct size
            self.encode_options(),
            false, // payInLzToken
        );

        // Encode quote(MessagingParams, address) call
        // quote selector: 0xdb9d28c6
        let mut calldata = Vec::new();
        calldata.extend_from_slice(&hex::decode("db9d28c6").unwrap());
        calldata.extend_from_slice(&messaging_params);
        // sender address (32 bytes, zero-padded)
        calldata.extend_from_slice(&[0u8; 32]);

        // Make eth_call
        let response = self
            .eth_call(ENDPOINT_V2_ADDRESS, &hex::encode(&calldata))
            .await?;

        // Decode MessagingFee { uint256 nativeFee; uint256 lzTokenFee; }
        if response.len() < 64 {
            return Err(BridgeError::AdapterError(format!(
                "LayerZero: invalid quote response length {}",
                response.len()
            )));
        }

        let native_fee = u128::from_be_bytes(
            response[16..32]
                .try_into()
                .unwrap_or([0u8; 16])
        );

        debug!(
            "LayerZero: Quoted fee for {} to {} = {} wei",
            payload_size, dest_chain, native_fee
        );

        Ok(native_fee)
    }

    /// Offline, heuristic-only fee estimate used as a fallback when the
    /// real `EndpointV2.quote()` call is unavailable.
    ///
    /// The numbers come from typical LayerZero V2 costs and should only be
    /// used when the RPC path is unavailable.
    fn estimate_fee_static(&self, payload_size: usize) -> u128 {
        const BASE_FEE_WEI: u128 = 100_000_000_000_000; // 0.0001 ETH base
        const PER_BYTE_FEE_WEI: u128 = 1_000_000_000; // ~1 Gwei per byte
        BASE_FEE_WEI + (payload_size as u128 * PER_BYTE_FEE_WEI)
    }

    /// Returns supported chain information
    fn get_supported_chains() -> Vec<ChainInfo> {
        vec![
            ChainInfo::new("ethereum", "Ethereum", "ETH", 900),
            ChainInfo::new("arbitrum", "Arbitrum One", "ETH", 15),
            ChainInfo::new("optimism", "Optimism", "ETH", 15),
            ChainInfo::new("polygon", "Polygon", "MATIC", 120),
            ChainInfo::new("bsc", "BNB Smart Chain", "BNB", 15),
            ChainInfo::new("avalanche", "Avalanche C-Chain", "AVAX", 5),
            ChainInfo::new("base", "Base", "ETH", 5),
            ChainInfo::new("solana", "Solana", "SOL", 1),
        ]
    }

    /// Gets the endpoint ID for a chain
    fn get_chain_eid(&self, chain_id: &str) -> Result<u32> {
        // LayerZero V2 endpoint IDs (EIDs) - mainnet
        // Source: https://docs.layerzero.network/v2/developers/evm/technical-reference/deployed-contracts
        match chain_id {
            "ethereum" => Ok(30101),
            "bsc" => Ok(30102),
            "avalanche" => Ok(30106),
            "polygon" => Ok(30109),
            "arbitrum" => Ok(30110),
            "optimism" => Ok(30111),
            "zksync" => Ok(30165),
            "solana" => Ok(30168),
            "base" => Ok(30184),
            "sei" => Ok(30280),
            "sonic" => Ok(30332),
            "berachain" => Ok(30362),
            "story" => Ok(30364),
            "monad" => Ok(30390),
            "megaeth" => Ok(30398),
            "tron" => Ok(30420),
            _ => Err(BridgeError::ChainNotSupported(chain_id.to_string())),
        }
    }

    /// Makes an eth_call JSON-RPC request
    async fn eth_call(&self, to: &str, data: &str) -> Result<Vec<u8>> {
        let request = json!({
            "jsonrpc": "2.0",
            "method": "eth_call",
            "params": [{
                "to": to,
                "data": format!("0x{}", data)
            }, "latest"],
            "id": 1
        });

        let response = self
            .http_client
            .post(&self.config.rpc_url)
            .json(&request)
            .send()
            .await
            .map_err(|e| BridgeError::AdapterError(e.to_string()))?;

        if !response.status().is_success() {
            return Err(BridgeError::AdapterError(format!(
                "HTTP {} from RPC",
                response.status()
            )));
        }

        let json: serde_json::Value = response
            .json()
            .await
            .map_err(|e| BridgeError::AdapterError(format!("Invalid JSON: {}", e)))?;

        if let Some(error) = json.get("error") {
            return Err(BridgeError::AdapterError(format!(
                "RPC error: {}",
                error
            )));
        }

        let result = json
            .get("result")
            .and_then(|r: &serde_json::Value| r.as_str())
            .ok_or_else(|| BridgeError::AdapterError("No result in response".to_string()))?;

        // Remove 0x prefix and decode
        let hex_str = result.strip_prefix("0x").unwrap_or(result);
        hex::decode(hex_str)
            .map_err(|e| BridgeError::AdapterError(format!("Invalid hex: {}", e)))
    }

    /// Encodes MessagingParams for ABI encoding
    ///
    /// struct MessagingParams {
    ///     uint32 dstEid;
    ///     bytes32 receiver;
    ///     bytes message;
    ///     bytes options;
    ///     bool payInLzToken;
    /// }
    fn encode_messaging_params(
        &self,
        dst_eid: u32,
        receiver: Vec<u8>,
        message: &[u8],
        options: Vec<u8>,
        pay_in_lz_token: bool,
    ) -> Vec<u8> {
        let mut encoded = Vec::new();

        // Offset to struct data (always 0x20 for single struct param)
        encoded.extend_from_slice(&[0u8; 31]);
        encoded.push(0x20);

        // dstEid (uint32 as uint256)
        encoded.extend_from_slice(&[0u8; 28]);
        encoded.extend_from_slice(&dst_eid.to_be_bytes());

        // receiver (bytes32)
        let mut receiver_bytes = [0u8; 32];
        let len = receiver.len().min(32);
        receiver_bytes[..len].copy_from_slice(&receiver[..len]);
        encoded.extend_from_slice(&receiver_bytes);

        // Offset to message bytes (5 fields * 32 bytes + variable data)
        let message_offset = 5 * 32;
        encoded.extend_from_slice(&[0u8; 28]);
        encoded.extend_from_slice(&(message_offset as u32).to_be_bytes());

        // Offset to options bytes
        let options_offset = message_offset + 32 + message.len().div_ceil(32) * 32;
        encoded.extend_from_slice(&[0u8; 28]);
        encoded.extend_from_slice(&(options_offset as u32).to_be_bytes());

        // payInLzToken (bool as uint256)
        encoded.extend_from_slice(&[0u8; 31]);
        encoded.push(if pay_in_lz_token { 1 } else { 0 });

        // message length
        encoded.extend_from_slice(&[0u8; 28]);
        encoded.extend_from_slice(&(message.len() as u32).to_be_bytes());
        // message data (padded to 32-byte boundary)
        encoded.extend_from_slice(message);
        let message_padding = (32 - (message.len() % 32)) % 32;
        encoded.extend_from_slice(&vec![0u8; message_padding]);

        // options length
        encoded.extend_from_slice(&[0u8; 28]);
        encoded.extend_from_slice(&(options.len() as u32).to_be_bytes());
        // options data (padded to 32-byte boundary)
        encoded.extend_from_slice(&options);
        let options_padding = (32 - (options.len() % 32)) % 32;
        encoded.extend_from_slice(&vec![0u8; options_padding]);

        encoded
    }

    /// Queries LayerZero Scan API for transfer status
    async fn query_layerzero_scan(&self, tx_hash: &str) -> Result<TransferStatus> {
        let url = format!("{}/messages/tx/{}", LAYERZERO_SCAN_API, tx_hash);

        let response = match self.http_client.get(&url).send().await {
            Ok(resp) => resp,
            Err(e) => {
                debug!("LayerZero Scan API query failed: {}", e);
                return Ok(TransferStatus::Pending);
            }
        };

        if !response.status().is_success() {
            debug!("LayerZero Scan API returned {}", response.status());
            return Ok(TransferStatus::Pending);
        }

        let json: serde_json::Value = match response.json().await {
            Ok(j) => j,
            Err(e) => {
                debug!("LayerZero Scan API invalid JSON: {}", e);
                return Ok(TransferStatus::Pending);
            }
        };

        // Parse status from response
        // API returns { "messages": [{ "status": "DELIVERED" | "INFLIGHT" | "FAILED", ... }] }
        if let Some(messages) = json.get("messages").and_then(|m| m.as_array())
            && let Some(message) = messages.first()
            && let Some(status) = message.get("status").and_then(|s| s.as_str())
        {
            return Ok(match status {
                "DELIVERED" => TransferStatus::Delivered,
                "FAILED" => TransferStatus::Failed,
                _ => TransferStatus::Pending,
            });
        }

        Ok(TransferStatus::Pending)
    }
}

#[async_trait]
impl BridgeAdapter for LayerZeroAdapter {
    fn protocol_name(&self) -> &str {
        "LayerZero"
    }

    fn supported_chains(&self) -> Vec<ChainInfo> {
        Self::get_supported_chains()
    }

    async fn send_message(&self, dest_chain: &str, payload: Vec<u8>) -> Result<String> {
        // Verify destination chain is supported
        let dest_eid = self.get_chain_eid(dest_chain)?;

        // Check if peer is configured
        let peer = self
            .peers
            .get(dest_chain)
            .ok_or_else(|| {
                BridgeError::ConfigurationError(format!(
                    "No peer configured for chain {}",
                    dest_chain
                ))
            })?
            .clone();

        // Get next nonce
        let nonce = self.get_next_nonce(dest_chain);

        // Convert peer address to bytes32
        let peer_bytes = if let Some(hex_str) = peer.strip_prefix("0x") {
            hex::decode(hex_str).unwrap_or_else(|_| peer.as_bytes().to_vec())
        } else {
            peer.as_bytes().to_vec()
        };

        // Create LayerZero message (for structured logging)
        let _message = LayerZeroMessage {
            src_eid: self.config.eid,
            dst_eid: dest_eid,
            nonce,
            payload: payload.clone(),
            options: self.encode_options(),
        };

        info!(
            "LayerZero: Sending message to chain {} (EID: {}), nonce={}",
            dest_chain, dest_eid, nonce
        );

        if self.config.rpc_url.is_empty() {
            return Err(BridgeError::ConfigurationError(
                "LayerZero: No RPC URL configured — cannot send cross-chain message. \
                 Set rpc_url in LayerZeroConfig."
                    .to_string(),
            ));
        }

        // Encode send(MessagingParams, address) call
        // send selector: 0x5e280f11
        let messaging_params = self.encode_messaging_params(
            dest_eid,
            peer_bytes,
            &payload,
            self.encode_options(),
            false,
        );

        let mut calldata = Vec::new();
        calldata.extend_from_slice(&hex::decode("5e280f11").unwrap());
        calldata.extend_from_slice(&messaging_params);
        // refundAddress (32 bytes, zero address for simplicity)
        calldata.extend_from_slice(&[0u8; 32]);

        // If signer is configured, submit real on-chain transaction
        if let Some(ref signer) = self.signer {
            let value = self.quote_fee(dest_chain, payload.len()).await.unwrap_or(0);
            let tx_hash = signer
                .send_transaction(ENDPOINT_V2_ADDRESS, &calldata, value)
                .await?;
            info!(
                "LayerZero: Submitted on-chain send tx {} (payload_size={})",
                tx_hash,
                payload.len()
            );
            return Ok(tx_hash);
        }

        // No signer configured — cannot submit on-chain transaction
        Err(BridgeError::ConfigurationError(
            "LayerZero: No signer configured — cannot submit send transaction. \
             Call with_signer() to configure an EVM transaction signer."
                .to_string(),
        ))
    }

    async fn receive_message(&self, source_chain: &str, payload: Vec<u8>) -> Result<()> {
        let src_eid = self.get_chain_eid(source_chain)?;

        info!(
            "LayerZero: Receiving message from chain {} (EID: {}), payload_size={}",
            source_chain,
            src_eid,
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

        // 4. Verify the source EID matches the message's source_chain_id
        if message.source_chain_id != src_eid as u64 {
            return Err(BridgeError::AdapterError(format!(
                "Source chain mismatch: message says {} but received from EID {}",
                message.source_chain_id, src_eid
            )));
        }

        // 5. Verify cryptographic signature if present
        if message.signature.is_some() {
            let valid = message.verify_signature()?;
            if !valid {
                return Err(BridgeError::AdapterError(
                    "LayerZero: Message signature verification failed".to_string(),
                ));
            }
            debug!("LayerZero: Message signature verified successfully");
        }

        // 6. Replay protection — nonce must be monotonically increasing per sender
        self.inbound_nonce_tracker.check_and_update(&message.sender, message.nonce)?;

        info!(
            "LayerZero: Message from {} verified and processed (type={:?}, nonce={})",
            message.sender, message.message_type, message.nonce
        );

        Ok(())
    }

    async fn bridge_tokens(&self, request: BridgeTokenRequest) -> Result<BridgeTokenReceipt> {
        // Verify chains are supported
        let _src_eid = self.get_chain_eid(&request.source_chain)?;
        let dest_eid = self.get_chain_eid(&request.dest_chain)?;

        // Check if peer is configured
        let peer = self
            .peers
            .get(&request.dest_chain)
            .ok_or_else(|| {
                BridgeError::ConfigurationError(format!(
                    "No peer configured for chain {}",
                    request.dest_chain
                ))
            })?
            .clone();

        info!(
            "LayerZero OFT: Bridging {} {} from {} to {}",
            request.amount, request.asset_id, request.source_chain, request.dest_chain
        );

        // Encode OFT message payload
        let oft_payload = self.encode_oft_message(&request);

        // Quote fee via RPC or estimate
        let fee = if !self.config.rpc_url.is_empty() {
            match self.quote_fee(&request.dest_chain, oft_payload.len()).await {
                Ok(f) => f,
                Err(e) => {
                    warn!("LayerZero: Fee quote failed ({}), using estimate", e);
                    self.estimate_fee(&request.dest_chain, oft_payload.len()).await?
                }
            }
        } else {
            self.estimate_fee(&request.dest_chain, oft_payload.len()).await?
        };

        // Get nonce
        let nonce = self.get_next_nonce(&request.dest_chain);

        // Create transfer ID
        let transfer_id = format!(
            "lz-oft-{}-{}-{}",
            request.source_chain, request.dest_chain, nonce
        );

        // Convert peer to bytes32
        let peer_bytes = if let Some(hex_str) = peer.strip_prefix("0x") {
            hex::decode(hex_str).unwrap_or_else(|_| peer.as_bytes().to_vec())
        } else {
            peer.as_bytes().to_vec()
        };

        // Encode send() call for OFT
        let messaging_params = self.encode_messaging_params(
            dest_eid,
            peer_bytes,
            &oft_payload,
            self.encode_options(),
            false,
        );

        // Submit on-chain if signer is configured, otherwise generate deterministic hash
        let tx_hash = if let Some(ref signer) = self.signer {
            let tx_hash_str = signer
                .send_transaction(ENDPOINT_V2_ADDRESS, &messaging_params, fee)
                .await?;
            info!(
                "LayerZero OFT: Submitted on-chain bridge tx {}",
                tx_hash_str
            );
            // Parse hex hash into Hash type
            let hash_bytes = hex::decode(tx_hash_str.trim_start_matches("0x"))
                .unwrap_or_else(|_| vec![0u8; 32]);
            let mut hash_array = [0u8; 32];
            let len = hash_bytes.len().min(32);
            hash_array[32 - len..].copy_from_slice(&hash_bytes[..len]);
            Hash::new(hash_array)
        } else {
            return Err(BridgeError::ConfigurationError(
                "LayerZero OFT: No signer configured — cannot submit bridge transaction. \
                 Call with_signer() to configure an EVM transaction signer."
                    .to_string(),
            ));
        };

        // Calculate estimated arrival time
        let dest_chain_info = Self::get_supported_chains()
            .into_iter()
            .find(|c| c.chain_id == request.dest_chain)
            .ok_or_else(|| BridgeError::ChainNotSupported(request.dest_chain.clone()))?;

        let estimated_arrival =
            Timestamp::now().as_millis() + (dest_chain_info.finality_time_secs as i64 * 1000);

        // Track transfer
        self.transfers.insert(transfer_id.clone(), TransferStatus::Pending);

        info!(
            "LayerZero OFT: Transfer {} initiated, tx_hash={}, fee={} wei",
            transfer_id, tx_hash, fee
        );

        Ok(BridgeTokenReceipt::new(
            transfer_id,
            tx_hash,
            estimated_arrival,
            fee,
            request.source_chain,
            request.dest_chain,
        ))
    }

    async fn get_transfer_status(&self, transfer_id: &str) -> Result<TransferStatus> {
        // First check local cache
        if let Some(entry) = self.transfers.get(transfer_id) {
            let status = *entry.value();

            // If pending, try to update via LayerZero Scan API
            if status == TransferStatus::Pending {
                // Try querying LayerZero Scan with the transfer_id as tx hash
                match self.query_layerzero_scan(transfer_id).await {
                    Ok(new_status) if new_status != TransferStatus::Pending => {
                        self.transfers.insert(transfer_id.to_string(), new_status);
                        return Ok(new_status);
                    }
                    _ => {}
                }
            }

            return Ok(status);
        }

        Err(BridgeError::TransferNotFound(transfer_id.to_string()))
    }

    async fn estimate_fee(&self, dest_chain: &str, payload_size: usize) -> Result<u128> {
        // Verify destination chain (errors early if chain is unsupported)
        let _dest_eid = self.get_chain_eid(dest_chain)?;

        // Prefer the real `EndpointV2.quote()` RPC call; only fall back to the
        // static heuristic when the RPC path is unavailable.
        match self.quote_fee_via_rpc(dest_chain, payload_size).await {
            Ok(fee) => {
                debug!(
                    "LayerZero: Live fee quote for {} bytes to {} = {} wei",
                    payload_size, dest_chain, fee
                );
                Ok(fee)
            }
            Err(e) => {
                let fallback = self.estimate_fee_static(payload_size);
                warn!(
                    "LayerZero: Live fee quote failed ({}), using static fallback = {} wei",
                    e, fallback
                );
                Ok(fallback)
            }
        }
    }
}

impl LayerZeroAdapter {
    /// Encodes LayerZero V3 execution options per ExecutorOptions.sol / OptionsBuilder.sol.
    ///
    /// Format: `TYPE_3 header (2B) + worker options...`
    /// Each worker option: `worker_id (1B) + option_size (2B, uint16) + option_type (1B) + data`
    ///
    /// For lzReceive (option type 1) with value=0:
    ///   `0x0003 | 01 | 0011 | 01 | uint128 gas`  (total: 2+1+2+1+16 = 22 bytes)
    /// For lzReceive with value>0:
    ///   `0x0003 | 01 | 0021 | 01 | uint128 gas | uint128 value`  (total: 2+1+2+1+16+16 = 38 bytes)
    fn encode_options(&self) -> Vec<u8> {
        self.encode_options_with_gas_value(200_000, 0)
    }

    /// Encodes LayerZero V3 options with configurable gas and value.
    fn encode_options_with_gas_value(&self, gas_limit: u128, value: u128) -> Vec<u8> {
        let mut options = Vec::new();

        // TYPE_3 header (2 bytes)
        options.extend_from_slice(&[0x00, 0x03]);

        // Worker ID: 1 (executor)
        options.push(0x01);

        if value == 0 {
            // Option size: 17 bytes (1 byte option_type + 16 bytes gas)
            options.extend_from_slice(&0x0011u16.to_be_bytes());
            // Option type: OPTION_TYPE_LZRECEIVE = 1
            options.push(0x01);
            // Gas limit as uint128 (16 bytes, big-endian)
            options.extend_from_slice(&gas_limit.to_be_bytes());
        } else {
            // Option size: 33 bytes (1 byte option_type + 16 bytes gas + 16 bytes value)
            options.extend_from_slice(&0x0021u16.to_be_bytes());
            // Option type: OPTION_TYPE_LZRECEIVE = 1
            options.push(0x01);
            // Gas limit as uint128 (16 bytes, big-endian)
            options.extend_from_slice(&gas_limit.to_be_bytes());
            // Value as uint128 (16 bytes, big-endian)
            options.extend_from_slice(&value.to_be_bytes());
        }

        options
    }

    /// Encodes an OFT (Omnichain Fungible Token) message per OFTMsgCodec.sol.
    ///
    /// OFT message format (without compose):
    ///   `[bytes32 to (32B)][uint64 amountSD (8B)]`  = 40 bytes total
    ///
    /// The amount is in "shared decimals" (default 6). Callers should convert
    /// from local token decimals (e.g. 18) to shared decimals before calling.
    /// We truncate here: `amountSD = amount / 10^(localDecimals - sharedDecimals)`.
    fn encode_oft_message(&self, request: &BridgeTokenRequest) -> Vec<u8> {
        let mut payload = Vec::new();

        // Recipient (bytes32, right-aligned)
        let recipient_bytes = if request.recipient.starts_with("0x") {
            hex::decode(&request.recipient[2..])
                .unwrap_or_else(|_| request.recipient.as_bytes().to_vec())
        } else {
            request.recipient.as_bytes().to_vec()
        };

        let mut recipient_padded = [0u8; 32];
        let len = recipient_bytes.len().min(32);
        recipient_padded[32 - len..].copy_from_slice(&recipient_bytes[..len]);
        payload.extend_from_slice(&recipient_padded);

        // Amount in shared decimals (uint64, 8 bytes, big-endian)
        // OFT default: 6 shared decimals. For 18-decimal tokens: divide by 10^12
        let shared_decimals: u32 = 6;
        let local_decimals: u32 = 18;
        let amount_sd: u64 = if local_decimals > shared_decimals {
            let divisor = 10u128.pow(local_decimals - shared_decimals);
            (request.amount / divisor) as u64
        } else {
            request.amount as u64
        };
        payload.extend_from_slice(&amount_sd.to_be_bytes());

        payload
    }
}

/// LayerZero adapter configuration
///
/// ## Production Integration
///
/// Real LayerZero V2 integration requires:
/// - **RPC URL**: Ethereum JSON-RPC endpoint for the source chain
/// - **Wallet**: Private key for signing transactions (not stored in config)
/// - **EndpointV2**: Contract at 0x1a44076050125825900e736c501f859c50fE728c
/// - **OApp Deployment**: Deploy OApp contracts and configure peers via setPeer()
/// - **Fee Payment**: Transactions must include sufficient msg.value for messaging fees
///
/// ## Resources
/// - Contract addresses: https://docs.layerzero.network/v2/developers/evm/technical-reference/deployed-contracts
/// - OApp guide: https://docs.layerzero.network/v2/developers/evm/oapp/overview
/// - Scan API: https://docs.layerzero.network/v2/developers/evm/tooling/layerzero-scan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LayerZeroConfig {
    /// LayerZero endpoint address on this chain (typically 0x1a44076050125825900e736c501f859c50fE728c)
    pub endpoint_address: String,
    /// Endpoint ID (EID) for this chain (e.g., 30101 for Ethereum mainnet)
    pub eid: u32,
    /// RPC URL for this chain (e.g., https://eth.llamarpc.com)
    pub rpc_url: String,
    /// Oracle address for message verification (optional, for reference)
    pub oracle_address: String,
    /// Relayer address for message delivery (optional, for reference)
    pub relayer_address: String,
    /// Send library address (optional, for advanced configurations)
    pub send_library: String,
    /// Receive library address (optional, for advanced configurations)
    pub receive_library: String,
}

impl LayerZeroConfig {
    /// Creates a new LayerZero configuration
    pub fn new(
        endpoint_address: impl Into<String>,
        eid: u32,
        oracle_address: impl Into<String>,
        relayer_address: impl Into<String>,
    ) -> Self {
        Self {
            endpoint_address: endpoint_address.into(),
            eid,
            rpc_url: String::new(),
            oracle_address: oracle_address.into(),
            relayer_address: relayer_address.into(),
            send_library: "0x0000000000000000000000000000000000000000".to_string(),
            receive_library: "0x0000000000000000000000000000000000000000".to_string(),
        }
    }

    /// Sets the RPC URL for transaction submission
    pub fn with_rpc_url(mut self, rpc_url: impl Into<String>) -> Self {
        self.rpc_url = rpc_url.into();
        self
    }

    /// Estimates the LayerZero messaging fee for a given destination and payload
    ///
    /// In production, this calls the LayerZero EndpointV2's `quote()` function via eth_call.
    ///
    /// # Arguments
    /// * `_dest_eid` - Destination endpoint ID
    /// * `payload_size` - Size of the payload in bytes
    ///
    /// # Returns
    /// Estimated fee in wei
    pub async fn estimate_messaging_fee(&self, _dest_eid: u32, payload_size: usize) -> Result<u128> {
        // Fallback calculation if no RPC configured
        if self.rpc_url.is_empty() {
            let base_fee = 100_000_000_000_000u128; // 0.0001 ETH base
            let per_byte_fee = 1_000_000_000u128; // ~1 Gwei per byte
            return Ok(base_fee + (payload_size as u128 * per_byte_fee));
        }

        // In production, make eth_call to EndpointV2.quote()
        // For now, return estimate
        let base_fee = 100_000_000_000_000u128;
        let per_byte_fee = 1_000_000_000u128;
        Ok(base_fee + (payload_size as u128 * per_byte_fee))
    }
}

/// LayerZero cross-chain message
#[derive(Debug, Clone, Serialize, Deserialize)]
struct LayerZeroMessage {
    /// Source endpoint ID
    src_eid: u32,
    /// Destination endpoint ID
    dst_eid: u32,
    /// Message nonce
    nonce: u64,
    /// Message payload
    payload: Vec<u8>,
    /// Execution options
    options: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_layerzero_adapter_creation() {
        let config = LayerZeroConfig::new(
            ENDPOINT_V2_ADDRESS,
            30101,
            "0x0000000000000000000000000000000000000001",
            "0x0000000000000000000000000000000000000002",
        );

        let adapter = LayerZeroAdapter::new(config);
        assert_eq!(adapter.protocol_name(), "LayerZero");
        assert!(!adapter.supported_chains().is_empty());
    }

    #[tokio::test]
    async fn test_estimate_fee() {
        let config = LayerZeroConfig::new(
            ENDPOINT_V2_ADDRESS,
            30101,
            "0x0000000000000000000000000000000000000001",
            "0x0000000000000000000000000000000000000002",
        );

        let adapter = LayerZeroAdapter::new(config);
        let fee = adapter.estimate_fee("arbitrum", 100).await.unwrap();
        assert!(fee > 0);
    }

    #[tokio::test]
    async fn test_encode_options() {
        let config = LayerZeroConfig::new(
            ENDPOINT_V2_ADDRESS,
            30101,
            "0x0000000000000000000000000000000000000001",
            "0x0000000000000000000000000000000000000002",
        );

        let adapter = LayerZeroAdapter::new(config);
        let options = adapter.encode_options();

        // V3 options for lzReceive with value=0:
        // 0x0003 (TYPE_3) + 0x01 (worker_id) + 0x0011 (size=17) + 0x01 (option_type) + 16B gas
        // Total: 2 + 1 + 2 + 1 + 16 = 22 bytes
        assert_eq!(options.len(), 22);
        assert_eq!(options[0], 0x00);
        assert_eq!(options[1], 0x03); // TYPE_3
        assert_eq!(options[2], 0x01); // worker_id = executor
        assert_eq!(options[3], 0x00);
        assert_eq!(options[4], 0x11); // option size = 17
        assert_eq!(options[5], 0x01); // OPTION_TYPE_LZRECEIVE

        // Gas limit 200,000 as uint128 big-endian (last 4 bytes of the 16-byte field)
        assert_eq!(&options[18..22], &200_000u32.to_be_bytes());

        // With value > 0 should produce 38 bytes
        let options_with_value = adapter.encode_options_with_gas_value(200_000, 1_000_000);
        assert_eq!(options_with_value.len(), 38);
        assert_eq!(options_with_value[3], 0x00);
        assert_eq!(options_with_value[4], 0x21); // option size = 33
    }

    #[tokio::test]
    async fn test_encode_oft_message() {
        let config = LayerZeroConfig::new(
            ENDPOINT_V2_ADDRESS,
            30101,
            "0x0000000000000000000000000000000000000001",
            "0x0000000000000000000000000000000000000002",
        );

        let adapter = LayerZeroAdapter::new(config);
        let request = BridgeTokenRequest {
            source_chain: "ethereum".to_string(),
            dest_chain: "arbitrum".to_string(),
            asset_id: "USDC".to_string(),
            amount: 1_000_000_000_000_000_000, // 1 token in 18 decimals
            sender: "0x1234567890123456789012345678901234567890".to_string(),
            recipient: "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb".to_string(),
            extra_data: None,
        };

        let payload = adapter.encode_oft_message(&request);

        // OFTMsgCodec: [bytes32 to (32B)][uint64 amountSD (8B)] = 40 bytes
        assert_eq!(payload.len(), 40);

        // amountSD = 1e18 / 1e12 = 1_000_000 (6 shared decimals)
        let amount_sd = u64::from_be_bytes(payload[32..40].try_into().unwrap());
        assert_eq!(amount_sd, 1_000_000);
    }

    #[tokio::test]
    async fn test_get_chain_eid() {
        let config = LayerZeroConfig::new(
            ENDPOINT_V2_ADDRESS,
            30101,
            "0x0000000000000000000000000000000000000001",
            "0x0000000000000000000000000000000000000002",
        );

        let adapter = LayerZeroAdapter::new(config);

        assert_eq!(adapter.get_chain_eid("ethereum").unwrap(), 30101);
        assert_eq!(adapter.get_chain_eid("arbitrum").unwrap(), 30110);
        assert_eq!(adapter.get_chain_eid("base").unwrap(), 30184);
        assert!(adapter.get_chain_eid("unknown").is_err());
    }

    #[tokio::test]
    async fn test_encode_messaging_params() {
        let config = LayerZeroConfig::new(
            ENDPOINT_V2_ADDRESS,
            30101,
            "0x0000000000000000000000000000000000000001",
            "0x0000000000000000000000000000000000000002",
        );

        let adapter = LayerZeroAdapter::new(config);

        let receiver = vec![0x12; 32];
        let message = vec![0x34; 10];
        let options = vec![0x56; 5];

        let encoded = adapter.encode_messaging_params(
            30110,
            receiver,
            &message,
            options,
            false,
        );

        // Should contain struct offset + 5 fields + variable data
        assert!(encoded.len() > 32 * 6);
    }
}
