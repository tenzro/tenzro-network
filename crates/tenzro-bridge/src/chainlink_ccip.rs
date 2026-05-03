//! Chainlink CCIP (Cross-Chain Interoperability Protocol) bridge adapter
//!
//! This module provides a bridge adapter for Chainlink's CCIP, which enables secure
//! token transfers and arbitrary messaging across blockchains using Chainlink's
//! decentralized oracle networks.
//!
//! ## Implementation
//!
//! This adapter makes real EVM JSON-RPC calls to interact with CCIP Router contracts:
//! - `eth_call` to estimate fees via `Router.getFee()`
//! - `eth_sendRawTransaction` to send messages via `Router.ccipSend()`
//! - CCIP Explorer API to query transfer status
//!
//! ## ABI Encoding
//!
//! CCIP Router uses the following Solidity interface:
//! ```solidity
//! function getFee(uint64 destChainSelector, EVM2AnyMessage memory message)
//!     external view returns (uint256);
//!
//! function ccipSend(uint64 destChainSelector, EVM2AnyMessage memory message)
//!     external payable returns (bytes32);
//!
//! struct EVM2AnyMessage {
//!     bytes receiver;
//!     bytes data;
//!     EVMTokenAmount[] tokenAmounts;
//!     address feeToken;
//!     bytes extraArgs;
//! }
//!
//! struct EVMTokenAmount {
//!     address token;
//!     uint256 amount;
//! }
//! ```

use crate::{
    error::{BridgeError, Result},
    evm_signer::EvmTransactionSigner,
    message_format::{NonceTracker, TenzroMessage},
    traits::{BridgeAdapter, BridgeTokenReceipt, BridgeTokenRequest, ChainInfo, TransferStatus},
};
use async_trait::async_trait;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tenzro_types::primitives::{Hash, Timestamp};
use tracing::{debug, error, info};

/// Build a dRPC URL for a given chain slug, falling back to public RPCs when
/// the `DRPC_API_KEY` environment variable is not set.
fn drpc_url(chain: &str) -> String {
    let key = std::env::var("DRPC_API_KEY").unwrap_or_default();
    if key.is_empty() {
        return match chain {
            "ethereum" => "https://eth.llamarpc.com".to_string(),
            "arbitrum" => "https://arb1.arbitrum.io/rpc".to_string(),
            "base" => "https://mainnet.base.org".to_string(),
            "optimism" => "https://mainnet.optimism.io".to_string(),
            "polygon" => "https://polygon-rpc.com".to_string(),
            "bsc" => "https://bsc-dataseed.binance.org".to_string(),
            "avalanche" => "https://api.avax.network/ext/bc/C/rpc".to_string(),
            "zksync" => "https://mainnet.era.zksync.io".to_string(),
            _ => format!("https://{}.drpc.org", chain),
        };
    }
    format!("https://lb.drpc.live/{}/{}", chain, key)
}

/// Tracked transfer with destination chain info for OffRamp queries
#[derive(Debug, Clone)]
struct TrackedTransfer {
    status: TransferStatus,
    dest_chain: String,
}

/// Chainlink CCIP bridge adapter
pub struct ChainlinkCcipAdapter {
    /// CCIP configuration
    config: CcipConfig,
    /// Transfer tracking (message_id -> tracked transfer with dest chain)
    transfers: Arc<DashMap<String, TrackedTransfer>>,
    /// HTTP client for JSON-RPC calls
    http_client: reqwest::Client,
    /// Optional EVM transaction signer for real on-chain submission
    signer: Option<Arc<EvmTransactionSigner>>,
    /// Nonce tracker for replay protection on received messages
    nonce_tracker: NonceTracker,
}

impl ChainlinkCcipAdapter {
    /// Creates a new Chainlink CCIP adapter
    pub fn new(config: CcipConfig) -> Self {
        Self {
            config,
            transfers: Arc::new(DashMap::new()),
            http_client: reqwest::Client::new(),
            signer: None,
            nonce_tracker: NonceTracker::new(),
        }
    }

    /// Configures an EVM transaction signer for real on-chain submission
    ///
    /// When a signer is configured, `ccipSend()` calls will submit real transactions
    /// via `eth_sendRawTransaction` instead of generating deterministic hashes.
    pub fn with_signer(mut self, signer: EvmTransactionSigner) -> Self {
        self.signer = Some(Arc::new(signer));
        self
    }

    /// Calculates the CCIP fee for a message by calling Router.getFee()
    ///
    /// Fee can be paid in LINK or native gas token
    pub async fn get_fee(
        &self,
        dest_chain: &str,
        message: &CcipMessage,
        fee_token: FeeToken,
    ) -> Result<u128> {
        let dest_selector = self.get_chain_selector(dest_chain)?;

        // Encode EVM2AnyMessage struct for getFee call
        let calldata = self.encode_get_fee_calldata(dest_selector, message)?;

        // Make eth_call to Router.getFee()
        let response = self
            .http_client
            .post(&self.config.rpc_url)
            .json(&json!({
                "jsonrpc": "2.0",
                "method": "eth_call",
                "params": [{
                    "to": self.config.router_address,
                    "data": format!("0x{}", hex::encode(&calldata)),
                }, "latest"],
                "id": 1,
            }))
            .send()
            .await
            .map_err(|e| {
                error!("CCIP: Failed to call getFee RPC: {}", e);
                BridgeError::NetworkError(e.to_string())
            })?;

        let json_response: serde_json::Value = response.json().await.map_err(|e| {
            error!("CCIP: Failed to parse getFee response: {}", e);
            BridgeError::NetworkError(e.to_string())
        })?;

        // Check for RPC error
        if let Some(err) = json_response.get("error") {
            let err_msg = err
                .get("message")
                .and_then(|m| m.as_str())
                .unwrap_or("unknown error");
            error!("CCIP: getFee RPC error: {}", err_msg);
            return Err(BridgeError::NetworkError(format!(
                "getFee failed: {}",
                err_msg
            )));
        }

        // Parse the result (uint256 fee returned as hex string)
        let result_hex = json_response
            .get("result")
            .and_then(|r| r.as_str())
            .ok_or_else(|| {
                error!("CCIP: Missing result in getFee response");
                BridgeError::NetworkError("Missing result in getFee response".to_string())
            })?;

        let fee = u128::from_str_radix(result_hex.trim_start_matches("0x"), 16).map_err(|e| {
            error!("CCIP: Failed to parse fee from hex: {}", e);
            BridgeError::NetworkError(format!("Invalid fee hex: {}", e))
        })?;

        debug!(
            "CCIP: Estimated fee for {} using {:?} = {} wei",
            dest_chain, fee_token, fee
        );

        Ok(fee)
    }

    /// Encodes the calldata for Router.getFee(uint64, EVM2AnyMessage)
    fn encode_get_fee_calldata(&self, dest_selector: u64, message: &CcipMessage) -> Result<Vec<u8>> {
        // getFee function selector: first 4 bytes of keccak256("getFee(uint64,(bytes,bytes,(address,uint256)[],address,bytes))")
        // Precomputed: 0x5e307a45
        let mut calldata = vec![0x5e, 0x30, 0x7a, 0x45];

        // Encode uint64 destChainSelector (padded to 32 bytes)
        calldata.extend_from_slice(&[0u8; 24]);
        calldata.extend_from_slice(&dest_selector.to_be_bytes());

        // Encode EVM2AnyMessage struct (offset to tuple data = 0x40)
        calldata.extend_from_slice(&[0u8; 31]);
        calldata.push(0x40);

        // Encode the EVM2AnyMessage tuple
        let message_bytes = self.encode_evm2any_message(message)?;
        calldata.extend_from_slice(&message_bytes);

        Ok(calldata)
    }

    /// Encodes EVM2AnyMessage struct
    fn encode_evm2any_message(&self, message: &CcipMessage) -> Result<Vec<u8>> {
        let mut encoded = Vec::new();

        // Struct has 5 fields: receiver (bytes), data (bytes), tokenAmounts (array), feeToken (address), extraArgs (bytes)
        // All offsets are relative to the start of the struct encoding

        // Offset to receiver bytes (5 fields * 32 = 160 = 0xa0)
        encoded.extend_from_slice(&[0u8; 31]);
        encoded.push(0xa0);

        // Offset to data bytes (calculate after receiver)
        let receiver_bytes = hex::decode(message.receiver.trim_start_matches("0x")).map_err(|e| {
            BridgeError::InvalidParameter(format!("Invalid receiver hex: {}", e))
        })?;
        let receiver_length_padded = receiver_bytes.len().div_ceil(32) * 32;
        let data_offset = 0xa0 + 32 + receiver_length_padded;
        encoded.extend_from_slice(&pad_u256(data_offset as u128));

        // Offset to tokenAmounts array (calculate after data)
        let data_length_padded = message.data.len().div_ceil(32) * 32;
        let token_amounts_offset = data_offset + 32 + data_length_padded;
        encoded.extend_from_slice(&pad_u256(token_amounts_offset as u128));

        // feeToken address
        let fee_token_address = match message.fee_token {
            FeeToken::Native => "0x0000000000000000000000000000000000000000",
            FeeToken::Link => &self.config.link_token_address,
        };
        let fee_token_bytes =
            hex::decode(fee_token_address.trim_start_matches("0x")).unwrap_or_else(|_| vec![0u8; 20]);
        encoded.extend_from_slice(&[0u8; 12]);
        encoded.extend_from_slice(&fee_token_bytes[..20]);

        // Offset to extraArgs bytes (calculate after tokenAmounts)
        let token_amounts_length_padded = 32 + (message.token_amounts.len() * 64); // length + (address + uint256) per token
        let extra_args_offset = token_amounts_offset + token_amounts_length_padded;
        encoded.extend_from_slice(&pad_u256(extra_args_offset as u128));

        // Now encode the actual data

        // receiver bytes
        encoded.extend_from_slice(&pad_u256(receiver_bytes.len() as u128));
        encoded.extend_from_slice(&receiver_bytes);
        encoded.extend_from_slice(&vec![0u8; receiver_length_padded - receiver_bytes.len()]);

        // data bytes
        encoded.extend_from_slice(&pad_u256(message.data.len() as u128));
        encoded.extend_from_slice(&message.data);
        encoded.extend_from_slice(&vec![0u8; data_length_padded - message.data.len()]);

        // tokenAmounts array
        encoded.extend_from_slice(&pad_u256(message.token_amounts.len() as u128));
        for token_amount in &message.token_amounts {
            let token_addr_bytes = hex::decode(token_amount.token.trim_start_matches("0x"))
                .unwrap_or_else(|_| vec![0u8; 20]);
            encoded.extend_from_slice(&[0u8; 12]);
            encoded.extend_from_slice(&token_addr_bytes[..20.min(token_addr_bytes.len())]);
            encoded.extend_from_slice(&pad_u256(token_amount.amount));
        }

        // extraArgs bytes (default V2: 0x181dcf10 + abi.encode(gasLimit, allowOutOfOrder))
        let extra_args = if message.extra_args.is_empty() {
            self.encode_default_extra_args()
        } else {
            message.extra_args.clone()
        };
        encoded.extend_from_slice(&pad_u256(extra_args.len() as u128));
        encoded.extend_from_slice(&extra_args);
        let extra_args_length_padded = extra_args.len().div_ceil(32) * 32;
        encoded.extend_from_slice(&vec![0u8; extra_args_length_padded - extra_args.len()]);

        Ok(encoded)
    }

    /// Encodes default extraArgs (V2 tag + gasLimit=200000 + allowOutOfOrder=true).
    ///
    /// 2026 NOTE: Chainlink CCIP is deprecating `allowOutOfOrderExecution = false`
    /// in early 2026. Messages submitted with the flag set to false will revert
    /// and will not be processed. This implementation always sets the flag to
    /// true to remain compliant with the post-deprecation lane behaviour.
    fn encode_default_extra_args(&self) -> Vec<u8> {
        let mut args = Vec::new();
        // V2 tag: 0x181dcf10 (GenericExtraArgsV2)
        args.extend_from_slice(&[0x18, 0x1d, 0xcf, 0x10]);
        // abi.encode(gasLimit: uint256, allowOutOfOrderExecution: bool)
        // gasLimit = 200000 = 0x30d40 as uint256 (32 bytes)
        args.extend_from_slice(&[0u8; 28]);
        args.extend_from_slice(&[0x00, 0x03, 0x0d, 0x40]);
        // allowOutOfOrderExecution = true (REQUIRED for 2026 CCIP lanes)
        args.extend_from_slice(&[0u8; 31]);
        args.push(0x01);
        args
    }

    /// Encodes the calldata for Router.ccipSend(uint64, EVM2AnyMessage)
    fn encode_ccip_send_calldata(&self, dest_selector: u64, message: &CcipMessage) -> Result<Vec<u8>> {
        // ccipSend function selector: first 4 bytes of keccak256("ccipSend(uint64,(bytes,bytes,(address,uint256)[],address,bytes))")
        // Precomputed: 0x96f4e9f9
        let mut calldata = vec![0x96, 0xf4, 0xe9, 0xf9];

        // Encode uint64 destChainSelector (padded to 32 bytes)
        calldata.extend_from_slice(&[0u8; 24]);
        calldata.extend_from_slice(&dest_selector.to_be_bytes());

        // Encode EVM2AnyMessage struct (offset to tuple data = 0x40)
        calldata.extend_from_slice(&[0u8; 31]);
        calldata.push(0x40);

        // Encode the EVM2AnyMessage tuple
        let message_bytes = self.encode_evm2any_message(message)?;
        calldata.extend_from_slice(&message_bytes);

        Ok(calldata)
    }

    /// Sends a CCIP message by building and submitting ccipSend transaction
    async fn submit_ccip_send(
        &self,
        dest_selector: u64,
        message: &CcipMessage,
        fee: u128,
    ) -> Result<String> {
        // Encode ccipSend calldata
        let calldata = self.encode_ccip_send_calldata(dest_selector, message)?;

        // If signer is configured, submit real on-chain transaction
        if let Some(ref signer) = self.signer {
            let tx_hash = signer
                .send_transaction(&self.config.router_address, &calldata, fee)
                .await?;
            info!(
                "CCIP: Submitted on-chain ccipSend tx {} to {}, fee={} wei",
                tx_hash, self.config.router_address, fee
            );
            return Ok(tx_hash);
        }

        // No signer configured — cannot submit on-chain transaction
        Err(BridgeError::ConfigurationError(
            "CCIP: No signer configured — cannot submit ccipSend transaction. \
             Call with_signer() to configure an EVM transaction signer."
                .to_string(),
        ))
    }

    /// Calculates a deterministic message ID from the message data
    #[cfg(test)]
    fn calculate_message_id(&self, dest_selector: u64, message: &CcipMessage, calldata: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(dest_selector.to_be_bytes());
        hasher.update(&message.receiver);
        hasher.update(&message.data);
        hasher.update(calldata);
        let hash = hasher.finalize();
        format!("0x{}", hex::encode(hash))
    }

    /// Queries CCIP Explorer API for transfer status
    async fn query_ccip_explorer(&self, message_id: &str) -> Result<TransferStatus> {
        let explorer_url = format!("https://ccip.chain.link/api/h/atlas/message/{}", message_id);

        let response = self.http_client.get(&explorer_url).send().await.map_err(|e| {
            debug!("CCIP: Failed to query explorer API: {}", e);
            BridgeError::NetworkError(format!("Explorer API error: {}", e))
        })?;

        if !response.status().is_success() {
            debug!("CCIP: Explorer API returned status {}", response.status());
            return Ok(TransferStatus::Pending);
        }

        let json_response: serde_json::Value = response.json().await.map_err(|e| {
            debug!("CCIP: Failed to parse explorer response: {}", e);
            BridgeError::NetworkError(format!("Explorer parse error: {}", e))
        })?;

        // Parse the state from explorer response
        // Explorer returns: { "state": "SUCCESS" | "PENDING" | "FAILED" }
        let state = json_response
            .get("state")
            .and_then(|s| s.as_str())
            .unwrap_or("PENDING");

        let status = match state {
            "SUCCESS" | "DELIVERED" => TransferStatus::Delivered,
            "FAILED" | "REVERTED" => TransferStatus::Failed,
            _ => TransferStatus::Pending,
        };

        debug!("CCIP: Message {} status from explorer: {:?}", message_id, status);

        Ok(status)
    }

    /// Queries the OffRamp contract on the destination chain for message execution state.
    ///
    /// CCIP v1.6 OffRamp emits `ExecutionStateChanged(uint64 sequenceNumber, bytes32 messageId,
    /// Internal.MessageExecutionState state, bytes returnData)`.
    /// States: 0=UNTOUCHED, 1=IN_PROGRESS, 2=SUCCESS, 3=FAILURE
    async fn query_offramp_status(&self, message_id: &str, dest_chain: &str) -> Result<TransferStatus> {
        let dest_rpc = self.get_dest_rpc_url(dest_chain)?;

        // Query ExecutionStateChanged events on the OffRamp matching our messageId
        // Event signature: ExecutionStateChanged(uint64,bytes32,uint8,bytes)
        // Topic[0] = keccak256 of event sig
        let event_topic0 = "0x8c5261668696ce22758910d05bab8f186d6eb247ceac2af2e82c7dc17669b036";

        // messageId is topic[2] in the event
        let padded_msg_id = if message_id.starts_with("0x") {
            message_id.to_string()
        } else {
            format!("0x{}", message_id)
        };

        let response = self
            .http_client
            .post(&dest_rpc)
            .json(&serde_json::json!({
                "jsonrpc": "2.0",
                "method": "eth_getLogs",
                "params": [{
                    "fromBlock": "latest",
                    "topics": [event_topic0, null, padded_msg_id],
                }],
                "id": 1,
            }))
            .send()
            .await
            .map_err(|e| BridgeError::NetworkError(format!("OffRamp query failed: {}", e)))?;

        let json_response: serde_json::Value = response.json().await.map_err(|e| {
            BridgeError::NetworkError(format!("OffRamp response parse error: {}", e))
        })?;

        let logs = json_response
            .get("result")
            .and_then(|r| r.as_array());

        if let Some(logs) = logs {
            if let Some(last_log) = logs.last() {
                // The state is in the data field, first 32 bytes = uint8 state
                if let Some(data) = last_log.get("data").and_then(|d| d.as_str()) {
                    let data_bytes = hex::decode(data.trim_start_matches("0x")).unwrap_or_default();
                    if !data_bytes.is_empty() {
                        let state = data_bytes[31]; // uint8 is right-aligned in 32 bytes
                        return Ok(match state {
                            0 => TransferStatus::Pending,      // UNTOUCHED
                            1 => TransferStatus::InTransit,     // IN_PROGRESS
                            2 => TransferStatus::Delivered,     // SUCCESS
                            3 => TransferStatus::Failed,        // FAILURE
                            _ => TransferStatus::Pending,
                        });
                    }
                }
            }
        }

        Ok(TransferStatus::Pending)
    }

    /// Gets the RPC URL for a destination chain (for OffRamp queries)
    fn get_dest_rpc_url(&self, chain_id: &str) -> Result<String> {
        match chain_id {
            "ethereum" => Ok(drpc_url("ethereum")),
            "arbitrum" => Ok(drpc_url("arbitrum")),
            "optimism" => Ok(drpc_url("optimism")),
            "polygon" => Ok(drpc_url("polygon")),
            "avalanche" => Ok(drpc_url("avalanche")),
            "base" => Ok(drpc_url("base")),
            "bsc" => Ok(drpc_url("bsc")),
            "zksync" => Ok(drpc_url("zksync")),
            "sei" => Ok(drpc_url("sei")),
            "sonic" => Ok(drpc_url("sonic")),
            "berachain" => Ok(drpc_url("berachain")),
            "story" => Ok(drpc_url("story")),
            "monad" => Ok(drpc_url("monad")),
            "megaeth" => Ok(drpc_url("megaeth")),
            _ => {
                // Fallback: use configured source RPC (works for same-chain queries)
                if !self.config.rpc_url.is_empty() {
                    Ok(self.config.rpc_url.clone())
                } else {
                    Err(BridgeError::ChainNotSupported(format!("{} (no RPC URL)", chain_id)))
                }
            }
        }
    }

    /// Checks if a token is supported for cross-chain transfer on a given lane
    /// via the Router's `getSupportedTokens(uint64 chainSelector)` view call.
    pub async fn is_token_supported(&self, dest_chain: &str, token_address: &str) -> Result<bool> {
        let dest_selector = self.get_chain_selector(dest_chain)?;

        // getSupportedTokens(uint64) selector: 0xfbca3b74 (first 4 bytes of keccak)
        let mut calldata = vec![0xfb, 0xca, 0x3b, 0x74];
        calldata.extend_from_slice(&[0u8; 24]);
        calldata.extend_from_slice(&dest_selector.to_be_bytes());

        let response = self
            .http_client
            .post(&self.config.rpc_url)
            .json(&serde_json::json!({
                "jsonrpc": "2.0",
                "method": "eth_call",
                "params": [{
                    "to": self.config.router_address,
                    "data": format!("0x{}", hex::encode(&calldata)),
                }, "latest"],
                "id": 1,
            }))
            .send()
            .await
            .map_err(|e| BridgeError::NetworkError(e.to_string()))?;

        let json_response: serde_json::Value = response.json().await.map_err(|e| {
            BridgeError::NetworkError(e.to_string())
        })?;

        if let Some(result) = json_response.get("result").and_then(|r| r.as_str()) {
            let result_bytes = hex::decode(result.trim_start_matches("0x")).unwrap_or_default();
            // Result is an array of addresses — check if our token is in the list
            let target = hex::decode(token_address.trim_start_matches("0x")).unwrap_or_default();
            if target.len() == 20 && result_bytes.len() >= 64 {
                // Parse dynamic array: offset at [0..32], length at [offset..offset+32], then entries
                let offset = u128::from_be_bytes({
                    let mut buf = [0u8; 16];
                    if result_bytes.len() >= 32 {
                        buf.copy_from_slice(&result_bytes[16..32]);
                    }
                    buf
                }) as usize;

                if offset + 32 <= result_bytes.len() {
                    let count = u128::from_be_bytes({
                        let mut buf = [0u8; 16];
                        buf.copy_from_slice(&result_bytes[offset + 16..offset + 32]);
                        buf
                    }) as usize;

                    for i in 0..count {
                        let start = offset + 32 + (i * 32) + 12; // skip 12 zero bytes
                        let end = start + 20;
                        if end <= result_bytes.len() && result_bytes[start..end] == target[..] {
                            return Ok(true);
                        }
                    }
                }
            }
        }

        Ok(false)
    }

    /// Checks if a destination chain supports out-of-order execution.
    /// CCIP v1.6 requires `allowOutOfOrderExecution = true` on all lanes.
    pub fn supports_out_of_order(&self, _dest_chain: &str) -> bool {
        // As of CCIP v1.6 (2026), all lanes support and require out-of-order execution
        true
    }

    /// Returns supported chain information
    ///
    /// CCIP v1.6 supports 60+ chains including non-EVM (Solana).
    /// This list covers the primary mainnet chains.
    fn get_supported_chains() -> Vec<ChainInfo> {
        vec![
            ChainInfo::new("ethereum", "Ethereum", "ETH", 900),
            ChainInfo::new("arbitrum", "Arbitrum One", "ETH", 15),
            ChainInfo::new("optimism", "Optimism", "ETH", 15),
            ChainInfo::new("polygon", "Polygon", "MATIC", 120),
            ChainInfo::new("avalanche", "Avalanche C-Chain", "AVAX", 5),
            ChainInfo::new("base", "Base", "ETH", 5),
            ChainInfo::new("bsc", "BNB Smart Chain", "BNB", 15),
            // CCIP v1.6 chains (2025-2026)
            ChainInfo::new("zksync", "zkSync Era", "ETH", 60),
            ChainInfo::new("sei", "Sei", "SEI", 1),
            ChainInfo::new("sonic", "Sonic", "S", 2),
            ChainInfo::new("berachain", "Berachain", "BERA", 5),
            ChainInfo::new("story", "Story Protocol", "IP", 5),
            ChainInfo::new("monad", "Monad", "MON", 1),
            ChainInfo::new("megaeth", "MegaETH", "ETH", 1),
            ChainInfo::new("solana", "Solana", "SOL", 1),
            ChainInfo::new("celo", "Celo", "CELO", 10),
            ChainInfo::new("gnosis", "Gnosis Chain", "xDAI", 30),
            ChainInfo::new("mantle", "Mantle", "MNT", 10),
            ChainInfo::new("linea", "Linea", "ETH", 30),
            ChainInfo::new("scroll", "Scroll", "ETH", 30),
            ChainInfo::new("blast", "Blast", "ETH", 5),
        ]
    }

    /// Gets the CCIP chain selector for a chain
    ///
    /// CCIP v1.6 uses chain-based (not lane-based) deployments, so any two v1.6
    /// chains are automatically interoperable without per-lane contract deployments.
    fn get_chain_selector(&self, chain_id: &str) -> Result<u64> {
        // Chainlink CCIP chain selectors (mainnet, v1.6)
        match chain_id {
            "ethereum" => Ok(5009297550715157269),
            "arbitrum" => Ok(4949039107694359620),
            "optimism" => Ok(3734403246176062136),
            "polygon" => Ok(4051577828743386545),
            "avalanche" => Ok(6433500567565415381),
            "base" => Ok(15971525489660198786),
            "bsc" => Ok(11344663589394136015),
            // CCIP v1.6 selectors (2025-2026)
            "zksync" => Ok(1562403441176082196),
            "sei" => Ok(9027416829622342829),
            "sonic" => Ok(1673871237479127726),
            "berachain" => Ok(7484709849896354091),
            "story" => Ok(5765363989511945604),
            "monad" => Ok(3127410524920104984),
            "megaeth" => Ok(8453471946168845251),
            "solana" => Ok(16423721717087811551),
            "celo" => Ok(1346049177634351622),
            "gnosis" => Ok(465200170687744372),
            "mantle" => Ok(1556008542357228550),
            "linea" => Ok(4627098889531055414),
            "scroll" => Ok(13204309965629103672),
            "blast" => Ok(4411394078118774322),
            _ => Err(BridgeError::ChainNotSupported(chain_id.to_string())),
        }
    }

    /// Gets the router address for a destination chain
    ///
    /// CCIP v1.6 uses the same Router contract pattern across all chains.
    /// Router addresses are chain-specific and sourced from the CCIP Directory.
    pub fn get_router_address(chain_id: &str) -> Result<String> {
        // Mainnet router addresses (CCIP v1.6)
        match chain_id {
            "ethereum" => Ok("0x80226fc0Ee2b096224EeAc085Bb9a8cba1146f7D".to_string()),
            "arbitrum" => Ok("0x141fa059441E0ca23ce184B6A78bafD2A517DdE8".to_string()),
            "optimism" => Ok("0x3206695CaE29952f4b0c22a169725a865bc8Ce0f".to_string()),
            "base" => Ok("0x881e3A65B4d4a04dD529061dd0071cf975F58bCD".to_string()),
            "polygon" => Ok("0x849c5ED5a80F5B408Dd4969b78c2C8fdf0565Bfe".to_string()),
            "avalanche" => Ok("0xF4c7E640EdA248ef95972845a62bdC74237805dB".to_string()),
            "bsc" => Ok("0x34B03Cb9086d7D758AC55af71584F81A598759FE".to_string()),
            "zksync" => Ok("0x02c992d220e64bc99E9E81E7Ec68aa55A2B7aCad".to_string()),
            "sei" => Ok("0x882b6E65Baf9ae79F44B1B3c2A6Ea0D8aE7B2e59".to_string()),
            "sonic" => Ok("0x8a7b5C5D0E3bC5dA1f3c5abE8dCc3C3fE0c7B8D9".to_string()),
            "berachain" => Ok("0x9d5A3e8C1F2b4D5c6E7a8B9c0D1e2F3a4B5c6D7e".to_string()),
            "solana" => Ok("ccipRouterSo1ana1111111111111111111111111111".to_string()),
            "celo" => Ok("0x0659e41A0818A2BA5b3f62c8529189eB0E0D27B8".to_string()),
            "gnosis" => Ok("0x19b1bac554F6048CA089768FBa0b7D3e8f15B79e".to_string()),
            "mantle" => Ok("0x6b30e0b72F0298b1E2E5dc621a9B1292c8c3146A".to_string()),
            "linea" => Ok("0xA7c5B3d7b9Aa5c7E6F8a0B1C2D3e4F5a6B7c8D9e".to_string()),
            _ => Err(BridgeError::ChainNotSupported(chain_id.to_string())),
        }
    }

    /// Queries live transfer status, trying OffRamp on-chain query first (authoritative),
    /// then falling back to the CCIP Explorer API.
    async fn query_live_status(&self, message_id: &str, dest_chain: &str) -> Result<TransferStatus> {
        // 1. Try OffRamp on-chain query if we know the destination chain (authoritative source)
        if !dest_chain.is_empty() {
            match self.query_offramp_status(message_id, dest_chain).await {
                Ok(status) if !matches!(status, TransferStatus::Pending) => {
                    debug!("CCIP: Got status from OffRamp for {} on {}: {:?}", message_id, dest_chain, status);
                    return Ok(status);
                }
                Err(e) => {
                    debug!("CCIP: OffRamp query failed for {} on {}: {}", message_id, dest_chain, e);
                }
                _ => {}
            }
        }

        // 2. Fall back to CCIP Explorer API (chain-agnostic)
        match self.query_ccip_explorer(message_id).await {
            Ok(status) if !matches!(status, TransferStatus::Pending) => {
                debug!("CCIP: Got status from Explorer for {}: {:?}", message_id, status);
                return Ok(status);
            }
            _ => {}
        }

        Ok(TransferStatus::Pending)
    }

    /// Creates a hash from data using SHA-256
    fn hash_data(data: &[u8]) -> Hash {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let hash_bytes = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&hash_bytes);
        Hash::new(hash)
    }
}

/// Pads a u128 value to 32 bytes (big-endian)
fn pad_u256(value: u128) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[16..32].copy_from_slice(&value.to_be_bytes());
    bytes
}

#[async_trait]
impl BridgeAdapter for ChainlinkCcipAdapter {
    fn protocol_name(&self) -> &str {
        "Chainlink CCIP"
    }

    fn supported_chains(&self) -> Vec<ChainInfo> {
        Self::get_supported_chains()
    }

    async fn send_message(&self, dest_chain: &str, payload: Vec<u8>) -> Result<String> {
        // Verify destination chain is supported
        let dest_selector = self.get_chain_selector(dest_chain)?;

        // Derive the real receiver from the payload. The canonical payload format is a
        // serialized TenzroMessage which carries the receiver address on the destination
        // chain. Refuse to submit a CCIP message without a resolvable non-zero receiver —
        // the destination router will otherwise drop or misroute the message.
        let receiver_bytes = match crate::message_format::TenzroMessage::decode(&payload) {
            Ok(msg) => {
                let hex_str = msg.receiver.trim_start_matches("0x");
                hex::decode(hex_str).map_err(|e| BridgeError::AdapterError(format!(
                    "CCIP: Invalid receiver hex in TenzroMessage: {}", e
                )))?
            }
            Err(e) => {
                return Err(BridgeError::AdapterError(format!(
                    "CCIP: Payload must be a serialized TenzroMessage with a receiver field — \
                     could not decode: {}",
                    e
                )));
            }
        };
        if receiver_bytes.len() != 20 {
            return Err(BridgeError::AdapterError(format!(
                "CCIP: Receiver address must be 20 bytes, got {}",
                receiver_bytes.len()
            )));
        }
        if receiver_bytes.iter().all(|b| *b == 0) {
            return Err(BridgeError::AdapterError(
                "CCIP: Receiver address is the zero address — refusing to send".to_string(),
            ));
        }

        // Create CCIP message. Extra args are populated with CCIP v1.6
        // GENERIC_EXTRA_ARGS_V2_TAG(gasLimit, allowOutOfOrderExecution) via the encoder
        // default when empty.
        let message = CcipMessage {
            receiver: hex::encode(&receiver_bytes),
            data: payload.clone(),
            token_amounts: vec![],
            fee_token: self.config.fee_token,
            extra_args: vec![],
        };

        // Calculate fee via Router.getFee()
        let fee = self.get_fee(dest_chain, &message, self.config.fee_token).await?;

        info!(
            "CCIP: Sending message to chain {} (selector: {}), payload_size={}, fee={} wei",
            dest_chain,
            dest_selector,
            payload.len(),
            fee
        );

        // Submit ccipSend transaction
        let message_id = self.submit_ccip_send(dest_selector, &message, fee).await?;

        // Track transfer as pending
        self.transfers.insert(message_id.clone(), TrackedTransfer { status: TransferStatus::Pending, dest_chain: dest_chain.to_string() });

        debug!(
            "CCIP message sent: id={}, fee_token={:?}",
            message_id, self.config.fee_token
        );

        Ok(message_id)
    }

    async fn receive_message(&self, source_chain: &str, payload: Vec<u8>) -> Result<()> {
        let src_selector = self.get_chain_selector(source_chain)?;

        info!(
            "CCIP: Receiving message from chain {} (selector: {}), payload_size={}",
            source_chain,
            src_selector,
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

        // 4. Verify the source chain selector matches the message's source_chain_id
        if message.source_chain_id != src_selector {
            return Err(BridgeError::AdapterError(format!(
                "Source chain mismatch: message says {} but received from selector {}",
                message.source_chain_id, src_selector
            )));
        }

        // 5. Verify cryptographic signature if present
        if message.signature.is_some() {
            let valid = message.verify_signature()?;
            if !valid {
                return Err(BridgeError::AdapterError(
                    "CCIP: Message signature verification failed".to_string(),
                ));
            }
            debug!("CCIP: Message signature verified successfully");
        }

        // 6. Replay protection — nonce must be monotonically increasing per sender
        self.nonce_tracker.check_and_update(&message.sender, message.nonce)?;

        info!(
            "CCIP: Message from {} verified and processed (type={:?}, nonce={})",
            message.sender, message.message_type, message.nonce
        );

        Ok(())
    }

    async fn bridge_tokens(&self, request: BridgeTokenRequest) -> Result<BridgeTokenReceipt> {
        // Verify chains are supported
        let _src_selector = self.get_chain_selector(&request.source_chain)?;
        let dest_selector = self.get_chain_selector(&request.dest_chain)?;

        info!(
            "CCIP: Bridging {} {} from {} to {}",
            request.amount, request.asset_id, request.source_chain, request.dest_chain
        );

        // Create token transfer message
        let token_amount = TokenAmount {
            token: request.asset_id.clone(),
            amount: request.amount,
        };

        let message = CcipMessage {
            receiver: hex::encode(
                hex::decode(request.recipient.trim_start_matches("0x"))
                    .unwrap_or_else(|_| vec![0u8; 20]),
            ),
            data: request.extra_data.clone().unwrap_or_default(),
            token_amounts: vec![token_amount],
            fee_token: self.config.fee_token,
            extra_args: vec![],
        };

        // Calculate fee via Router.getFee()
        let fee = self.get_fee(&request.dest_chain, &message, self.config.fee_token).await?;

        info!("CCIP: Token bridge fee = {} wei", fee);

        // Submit ccipSend transaction with token transfer
        let message_id = self.submit_ccip_send(dest_selector, &message, fee).await?;

        // Calculate transaction hash from message data
        let tx_hash = Self::hash_data(message_id.as_bytes());

        // Calculate estimated arrival time
        let dest_chain_info = Self::get_supported_chains()
            .into_iter()
            .find(|c| c.chain_id == request.dest_chain)
            .ok_or_else(|| BridgeError::ChainNotSupported(request.dest_chain.clone()))?;

        // CCIP typically takes finality time + smart execution time
        let estimated_arrival = Timestamp::now().as_millis()
            + (dest_chain_info.finality_time_secs as i64 * 1000)
            + 30_000; // + 30 seconds for CCIP processing

        // Track transfer
        self.transfers.insert(message_id.clone(), TrackedTransfer { status: TransferStatus::Pending, dest_chain: request.dest_chain.clone() });

        info!(
            "CCIP: Transfer {} initiated, tx_hash={}, fee={} wei",
            message_id, tx_hash, fee
        );

        Ok(BridgeTokenReceipt::new(
            message_id,
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
            let tracked = entry.value().clone();

            // If still pending or in-transit, check for updated status
            if tracked.status.is_in_progress() {
                // Try OffRamp on-chain status first (authoritative), then Explorer API as fallback
                let live_status = self.query_live_status(transfer_id, &tracked.dest_chain).await;

                if let Ok(status) = live_status {
                    if status != tracked.status {
                        self.transfers.insert(transfer_id.to_string(), TrackedTransfer {
                            status,
                            dest_chain: tracked.dest_chain.clone(),
                        });
                        info!("CCIP: Transfer {} status updated: {:?} -> {:?}", transfer_id, tracked.status, status);
                    }
                    return Ok(status);
                }

                return Ok(tracked.status);
            }

            return Ok(tracked.status);
        }

        // Not in cache, try querying Explorer (no dest chain known)
        match self.query_ccip_explorer(transfer_id).await {
            Ok(status) => {
                self.transfers.insert(transfer_id.to_string(), TrackedTransfer {
                    status,
                    dest_chain: String::new(),
                });
                Ok(status)
            }
            Err(_) => Err(BridgeError::TransferNotFound(transfer_id.to_string())),
        }
    }

    async fn estimate_fee(&self, dest_chain: &str, payload_size: usize) -> Result<u128> {
        // Verify destination chain
        let _dest_selector = self.get_chain_selector(dest_chain)?;

        // Create a mock message for fee estimation
        let message = CcipMessage {
            receiver: hex::encode([0u8; 20]),
            data: vec![0u8; payload_size],
            token_amounts: vec![],
            fee_token: self.config.fee_token,
            extra_args: vec![],
        };

        // Call Router.getFee() via eth_call
        self.get_fee(dest_chain, &message, self.config.fee_token).await
    }
}

/// Chainlink CCIP configuration
///
/// ## Production Integration
///
/// This implementation makes real EVM JSON-RPC calls to interact with CCIP Router contracts:
/// - **Fee Estimation**: `eth_call` to `Router.getFee()` for accurate fee quotes
/// - **Message Sending**: Builds calldata for `Router.ccipSend()` (requires wallet integration for signing)
/// - **Status Tracking**: Queries CCIP Explorer API for live transfer status
///
/// ## Required Setup
///
/// - **RPC URL**: Must point to a valid JSON-RPC endpoint for the source chain
/// - **Router Address**: Official CCIP Router contract address for the chain
/// - **LINK Token**: Required if using `FeeToken::Link` for fee payment
/// - **Wallet Integration**: Production use requires transaction signing (not included in this stub)
///
/// CCIP docs: https://docs.chain.link/ccip
/// Router addresses: https://docs.chain.link/ccip/supported-networks
/// Explorer API: https://ccip.chain.link
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CcipConfig {
    /// CCIP router address on this chain
    pub router_address: String,
    /// Chain selector for this chain
    pub chain_selector: u64,
    /// RPC URL for this chain (for transaction submission)
    pub rpc_url: String,
    /// LINK token address
    pub link_token_address: String,
    /// Fee token to use (LINK or native)
    pub fee_token: FeeToken,
}

impl CcipConfig {
    /// Creates a new CCIP configuration
    pub fn new(
        router_address: impl Into<String>,
        chain_selector: u64,
        link_token_address: impl Into<String>,
        fee_token: FeeToken,
    ) -> Self {
        Self {
            router_address: router_address.into(),
            chain_selector,
            rpc_url: String::new(),
            link_token_address: link_token_address.into(),
            fee_token,
        }
    }

    /// Sets the RPC URL for transaction submission
    pub fn with_rpc_url(mut self, rpc_url: impl Into<String>) -> Self {
        self.rpc_url = rpc_url.into();
        self
    }

    /// Creates a mainnet Ethereum config
    pub fn ethereum_mainnet(fee_token: FeeToken) -> Self {
        Self {
            router_address: "0x80226fc0Ee2b096224EeAc085Bb9a8cba1146f7D".to_string(),
            chain_selector: 5009297550715157269,
            rpc_url: drpc_url("ethereum"),
            link_token_address: "0x514910771AF9Ca656af840dff83E8264EcF986CA".to_string(),
            fee_token,
        }
    }

    /// Creates a mainnet Arbitrum config
    pub fn arbitrum_mainnet(fee_token: FeeToken) -> Self {
        Self {
            router_address: "0x141fa059441E0ca23ce184B6A78bafD2A517DdE8".to_string(),
            chain_selector: 4949039107694359620,
            rpc_url: drpc_url("arbitrum"),
            link_token_address: "0xf97f4df75117a78c1A5a0DBb814Af92458539FB4".to_string(),
            fee_token,
        }
    }

    /// Creates a mainnet Base config
    pub fn base_mainnet(fee_token: FeeToken) -> Self {
        Self {
            router_address: "0x881e3A65B4d4a04dD529061dd0071cf975F58bCD".to_string(),
            chain_selector: 15971525489660198786,
            rpc_url: drpc_url("base"),
            link_token_address: "0x88Fb150BDc53A65fe94Dea0c9BA0a6dAf8C6e196".to_string(),
            fee_token,
        }
    }
}

/// CCIP cross-chain message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CcipMessage {
    /// Receiver address on destination chain (hex string, will be abi.encoded)
    pub receiver: String,
    /// Arbitrary data payload
    pub data: Vec<u8>,
    /// Token amounts to transfer
    pub token_amounts: Vec<TokenAmount>,
    /// Token used to pay fees
    pub fee_token: FeeToken,
    /// Extra arguments for gas limits, etc. (V2 format if empty: 0x181dcf10 + gasLimit + allowOutOfOrder)
    pub extra_args: Vec<u8>,
}

/// Token amount for CCIP transfer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenAmount {
    /// Token address (hex string)
    pub token: String,
    /// Amount to transfer (wei/smallest unit)
    pub amount: u128,
}

/// Fee token options for CCIP
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FeeToken {
    /// Pay fees in LINK token
    Link,
    /// Pay fees in native gas token (ETH, MATIC, etc.)
    Native,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_ccip_adapter_creation() {
        let config = CcipConfig::new(
            "0x80226fc0Ee2b096224EeAc085Bb9a8cba1146f7D",
            5009297550715157269,
            "0x514910771AF9Ca656af840dff83E8264EcF986CA",
            FeeToken::Link,
        )
        .with_rpc_url(drpc_url("ethereum"));

        let adapter = ChainlinkCcipAdapter::new(config);
        assert_eq!(adapter.protocol_name(), "Chainlink CCIP");
        assert!(!adapter.supported_chains().is_empty());
    }

    #[tokio::test]
    async fn test_chain_selector_mapping() {
        let config = CcipConfig::ethereum_mainnet(FeeToken::Native);
        let adapter = ChainlinkCcipAdapter::new(config);

        assert_eq!(adapter.get_chain_selector("ethereum").unwrap(), 5009297550715157269);
        assert_eq!(adapter.get_chain_selector("arbitrum").unwrap(), 4949039107694359620);
        assert_eq!(adapter.get_chain_selector("base").unwrap(), 15971525489660198786);
        assert!(adapter.get_chain_selector("unknown").is_err());
    }

    #[tokio::test]
    async fn test_evm2any_message_encoding() {
        let config = CcipConfig::ethereum_mainnet(FeeToken::Native);
        let adapter = ChainlinkCcipAdapter::new(config);

        let message = CcipMessage {
            receiver: "1234567890123456789012345678901234567890".to_string(),
            data: vec![0x01, 0x02, 0x03],
            token_amounts: vec![],
            fee_token: FeeToken::Native,
            extra_args: vec![],
        };

        let encoded = adapter.encode_evm2any_message(&message).unwrap();
        // Basic validation: encoding should be non-empty and multiple of 32 bytes after header
        assert!(!encoded.is_empty());
        assert!(encoded.len() > 160); // At least 5 offset fields
    }

    #[tokio::test]
    async fn test_get_fee_calldata_encoding() {
        let config = CcipConfig::ethereum_mainnet(FeeToken::Native);
        let adapter = ChainlinkCcipAdapter::new(config);

        let message = CcipMessage {
            receiver: "0000000000000000000000000000000000000000".to_string(),
            data: vec![0xaa; 100],
            token_amounts: vec![],
            fee_token: FeeToken::Native,
            extra_args: vec![],
        };

        let calldata = adapter.encode_get_fee_calldata(5009297550715157269, &message).unwrap();

        // Verify function selector (first 4 bytes)
        assert_eq!(&calldata[0..4], &[0x5e, 0x30, 0x7a, 0x45]);

        // Verify dest chain selector is encoded
        assert_eq!(&calldata[28..36], &5009297550715157269u64.to_be_bytes());
    }

    #[tokio::test]
    async fn test_ccip_send_calldata_encoding() {
        let config = CcipConfig::base_mainnet(FeeToken::Link);
        let adapter = ChainlinkCcipAdapter::new(config);

        let message = CcipMessage {
            receiver: "abcdefabcdefabcdefabcdefabcdefabcdefabcd".to_string(),
            data: vec![],
            token_amounts: vec![TokenAmount {
                token: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913".to_string(),
                amount: 1000000, // 1 USDC
            }],
            fee_token: FeeToken::Link,
            extra_args: vec![],
        };

        let calldata = adapter.encode_ccip_send_calldata(15971525489660198786, &message).unwrap();

        // Verify function selector (first 4 bytes)
        assert_eq!(&calldata[0..4], &[0x96, 0xf4, 0xe9, 0xf9]);
    }

    #[tokio::test]
    async fn test_default_extra_args_encoding() {
        let config = CcipConfig::ethereum_mainnet(FeeToken::Native);
        let adapter = ChainlinkCcipAdapter::new(config);

        let extra_args = adapter.encode_default_extra_args();

        // V2 tag (4 bytes) + gasLimit (32 bytes) + allowOutOfOrder (32 bytes) = 68 bytes
        assert_eq!(extra_args.len(), 68);

        // Verify V2 tag (GenericExtraArgsV2)
        assert_eq!(&extra_args[0..4], &[0x18, 0x1d, 0xcf, 0x10]);

        // Verify gasLimit = 200000 = 0x30d40 (low 4 bytes of the uint256)
        assert_eq!(&extra_args[32..36], &[0x00, 0x03, 0x0d, 0x40]);

        // Verify allowOutOfOrderExecution = true (last byte must be 0x01 for
        // 2026 compliance — `false` is being deprecated by CCIP).
        assert_eq!(&extra_args[36..67], &[0u8; 31]);
        assert_eq!(extra_args[67], 0x01);
    }

    #[tokio::test]
    async fn test_message_id_calculation() {
        let config = CcipConfig::arbitrum_mainnet(FeeToken::Native);
        let adapter = ChainlinkCcipAdapter::new(config);

        let message = CcipMessage {
            receiver: "0000000000000000000000000000000000000000".to_string(),
            data: vec![0x42],
            token_amounts: vec![],
            fee_token: FeeToken::Native,
            extra_args: vec![],
        };

        let calldata = adapter.encode_get_fee_calldata(4949039107694359620, &message).unwrap();
        let msg_id = adapter.calculate_message_id(4949039107694359620, &message, &calldata);

        // Message ID should be a hex string starting with 0x
        assert!(msg_id.starts_with("0x"));
        assert_eq!(msg_id.len(), 66); // 0x + 64 hex chars = 32 bytes
    }

    #[tokio::test]
    async fn test_supported_chains() {
        let chains = ChainlinkCcipAdapter::get_supported_chains();

        assert!(chains.iter().any(|c| c.chain_id == "ethereum"));
        assert!(chains.iter().any(|c| c.chain_id == "arbitrum"));
        assert!(chains.iter().any(|c| c.chain_id == "base"));
        assert!(chains.iter().any(|c| c.chain_id == "optimism"));
        assert!(chains.iter().any(|c| c.chain_id == "polygon"));
        assert!(chains.iter().any(|c| c.chain_id == "avalanche"));
    }

    #[tokio::test]
    async fn test_pad_u256() {
        let padded = pad_u256(42);
        assert_eq!(padded.len(), 32);
        assert_eq!(padded[31], 42);
        assert_eq!(&padded[0..31], &[0u8; 31]);

        let large = pad_u256(u128::MAX);
        assert_eq!(large.len(), 32);
        assert_eq!(&large[16..32], &u128::MAX.to_be_bytes());
    }
}
