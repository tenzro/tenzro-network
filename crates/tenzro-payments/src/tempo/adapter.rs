//! Tempo bridge adapter implementing the BridgeAdapter trait

use crate::error::Result as PaymentResult;
use crate::tempo::config::TempoConfig;
use crate::tempo::participant::TempoRpcClient;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tenzro_bridge::traits::{
    BridgeAdapter, BridgeTokenReceipt, BridgeTokenRequest, ChainInfo, TransferStatus,
};
use tenzro_types::primitives::Hash;
use tracing::{debug, info, warn};

/// Tempo RPC transfer request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TempoTransferRequest {
    /// Source participant ID
    pub from_participant: String,
    /// Destination participant ID
    pub to_participant: String,
    /// Asset identifier (e.g., "USDC", "TNZO")
    pub asset_id: String,
    /// Transfer amount in smallest unit
    pub amount: u128,
    /// Optional memo/reference
    pub memo: Option<String>,
}

impl TempoTransferRequest {
    /// Creates a new Tempo transfer request
    pub fn new(
        from: impl Into<String>,
        to: impl Into<String>,
        asset: impl Into<String>,
        amount: u128,
    ) -> Self {
        Self {
            from_participant: from.into(),
            to_participant: to.into(),
            asset_id: asset.into(),
            amount,
            memo: None,
        }
    }

    /// Sets the memo field
    pub fn with_memo(mut self, memo: impl Into<String>) -> Self {
        self.memo = Some(memo.into());
        self
    }
}

/// Tempo RPC transfer result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TempoTransferResult {
    /// Transfer ID assigned by Tempo
    pub transfer_id: String,
    /// Transaction hash on Tempo ledger
    pub tx_hash: String,
    /// Transfer status
    pub status: String,
    /// Timestamp (milliseconds since epoch)
    pub timestamp: i64,
}

/// Bridge adapter for Tenzro <-> Tempo cross-chain transfers
pub struct TempoBridgeAdapter {
    config: TempoConfig,
    rpc_client: TempoRpcClient,
    signing_key: Option<k256::ecdsa::SigningKey>,
    sender_address: Option<[u8; 20]>,
}

impl TempoBridgeAdapter {
    /// Creates a new Tempo bridge adapter (unsigned mode — calldata only).
    pub fn new(config: TempoConfig) -> Self {
        let rpc_client = TempoRpcClient::new(&config.rpc_url, config.chain_id);
        Self {
            config,
            rpc_client,
            signing_key: None,
            sender_address: None,
        }
    }

    /// Creates a Tempo bridge adapter with a signing key for real transaction submission.
    pub fn with_signing_key(config: TempoConfig, signing_key: k256::ecdsa::SigningKey) -> Self {
        let sender_address = crate::tempo::participant::signing_key_to_address(&signing_key);
        let rpc_client = TempoRpcClient::new(&config.rpc_url, config.chain_id);
        Self {
            config,
            rpc_client,
            signing_key: Some(signing_key),
            sender_address: Some(sender_address),
        }
    }

    /// Submits a transfer to the Tempo network via EVM-compatible JSON-RPC
    ///
    /// Encodes a TIP-20 `transfer(address, uint256)` call and sends it via
    /// `eth_sendRawTransaction`. If no stablecoin contract is configured for
    /// the requested asset, falls back to returning a reference for manual settlement.
    async fn submit_tempo_transfer(
        &self,
        request: TempoTransferRequest,
    ) -> PaymentResult<TempoTransferResult> {
        debug!(
            "Submitting Tempo transfer: {} -> {} amount={} asset={}",
            request.from_participant, request.to_participant, request.amount, request.asset_id
        );

        // Look up the contract address for the asset
        let contract_address = self
            .config
            .stablecoin_addresses
            .get(&request.asset_id)
            .cloned()
            .unwrap_or_default();

        if contract_address.is_empty() {
            // No contract configured — return a pending reference for manual settlement
            debug!(
                "No contract configured for {}, creating settlement reference",
                request.asset_id
            );
            let transfer_id = format!("tempo-ref-{}", uuid::Uuid::new_v4());
            return Ok(TempoTransferResult {
                transfer_id,
                tx_hash: String::new(),
                status: "pending".to_string(),
                timestamp: chrono::Utc::now().timestamp_millis(),
            });
        }

        // Encode transfer(to, amount) calldata
        let calldata =
            crate::tempo::stablecoin::encode_transfer(&request.to_participant, request.amount);

        // Estimate gas for the transfer
        let gas_estimate = self
            .rpc_client
            .estimate_gas(&contract_address, &calldata)
            .await
            .unwrap_or(65_000);

        let gas_price = self.rpc_client.gas_price().await.unwrap_or(1_000_000_000);

        debug!(
            "Transfer gas: {} units @ {} wei/gas (contract: {})",
            gas_estimate, gas_price, contract_address
        );

        if let (Some(signing_key), Some(sender_addr)) = (&self.signing_key, &self.sender_address) {
            // Real signed transaction path
            let sender_hex = crate::tempo::participant::format_address(sender_addr);
            let nonce = self.rpc_client.get_nonce(&sender_hex).await.map_err(|e| {
                crate::error::PaymentError::SettlementError(format!("nonce fetch: {}", e))
            })?;
            let contract_addr = crate::tempo::participant::parse_address(&contract_address)
                .map_err(|e| {
                    crate::error::PaymentError::SettlementError(format!("bad address: {}", e))
                })?;

            let tx = crate::tempo::participant::EvmTransaction {
                nonce,
                gas_price,
                gas_limit: gas_estimate,
                to: contract_addr,
                value: 0,
                data: calldata,
            };

            let signed_tx_hex = tx
                .sign_eip155(signing_key, self.config.chain_id)
                .map_err(|e| {
                    crate::error::PaymentError::SettlementError(format!("signing: {}", e))
                })?;

            info!(
                "Submitting signed Tempo transfer (nonce={}, gas={})",
                nonce, gas_estimate
            );

            let tx_hash = self
                .rpc_client
                .send_raw_transaction(&signed_tx_hex)
                .await
                .map_err(|e| crate::error::PaymentError::SettlementError(format!("send: {}", e)))?;

            info!("Tempo transfer submitted: {}", tx_hash);

            Ok(TempoTransferResult {
                transfer_id: tx_hash.clone(),
                tx_hash,
                status: "submitted".to_string(),
                timestamp: chrono::Utc::now().timestamp_millis(),
            })
        } else {
            // No signing key — return unsigned calldata for external signing
            let transfer_id = format!("tempo-tx-{}", uuid::Uuid::new_v4());
            let calldata_hex = format!("0x{}", hex::encode(&calldata));

            warn!(
                "No signing key configured — returning unsigned calldata for external signing. \
                 Contract: {}, gas: {}",
                contract_address, gas_estimate
            );

            Ok(TempoTransferResult {
                transfer_id,
                tx_hash: calldata_hex,
                status: "unsigned".to_string(),
                timestamp: chrono::Utc::now().timestamp_millis(),
            })
        }
    }

    /// Queries the status of a Tempo transfer via `eth_getTransactionReceipt`
    ///
    /// If the transfer_id starts with "0x" it's treated as a transaction hash
    /// and queried directly. Otherwise, it's a reference ID and we return pending.
    async fn query_tempo_transfer(&self, transfer_id: &str) -> PaymentResult<TempoTransferResult> {
        debug!("Querying Tempo transfer status: {}", transfer_id);

        // If the transfer_id looks like a tx hash, query the receipt
        if transfer_id.starts_with("0x") && transfer_id.len() == 66 {
            let receipt = self
                .rpc_client
                .get_transaction_receipt(transfer_id)
                .await
                .map_err(|e| {
                    crate::error::PaymentError::NetworkError(format!(
                        "Failed to query transfer {}: {}",
                        transfer_id, e
                    ))
                })?;

            return match receipt {
                Some(receipt_val) => {
                    let status_hex = receipt_val
                        .get("status")
                        .and_then(|s| s.as_str())
                        .unwrap_or("0x1");
                    let status = if status_hex == "0x1" {
                        "delivered"
                    } else {
                        "failed"
                    };
                    Ok(TempoTransferResult {
                        transfer_id: transfer_id.to_string(),
                        tx_hash: transfer_id.to_string(),
                        status: status.to_string(),
                        timestamp: chrono::Utc::now().timestamp_millis(),
                    })
                }
                None => Ok(TempoTransferResult {
                    transfer_id: transfer_id.to_string(),
                    tx_hash: transfer_id.to_string(),
                    status: "pending".to_string(),
                    timestamp: chrono::Utc::now().timestamp_millis(),
                }),
            };
        }

        // Non-tx-hash transfer IDs (references) — return pending
        debug!("Transfer {} is a reference ID, not a tx hash", transfer_id);
        Ok(TempoTransferResult {
            transfer_id: transfer_id.to_string(),
            tx_hash: String::new(),
            status: "pending".to_string(),
            timestamp: chrono::Utc::now().timestamp_millis(),
        })
    }
}

#[async_trait]
impl BridgeAdapter for TempoBridgeAdapter {
    fn protocol_name(&self) -> &str {
        "tempo"
    }

    fn supported_chains(&self) -> Vec<ChainInfo> {
        vec![
            ChainInfo::new("tempo", "Tempo Network", "ETH", 1),
            ChainInfo::new("tenzro", "Tenzro Network", "TNZO", 3),
        ]
    }

    async fn send_message(
        &self,
        dest_chain: &str,
        payload: Vec<u8>,
    ) -> tenzro_bridge::error::Result<String> {
        info!(
            "Sending bridge message to {} ({} bytes)",
            dest_chain,
            payload.len()
        );
        Ok(format!("tempo-msg-{}", uuid::Uuid::new_v4()))
    }

    async fn receive_message(
        &self,
        source_chain: &str,
        _payload: Vec<u8>,
    ) -> tenzro_bridge::error::Result<Option<tenzro_bridge::message_format::TenzroMessage>> {
        // Fail-closed. Tempo settlement finality is observed on the
        // Tempo chain itself (EIP-155 transactions queried over RPC),
        // not attested by a committee this adapter can verify. An
        // unverified inbound payload must never be admitted as
        // cross-chain authority.
        Err(tenzro_bridge::error::BridgeError::AdapterError(format!(
            "Tempo adapter does not admit inbound bridge messages from {source_chain}; \
             verify settlement directly against Tempo chain state"
        )))
    }

    async fn bridge_tokens(
        &self,
        request: BridgeTokenRequest,
    ) -> tenzro_bridge::error::Result<BridgeTokenReceipt> {
        info!(
            "Bridging {} {} from {} to {}",
            request.amount, request.asset_id, request.source_chain, request.dest_chain
        );

        // Create a Tempo transfer request
        let tempo_request = TempoTransferRequest::new(
            &request.source_chain,
            &request.dest_chain,
            &request.asset_id,
            request.amount,
        )
        .with_memo(format!("Bridge transfer {}", request.sender));

        // Submit the transfer to Tempo
        let tempo_result = self
            .submit_tempo_transfer(tempo_request)
            .await
            .map_err(|e| tenzro_bridge::error::BridgeError::TransferFailed(e.to_string()))?;

        debug!("Tempo transfer submitted: {}", tempo_result.transfer_id);

        // Convert Tempo tx hash to Hash type
        let tx_hash_bytes = hex::decode(tempo_result.tx_hash.trim_start_matches("0x"))
            .unwrap_or_else(|_| vec![0u8; 32]);
        let mut hash_array = [0u8; 32];
        hash_array.copy_from_slice(&tx_hash_bytes[..32.min(tx_hash_bytes.len())]);

        Ok(BridgeTokenReceipt::new(
            tempo_result.transfer_id,
            Hash::new(hash_array),
            chrono::Utc::now().timestamp_millis() + 60_000,
            0,
            &request.source_chain,
            &request.dest_chain,
        ))
    }

    async fn get_transfer_status(
        &self,
        transfer_id: &str,
    ) -> tenzro_bridge::error::Result<TransferStatus> {
        info!("Checking transfer status: {}", transfer_id);

        // Query the Tempo network for transfer status
        let tempo_result = self
            .query_tempo_transfer(transfer_id)
            .await
            .map_err(|e| tenzro_bridge::error::BridgeError::TransferFailed(e.to_string()))?;

        // Map Tempo status to TransferStatus
        let status = match tempo_result.status.as_str() {
            "pending" => TransferStatus::Pending,
            "delivered" | "completed" => TransferStatus::Delivered,
            "failed" => TransferStatus::Failed,
            _ => {
                warn!("Unknown Tempo transfer status: {}", tempo_result.status);
                TransferStatus::Pending
            }
        };

        debug!("Transfer {} status: {:?}", transfer_id, status);

        Ok(status)
    }

    async fn estimate_fee(
        &self,
        dest_chain: &str,
        payload_size: usize,
    ) -> tenzro_bridge::error::Result<u128> {
        info!(
            "Estimating fee for {} bytes to {}",
            payload_size, dest_chain
        );
        // Minimal fee estimate
        Ok((payload_size as u128) * 100)
    }
}
