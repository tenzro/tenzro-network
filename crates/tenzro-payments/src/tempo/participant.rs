//! Tempo network participant
//!
//! Allows Tenzro nodes to participate in the Tempo network
//! for direct stablecoin settlement and MPP batch operations.
//!
//! Uses standard EVM-compatible JSON-RPC calls since Tempo is EVM-compatible:
//! - `eth_call` for reading TIP-20 token balances
//! - `eth_sendRawTransaction` for sending signed transactions
//! - `eth_getTransactionReceipt` for checking transaction finality
//! - `eth_blockNumber` for current block height
//! - `eth_gasPrice` for gas price estimation
//! - `eth_estimateGas` for gas estimation
//!
//! # Transaction Signing
//!
//! Implements EIP-155 transaction signing using Secp256k1 (k256 crate):
//! 1. Build legacy transaction fields (nonce, gasPrice, gasLimit, to, value, data)
//! 2. RLP-encode with chain_id for EIP-155 replay protection
//! 3. Keccak-256 hash the RLP-encoded unsigned tx
//! 4. Sign with Secp256k1 recoverable signature
//! 5. RLP-encode the signed tx (with v, r, s) for submission

use crate::error::{PaymentError, Result};
use crate::tempo::config::TempoConfig;
use crate::tempo::stablecoin::{self, Tip20Balance};
use k256::ecdsa::{SigningKey, VerifyingKey};
use rlp::RlpStream;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use tracing::{debug, info, warn};

/// Status of block finality on Tempo
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FinalityStatus {
    /// Block not yet seen
    Unknown,
    /// Block is pending
    Pending,
    /// Block is finalized (deterministic finality via Simplex BFT)
    Finalized,
    /// Block was reverted (should not happen with Simplex)
    Reverted,
}

/// A settlement entry for batch MPP settlement on Tempo
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettlementEntry {
    /// Payer address
    pub payer: String,
    /// Recipient address
    pub recipient: String,
    /// Amount (in smallest unit)
    pub amount: u128,
    /// Token symbol
    pub token: String,
    /// Session ID this settlement is for
    pub session_id: Option<String>,
}

/// EVM legacy transaction fields for EIP-155 signing
#[derive(Debug, Clone)]
pub struct EvmTransaction {
    /// Transaction nonce (sequential per sender)
    pub nonce: u64,
    /// Gas price in wei
    pub gas_price: u128,
    /// Gas limit
    pub gas_limit: u64,
    /// Recipient address (20 bytes)
    pub to: [u8; 20],
    /// Value in wei (0 for ERC-20 transfers)
    pub value: u128,
    /// Transaction calldata
    pub data: Vec<u8>,
}

impl EvmTransaction {
    /// RLP-encode the unsigned transaction with EIP-155 chain_id for signing.
    ///
    /// EIP-155 unsigned encoding: `rlp([nonce, gasPrice, gasLimit, to, value, data, chainId, 0, 0])`
    pub fn rlp_encode_unsigned(&self, chain_id: u64) -> Vec<u8> {
        let mut stream = RlpStream::new_list(9);
        stream.append(&self.nonce);
        rlp_append_u128(&mut stream, self.gas_price);
        stream.append(&self.gas_limit);
        stream.append(&self.to.as_slice());
        rlp_append_u128(&mut stream, self.value);
        stream.append(&self.data);
        // EIP-155: append chain_id, 0, 0
        stream.append(&chain_id);
        stream.append(&0u8);
        stream.append(&0u8);
        stream.out().to_vec()
    }

    /// RLP-encode the signed transaction for submission.
    ///
    /// Signed encoding: `rlp([nonce, gasPrice, gasLimit, to, value, data, v, r, s])`
    pub fn rlp_encode_signed(&self, v: u64, r: &[u8; 32], s: &[u8; 32]) -> Vec<u8> {
        let mut stream = RlpStream::new_list(9);
        stream.append(&self.nonce);
        rlp_append_u128(&mut stream, self.gas_price);
        stream.append(&self.gas_limit);
        stream.append(&self.to.as_slice());
        rlp_append_u128(&mut stream, self.value);
        stream.append(&self.data);
        stream.append(&v);
        // r and s: strip leading zeros for RLP encoding
        stream.append(&strip_leading_zeros(r));
        stream.append(&strip_leading_zeros(s));
        stream.out().to_vec()
    }

    /// Sign the transaction with EIP-155 replay protection.
    ///
    /// Returns the signed raw transaction hex string (with 0x prefix) ready for
    /// `eth_sendRawTransaction`.
    pub fn sign_eip155(&self, signing_key: &SigningKey, chain_id: u64) -> Result<String> {
        // 1. RLP-encode unsigned transaction with chain_id
        let unsigned_rlp = self.rlp_encode_unsigned(chain_id);

        // 2. Keccak-256 hash
        let tx_hash = Keccak256::digest(&unsigned_rlp);

        // 3. Sign with recoverable signature
        let (signature, recovery_id) = signing_key
            .sign_prehash_recoverable(&tx_hash)
            .map_err(|e| PaymentError::CryptoError(format!("Secp256k1 signing failed: {}", e)))?;

        // 4. Extract r and s (each 32 bytes)
        let sig_bytes = signature.to_bytes();
        let r: [u8; 32] = sig_bytes[..32]
            .try_into()
            .map_err(|_| PaymentError::CryptoError("invalid r length".to_string()))?;
        let s: [u8; 32] = sig_bytes[32..64]
            .try_into()
            .map_err(|_| PaymentError::CryptoError("invalid s length".to_string()))?;

        // 5. Compute v per EIP-155: v = chain_id * 2 + 35 + recovery_id
        let v = chain_id * 2 + 35 + recovery_id.to_byte() as u64;

        // 6. RLP-encode signed transaction
        let signed_rlp = self.rlp_encode_signed(v, &r, &s);

        Ok(format!("0x{}", hex::encode(signed_rlp)))
    }
}

/// Derive an Ethereum address from a Secp256k1 signing key.
///
/// Takes the uncompressed public key (64 bytes without 0x04 prefix),
/// hashes with Keccak-256, and takes the last 20 bytes.
pub fn signing_key_to_address(signing_key: &SigningKey) -> [u8; 20] {
    let verifying_key = VerifyingKey::from(signing_key);
    let encoded = verifying_key.to_encoded_point(false);
    // Skip the 0x04 prefix byte, hash the 64-byte x||y
    let hash = Keccak256::digest(&encoded.as_bytes()[1..]);
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&hash[12..]);
    addr
}

/// Format a 20-byte address as a checksummed hex string (EIP-55).
pub fn format_address(addr: &[u8; 20]) -> String {
    let hex_addr = hex::encode(addr);
    let hash = Keccak256::digest(hex_addr.as_bytes());

    let mut checksummed = String::with_capacity(42);
    checksummed.push_str("0x");
    for (i, c) in hex_addr.chars().enumerate() {
        if c.is_ascii_alphabetic() {
            // If the corresponding nibble of the hash is >= 8, uppercase
            let hash_nibble = if i % 2 == 0 {
                hash[i / 2] >> 4
            } else {
                hash[i / 2] & 0x0f
            };
            if hash_nibble >= 8 {
                checksummed.push(c.to_ascii_uppercase());
            } else {
                checksummed.push(c);
            }
        } else {
            checksummed.push(c);
        }
    }
    checksummed
}

/// Parse a hex address string (with or without 0x prefix) to 20 bytes.
pub fn parse_address(addr_str: &str) -> Result<[u8; 20]> {
    let clean = addr_str.strip_prefix("0x").unwrap_or(addr_str);
    let bytes = hex::decode(clean)
        .map_err(|e| PaymentError::ConfigError(format!("invalid address hex: {}", e)))?;
    if bytes.len() != 20 {
        return Err(PaymentError::ConfigError(format!(
            "address must be 20 bytes, got {}",
            bytes.len()
        )));
    }
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&bytes);
    Ok(addr)
}

/// JSON-RPC client for Tempo network (EVM-compatible)
pub struct TempoRpcClient {
    http_client: reqwest::Client,
    rpc_url: String,
    chain_id: u64,
}

impl TempoRpcClient {
    /// Creates a new Tempo RPC client
    pub fn new(rpc_url: &str, chain_id: u64) -> Self {
        Self {
            http_client: reqwest::Client::new(),
            rpc_url: rpc_url.to_string(),
            chain_id,
        }
    }

    /// Sends a JSON-RPC request to Tempo
    pub async fn rpc_call(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value> {
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": 1
        });

        let response = self
            .http_client
            .post(&self.rpc_url)
            .json(&request)
            .send()
            .await
            .map_err(|e| PaymentError::NetworkError(e.to_string()))?;

        let body: serde_json::Value = response
            .json()
            .await
            .map_err(|e| PaymentError::NetworkError(e.to_string()))?;

        if let Some(error) = body.get("error") {
            return Err(PaymentError::NetworkError(format!(
                "RPC error: {}",
                error
            )));
        }

        body.get("result")
            .cloned()
            .ok_or_else(|| PaymentError::NetworkError("missing result in RPC response".to_string()))
    }

    /// Returns the chain ID
    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    /// Gets the current gas price via `eth_gasPrice`
    pub async fn gas_price(&self) -> Result<u128> {
        let result = self
            .rpc_call("eth_gasPrice", serde_json::json!([]))
            .await?;
        let hex_str = result.as_str().unwrap_or("0x0");
        Ok(parse_hex_u128(hex_str))
    }

    /// Gets the native balance of an address via `eth_getBalance`
    pub async fn get_balance(&self, address: &str) -> Result<u128> {
        let result = self
            .rpc_call(
                "eth_getBalance",
                serde_json::json!([address, "latest"]),
            )
            .await?;
        let hex_str = result.as_str().unwrap_or("0x0");
        Ok(parse_hex_u128(hex_str))
    }

    /// Gets the transaction count (nonce) for an address via `eth_getTransactionCount`
    pub async fn get_nonce(&self, address: &str) -> Result<u64> {
        let result = self
            .rpc_call(
                "eth_getTransactionCount",
                serde_json::json!([address, "pending"]),
            )
            .await?;
        let hex_str = result.as_str().unwrap_or("0x0");
        Ok(parse_hex_u64(hex_str))
    }

    /// Calls a contract via `eth_call` (read-only, no gas needed)
    pub async fn eth_call(
        &self,
        to: &str,
        data: &[u8],
    ) -> Result<String> {
        let call_obj = serde_json::json!({
            "to": to,
            "data": format!("0x{}", hex::encode(data)),
        });
        let result = self
            .rpc_call("eth_call", serde_json::json!([call_obj, "latest"]))
            .await?;
        result
            .as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| PaymentError::NetworkError("invalid eth_call response".to_string()))
    }

    /// Sends a signed raw transaction via `eth_sendRawTransaction`
    pub async fn send_raw_transaction(&self, signed_tx_hex: &str) -> Result<String> {
        let result = self
            .rpc_call(
                "eth_sendRawTransaction",
                serde_json::json!([signed_tx_hex]),
            )
            .await?;
        result
            .as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| {
                PaymentError::NetworkError("invalid sendRawTransaction response".to_string())
            })
    }

    /// Gets a transaction receipt via `eth_getTransactionReceipt`
    pub async fn get_transaction_receipt(
        &self,
        tx_hash: &str,
    ) -> Result<Option<serde_json::Value>> {
        let result = self
            .rpc_call(
                "eth_getTransactionReceipt",
                serde_json::json!([tx_hash]),
            )
            .await?;
        if result.is_null() {
            Ok(None)
        } else {
            Ok(Some(result))
        }
    }

    /// Estimates gas for a transaction via `eth_estimateGas`
    pub async fn estimate_gas(&self, to: &str, data: &[u8]) -> Result<u64> {
        let call_obj = serde_json::json!({
            "to": to,
            "data": format!("0x{}", hex::encode(data)),
        });
        let result = self
            .rpc_call("eth_estimateGas", serde_json::json!([call_obj]))
            .await?;
        let hex_str = result.as_str().unwrap_or("0x0");
        Ok(parse_hex_u64(hex_str))
    }
}

/// Tempo network participant for direct settlement.
///
/// When a `signing_key` is provided, transactions are signed with EIP-155
/// and submitted via `eth_sendRawTransaction`. Without a signing key,
/// unsigned calldata is returned for external signing.
pub struct TempoParticipant {
    config: TempoConfig,
    rpc_client: TempoRpcClient,
    /// Optional Secp256k1 signing key for transaction signing.
    /// When present, enables real on-chain settlement.
    signing_key: Option<SigningKey>,
    /// Cached sender address derived from signing key
    sender_address: Option<[u8; 20]>,
}

impl TempoParticipant {
    /// Creates a new Tempo participant without a signing key.
    ///
    /// Can query balances and estimate fees but cannot submit transactions.
    pub fn new(config: TempoConfig) -> Self {
        let rpc_client = TempoRpcClient::new(&config.rpc_url, config.chain_id);
        Self {
            config,
            rpc_client,
            signing_key: None,
            sender_address: None,
        }
    }

    /// Creates a new Tempo participant with a Secp256k1 signing key.
    ///
    /// Enables real on-chain settlement via signed EIP-155 transactions.
    pub fn with_signing_key(config: TempoConfig, signing_key: SigningKey) -> Self {
        let rpc_client = TempoRpcClient::new(&config.rpc_url, config.chain_id);
        let sender_address = signing_key_to_address(&signing_key);
        info!(
            "Tempo participant initialized with sender {}",
            format_address(&sender_address)
        );
        Self {
            config,
            rpc_client,
            signing_key: Some(signing_key),
            sender_address: Some(sender_address),
        }
    }

    /// Creates a participant from a raw 32-byte Secp256k1 secret key.
    pub fn with_secret_key(config: TempoConfig, secret_key: &[u8; 32]) -> Result<Self> {
        let signing_key = SigningKey::from_bytes(secret_key.into())
            .map_err(|e| PaymentError::CryptoError(format!("invalid secret key: {}", e)))?;
        Ok(Self::with_signing_key(config, signing_key))
    }

    /// Returns the sender address if a signing key is configured.
    pub fn sender_address(&self) -> Option<String> {
        self.sender_address.map(|a| format_address(&a))
    }

    /// Returns whether this participant can sign transactions.
    pub fn can_sign(&self) -> bool {
        self.signing_key.is_some()
    }

    /// Queries the balance of a TIP-20 stablecoin on Tempo via `eth_call`
    ///
    /// Encodes `balanceOf(address)` and calls the token contract.
    pub async fn get_stablecoin_balance(
        &self,
        address: &str,
        token: &str,
    ) -> Result<Tip20Balance> {
        info!("Querying {} balance for {} on Tempo", token, address);

        let contract_address = self
            .config
            .stablecoin_addresses
            .get(token)
            .ok_or_else(|| {
                PaymentError::ConfigError(format!("unknown stablecoin: {}", token))
            })?;

        // If no contract address configured, return zero
        if contract_address.is_empty() {
            debug!("No contract address configured for {}, returning zero balance", token);
            return Ok(Tip20Balance {
                symbol: token.to_string(),
                balance: 0,
                decimals: 6,
            });
        }

        // Encode balanceOf(address) call
        let calldata = stablecoin::encode_balance_of(address);

        // Call the token contract via eth_call
        let result = self
            .rpc_client
            .eth_call(contract_address, &calldata)
            .await?;

        let balance = stablecoin::decode_uint256(&result);
        debug!("{} balance for {}: {} (raw)", token, address, balance);

        Ok(Tip20Balance {
            symbol: token.to_string(),
            balance,
            decimals: 6, // USDC and USDT both use 6 decimals
        })
    }

    /// Submits a TIP-20 stablecoin transfer on Tempo.
    ///
    /// If a signing key is configured, builds an EIP-155 transaction, signs it,
    /// and submits via `eth_sendRawTransaction`. Returns the transaction hash.
    ///
    /// If no signing key is configured, returns unsigned calldata for external signing.
    pub async fn transfer_stablecoin(
        &self,
        to: &str,
        amount: u128,
        token: &str,
    ) -> Result<String> {
        info!(
            "Transferring {} {} to {} on Tempo",
            amount, token, to
        );

        let contract_address = self
            .config
            .stablecoin_addresses
            .get(token)
            .ok_or_else(|| {
                PaymentError::ConfigError(format!("unknown stablecoin: {}", token))
            })?;

        if contract_address.is_empty() {
            return Err(PaymentError::ConfigError(format!(
                "no contract address configured for {} — set via with_stablecoin()",
                token
            )));
        }

        // Encode transfer(to, amount) calldata
        let calldata = stablecoin::encode_transfer(to, amount);

        // Estimate gas for the transfer
        let gas_estimate = self
            .rpc_client
            .estimate_gas(contract_address, &calldata)
            .await
            .unwrap_or(65_000); // Default ERC-20 transfer gas

        let gas_price = self
            .rpc_client
            .gas_price()
            .await
            .unwrap_or(1_000_000_000); // 1 Gwei default

        debug!(
            "Transfer gas estimate: {} units @ {} wei/gas",
            gas_estimate, gas_price
        );

        // If we have a signing key, build and submit a real signed transaction
        if let (Some(signing_key), Some(sender_addr)) =
            (&self.signing_key, &self.sender_address)
        {
            let sender_hex = format_address(sender_addr);
            let nonce = self.rpc_client.get_nonce(&sender_hex).await?;
            let contract_addr = parse_address(contract_address)?;

            let tx = EvmTransaction {
                nonce,
                gas_price,
                gas_limit: gas_estimate,
                to: contract_addr,
                value: 0, // ERC-20 transfer: value in calldata, not msg.value
                data: calldata,
            };

            let signed_tx_hex = tx.sign_eip155(signing_key, self.config.chain_id)?;

            info!(
                "Submitting signed EIP-155 transaction (nonce={}, gas={}, gasPrice={})",
                nonce, gas_estimate, gas_price
            );

            let tx_hash = self.rpc_client.send_raw_transaction(&signed_tx_hex).await?;
            info!("Transaction submitted: {}", tx_hash);
            Ok(tx_hash)
        } else {
            // No signing key — return unsigned calldata for external signing
            let tx_data = format!("0x{}", hex::encode(&calldata));
            warn!(
                "No signing key configured — returning unsigned calldata. \
                 Contract: {}, gas: {}, gasPrice: {}",
                contract_address, gas_estimate, gas_price
            );
            Ok(format!(
                "unsigned:{}:{}:{}",
                contract_address, tx_data, gas_estimate
            ))
        }
    }

    /// Settles a batch of MPP sessions on Tempo.
    ///
    /// Processes each settlement entry as an individual TIP-20 transfer.
    /// When a signing key is configured, each transfer is signed and submitted.
    /// Returns a batch reference with individual transaction hashes.
    pub async fn settle_mpp_batch(
        &self,
        settlements: Vec<SettlementEntry>,
    ) -> Result<String> {
        info!(
            "Settling batch of {} MPP sessions on Tempo",
            settlements.len()
        );

        if settlements.is_empty() {
            return Err(PaymentError::SettlementError(
                "empty settlement batch".to_string(),
            ));
        }

        let mut tx_hashes = Vec::new();
        let mut failures = Vec::new();

        for (i, entry) in settlements.iter().enumerate() {
            match self
                .transfer_stablecoin(&entry.recipient, entry.amount, &entry.token)
                .await
            {
                Ok(tx_hash) => {
                    debug!("Settlement {}/{}: {}", i + 1, settlements.len(), tx_hash);
                    tx_hashes.push(tx_hash);
                }
                Err(e) => {
                    warn!(
                        "Settlement {}/{} failed for {} → {}: {}",
                        i + 1,
                        settlements.len(),
                        entry.payer,
                        entry.recipient,
                        e
                    );
                    failures.push(format!("entry[{}]: {}", i, e));
                }
            }
        }

        if tx_hashes.is_empty() {
            return Err(PaymentError::SettlementError(format!(
                "all {} settlements failed: {}",
                settlements.len(),
                failures.join("; ")
            )));
        }

        let batch_id = uuid::Uuid::new_v4();
        info!(
            "Batch {} complete: {}/{} succeeded",
            batch_id,
            tx_hashes.len(),
            settlements.len()
        );

        // Return batch summary with all tx hashes
        Ok(format!(
            "batch:{}:ok={},fail={}:{}",
            batch_id,
            tx_hashes.len(),
            failures.len(),
            tx_hashes.join(",")
        ))
    }

    /// Gets the finality status of a transaction on Tempo via `eth_getTransactionReceipt`
    ///
    /// Tempo uses Simplex BFT with deterministic finality (~600ms block time),
    /// so once a receipt is available, the transaction is final.
    pub async fn get_finality_status(&self, tx_hash: &str) -> Result<FinalityStatus> {
        info!("Checking finality status for tx {}", tx_hash);

        let receipt = self.rpc_client.get_transaction_receipt(tx_hash).await?;

        match receipt {
            None => {
                debug!("No receipt found for {} — tx is pending", tx_hash);
                Ok(FinalityStatus::Pending)
            }
            Some(receipt_val) => {
                // Check the status field: "0x1" = success, "0x0" = reverted
                let status = receipt_val
                    .get("status")
                    .and_then(|s| s.as_str())
                    .unwrap_or("0x1");

                if status == "0x0" {
                    debug!("Transaction {} reverted", tx_hash);
                    Ok(FinalityStatus::Reverted)
                } else {
                    // With Simplex BFT, once a receipt exists the block is final
                    let block_number = receipt_val
                        .get("blockNumber")
                        .and_then(|b| b.as_str())
                        .unwrap_or("0x0");
                    debug!(
                        "Transaction {} finalized in block {}",
                        tx_hash, block_number
                    );
                    Ok(FinalityStatus::Finalized)
                }
            }
        }
    }

    /// Gets the current block number on Tempo via `eth_blockNumber`
    pub async fn get_block_number(&self) -> Result<u64> {
        let result = self
            .rpc_client
            .rpc_call("eth_blockNumber", serde_json::json!([]))
            .await?;

        let hex_str = result
            .as_str()
            .ok_or_else(|| PaymentError::NetworkError("invalid block number format".to_string()))?;

        Ok(parse_hex_u64(hex_str))
    }

    /// Gets the current gas price on Tempo
    pub async fn get_gas_price(&self) -> Result<u128> {
        self.rpc_client.gas_price().await
    }

    /// Gets the native token balance of an address on Tempo
    pub async fn get_native_balance(&self, address: &str) -> Result<u128> {
        self.rpc_client.get_balance(address).await
    }

    /// Estimates the fee for a TIP-20 transfer in wei
    pub async fn estimate_transfer_fee(
        &self,
        token: &str,
        to: &str,
        amount: u128,
    ) -> Result<u128> {
        let contract_address = self
            .config
            .stablecoin_addresses
            .get(token)
            .ok_or_else(|| {
                PaymentError::ConfigError(format!("unknown stablecoin: {}", token))
            })?;

        if contract_address.is_empty() {
            return Ok(0);
        }

        let calldata = stablecoin::encode_transfer(to, amount);
        let gas = self
            .rpc_client
            .estimate_gas(contract_address, &calldata)
            .await
            .unwrap_or(65_000) as u128;
        let gas_price = self.rpc_client.gas_price().await.unwrap_or(1_000_000_000);

        Ok(gas * gas_price)
    }

    /// Returns the Tempo configuration
    pub fn config(&self) -> &TempoConfig {
        &self.config
    }

    /// Returns a reference to the RPC client
    pub fn rpc_client(&self) -> &TempoRpcClient {
        &self.rpc_client
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Append a u128 value to an RLP stream.
///
/// RLP requires minimal-length big-endian encoding (no leading zeros).
fn rlp_append_u128(stream: &mut RlpStream, value: u128) {
    if value == 0 {
        stream.append(&0u8);
    } else {
        let bytes = value.to_be_bytes();
        // Strip leading zeros
        let start = bytes.iter().position(|&b| b != 0).unwrap_or(15);
        stream.append(&bytes[start..].to_vec());
    }
}

/// Strip leading zeros from a 32-byte array for RLP encoding.
fn strip_leading_zeros(bytes: &[u8; 32]) -> &[u8] {
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(31);
    &bytes[start..]
}

/// Parses a hex string (with or without 0x prefix) to u64
fn parse_hex_u64(hex_str: &str) -> u64 {
    let clean = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    u64::from_str_radix(clean, 16).unwrap_or(0)
}

/// Parses a hex string (with or without 0x prefix) to u128
fn parse_hex_u128(hex_str: &str) -> u128 {
    let clean = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    u128::from_str_radix(clean, 16).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::{RecoveryId, Signature as K256Signature};

    #[test]
    fn test_parse_hex_u64() {
        assert_eq!(parse_hex_u64("0x0"), 0);
        assert_eq!(parse_hex_u64("0x1"), 1);
        assert_eq!(parse_hex_u64("0xff"), 255);
        assert_eq!(parse_hex_u64("0xFE502"), 1_041_666);
        assert_eq!(parse_hex_u64("ff"), 255);
    }

    #[test]
    fn test_parse_hex_u128() {
        assert_eq!(parse_hex_u128("0x0"), 0);
        assert_eq!(parse_hex_u128("0x3b9aca00"), 1_000_000_000); // 1 Gwei
        assert_eq!(
            parse_hex_u128("0xde0b6b3a7640000"),
            1_000_000_000_000_000_000 // 1 ETH in wei
        );
    }

    #[test]
    fn test_signing_key_to_address() {
        // Known test vector: private key 0x01 should produce a deterministic address
        let mut secret = [0u8; 32];
        secret[31] = 1;
        let key = SigningKey::from_bytes(&secret.into()).unwrap();
        let addr = signing_key_to_address(&key);
        // The address derived from private key 0x01 is well-known
        assert_eq!(addr.len(), 20);
        // Verify it matches the expected Ethereum address for privkey=1
        let addr_hex = hex::encode(addr);
        assert_eq!(
            addr_hex,
            "7e5f4552091a69125d5dfcb7b8c2659029395bdf"
        );
    }

    #[test]
    fn test_format_address_eip55() {
        // Test EIP-55 checksum encoding
        let addr_bytes =
            hex::decode("7e5f4552091a69125d5dfcb7b8c2659029395bdf").unwrap();
        let mut addr = [0u8; 20];
        addr.copy_from_slice(&addr_bytes);
        let formatted = format_address(&addr);
        assert!(formatted.starts_with("0x"));
        assert_eq!(formatted.len(), 42);
        // Mixed case indicates EIP-55 checksumming
        assert_eq!(
            formatted.to_lowercase(),
            "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf"
        );
    }

    #[test]
    fn test_parse_address() {
        let addr = parse_address("0x7e5f4552091a69125d5dfcb7b8c2659029395bdf").unwrap();
        assert_eq!(addr.len(), 20);
        assert_eq!(
            hex::encode(addr),
            "7e5f4552091a69125d5dfcb7b8c2659029395bdf"
        );

        // Without 0x prefix
        let addr2 = parse_address("7e5f4552091a69125d5dfcb7b8c2659029395bdf").unwrap();
        assert_eq!(addr, addr2);

        // Invalid length
        assert!(parse_address("0x1234").is_err());
    }

    #[test]
    fn test_evm_transaction_rlp_unsigned() {
        let tx = EvmTransaction {
            nonce: 9,
            gas_price: 20_000_000_000, // 20 Gwei
            gas_limit: 21000,
            to: [0u8; 20], // zero address
            value: 1_000_000_000_000_000_000, // 1 ETH
            data: vec![],
        };

        let rlp = tx.rlp_encode_unsigned(1); // mainnet chain_id
        assert!(!rlp.is_empty());

        // Should be a valid RLP list
        let decoded: Vec<Vec<u8>> = rlp::decode_list(&rlp);
        assert_eq!(decoded.len(), 9); // 6 tx fields + 3 EIP-155 fields
    }

    #[test]
    fn test_evm_transaction_sign_eip155() {
        // Use a known test private key
        let mut secret = [0u8; 32];
        secret[31] = 1; // private key = 1
        let signing_key = SigningKey::from_bytes(&secret.into()).unwrap();

        let to_addr = parse_address("0xdead000000000000000000000000000000000000").unwrap();

        let tx = EvmTransaction {
            nonce: 0,
            gas_price: 1_000_000_000, // 1 Gwei
            gas_limit: 65_000,
            to: to_addr,
            value: 0,
            data: vec![0xa9, 0x05, 0x9c, 0xbb], // transfer selector
        };

        let chain_id = 1337; // Tenzro testnet
        let signed = tx.sign_eip155(&signing_key, chain_id).unwrap();

        // Should be a hex string starting with 0x
        assert!(signed.starts_with("0x"));

        // Decode and verify it's valid RLP
        let raw_bytes = hex::decode(&signed[2..]).unwrap();
        assert!(!raw_bytes.is_empty());

        // The signed tx should be decodable as an RLP list with 9 elements
        let decoded: Vec<Vec<u8>> = rlp::decode_list(&raw_bytes);
        assert_eq!(decoded.len(), 9, "signed tx should have 9 RLP elements");
    }

    #[test]
    fn test_eip155_v_value() {
        // For chain_id=1337, v should be chain_id*2 + 35 + recovery_id (0 or 1)
        // So v ∈ {2709, 2710}
        let mut secret = [0u8; 32];
        secret[31] = 1;
        let signing_key = SigningKey::from_bytes(&secret.into()).unwrap();

        let tx = EvmTransaction {
            nonce: 0,
            gas_price: 1_000_000_000,
            gas_limit: 21000,
            to: [0xdeu8; 20],
            value: 0,
            data: vec![],
        };

        let signed_hex = tx.sign_eip155(&signing_key, 1337).unwrap();
        let raw = hex::decode(&signed_hex[2..]).unwrap();
        let decoded: Vec<Vec<u8>> = rlp::decode_list(&raw);

        // Element 6 is v (after nonce, gasPrice, gasLimit, to, value, data)
        let v_bytes = &decoded[6];
        let v = if v_bytes.is_empty() {
            0u64
        } else {
            let mut arr = [0u8; 8];
            let start = 8 - v_bytes.len();
            arr[start..].copy_from_slice(v_bytes);
            u64::from_be_bytes(arr)
        };

        // v must be 2709 or 2710 for chain_id=1337
        assert!(
            v == 2709 || v == 2710,
            "EIP-155 v should be 2709 or 2710 for chain_id=1337, got {}",
            v
        );
    }

    #[test]
    fn test_rlp_append_u128() {
        // Zero
        let mut stream = RlpStream::new();
        rlp_append_u128(&mut stream, 0);
        let encoded = stream.out();
        assert!(!encoded.is_empty());

        // 1 Gwei
        let mut stream = RlpStream::new();
        rlp_append_u128(&mut stream, 1_000_000_000);
        let encoded = stream.out();
        assert!(!encoded.is_empty());

        // 1 ETH
        let mut stream = RlpStream::new();
        rlp_append_u128(&mut stream, 1_000_000_000_000_000_000);
        let encoded = stream.out();
        assert!(!encoded.is_empty());
    }

    #[test]
    fn test_strip_leading_zeros() {
        let mut arr = [0u8; 32];
        arr[31] = 1;
        assert_eq!(strip_leading_zeros(&arr), &[1]);

        arr[30] = 0xff;
        assert_eq!(strip_leading_zeros(&arr), &[0xff, 1]);

        let full = [0xff; 32];
        assert_eq!(strip_leading_zeros(&full).len(), 32);

        let zero = [0u8; 32];
        assert_eq!(strip_leading_zeros(&zero), &[0]);
    }

    #[test]
    fn test_eip155_roundtrip_signing_and_recovery() {
        // Sign a tx and verify the signature recovers to the correct address
        let mut secret = [0u8; 32];
        secret[31] = 42;
        let signing_key = SigningKey::from_bytes(&secret.into()).unwrap();
        let expected_addr = signing_key_to_address(&signing_key);

        let tx = EvmTransaction {
            nonce: 5,
            gas_price: 20_000_000_000,
            gas_limit: 65_000,
            to: [0xab; 20],
            value: 0,
            data: stablecoin::encode_transfer(
                "0x1234567890abcdef1234567890abcdef12345678",
                1_000_000,
            ),
        };

        let chain_id = 1337u64;
        let signed_hex = tx.sign_eip155(&signing_key, chain_id).unwrap();

        // Decode the signed tx
        let raw = hex::decode(&signed_hex[2..]).unwrap();
        let decoded: Vec<Vec<u8>> = rlp::decode_list(&raw);

        // Extract v, r, s
        let v_bytes = &decoded[6];
        let v = {
            let mut arr = [0u8; 8];
            let start = 8usize.saturating_sub(v_bytes.len());
            arr[start..].copy_from_slice(v_bytes);
            u64::from_be_bytes(arr)
        };
        let recovery_id = ((v - (chain_id * 2 + 35)) & 1) as u8;

        let mut r_arr = [0u8; 32];
        let r_bytes = &decoded[7];
        r_arr[32 - r_bytes.len()..].copy_from_slice(r_bytes);

        let mut s_arr = [0u8; 32];
        let s_bytes = &decoded[8];
        s_arr[32 - s_bytes.len()..].copy_from_slice(s_bytes);

        // Reconstruct signature and recover public key
        let mut sig_bytes = [0u8; 64];
        sig_bytes[..32].copy_from_slice(&r_arr);
        sig_bytes[32..].copy_from_slice(&s_arr);
        let signature = K256Signature::from_bytes(&sig_bytes.into()).unwrap();
        let recid = RecoveryId::from_byte(recovery_id).unwrap();

        // Hash the unsigned tx to recover from
        let unsigned_rlp = tx.rlp_encode_unsigned(chain_id);
        let tx_hash = Keccak256::digest(&unsigned_rlp);

        let recovered_key =
            VerifyingKey::recover_from_prehash(&tx_hash, &signature, recid).unwrap();
        let recovered_point = recovered_key.to_encoded_point(false);
        let recovered_hash = Keccak256::digest(&recovered_point.as_bytes()[1..]);
        let mut recovered_addr = [0u8; 20];
        recovered_addr.copy_from_slice(&recovered_hash[12..]);

        assert_eq!(
            recovered_addr, expected_addr,
            "recovered address should match sender"
        );
    }

    #[test]
    fn test_tempo_participant_without_key() {
        let config = TempoConfig::testnet();
        let participant = TempoParticipant::new(config);
        assert!(!participant.can_sign());
        assert!(participant.sender_address().is_none());
    }

    #[test]
    fn test_tempo_participant_with_key() {
        let config = TempoConfig::testnet();
        let mut secret = [0u8; 32];
        secret[31] = 1;
        let participant = TempoParticipant::with_secret_key(config, &secret).unwrap();
        assert!(participant.can_sign());
        let addr = participant.sender_address().unwrap();
        assert!(addr.starts_with("0x"));
        assert_eq!(addr.len(), 42);
    }
}
