//! EVM transaction signing for bridge adapters
//!
//! Provides EIP-1559 (type 2) transaction signing and submission via JSON-RPC.
//! Used by LayerZero, Chainlink CCIP, and deBridge adapters to submit real
//! on-chain transactions.

use crate::error::{BridgeError, Result};
use k256::ecdsa::{SigningKey, signature::hazmat::PrehashSigner};
use reqwest::Client;
use serde_json::json;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::{debug, info};

/// EVM transaction signer for bridge operations
///
/// Signs EIP-1559 (type 2) transactions using secp256k1 and submits them
/// via `eth_sendRawTransaction`. Handles nonce management and gas estimation.
pub struct EvmTransactionSigner {
    /// Secp256k1 signing key
    signing_key: SigningKey,
    /// Sender address (derived from signing key)
    sender_address: [u8; 20],
    /// EVM chain ID
    chain_id: u64,
    /// JSON-RPC endpoint URL
    rpc_url: String,
    /// HTTP client for JSON-RPC calls
    http_client: Client,
    /// Local nonce counter (synced from chain on first use)
    nonce: AtomicU64,
    /// Whether the nonce has been synced from chain
    nonce_synced: std::sync::atomic::AtomicBool,
}

impl EvmTransactionSigner {
    /// Creates a new EVM transaction signer
    ///
    /// # Arguments
    /// * `private_key` - 32-byte secp256k1 private key
    /// * `chain_id` - EVM chain ID (e.g., 1 for Ethereum mainnet)
    /// * `rpc_url` - JSON-RPC endpoint URL
    pub fn new(private_key: &[u8; 32], chain_id: u64, rpc_url: String) -> Result<Self> {
        let signing_key = SigningKey::from_bytes(private_key.into())
            .map_err(|e| BridgeError::ConfigurationError(format!("Invalid private key: {}", e)))?;

        // Derive address from public key: keccak256(uncompressed_pubkey[1..])[12..]
        let verifying_key = signing_key.verifying_key();
        let public_key_bytes = verifying_key.to_encoded_point(false);
        let public_key_uncompressed = &public_key_bytes.as_bytes()[1..]; // skip 0x04 prefix

        let address_hash = keccak256(public_key_uncompressed);
        let mut sender_address = [0u8; 20];
        sender_address.copy_from_slice(&address_hash[12..]);

        let http_client = Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .unwrap_or_else(|_| Client::new());

        Ok(Self {
            signing_key,
            sender_address,
            chain_id,
            rpc_url,
            http_client,
            nonce: AtomicU64::new(0),
            nonce_synced: std::sync::atomic::AtomicBool::new(false),
        })
    }

    /// Returns the sender address as a hex string (0x-prefixed)
    pub fn sender_address(&self) -> String {
        format!("0x{}", hex::encode(self.sender_address))
    }

    /// Returns the sender address as raw bytes
    pub fn sender_address_bytes(&self) -> &[u8; 20] {
        &self.sender_address
    }

    /// Syncs the nonce from the chain if not already synced
    async fn sync_nonce(&self) -> Result<u64> {
        if self.nonce_synced.load(Ordering::SeqCst) {
            return Ok(self.nonce.fetch_add(1, Ordering::SeqCst));
        }

        let request = json!({
            "jsonrpc": "2.0",
            "method": "eth_getTransactionCount",
            "params": [self.sender_address(), "pending"],
            "id": 1
        });

        let response = self
            .http_client
            .post(&self.rpc_url)
            .json(&request)
            .send()
            .await
            .map_err(|e| BridgeError::NetworkError(format!("Failed to get nonce: {}", e)))?;

        let json: serde_json::Value = response
            .json()
            .await
            .map_err(|e| BridgeError::NetworkError(format!("Invalid nonce response: {}", e)))?;

        let nonce_hex = json
            .get("result")
            .and_then(|r| r.as_str())
            .unwrap_or("0x0");

        let nonce_hex = nonce_hex.strip_prefix("0x").unwrap_or(nonce_hex);
        let chain_nonce = u64::from_str_radix(nonce_hex, 16).unwrap_or(0);

        self.nonce.store(chain_nonce + 1, Ordering::SeqCst);
        self.nonce_synced.store(true, Ordering::SeqCst);

        debug!("Synced nonce from chain: {}", chain_nonce);
        Ok(chain_nonce)
    }

    /// Estimates gas for a transaction via eth_estimateGas
    async fn estimate_gas(&self, to: &str, data: &[u8], value: u128) -> Result<u64> {
        let request = json!({
            "jsonrpc": "2.0",
            "method": "eth_estimateGas",
            "params": [{
                "from": self.sender_address(),
                "to": to,
                "data": format!("0x{}", hex::encode(data)),
                "value": format!("0x{:x}", value),
            }],
            "id": 1
        });

        let response = self
            .http_client
            .post(&self.rpc_url)
            .json(&request)
            .send()
            .await
            .map_err(|e| BridgeError::NetworkError(format!("Failed to estimate gas: {}", e)))?;

        let json: serde_json::Value = response
            .json()
            .await
            .map_err(|e| BridgeError::NetworkError(format!("Invalid gas estimate: {}", e)))?;

        if let Some(error) = json.get("error") {
            return Err(BridgeError::AdapterError(format!(
                "Gas estimation failed: {}",
                error
            )));
        }

        let gas_hex = json
            .get("result")
            .and_then(|r| r.as_str())
            .unwrap_or("0x30d40"); // default 200k

        let gas_hex = gas_hex.strip_prefix("0x").unwrap_or(gas_hex);
        let gas = u64::from_str_radix(gas_hex, 16).unwrap_or(200_000);

        // Add 20% buffer
        Ok(gas + gas / 5)
    }

    /// Gets the current base fee from the latest block
    async fn get_base_fee(&self) -> Result<u128> {
        let request = json!({
            "jsonrpc": "2.0",
            "method": "eth_getBlockByNumber",
            "params": ["latest", false],
            "id": 1
        });

        let response = self
            .http_client
            .post(&self.rpc_url)
            .json(&request)
            .send()
            .await
            .map_err(|e| BridgeError::NetworkError(format!("Failed to get base fee: {}", e)))?;

        let json: serde_json::Value = response
            .json()
            .await
            .map_err(|e| BridgeError::NetworkError(format!("Invalid block response: {}", e)))?;

        let base_fee_hex = json
            .get("result")
            .and_then(|r| r.get("baseFeePerGas"))
            .and_then(|b| b.as_str())
            .unwrap_or("0x3b9aca00"); // default 1 gwei

        let base_fee_hex = base_fee_hex.strip_prefix("0x").unwrap_or(base_fee_hex);
        let base_fee = u128::from_str_radix(base_fee_hex, 16).unwrap_or(1_000_000_000);

        Ok(base_fee)
    }

    /// Signs and submits an EIP-1559 transaction
    ///
    /// # Arguments
    /// * `to` - Contract address to call (0x-prefixed hex)
    /// * `calldata` - Encoded function call data
    /// * `value` - ETH value to send (in wei)
    ///
    /// # Returns
    /// The transaction hash as a hex string
    pub async fn send_transaction(
        &self,
        to: &str,
        calldata: &[u8],
        value: u128,
    ) -> Result<String> {
        let nonce = self.sync_nonce().await?;
        let gas_limit = self.estimate_gas(to, calldata, value).await?;
        let base_fee = self.get_base_fee().await?;

        // Set max fee per gas to 2x base fee, priority fee to 2 gwei
        let max_priority_fee: u128 = 2_000_000_000; // 2 gwei
        let max_fee_per_gas = base_fee * 2 + max_priority_fee;

        info!(
            "Signing EIP-1559 tx: to={}, nonce={}, gas_limit={}, max_fee={}, value={}",
            to, nonce, gas_limit, max_fee_per_gas, value
        );

        // Encode EIP-1559 transaction
        let raw_tx = self.encode_eip1559_transaction(
            nonce,
            max_priority_fee,
            max_fee_per_gas,
            gas_limit,
            to,
            value,
            calldata,
        )?;

        // Submit via eth_sendRawTransaction
        let tx_hex = format!("0x{}", hex::encode(&raw_tx));

        let request = json!({
            "jsonrpc": "2.0",
            "method": "eth_sendRawTransaction",
            "params": [tx_hex],
            "id": 1
        });

        let response = self
            .http_client
            .post(&self.rpc_url)
            .json(&request)
            .send()
            .await
            .map_err(|e| BridgeError::NetworkError(format!("Failed to send tx: {}", e)))?;

        let json: serde_json::Value = response
            .json()
            .await
            .map_err(|e| BridgeError::NetworkError(format!("Invalid tx response: {}", e)))?;

        if let Some(error) = json.get("error") {
            return Err(BridgeError::TransferFailed(format!(
                "Transaction rejected: {}",
                error
            )));
        }

        let tx_hash = json
            .get("result")
            .and_then(|r| r.as_str())
            .unwrap_or("0x0")
            .to_string();

        info!("Transaction submitted: {}", tx_hash);
        Ok(tx_hash)
    }

    /// Encodes an EIP-1559 (type 2) transaction and signs it
    ///
    /// EIP-1559 tx RLP:
    /// 0x02 || rlp([chain_id, nonce, max_priority_fee, max_fee, gas_limit, to, value, data, access_list, v, r, s])
    fn encode_eip1559_transaction(
        &self,
        nonce: u64,
        max_priority_fee_per_gas: u128,
        max_fee_per_gas: u128,
        gas_limit: u64,
        to: &str,
        value: u128,
        data: &[u8],
    ) -> Result<Vec<u8>> {
        // Parse 'to' address
        let to_hex = to.strip_prefix("0x").unwrap_or(to);
        let to_bytes = hex::decode(to_hex)
            .map_err(|e| BridgeError::InvalidParameter(format!("Invalid 'to' address: {}", e)))?;

        // Build the unsigned transaction fields for RLP encoding
        // [chain_id, nonce, max_priority_fee, max_fee, gas_limit, to, value, data, access_list]
        let mut unsigned_fields = Vec::new();
        rlp_encode_u64(&mut unsigned_fields, self.chain_id);
        rlp_encode_u64(&mut unsigned_fields, nonce);
        rlp_encode_u128(&mut unsigned_fields, max_priority_fee_per_gas);
        rlp_encode_u128(&mut unsigned_fields, max_fee_per_gas);
        rlp_encode_u64(&mut unsigned_fields, gas_limit);
        rlp_encode_bytes(&mut unsigned_fields, &to_bytes);
        rlp_encode_u128(&mut unsigned_fields, value);
        rlp_encode_bytes(&mut unsigned_fields, data);
        // Empty access list
        unsigned_fields.push(0xc0); // RLP empty list

        // Wrap in RLP list
        let unsigned_rlp = rlp_encode_list(&unsigned_fields);

        // Hash for signing: keccak256(0x02 || unsigned_rlp)
        let mut signing_input = Vec::new();
        signing_input.push(0x02); // EIP-1559 tx type
        signing_input.extend_from_slice(&unsigned_rlp);

        let msg_hash = keccak256(&signing_input);

        // Sign the hash with secp256k1
        let (signature, recovery_id) = self
            .signing_key
            .sign_prehash(&msg_hash)
            .map_err(|e| BridgeError::AdapterError(format!("Signing failed: {}", e)))?;

        let sig_bytes = signature.to_bytes();
        let r = &sig_bytes[..32];
        let s = &sig_bytes[32..];
        let v = recovery_id.to_byte();

        // Build signed transaction fields
        // [chain_id, nonce, max_priority_fee, max_fee, gas_limit, to, value, data, access_list, v, r, s]
        let mut signed_fields = unsigned_fields;
        rlp_encode_u64(&mut signed_fields, v as u64);
        rlp_encode_bytes(&mut signed_fields, r);
        rlp_encode_bytes(&mut signed_fields, s);

        let signed_rlp = rlp_encode_list(&signed_fields);

        // Final encoding: 0x02 || signed_rlp
        let mut result = Vec::new();
        result.push(0x02);
        result.extend_from_slice(&signed_rlp);

        Ok(result)
    }
}

/// Keccak-256 hash function
fn keccak256(data: &[u8]) -> [u8; 32] {
    use sha3::{Digest as Sha3Digest, Keccak256};
    let mut hasher = Keccak256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(&result);
    output
}

/// RLP-encodes a u64 value and appends to buffer
fn rlp_encode_u64(buf: &mut Vec<u8>, value: u64) {
    if value == 0 {
        buf.push(0x80); // RLP encoding of empty byte string (represents 0)
    } else if value < 128 {
        buf.push(value as u8);
    } else {
        let bytes = value.to_be_bytes();
        let start = bytes.iter().position(|&b| b != 0).unwrap_or(7);
        let len = 8 - start;
        buf.push(0x80 + len as u8);
        buf.extend_from_slice(&bytes[start..]);
    }
}

/// RLP-encodes a u128 value and appends to buffer
fn rlp_encode_u128(buf: &mut Vec<u8>, value: u128) {
    if value == 0 {
        buf.push(0x80);
    } else if value < 128 {
        buf.push(value as u8);
    } else {
        let bytes = value.to_be_bytes();
        let start = bytes.iter().position(|&b| b != 0).unwrap_or(15);
        let len = 16 - start;
        buf.push(0x80 + len as u8);
        buf.extend_from_slice(&bytes[start..]);
    }
}

/// RLP-encodes a byte slice and appends to buffer
fn rlp_encode_bytes(buf: &mut Vec<u8>, data: &[u8]) {
    if data.len() == 1 && data[0] < 128 {
        buf.push(data[0]);
    } else if data.len() < 56 {
        buf.push(0x80 + data.len() as u8);
        buf.extend_from_slice(data);
    } else {
        let len_bytes = data.len().to_be_bytes();
        let start = len_bytes.iter().position(|&b| b != 0).unwrap_or(7);
        let len_of_len = 8 - start;
        buf.push(0xb7 + len_of_len as u8);
        buf.extend_from_slice(&len_bytes[start..]);
        buf.extend_from_slice(data);
    }
}

/// RLP-encodes a list from pre-encoded items
fn rlp_encode_list(items: &[u8]) -> Vec<u8> {
    let mut result = Vec::new();
    if items.len() < 56 {
        result.push(0xc0 + items.len() as u8);
    } else {
        let len_bytes = items.len().to_be_bytes();
        let start = len_bytes.iter().position(|&b| b != 0).unwrap_or(7);
        let len_of_len = 8 - start;
        result.push(0xf7 + len_of_len as u8);
        result.extend_from_slice(&len_bytes[start..]);
    }
    result.extend_from_slice(items);
    result
}

/// Configuration for EVM signer setup
pub struct EvmSignerConfig {
    /// 32-byte private key (hex-encoded, without 0x prefix)
    pub private_key_hex: String,
    /// EVM chain ID
    pub chain_id: u64,
    /// JSON-RPC endpoint URL
    pub rpc_url: String,
}

impl EvmSignerConfig {
    /// Creates a signer config for Ethereum mainnet
    pub fn ethereum(private_key_hex: String, rpc_url: String) -> Self {
        Self {
            private_key_hex,
            chain_id: 1,
            rpc_url,
        }
    }

    /// Creates a signer config for Arbitrum
    pub fn arbitrum(private_key_hex: String, rpc_url: String) -> Self {
        Self {
            private_key_hex,
            chain_id: 42161,
            rpc_url,
        }
    }

    /// Creates a signer config for a custom chain
    pub fn custom(private_key_hex: String, chain_id: u64, rpc_url: String) -> Self {
        Self {
            private_key_hex,
            chain_id,
            rpc_url,
        }
    }

    /// Builds an EvmTransactionSigner from this config
    pub fn build(&self) -> Result<EvmTransactionSigner> {
        let key_bytes = hex::decode(&self.private_key_hex)
            .map_err(|e| BridgeError::ConfigurationError(format!("Invalid private key hex: {}", e)))?;

        if key_bytes.len() != 32 {
            return Err(BridgeError::ConfigurationError(format!(
                "Private key must be 32 bytes, got {}",
                key_bytes.len()
            )));
        }

        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(&key_bytes);

        EvmTransactionSigner::new(&key_array, self.chain_id, self.rpc_url.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rlp_encode_u64() {
        let mut buf = Vec::new();

        // Zero
        rlp_encode_u64(&mut buf, 0);
        assert_eq!(buf, vec![0x80]);

        // Single byte
        buf.clear();
        rlp_encode_u64(&mut buf, 42);
        assert_eq!(buf, vec![42]);

        // Multi-byte
        buf.clear();
        rlp_encode_u64(&mut buf, 256);
        assert_eq!(buf, vec![0x82, 0x01, 0x00]);
    }

    #[test]
    fn test_rlp_encode_u128() {
        let mut buf = Vec::new();

        // Zero
        rlp_encode_u128(&mut buf, 0);
        assert_eq!(buf, vec![0x80]);

        // Small value
        buf.clear();
        rlp_encode_u128(&mut buf, 100);
        assert_eq!(buf, vec![100]);

        // Gwei value (1 gwei = 10^9)
        buf.clear();
        rlp_encode_u128(&mut buf, 1_000_000_000);
        let expected_bytes = 1_000_000_000u128.to_be_bytes();
        let start = expected_bytes.iter().position(|&b| b != 0).unwrap();
        let len = 16 - start;
        let mut expected = vec![0x80 + len as u8];
        expected.extend_from_slice(&expected_bytes[start..]);
        assert_eq!(buf, expected);
    }

    #[test]
    fn test_rlp_encode_bytes() {
        let mut buf = Vec::new();

        // Empty
        rlp_encode_bytes(&mut buf, &[]);
        assert_eq!(buf, vec![0x80]);

        // Short bytes
        buf.clear();
        rlp_encode_bytes(&mut buf, &[0x01, 0x02, 0x03]);
        assert_eq!(buf, vec![0x83, 0x01, 0x02, 0x03]);

        // Single byte < 128
        buf.clear();
        rlp_encode_bytes(&mut buf, &[42]);
        assert_eq!(buf, vec![42]);
    }

    #[test]
    fn test_rlp_encode_list() {
        // Short list
        let items = vec![0x01, 0x02, 0x03];
        let encoded = rlp_encode_list(&items);
        assert_eq!(encoded, vec![0xc3, 0x01, 0x02, 0x03]);
    }

    #[test]
    fn test_keccak256() {
        let hash = keccak256(b"hello");
        // Known keccak256("hello")
        let expected = hex::decode(
            "1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8"
        ).unwrap();
        assert_eq!(&hash[..], &expected[..]);
    }

    #[test]
    fn test_evm_signer_creation() {
        // Use a known test private key (DO NOT use in production)
        let private_key = [0x01u8; 32];
        let signer = EvmTransactionSigner::new(
            &private_key,
            1,
            "http://localhost:8545".to_string(),
        ).unwrap();

        let addr = signer.sender_address();
        assert!(addr.starts_with("0x"));
        assert_eq!(addr.len(), 42); // 0x + 40 hex chars
    }

    #[test]
    fn test_evm_signer_config() {
        let rpc_url = {
            let key = std::env::var("DRPC_API_KEY").unwrap_or_default();
            if key.is_empty() {
                "https://eth.llamarpc.com".to_string()
            } else {
                format!("https://lb.drpc.live/ethereum/{}", key)
            }
        };
        let config = EvmSignerConfig::ethereum(
            "0101010101010101010101010101010101010101010101010101010101010101".to_string(),
            rpc_url,
        );
        assert_eq!(config.chain_id, 1);

        let signer = config.build().unwrap();
        assert!(signer.sender_address().starts_with("0x"));
    }

    #[test]
    fn test_eip1559_transaction_encoding() {
        let private_key = [0x01u8; 32];
        let signer = EvmTransactionSigner::new(
            &private_key,
            1,
            "http://localhost:8545".to_string(),
        ).unwrap();

        let result = signer.encode_eip1559_transaction(
            0,                       // nonce
            2_000_000_000,           // max priority fee (2 gwei)
            30_000_000_000,          // max fee per gas (30 gwei)
            21_000,                  // gas limit
            "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb0",
            0,                       // value
            &[],                     // empty data
        );

        assert!(result.is_ok());
        let raw_tx = result.unwrap();
        // EIP-1559 tx starts with 0x02
        assert_eq!(raw_tx[0], 0x02);
        // Should be a valid RLP-encoded transaction
        assert!(raw_tx.len() > 100);
    }
}
