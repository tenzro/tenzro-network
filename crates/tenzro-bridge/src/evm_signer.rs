//! EVM transaction signing
//!
//! Provides EIP-1559 (type 2) transaction signing and submission via JSON-RPC
//! for the node's on-chain EVM writes.
//!
//! # Custody
//!
//! The signing key lives in a hardware device behind
//! [`tenzro_wallet::pluggable_signer::PluggableSigner`]: a Ledger, Trezor or
//! GridPlus Lattice holding a secp256k1 key. This module never holds a private
//! scalar. It asks the device for its public key once, derives the sender
//! address from it, and sends the device a 32-byte transaction hash for every
//! signature. There is no constructor that takes key bytes.

use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::error::{BridgeError, Result};
use crate::relayer_nonce::NonceLane;
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use reqwest::Client;
use serde_json::json;
use tenzro_wallet::pluggable_signer::PluggableSigner;
use tracing::{debug, info};

/// EVM transaction signer for the node's relayer keys.
///
/// Signs EIP-1559 (type 2) transactions through a hardware signer and submits
/// them via `eth_sendRawTransaction`. Handles nonce management and gas
/// estimation. A relayer key pays fees only: every transaction it signs
/// carries zero native value, so it can submit a call another party
/// authorized but never move value of its own accord.
pub struct EvmTransactionSigner {
    /// The hardware device that holds the key.
    device: Arc<dyn PluggableSigner>,
    /// The device's public key.
    verifying_key: VerifyingKey,
    /// Sender address (derived from the device's public key)
    sender_address: [u8; 20],
    /// EVM chain ID
    chain_id: u64,
    /// JSON-RPC endpoint URL
    rpc_url: String,
    /// HTTP client for JSON-RPC calls
    http_client: Client,
    /// The relayer's nonces: the count, its gaps and those the node may hold.
    nonces: NonceLane,
}

/// How long one JSON-RPC request may take.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Gas of a plain value transfer, used by a filler transaction.
const TRANSFER_GAS: u64 = 21_000;

impl EvmTransactionSigner {
    /// A signer backed by `device`, a hardware secp256k1 signer.
    ///
    /// Reads the device's public key (33-byte compressed or 65-byte
    /// uncompressed SEC1) and derives the Ethereum address from it.
    pub async fn from_hardware(
        device: Arc<dyn PluggableSigner>,
        chain_id: u64,
        rpc_url: String,
    ) -> Result<Self> {
        let public_key = device.public_key().await.map_err(|e| {
            BridgeError::ConfigurationError(format!(
                "{} signer did not return its public key: {e}",
                device.device_kind().as_str()
            ))
        })?;
        let verifying_key = VerifyingKey::from_sec1_bytes(&public_key).map_err(|e| {
            BridgeError::ConfigurationError(format!(
                "{} signer returned a key that is not secp256k1 SEC1 ({} bytes): {e}",
                device.device_kind().as_str(),
                public_key.len()
            ))
        })?;
        let point = verifying_key.to_sec1_point(false);
        let address_hash = keccak256(&point.as_bytes()[1..]);
        let mut sender_address = [0u8; 20];
        sender_address.copy_from_slice(&address_hash[12..]);

        let http_client = Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .build()
            .unwrap_or_else(|_| Client::new());
        Ok(Self {
            device,
            verifying_key,
            sender_address,
            chain_id,
            rpc_url,
            http_client,
            nonces: NonceLane::default(),
        })
    }

    /// The kind of device holding the key (`"ledger"`, `"trezor"`, ...).
    pub fn device_kind(&self) -> &'static str {
        self.device.device_kind().as_str()
    }

    /// Returns the sender address as a hex string (0x-prefixed)
    pub fn sender_address(&self) -> String {
        format!("0x{}", hex::encode(self.sender_address))
    }

    /// The 20-byte address of the device key.
    pub fn address(&self) -> [u8; 20] {
        self.sender_address
    }

    /// Sign a 32-byte digest on the device and return `r || s || v`, low-s,
    /// with `v` the recovery id (0 or 1) that recovers the device key.
    pub async fn sign_digest(&self, digest: &[u8; 32]) -> Result<[u8; 65]> {
        let (signature, recovery_id) = self.sign_prehash(digest).await?;
        let mut out = [0u8; 65];
        out[..64].copy_from_slice(&signature.to_bytes());
        out[64] = recovery_id.to_byte();
        Ok(out)
    }

    /// Ask the device to sign `digest`, and return a low-s signature with the
    /// recovery id that recovers the device's public key.
    ///
    /// Devices return `r || s` or `r || s || v`; the recovery id is recomputed
    /// by trial recovery rather than trusted, so a device that encodes `v`
    /// differently still yields a transaction that recovers to the sender.
    async fn sign_prehash(&self, digest: &[u8; 32]) -> Result<(Signature, RecoveryId)> {
        let raw = self.device.sign_hash(digest).await.map_err(|e| {
            BridgeError::AdapterError(format!("{} signer refused: {e}", self.device_kind()))
        })?;
        if raw.len() != 64 && raw.len() != 65 {
            return Err(BridgeError::AdapterError(format!(
                "{} signer returned a {}-byte signature; expected 64 or 65",
                self.device_kind(),
                raw.len()
            )));
        }
        let signature = Signature::from_slice(&raw[..64]).map_err(|e| {
            BridgeError::AdapterError(format!(
                "{} signature is malformed: {e}",
                self.device_kind()
            ))
        })?;
        let signature = signature.normalize_s();
        for byte in 0..=1u8 {
            let Some(recovery_id) = RecoveryId::from_byte(byte) else {
                continue;
            };
            if VerifyingKey::recover_from_prehash(digest, &signature, recovery_id)
                .is_ok_and(|vk| vk == self.verifying_key)
            {
                return Ok((signature, recovery_id));
            }
        }
        Err(BridgeError::AdapterError(format!(
            "{} signature does not recover to the device's public key",
            self.device_kind()
        )))
    }

    /// Reads the pending nonce from chain. An RPC error is an error, never a
    /// nonce of zero.
    async fn chain_nonce(&self) -> Result<u64> {
        let request = json!({
            "jsonrpc": "2.0",
            "method": "eth_getTransactionCount",
            "params": [self.sender_address(), "pending"],
            "id": 1
        });
        let json: serde_json::Value = self
            .http_client
            .post(&self.rpc_url)
            .json(&request)
            .send()
            .await
            .map_err(|e| BridgeError::NetworkError(format!("Failed to get nonce: {}", e)))?
            .json()
            .await
            .map_err(|e| BridgeError::NetworkError(format!("Invalid nonce response: {}", e)))?;
        let nonce_hex = json.get("result").and_then(|r| r.as_str()).ok_or_else(|| {
            BridgeError::NetworkError(format!(
                "eth_getTransactionCount returned no result: {json}"
            ))
        })?;
        u64::from_str_radix(nonce_hex.strip_prefix("0x").unwrap_or(nonce_hex), 16)
            .map_err(|e| BridgeError::NetworkError(format!("unparseable nonce {nonce_hex}: {e}")))
    }

    /// Reserves the next nonce, reading it from the chain while the count
    /// is unknown.
    async fn next_nonce(&self) -> Result<u64> {
        loop {
            let chain = if self.nonces.unsynced() {
                let chain_nonce = self.chain_nonce().await?;
                debug!("Read nonce from chain: {}", chain_nonce);
                Some(chain_nonce)
            } else {
                None
            };
            if let Some(nonce) = self.nonces.reserve(chain) {
                return Ok(nonce);
            }
        }
    }

    /// Estimates gas for a transaction via eth_estimateGas
    async fn estimate_gas(&self, to: &str, data: &[u8]) -> Result<u64> {
        let request = json!({
            "jsonrpc": "2.0",
            "method": "eth_estimateGas",
            "params": [{
                "from": self.sender_address(),
                "to": to,
                "data": format!("0x{}", hex::encode(data)),
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

        let gas_hex = json.get("result").and_then(|r| r.as_str()).ok_or_else(|| {
            BridgeError::NetworkError("eth_estimateGas returned no result".into())
        })?;
        let gas = u64::from_str_radix(gas_hex.strip_prefix("0x").unwrap_or(gas_hex), 16)
            .map_err(|e| BridgeError::NetworkError(format!("unparseable gas {gas_hex}: {e}")))?;

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
            .ok_or_else(|| BridgeError::NetworkError("latest block carries no base fee".into()))?;
        u128::from_str_radix(base_fee_hex.strip_prefix("0x").unwrap_or(base_fee_hex), 16)
            .map_err(|e| BridgeError::NetworkError(format!("unparseable base fee: {e}")))
    }

    /// Signs and submits an EIP-1559 transaction
    ///
    /// # Arguments
    /// * `to` - Contract address to call (0x-prefixed hex)
    /// * `calldata` - Encoded function call data
    ///
    /// # Returns
    /// The transaction hash as a hex string
    pub async fn send_transaction(&self, to: &str, calldata: &[u8]) -> Result<String> {
        // Gas and fee first, so a failed estimate holds no nonce.
        let gas_limit = self.estimate_gas(to, calldata).await?;
        let base_fee = self.get_base_fee().await?;

        // Set max fee per gas to 2x base fee, priority fee to 2 gwei
        let max_priority_fee: u128 = 2_000_000_000; // 2 gwei
        let max_fee_per_gas = base_fee.saturating_mul(2).saturating_add(max_priority_fee);

        self.settle_unknown().await?;
        let nonce = self.next_nonce().await?;
        info!(
            "Signing EIP-1559 tx: to={}, nonce={}, gas_limit={}, max_fee={}",
            to, nonce, gas_limit, max_fee_per_gas
        );
        let encoded = self
            .encode_eip1559_transaction(
                nonce,
                max_priority_fee,
                max_fee_per_gas,
                gas_limit,
                to,
                calldata,
            )
            .await;
        let sent = self.submit_encoded(nonce, encoded).await;
        if sent.is_err() {
            self.fill_gaps(max_priority_fee, max_fee_per_gas).await;
        }
        sent
    }

    /// Settles the nonces the node may hold against the chain's pending nonce.
    async fn settle_unknown(&self) -> Result<()> {
        if self.nonces.has_unknown() {
            let chain = self.chain_nonce().await?;
            self.nonces
                .resync(chain, Instant::now(), REQUEST_TIMEOUT * 2);
        }
        Ok(())
    }

    /// Fills each gap a failed send left below a nonce still out with a
    /// zero-value transfer to this signer's own address, so the transactions
    /// above it do not wait on a nonce no sender comes for. A filler that
    /// fails leaves its gap to the next send, which takes gaps first and
    /// fills again if it fails too.
    async fn fill_gaps(&self, max_priority_fee: u128, max_fee_per_gas: u128) {
        if let Err(e) = self.settle_unknown().await {
            debug!("nonce gaps not settled: {e}");
        }
        let own = self.sender_address();
        while let Some(nonce) = self.nonces.take_gap() {
            info!("Filling nonce gap {nonce}");
            let encoded = self
                .encode_eip1559_transaction(
                    nonce,
                    max_priority_fee,
                    max_fee_per_gas,
                    TRANSFER_GAS,
                    &own,
                    &[],
                )
                .await;
            if let Err(e) = self.submit_encoded(nonce, encoded).await {
                debug!("filler for nonce {nonce} failed: {e}");
                break;
            }
        }
    }

    /// Submits a transaction signed under the reserved `nonce`, or releases
    /// the nonce when signing failed, and records what became of it.
    async fn submit_encoded(&self, nonce: u64, encoded: Result<Vec<u8>>) -> Result<String> {
        let raw_tx = match encoded {
            Ok(tx) => tx,
            Err(e) => {
                self.nonces.release(nonce);
                return Err(e);
            }
        };

        let request = json!({
            "jsonrpc": "2.0",
            "method": "eth_sendRawTransaction",
            "params": [format!("0x{}", hex::encode(&raw_tx))],
            "id": 1
        });

        let response = match self
            .http_client
            .post(&self.rpc_url)
            .json(&request)
            .send()
            .await
        {
            Ok(response) => response,
            Err(e) => {
                if e.is_connect() {
                    // No connection, so the body never left.
                    self.nonces.release(nonce);
                } else {
                    // The body may have reached the node: a different
                    // transaction under this nonce could replace it.
                    self.nonces.unknown(nonce, Instant::now());
                }
                return Err(BridgeError::NetworkError(format!("Failed to send tx: {e}")));
            }
        };
        let json: serde_json::Value = match response.json().await {
            Ok(json) => json,
            Err(e) => {
                self.nonces.unknown(nonce, Instant::now());
                return Err(BridgeError::NetworkError(format!(
                    "Invalid tx response: {e}"
                )));
            }
        };

        if let Some(error) = json.get("error") {
            // A refusal can still name a transaction the pool holds under this
            // nonce, so the chain's pending nonce decides: below it the nonce
            // is used, at it the pool has nothing under it and it is free
            // (no request carrying it is on its way: the node answered).
            self.nonces.unknown(nonce, Instant::now());
            match self.chain_nonce().await {
                Ok(chain) => self.nonces.resync(chain, Instant::now(), Duration::ZERO),
                Err(e) => debug!("nonce {nonce} left to settle: {e}"),
            }
            return Err(BridgeError::TransferFailed(format!(
                "Transaction rejected: {}",
                error
            )));
        }

        let Some(tx_hash) = json.get("result").and_then(|r| r.as_str()) else {
            self.nonces.unknown(nonce, Instant::now());
            return Err(BridgeError::NetworkError(
                "eth_sendRawTransaction returned no hash".into(),
            ));
        };
        info!("Transaction submitted: {}", tx_hash);
        Ok(tx_hash.to_string())
    }

    /// Encodes an EIP-1559 (type 2) transaction and signs it
    ///
    /// EIP-1559 tx RLP:
    /// 0x02 || rlp([chain_id, nonce, max_priority_fee, max_fee, gas_limit, to, value, data, access_list, v, r, s])
    async fn encode_eip1559_transaction(
        &self,
        nonce: u64,
        max_priority_fee_per_gas: u128,
        max_fee_per_gas: u128,
        gas_limit: u64,
        to: &str,
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
        // Native value: always zero.
        rlp_encode_u128(&mut unsigned_fields, 0);
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

        let (signature, recovery_id) = self.sign_prehash(&msg_hash).await?;

        let sig_bytes = signature.to_bytes();
        let r = strip_leading_zeros(&sig_bytes[..32]);
        let s = strip_leading_zeros(&sig_bytes[32..]);
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

/// RLP integers carry no leading zero bytes.
fn strip_leading_zeros(bytes: &[u8]) -> &[u8] {
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    &bytes[start..]
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

#[cfg(test)]
pub(crate) mod test_support {
    //! A hardware-signer stand-in for tests: a `GenericSigner` whose closure
    //! signs with a deterministic in-memory key. Test code only.

    use super::*;
    use k256::ecdsa::SigningKey;
    use k256::ecdsa::signature::hazmat::PrehashSigner;
    use tenzro_wallet::pluggable_signer::GenericSigner;

    /// A device whose key is derived from `seed`, returning `r || s || v`.
    pub fn test_device(seed: u8) -> Arc<dyn PluggableSigner> {
        let mut bytes = [0u8; 32];
        bytes[31] = seed.max(1);
        bytes[0] = 0x42;
        let sk = SigningKey::from_bytes((&bytes).into()).expect("valid scalar");
        let pk = sk.verifying_key().to_sec1_point(true).as_bytes().to_vec();
        Arc::new(GenericSigner::new(pk, move |hash| {
            let (sig, rec): (Signature, RecoveryId) = sk
                .sign_prehash(hash)
                .map_err(|e| tenzro_wallet::WalletError::SignatureFailed(e.to_string()))?;
            let mut out = sig.to_bytes().to_vec();
            out.push(rec.to_byte());
            Ok(out)
        }))
    }

    /// A signer over `test_device(seed)` against an unreachable RPC.
    pub async fn test_signer(seed: u8) -> EvmTransactionSigner {
        EvmTransactionSigner::from_hardware(test_device(seed), 1, "http://127.0.0.1:1".into())
            .await
            .expect("test device")
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::*;
    use super::*;
    use tenzro_wallet::pluggable_signer::GenericSigner;

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
        let expected =
            hex::decode("1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8")
                .unwrap();
        assert_eq!(&hash[..], &expected[..]);
    }

    #[tokio::test]
    async fn the_sender_address_is_derived_from_the_device_key() {
        let signer = test_signer(1).await;
        let addr = signer.sender_address();
        assert!(addr.starts_with("0x"));
        assert_eq!(addr.len(), 42);
        assert_eq!(signer.device_kind(), "generic");
    }

    #[tokio::test]
    async fn a_device_key_that_is_not_secp256k1_is_refused() {
        let device: Arc<dyn PluggableSigner> =
            Arc::new(GenericSigner::new(vec![0u8; 64], |_| Ok(vec![0u8; 64])));
        assert!(
            EvmTransactionSigner::from_hardware(device, 1, "http://127.0.0.1:1".into())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn a_signature_by_another_key_is_refused() {
        // A device that reports one public key but signs with another cannot
        // produce a transaction that recovers to the reported sender.
        let honest = test_device(1);
        let impostor = test_device(2);
        let pk = honest.public_key().await.unwrap();
        let device: Arc<dyn PluggableSigner> = Arc::new(GenericSigner::new(pk, move |h| {
            futures_lite_block_on(impostor.sign_hash(h))
        }));
        let signer = EvmTransactionSigner::from_hardware(device, 1, "http://127.0.0.1:1".into())
            .await
            .unwrap();
        assert!(signer.sign_prehash(&[7u8; 32]).await.is_err());
    }

    /// The raw encoding of item `index` of an RLP list.
    fn rlp_list_item(list: &[u8], index: usize) -> Vec<u8> {
        fn len_of(b: &[u8]) -> (usize, usize) {
            match b[0] {
                0x00..=0x7f => (0, 1),
                p @ 0x80..=0xb7 => (1, (p - 0x80) as usize),
                p @ 0xb8..=0xbf => {
                    let n = (p - 0xb7) as usize;
                    (
                        1 + n,
                        b[1..1 + n].iter().fold(0, |a, x| a << 8 | *x as usize),
                    )
                }
                p @ 0xc0..=0xf7 => (1, (p - 0xc0) as usize),
                p => {
                    let n = (p - 0xf7) as usize;
                    (
                        1 + n,
                        b[1..1 + n].iter().fold(0, |a, x| a << 8 | *x as usize),
                    )
                }
            }
        }
        let (head, _) = len_of(list);
        let mut at = head;
        for i in 0.. {
            let (h, l) = len_of(&list[at..]);
            let total = if list[at] < 0x80 { 1 } else { h + l };
            if i == index {
                return list[at..at + total].to_vec();
            }
            at += total;
        }
        unreachable!()
    }

    /// Drive a ready future to completion; the test devices never await.
    fn futures_lite_block_on<F: std::future::Future>(f: F) -> F::Output {
        let waker = std::task::Waker::noop();
        let mut cx = std::task::Context::from_waker(waker);
        let mut f = std::pin::pin!(f);
        match f.as_mut().poll(&mut cx) {
            std::task::Poll::Ready(v) => v,
            std::task::Poll::Pending => panic!("test device future was not ready"),
        }
    }

    #[tokio::test]
    async fn an_eip1559_transaction_recovers_to_the_device_address() {
        let signer = test_signer(1).await;
        let raw_tx = signer
            .encode_eip1559_transaction(
                0,
                2_000_000_000,
                30_000_000_000,
                21_000,
                "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb0",
                &[],
            )
            .await
            .unwrap();
        assert_eq!(raw_tx[0], 0x02);
        assert!(raw_tx.len() > 100);
        assert_eq!(
            rlp_list_item(&raw_tx[1..], 6),
            vec![0x80],
            "a relayer transaction moves no native value"
        );

        // The signature over the unsigned payload recovers to the sender.
        let digest = [9u8; 32];
        let (sig, rec) = signer.sign_prehash(&digest).await.unwrap();
        let vk = VerifyingKey::recover_from_prehash(&digest, &sig, rec).unwrap();
        assert_eq!(vk, signer.verifying_key);
    }

    /// A JSON-RPC node on loopback. `answer(method, nth)` gives the result of
    /// the `nth` call (from 0) of `method`: `Ok(result)`, `Err(error)`, or
    /// `None` for a reply that is not JSON. Records every raw transaction.
    struct FakeNode {
        url: String,
        sent: Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
    }

    impl FakeNode {
        /// The nonce and recipient of every raw transaction sent.
        fn sent(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
            self.sent
                .lock()
                .unwrap()
                .iter()
                .map(|tx| (rlp_list_item(&tx[1..], 1), rlp_list_item(&tx[1..], 5)))
                .collect()
        }
    }

    type Answer = Option<std::result::Result<serde_json::Value, serde_json::Value>>;

    async fn fake_node(answer: impl Fn(&str, usize) -> Answer + Send + Sync + 'static) -> FakeNode {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        async fn read_request(
            sock: &mut tokio::net::TcpStream,
            buf: &mut Vec<u8>,
        ) -> Option<Vec<u8>> {
            loop {
                if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    let head = String::from_utf8_lossy(&buf[..end]).to_ascii_lowercase();
                    let len = head
                        .lines()
                        .find_map(|l| l.strip_prefix("content-length:"))
                        .map_or(0, |v| v.trim().parse::<usize>().unwrap());
                    if buf.len() >= end + 4 + len {
                        let body = buf[end + 4..end + 4 + len].to_vec();
                        *buf = buf.split_off(end + 4 + len);
                        return Some(body);
                    }
                }
                let mut chunk = [0u8; 4096];
                let n = sock.read(&mut chunk).await.ok()?;
                if n == 0 {
                    return None;
                }
                buf.extend_from_slice(&chunk[..n]);
            }
        }

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let sent = Arc::new(std::sync::Mutex::new(Vec::new()));
        let calls = Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
        let answer = Arc::new(answer);
        let log = sent.clone();
        tokio::spawn(async move {
            loop {
                let (mut sock, _) = listener.accept().await.unwrap();
                let (log, calls, answer) = (log.clone(), calls.clone(), answer.clone());
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    while let Some(body) = read_request(&mut sock, &mut buf).await {
                        let request: serde_json::Value = serde_json::from_slice(&body).unwrap();
                        let method = request["method"].as_str().unwrap().to_string();
                        if method == "eth_sendRawTransaction" {
                            let raw = request["params"][0].as_str().unwrap();
                            log.lock().unwrap().push(hex::decode(&raw[2..]).unwrap());
                        }
                        let nth = {
                            let mut calls = calls.lock().unwrap();
                            let n = calls.entry(method.clone()).or_insert(0usize);
                            *n += 1;
                            *n - 1
                        };
                        let reply = match answer(&method, nth) {
                            Some(Ok(result)) => {
                                json!({"jsonrpc": "2.0", "id": 1, "result": result}).to_string()
                            }
                            Some(Err(error)) => {
                                json!({"jsonrpc": "2.0", "id": 1, "error": error}).to_string()
                            }
                            None => "not json".to_string(),
                        };
                        let response = format!(
                            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{reply}",
                            reply.len()
                        );
                        if sock.write_all(response.as_bytes()).await.is_err() {
                            return;
                        }
                    }
                });
            }
        });
        FakeNode { url, sent }
    }

    /// The answers of a node that has everything but the transaction itself.
    fn chain(method: &str, nth: usize, pending: impl Fn(usize) -> u64) -> Answer {
        match method {
            "eth_estimateGas" => Some(Ok(json!("0x5208"))),
            "eth_getBlockByNumber" => Some(Ok(json!({"baseFeePerGas": "0x1"}))),
            "eth_getTransactionCount" => Some(Ok(json!(format!("{:#x}", pending(nth))))),
            _ => unreachable!("{method}"),
        }
    }

    async fn signer_on(node: &FakeNode) -> EvmTransactionSigner {
        EvmTransactionSigner::from_hardware(test_device(1), 1, node.url.clone())
            .await
            .expect("test device")
    }

    const TO: &str = "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb0";

    /// The node may hold a transaction whose reply never came: its nonce is
    /// not given to the next transaction, which could replace it in the pool.
    #[tokio::test]
    async fn a_send_whose_reply_is_lost_holds_its_nonce() {
        let node = fake_node(|method, nth| match method {
            "eth_sendRawTransaction" if nth == 0 => None,
            "eth_sendRawTransaction" => Some(Ok(json!("0xab"))),
            _ => chain(method, nth, |_| 7),
        })
        .await;
        let signer = signer_on(&node).await;
        assert!(signer.send_transaction(TO, &[1]).await.is_err());
        signer.send_transaction(TO, &[1]).await.unwrap();
        let nonces: Vec<_> = node.sent().into_iter().map(|(n, _)| n).collect();
        assert_eq!(nonces, vec![vec![7], vec![8]]);
    }

    /// Whether a refused nonce was used is the chain's to say, whatever the
    /// refusal's wording: here another holder of the key used 7 and 8.
    #[tokio::test]
    async fn a_refusal_is_judged_by_the_chain_nonce_not_its_wording() {
        let node = fake_node(|method, nth| match method {
            "eth_sendRawTransaction" if nth == 0 => {
                Some(Err(json!({"code": -32000, "message": "rejected"})))
            }
            "eth_sendRawTransaction" => Some(Ok(json!("0xab"))),
            _ => chain(method, nth, |n| if n == 0 { 7 } else { 9 }),
        })
        .await;
        let signer = signer_on(&node).await;
        assert!(signer.send_transaction(TO, &[1]).await.is_err());
        signer.send_transaction(TO, &[1]).await.unwrap();
        let nonces: Vec<_> = node.sent().into_iter().map(|(n, _)| n).collect();
        assert_eq!(nonces, vec![vec![7], vec![9]]);
    }

    /// A refusal while the chain still waits on the nonce frees it at once.
    #[tokio::test]
    async fn a_refused_nonce_the_chain_still_waits_on_is_used_by_the_next_send() {
        let node = fake_node(|method, nth| match method {
            "eth_sendRawTransaction" if nth == 0 => {
                Some(Err(json!({"code": -32000, "message": "rejected"})))
            }
            "eth_sendRawTransaction" => Some(Ok(json!("0xab"))),
            _ => chain(method, nth, |_| 7),
        })
        .await;
        let signer = signer_on(&node).await;
        assert!(signer.send_transaction(TO, &[1]).await.is_err());
        signer.send_transaction(TO, &[1]).await.unwrap();
        let nonces: Vec<_> = node.sent().into_iter().map(|(n, _)| n).collect();
        assert_eq!(nonces, vec![vec![7], vec![7]]);
    }

    /// A send that fails below one already in the pool leaves a gap the pool
    /// would wait on for good: it is filled with a transfer to the signer.
    #[tokio::test]
    async fn a_gap_below_a_sent_transaction_is_filled() {
        let node = fake_node(|method, nth| match method {
            "eth_sendRawTransaction" => Some(Ok(json!("0xab"))),
            _ => chain(method, nth, |_| 7),
        })
        .await;
        let signer = signer_on(&node).await;
        // Another send holds 7 while this one goes out under 8; then 7 fails.
        assert_eq!(signer.nonces.reserve(Some(7)), Some(7));
        signer.send_transaction(TO, &[1]).await.unwrap();
        signer.nonces.release(7);
        signer.fill_gaps(1, 3).await;
        let own = hex::decode(signer.sender_address().trim_start_matches("0x")).unwrap();
        let mut filler = vec![0x94];
        filler.extend(own);
        assert_eq!(
            node.sent(),
            vec![
                (vec![8], {
                    let mut to = vec![0x94];
                    to.extend(hex::decode(&TO[2..]).unwrap());
                    to
                }),
                (vec![7], filler),
            ]
        );
    }
}
