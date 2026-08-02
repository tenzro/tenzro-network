//! EVM transaction signing for bridge adapters
//!
//! Provides EIP-1559 (type 2) transaction signing and submission via JSON-RPC.
//! Used by LayerZero, Chainlink CCIP, and deBridge adapters to submit real
//! on-chain transactions.

use crate::error::{BridgeError, Result};
use crate::mpc::sign::ThresholdSigner;
use k256::ecdsa::{RecoveryId, Signature, SigningKey, signature::hazmat::PrehashSigner};
use reqwest::Client;
use serde_json::json;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tenzro_tee::SealedSecp256k1Key;
use tracing::{debug, info};

/// Backing key material for an [`EvmTransactionSigner`].
///
/// Three variants:
///
/// - [`SignerBackend::RawKey`] — secp256k1 private key sitting in process
///   memory. Used for development, local testing, and any deployment that
///   has not (or cannot) provision a TEE. Documented as **dev-only** for
///   production bridge custody.
/// - [`SignerBackend::SealedKey`] — secp256k1 key derived inside an AMD
///   SEV-SNP or Intel TDX enclave via [`SealedSecp256k1Key`]. The private
///   scalar lives in `Zeroizing<[u8; 32]>` inside the wrapper and is
///   reproducible only inside the same VM image (measurement-bound).
/// - [`SignerBackend::ThresholdKey`] — DKLS23 t-of-n distributed signer.
///   No single party holds the full private scalar; signatures are
///   produced by a quorum drawn from the MPC group via
///   `committee::build_committee_bound_sign_config` and driven through a
///   `SignSession` over libp2p. The handle is constructed by the node
///   layer (which owns the keyshare store, sealer, transport, and chain
///   entropy source) and passed in via [`Self::with_threshold_signer`].
///   This is the production posture for bridge custody once threshold
///   signing is fully wired.
///
/// All three variants expose the same `sign_prehash` interface and produce
/// the same 20-byte Ethereum address derivation (Keccak-256 of the
/// uncompressed secp256k1 public key tail), so the surrounding RLP /
/// nonce / gas logic is identical. The `ThresholdKey` variant is async
/// (libp2p round-trip); the other two are sync internally but exposed
/// through the same `async fn sign_prehash` for a uniform call site.
pub enum SignerBackend {
    /// In-memory secp256k1 key (dev / non-TEE deployments).
    RawKey(SigningKey),
    /// TEE-sealed secp256k1 key (single-key production custody).
    SealedKey(SealedSecp256k1Key),
    /// DKLS23 threshold signer handle (threshold-ECDSA production custody).
    ThresholdKey(Arc<dyn ThresholdSigner>),
}

impl SignerBackend {
    /// Signs a 32-byte digest, returning the ECDSA signature plus recovery
    /// id needed to construct the Ethereum `v`.
    ///
    /// `RawKey` and `SealedKey` are sync internally but awaited as
    /// completed futures so the call site is uniform across all three
    /// variants. `ThresholdKey` actually awaits a libp2p round-trip
    /// through the DKLS23 sign session.
    async fn sign_prehash(&self, digest: &[u8; 32]) -> Result<(Signature, RecoveryId)> {
        match self {
            SignerBackend::RawKey(sk) => sk
                .sign_prehash(digest)
                .map_err(|e| BridgeError::AdapterError(format!("Signing failed: {}", e))),
            SignerBackend::SealedKey(sealed) => sealed
                .sign_prehash(digest)
                .map_err(|e| BridgeError::AdapterError(format!("Sealed signing failed: {}", e))),
            SignerBackend::ThresholdKey(handle) => {
                let output = handle.sign_prehash(*digest).await.map_err(|e| {
                    BridgeError::AdapterError(format!("Threshold signing failed: {}", e))
                })?;
                // Reassemble the k256 `Signature` + `RecoveryId` from the
                // `(r, s, v)` triple so downstream RLP encoding is
                // identical to the single-key path.
                let mut rs = [0u8; 64];
                rs[..32].copy_from_slice(&output.r);
                rs[32..].copy_from_slice(&output.s);
                let signature = Signature::from_slice(&rs).map_err(|e| {
                    BridgeError::AdapterError(format!("Threshold signature decode failed: {}", e))
                })?;
                let recovery_id = RecoveryId::from_byte(output.v).ok_or_else(|| {
                    BridgeError::AdapterError(format!(
                        "Threshold signature carried invalid recovery id: {}",
                        output.v
                    ))
                })?;
                Ok((signature, recovery_id))
            }
        }
    }
}

/// EVM transaction signer for bridge operations
///
/// Signs EIP-1559 (type 2) transactions using secp256k1 and submits them
/// via `eth_sendRawTransaction`. Handles nonce management and gas estimation.
///
/// The underlying key may be a raw in-memory `SigningKey` (dev) or a
/// TEE-sealed key derived inside SEV-SNP / TDX (production). See
/// [`SignerBackend`].
pub struct EvmTransactionSigner {
    /// Backing key material — raw or TEE-sealed.
    backend: SignerBackend,
    /// Sender address (derived from the backend's public key)
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
    /// Creates a new EVM transaction signer from a raw 32-byte private key.
    ///
    /// **Dev / non-TEE only.** For production bridge custody, use
    /// [`Self::with_sealed_key`] or [`Self::with_tee_sealed`] so the
    /// private scalar is bound to a TEE measurement and not retained in
    /// plain process memory.
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
        let public_key_bytes = verifying_key.to_sec1_point(false);
        let public_key_uncompressed = &public_key_bytes.as_bytes()[1..]; // skip 0x04 prefix

        let address_hash = keccak256(public_key_uncompressed);
        let mut sender_address = [0u8; 20];
        sender_address.copy_from_slice(&address_hash[12..]);

        Ok(Self::with_backend(
            SignerBackend::RawKey(signing_key),
            sender_address,
            chain_id,
            rpc_url,
        ))
    }

    /// Creates a new EVM transaction signer wrapping a TEE-sealed key.
    ///
    /// The sealed key was derived inside the enclave via
    /// [`SealedSecp256k1Key::derive_auto`], which roots in the SEV-SNP
    /// PSP-derived key or the TDX MRTD. The 20-byte sender address is
    /// taken directly from the sealed key's public-side metadata; no
    /// secret material crosses this API.
    pub fn with_sealed_key(sealed: SealedSecp256k1Key, chain_id: u64, rpc_url: String) -> Self {
        let sender_address = sealed.address();
        Self::with_backend(
            SignerBackend::SealedKey(sealed),
            sender_address,
            chain_id,
            rpc_url,
        )
    }

    /// Convenience: auto-detect the available TEE (SEV-SNP preferred,
    /// then TDX), derive a sealed bridge signer key, and return a ready
    /// signer.
    ///
    /// Returns `BridgeError::ConfigurationError` if no TEE is available
    /// — there is **no simulation fallback** per testnet policy.
    pub async fn with_tee_sealed(label: &[u8], chain_id: u64, rpc_url: String) -> Result<Self> {
        let sealed = SealedSecp256k1Key::derive_auto(label).await.map_err(|e| {
            BridgeError::ConfigurationError(format!(
                "TEE-sealed bridge key derivation failed: {}",
                e
            ))
        })?;
        Ok(Self::with_sealed_key(sealed, chain_id, rpc_url))
    }

    /// Internal constructor — assembles the rest of the signer state once
    /// the backend and sender address are known.
    fn with_backend(
        backend: SignerBackend,
        sender_address: [u8; 20],
        chain_id: u64,
        rpc_url: String,
    ) -> Self {
        let http_client = Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .unwrap_or_else(|_| Client::new());

        Self {
            backend,
            sender_address,
            chain_id,
            rpc_url,
            http_client,
            nonce: AtomicU64::new(0),
            nonce_synced: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Creates a new EVM transaction signer wrapping a DKLS23 threshold
    /// signing handle.
    ///
    /// The handle is constructed by the node layer (which owns the
    /// `Arc<dyn KeyshareStore>`, `Arc<dyn KeyshareSealer>`, libp2p
    /// transport factory, and finalized-block-hash source used as
    /// `chain_entropy`). The 20-byte sender address comes directly from
    /// the handle's group public key — no secret material crosses this
    /// API.
    ///
    /// This is the production posture for threshold bridge custody:
    /// no single party holds the full private scalar; signatures are
    /// produced by a quorum drawn from the MPC group.
    pub fn with_threshold_signer(
        signer: Arc<dyn ThresholdSigner>,
        chain_id: u64,
        rpc_url: String,
    ) -> Self {
        let sender_address = signer.sender_address();
        Self::with_backend(
            SignerBackend::ThresholdKey(signer),
            sender_address,
            chain_id,
            rpc_url,
        )
    }

    /// Returns whether the underlying key is TEE-sealed (single-key
    /// production posture) or a raw in-memory key (dev posture).
    pub fn is_tee_sealed(&self) -> bool {
        matches!(self.backend, SignerBackend::SealedKey(_))
    }

    /// Returns whether the underlying key is a DKLS23 threshold signer
    /// (threshold production posture — no single party holds the
    /// full private scalar).
    pub fn is_threshold(&self) -> bool {
        matches!(self.backend, SignerBackend::ThresholdKey(_))
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

        let nonce_hex = json.get("result").and_then(|r| r.as_str()).unwrap_or("0x0");

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
    pub async fn send_transaction(&self, to: &str, calldata: &[u8], value: u128) -> Result<String> {
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
        let raw_tx = self
            .encode_eip1559_transaction(
                nonce,
                max_priority_fee,
                max_fee_per_gas,
                gas_limit,
                to,
                value,
                calldata,
            )
            .await?;

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
    ///
    /// `async` because the underlying `sign_prehash` may be a DKLS23
    /// distributed signing session (`SignerBackend::ThresholdKey`) that
    /// drives a libp2p round-trip. Raw and TEE-sealed backends complete
    /// synchronously inside the future.
    async fn encode_eip1559_transaction(
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

        // Sign the hash with secp256k1 (raw / TEE-sealed / threshold backend)
        let (signature, recovery_id) = self.backend.sign_prehash(&msg_hash).await?;

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
        let key_bytes = hex::decode(&self.private_key_hex).map_err(|e| {
            BridgeError::ConfigurationError(format!("Invalid private key hex: {}", e))
        })?;

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
        let expected =
            hex::decode("1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8")
                .unwrap();
        assert_eq!(&hash[..], &expected[..]);
    }

    #[test]
    fn test_evm_signer_creation() {
        // Use a known test private key (DO NOT use in production)
        let private_key = [0x01u8; 32];
        let signer =
            EvmTransactionSigner::new(&private_key, 1, "http://localhost:8545".to_string())
                .unwrap();

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

    #[tokio::test]
    async fn test_with_tee_sealed_off_hardware_returns_error() {
        // On dev hardware (no /dev/sev-guest, no /dev/tdx_guest), the
        // TEE-sealed constructor must fail loudly rather than fall back
        // to a fabricated key. This is the no-simulation policy.
        let result = EvmTransactionSigner::with_tee_sealed(
            b"tenzro/bridge/evm-signer",
            1,
            "http://localhost:8545".to_string(),
        )
        .await;
        assert!(
            result.is_err(),
            "must error off-hardware, not silently fall back"
        );
        let err = result.err().unwrap();
        let msg = err.to_string();
        assert!(
            msg.contains("TEE-sealed bridge key derivation failed"),
            "unexpected error message: {}",
            msg
        );
    }

    #[test]
    fn test_raw_key_signer_is_not_tee_sealed() {
        // RawKey path should report itself as non-TEE for posture telemetry.
        let private_key = [0x01u8; 32];
        let signer =
            EvmTransactionSigner::new(&private_key, 1, "http://localhost:8545".to_string())
                .unwrap();
        assert!(
            !signer.is_tee_sealed(),
            "RawKey backend must not report TEE-sealed"
        );
    }

    #[tokio::test]
    async fn test_eip1559_transaction_encoding() {
        let private_key = [0x01u8; 32];
        let signer =
            EvmTransactionSigner::new(&private_key, 1, "http://localhost:8545".to_string())
                .unwrap();

        let result = signer
            .encode_eip1559_transaction(
                0,              // nonce
                2_000_000_000,  // max priority fee (2 gwei)
                30_000_000_000, // max fee per gas (30 gwei)
                21_000,         // gas limit
                "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb0",
                0,   // value
                &[], // empty data
            )
            .await;

        assert!(result.is_ok());
        let raw_tx = result.unwrap();
        // EIP-1559 tx starts with 0x02
        assert_eq!(raw_tx[0], 0x02);
        // Should be a valid RLP-encoded transaction
        assert!(raw_tx.len() > 100);
    }

    /// Stub [`ThresholdSigner`] used to verify the [`SignerBackend::ThresholdKey`]
    /// wiring without standing up a full DKLS23 session. Returns a fixed
    /// dummy signature shaped like a valid k256 output so the surrounding
    /// RLP encode + signature-decode round-trip can be exercised in
    /// full.
    struct StubThresholdSigner {
        address: [u8; 20],
    }

    #[async_trait::async_trait]
    impl ThresholdSigner for StubThresholdSigner {
        fn sender_address(&self) -> [u8; 20] {
            self.address
        }

        async fn sign_prehash(
            &self,
            _msg_hash: [u8; 32],
        ) -> std::result::Result<crate::mpc::sign::SignOutput, crate::mpc::sign::SignError>
        {
            // Construct a (r, s, v) triple that round-trips through
            // `Signature::from_slice`. The actual scalar values are not
            // cryptographically meaningful — this exercises only the
            // backend's signature decode path.
            //
            // r and s must each fit in [1, n) where n is the secp256k1
            // group order. Using small constants well below n is safe.
            let mut r = [0u8; 32];
            let mut s = [0u8; 32];
            r[31] = 0x01;
            s[31] = 0x01;
            Ok(crate::mpc::sign::SignOutput { r, s, v: 0 })
        }
    }

    #[test]
    fn test_threshold_backend_is_threshold() {
        let stub = Arc::new(StubThresholdSigner {
            address: [0x11; 20],
        });
        let signer = EvmTransactionSigner::with_threshold_signer(
            stub,
            1,
            "http://localhost:8545".to_string(),
        );
        assert!(
            signer.is_threshold(),
            "ThresholdKey backend must report is_threshold()"
        );
        assert!(
            !signer.is_tee_sealed(),
            "ThresholdKey backend must NOT report is_tee_sealed()"
        );
        assert_eq!(signer.sender_address_bytes(), &[0x11; 20]);
    }

    /// Stub that returns an out-of-range recovery id so the decode-path
    /// failure handling can be exercised. `RecoveryId::from_byte` accepts
    /// `0..=3`; values ≥ 4 must surface as an `AdapterError`.
    struct BadRecoveryIdStub;
    #[async_trait::async_trait]
    impl ThresholdSigner for BadRecoveryIdStub {
        fn sender_address(&self) -> [u8; 20] {
            [0x33; 20]
        }
        async fn sign_prehash(
            &self,
            _msg_hash: [u8; 32],
        ) -> std::result::Result<crate::mpc::sign::SignOutput, crate::mpc::sign::SignError>
        {
            let mut r = [0u8; 32];
            let mut s = [0u8; 32];
            r[31] = 0x01;
            s[31] = 0x01;
            Ok(crate::mpc::sign::SignOutput { r, s, v: 99 })
        }
    }

    /// Stub that returns a malformed (all-zero) signature blob. k256's
    /// `Signature::from_slice` rejects zero scalars, surfacing as an
    /// `AdapterError`.
    struct ZeroSignatureStub;
    #[async_trait::async_trait]
    impl ThresholdSigner for ZeroSignatureStub {
        fn sender_address(&self) -> [u8; 20] {
            [0x44; 20]
        }
        async fn sign_prehash(
            &self,
            _msg_hash: [u8; 32],
        ) -> std::result::Result<crate::mpc::sign::SignOutput, crate::mpc::sign::SignError>
        {
            Ok(crate::mpc::sign::SignOutput {
                r: [0u8; 32],
                s: [0u8; 32],
                v: 0,
            })
        }
    }

    #[tokio::test]
    async fn test_threshold_backend_rejects_invalid_recovery_id() {
        let stub = Arc::new(BadRecoveryIdStub);
        let signer = EvmTransactionSigner::with_threshold_signer(
            stub,
            1,
            "http://localhost:8545".to_string(),
        );
        let result = signer
            .encode_eip1559_transaction(
                0,
                2_000_000_000,
                30_000_000_000,
                21_000,
                "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb0",
                0,
                &[],
            )
            .await;
        assert!(result.is_err(), "out-of-range recovery id must fail");
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("invalid recovery id"),
            "expected recovery-id error, got: {}",
            msg
        );
    }

    #[tokio::test]
    async fn test_threshold_backend_rejects_zero_signature() {
        let stub = Arc::new(ZeroSignatureStub);
        let signer = EvmTransactionSigner::with_threshold_signer(
            stub,
            1,
            "http://localhost:8545".to_string(),
        );
        let result = signer
            .encode_eip1559_transaction(
                0,
                2_000_000_000,
                30_000_000_000,
                21_000,
                "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb0",
                0,
                &[],
            )
            .await;
        assert!(result.is_err(), "all-zero signature must fail decode");
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("signature decode failed"),
            "expected decode error, got: {}",
            msg
        );
    }

    #[tokio::test]
    async fn test_threshold_backend_signs_eip1559_transaction() {
        let stub = Arc::new(StubThresholdSigner {
            address: [0x22; 20],
        });
        let signer = EvmTransactionSigner::with_threshold_signer(
            stub,
            1,
            "http://localhost:8545".to_string(),
        );

        let result = signer
            .encode_eip1559_transaction(
                0,
                2_000_000_000,
                30_000_000_000,
                21_000,
                "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb0",
                0,
                &[],
            )
            .await;

        assert!(
            result.is_ok(),
            "threshold-signed encode must succeed: {:?}",
            result.err()
        );
        let raw_tx = result.unwrap();
        assert_eq!(raw_tx[0], 0x02);
        assert!(raw_tx.len() > 100);
    }
}
