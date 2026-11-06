//! Real Tenzro JSON-RPC adapter for [`ChainStateProvider`].
//!
//! This module replaces the previous `LocalStateProvider`-only chain wiring
//! with a `reqwest`-backed adapter that talks to a live Tenzro node over
//! JSON-RPC. The wallet kernel uses it for all on-chain reads (balance,
//! nonce, tx-status, block height) and for transaction submission.
//!
//! # Endpoints used
//!
//! | RPC method                   | Purpose                              |
//! |------------------------------|--------------------------------------|
//! | `eth_getBalance`             | TNZO native balance                  |
//! | `tenzro_tokenBalance`        | Non-native asset balance (registry)  |
//! | `eth_getTransactionCount`    | Sender nonce (pending block tag)     |
//! | `eth_getTransactionReceipt`  | Tx status (Pending/Confirmed/Failed) |
//! | `eth_blockNumber`            | Current block height                 |
//! | `tenzro_sendRawTransaction`     | Submit a signed transaction          |

use crate::error::{Result, WalletError};
use crate::history::TxStatus;
use crate::state_sync::ChainStateProvider;
use async_trait::async_trait;
use reqwest::Client;
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tenzro_types::primitives::{Address, Hash};
use tenzro_types::{AssetId, Transaction};

/// JSON-RPC adapter that resolves chain state via a Tenzro node.
///
/// Cheap to clone — internally `Arc`s the underlying `reqwest::Client` and
/// shares a per-instance request-id counter.
pub struct TenzroRpcChainProvider {
    client: Client,
    rpc_url: String,
    request_id: AtomicU64,
}

impl TenzroRpcChainProvider {
    /// Construct a provider pointing at the given JSON-RPC endpoint.
    ///
    /// `rpc_url` should include the scheme and (if non-default) port, e.g.
    /// `https://rpc.tenzro.com` or `http://127.0.0.1:8545`.
    pub fn new(rpc_url: impl Into<String>) -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .pool_idle_timeout(Duration::from_secs(60))
            .build()
            .map_err(|e| WalletError::Other(format!("HTTP client init: {}", e)))?;
        Ok(Self {
            client,
            rpc_url: rpc_url.into(),
            request_id: AtomicU64::new(1),
        })
    }

    /// Construct from a pre-configured `reqwest::Client` (e.g. with custom
    /// TLS roots, proxy, or auth headers).
    pub fn with_client(client: Client, rpc_url: impl Into<String>) -> Self {
        Self {
            client,
            rpc_url: rpc_url.into(),
            request_id: AtomicU64::new(1),
        }
    }

    /// Issue a JSON-RPC call and return the `result` field as a generic
    /// `serde_json::Value`. Caller is responsible for shape-checking.
    async fn call(&self, method: &str, params: Value) -> Result<Value> {
        let id = self.request_id.fetch_add(1, Ordering::Relaxed);
        let body = json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": id,
        });

        let resp = self
            .client
            .post(&self.rpc_url)
            .json(&body)
            .send()
            .await
            .map_err(|e| WalletError::Other(format!("RPC {} send: {}", method, e)))?;

        if !resp.status().is_success() {
            return Err(WalletError::Other(format!(
                "RPC {} HTTP {}",
                method,
                resp.status()
            )));
        }

        let envelope: JsonRpcEnvelope = resp
            .json()
            .await
            .map_err(|e| WalletError::Other(format!("RPC {} decode: {}", method, e)))?;

        if let Some(err) = envelope.error {
            return Err(WalletError::Other(format!(
                "RPC {} error {}: {}",
                method, err.code, err.message
            )));
        }

        envelope
            .result
            .ok_or_else(|| WalletError::Other(format!("RPC {}: missing result", method)))
    }

    /// Format a Tenzro `Address` as the canonical 0x-prefixed hex string used
    /// by the RPC API. Tenzro addresses are 32 bytes; the RPC accepts the
    /// full 32-byte hex form.
    fn addr_hex(addr: &Address) -> String {
        format!("0x{}", hex::encode(addr.as_bytes()))
    }

    /// Parse a 0x-prefixed quantity (e.g. `"0x2a"` → `42`). Tolerates
    /// missing prefix for resilience.
    fn parse_hex_quantity(value: &Value) -> Result<u128> {
        let s = value
            .as_str()
            .ok_or_else(|| WalletError::Other("expected hex string quantity".into()))?;
        let trimmed = s.strip_prefix("0x").unwrap_or(s);
        if trimmed.is_empty() {
            return Ok(0);
        }
        u128::from_str_radix(trimmed, 16)
            .map_err(|e| WalletError::Other(format!("invalid hex quantity {}: {}", s, e)))
    }

    fn parse_hex_u64(value: &Value) -> Result<u64> {
        Self::parse_hex_quantity(value).and_then(|q| {
            u64::try_from(q)
                .map_err(|_| WalletError::Other(format!("hex quantity overflows u64: {}", q)))
        })
    }
}

#[derive(Debug, Deserialize)]
struct JsonRpcEnvelope {
    #[serde(default)]
    result: Option<Value>,
    #[serde(default)]
    error: Option<JsonRpcErrorBody>,
}

#[derive(Debug, Deserialize)]
struct JsonRpcErrorBody {
    code: i64,
    message: String,
}

#[async_trait]
impl ChainStateProvider for TenzroRpcChainProvider {
    async fn get_on_chain_balance(&self, address: &Address, asset_id: &AssetId) -> Result<u128> {
        let addr_hex = Self::addr_hex(address);
        if asset_id.as_str() == "TNZO" {
            // Native TNZO via eth_getBalance.
            let result = self
                .call("eth_getBalance", json!([addr_hex, "latest"]))
                .await?;
            Self::parse_hex_quantity(&result)
        } else {
            // Non-native asset via tenzro_tokenBalance.
            let result = self
                .call(
                    "tenzro_tokenBalance",
                    json!({
                        "address": addr_hex,
                        "symbol": asset_id.as_str(),
                    }),
                )
                .await?;
            // Result may be {"balance": "0x..."} or a bare hex string.
            if let Some(obj) = result.as_object()
                && let Some(bal) = obj.get("balance")
            {
                return Self::parse_hex_quantity(bal);
            }
            Self::parse_hex_quantity(&result)
        }
    }

    async fn get_on_chain_balances(&self, address: &Address) -> Result<Vec<(AssetId, u128)>> {
        // Best-effort: fetch native TNZO; non-native enumeration would
        // require a paginated `tenzro_listTokens` walk per address. That's
        // out of scope for the kernel — callers that need a multi-asset
        // view supply the explicit asset list to `sync_balances`.
        let tnzo = AssetId::tnzo();
        let bal = self.get_on_chain_balance(address, &tnzo).await?;
        Ok(vec![(tnzo, bal)])
    }

    async fn get_on_chain_nonce(&self, address: &Address) -> Result<u64> {
        let addr_hex = Self::addr_hex(address);
        // "pending" tag includes mempool — matches what local nonce manager
        // tracks, so the wallet does not double-spend pending nonces.
        let result = self
            .call("eth_getTransactionCount", json!([addr_hex, "pending"]))
            .await?;
        Self::parse_hex_u64(&result)
    }

    async fn get_transaction_status(&self, tx_hash: &Hash) -> Result<TxStatus> {
        let hash_hex = format!("0x{}", hex::encode(tx_hash.as_bytes()));
        let result = self
            .call("eth_getTransactionReceipt", json!([hash_hex]))
            .await?;

        // null receipt → still pending (or unknown).
        if result.is_null() {
            return Ok(TxStatus::Pending);
        }

        // Receipt present: read status field. "0x1" = Confirmed, "0x0" = Failed.
        let status = result
            .get("status")
            .and_then(|s| s.as_str())
            .unwrap_or("0x0");
        if status == "0x1" || status == "0x01" {
            Ok(TxStatus::Confirmed)
        } else {
            Ok(TxStatus::Failed)
        }
    }

    async fn get_block_height(&self) -> Result<u64> {
        let result = self.call("eth_blockNumber", json!([])).await?;
        Self::parse_hex_u64(&result)
    }

    async fn submit_signed_transaction(
        &self,
        tx: &Transaction,
        public_key: &[u8],
        signature: &tenzro_crypto::CompositeSignature,
    ) -> Result<Hash> {
        // Wire format matches `handle_signed_submission` in
        // crates/tenzro-node/src/rpc.rs — a JSON object (NOT a raw RLP
        // hex blob). The node parses these fields, rebuilds the canonical
        // `Transaction`, and verifies the composite signature
        // against `Transaction::hash()`.
        // Field naming follows the parser's accepted aliases (snake_case).
        //
        // `value` is encoded as a decimal string for u128 fidelity — the
        // node's parser tries `as_u64` then falls back to `parse::<u128>`
        // on the string form. Hex would be parsed as u64 only.
        let from_hex = Self::addr_hex(&tx.from);
        let to_hex = Self::addr_hex(&tx.to);
        let amount_dec = match &tx.tx_type {
            tenzro_types::TransactionType::Transfer { amount } => amount.to_string(),
            // For non-transfer types the parser still requires a `value`
            // field but it's read as 0 unless overridden by tx_type. Pass
            // "0" to keep the wire shape uniform.
            _ => "0".to_string(),
        };

        let params = json!({
            "from": from_hex,
            "to": to_hex,
            "value": amount_dec,
            "nonce": tx.nonce.0,
            "gas_limit": tx.gas_limit,
            "gas_price": tx.gas_price,
            "chain_id": tx.chain_id.0,
            "timestamp": tx.timestamp.0,
            "tx_type": tx.tx_type,
            "public_key": format!("0x{}", hex::encode(public_key)),
            "signature": signature,
        });

        let result = self.call("tenzro_sendRawTransaction", params).await?;
        let hash_str = result.as_str().ok_or_else(|| {
            WalletError::Other("tenzro_sendRawTransaction: expected hash string".into())
        })?;
        let trimmed = hash_str.strip_prefix("0x").unwrap_or(hash_str);
        let bytes = hex::decode(trimmed)
            .map_err(|e| WalletError::Other(format!("invalid tx hash hex: {}", e)))?;
        if bytes.len() != 32 {
            return Err(WalletError::Other(format!(
                "tx hash wrong length: got {}, want 32",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Hash::new(arr))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_hex_quantity_zero_and_value() {
        assert_eq!(
            TenzroRpcChainProvider::parse_hex_quantity(&Value::String("0x0".into())).unwrap(),
            0
        );
        assert_eq!(
            TenzroRpcChainProvider::parse_hex_quantity(&Value::String("0x2a".into())).unwrap(),
            42
        );
        assert_eq!(
            TenzroRpcChainProvider::parse_hex_quantity(&Value::String("0x".into())).unwrap(),
            0
        );
    }
}
