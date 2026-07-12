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
//! | `eth_sendRawTransaction`     | Submit a signed transaction          |
//!
//! # ABI calldata for cross-VM transfer (EVM 0x1003)
//!
//! [`cross_vm_transfer_calldata`] builds the ABI-encoded calldata for the
//! `cross_vm_bridge` precompile at EVM address `0x1003`. The selector is
//! `0x3eaaf86b` (`CROSS_VM_TRANSFER`) and the layout matches the precompile's
//! expected format. This lets the wallet construct cross-VM transfer
//! transactions without depending on the VM crate.

use crate::error::{Result, WalletError};
use crate::history::TxStatus;
use crate::state_sync::ChainStateProvider;
use async_trait::async_trait;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tenzro_types::primitives::{Address, Hash, Signature};
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
    /// `https://rpc.tenzro.xyz` or `http://127.0.0.1:8545`.
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
    async fn get_on_chain_balance(
        &self,
        address: &Address,
        asset_id: &AssetId,
    ) -> Result<u128> {
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

    async fn get_on_chain_balances(
        &self,
        address: &Address,
    ) -> Result<Vec<(AssetId, u128)>> {
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
        classical_sig: &Signature,
        pq_sig: &[u8],
    ) -> Result<Hash> {
        // Wire format matches `handle_send_raw_transaction` in
        // crates/tenzro-node/src/rpc.rs — a JSON object (NOT a raw RLP
        // hex blob). The node parses these fields, rebuilds the canonical
        // `Transaction`, and synchronously verifies BOTH the classical
        // Ed25519 leg AND the ML-DSA-65 leg against `Transaction::hash()`.
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
            "signature": format!("0x{}", hex::encode(&classical_sig.bytes)),
            "public_key": format!("0x{}", hex::encode(&classical_sig.public_key)),
            "pq_signature": format!("0x{}", hex::encode(pq_sig)),
            "pq_public_key": format!("0x{}", hex::encode(&tx.pq_public_key)),
        });

        let result = self
            .call("eth_sendRawTransaction", params)
            .await?;
        let hash_str = result
            .as_str()
            .ok_or_else(|| WalletError::Other("eth_sendRawTransaction: expected hash string".into()))?;
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

// ---------------------------------------------------------------------------
// ABI calldata builders for the EVM cross_vm_bridge precompile (0x1003).
// ---------------------------------------------------------------------------

/// EVM `cross_vm_bridge` precompile address.
pub const CROSS_VM_BRIDGE_ADDRESS: [u8; 20] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10, 0x03,
];

/// Selector for `crossVmTransfer(bytes32 tokenId, uint256 amount, uint8 destVm, bytes destAddress)`
/// dispatched to the EVM `cross_vm_bridge` precompile at `0x1003`.
///
/// Pinned to the value the precompile dispatcher matches against
/// (`tenzro_vm::cross_vm_bridge::selectors::CROSS_VM_TRANSFER`); wallet code
/// stays independent of the VM crate by hard-coding the same 4 bytes here.
/// **Both ends of the wire MUST agree on these bytes** — if the precompile's
/// selector ever changes, this constant changes in the same flag-day cutover.
pub const CROSS_VM_TRANSFER_SELECTOR: [u8; 4] = [0x3e, 0xaa, 0xf8, 0x6b];

/// Selector for `GET_VM_BALANCE(uint8 vmType, bytes32 address, bytes32 tokenId)`.
pub const GET_VM_BALANCE_SELECTOR: [u8; 4] = [0xa3, 0xc5, 0x73, 0xeb];

/// Selector for `GET_SUPPORTED_VMS()`.
pub const GET_SUPPORTED_VMS_SELECTOR: [u8; 4] = [0x12, 0x06, 0x5f, 0xe0];

/// Destination VM type — opaque to the wallet, mirrors the VM crate enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum DestVm {
    Native = 0,
    Evm = 1,
    Svm = 2,
    Daml = 3,
}

/// Build the ABI-encoded calldata for `crossVmTransfer` against the
/// `cross_vm_bridge` precompile at EVM address `0x1003`.
///
/// # Arguments
///
/// - `token_id`     — 32-byte unified-token-registry ID (use `[0u8; 32]` for native TNZO)
/// - `amount`       — transfer amount in token native units (256-bit, big-endian)
/// - `dest_vm`      — destination VM identifier (Native | Evm | Svm | Daml)
/// - `caller`       — sender's EVM 20-byte address. The precompile reads this
///   from the calldata and uses it as the source of the cross-VM transfer.
/// - `dest_address` — destination address payload, length-prefixed in the
///   dynamic-bytes section. EVM 20-byte targets pass 20 raw bytes; SVM/DAML
///   pass their native address bytes. The precompile reads this verbatim — the
///   caller is responsible for picking the right encoding for the target VM.
///
/// # ABI layout (5-slot head, mixed static + 1 dynamic-bytes arg)
///
/// The Tenzro `cross_vm_bridge` precompile is invoked directly with the
/// post-selector calldata — no caller injection happens at the dispatch
/// boundary. So the **wallet itself** must populate the caller slot at
/// position [128..160]. The dynamic-bytes offset is `0xa0` (= 160 bytes from
/// args start), placing the length prefix immediately after the caller slot.
///
/// ```text
/// selector(4)         = 0x3eaaf86b
/// [0..32]    tokenId         (bytes32)
/// [32..64]   amount          (uint256, 32-byte big-endian)
/// [64..96]   destVm          (uint8 right-aligned in a 32-byte slot)
/// [96..128]  offset = 0xa0   (uint256 — pointer to dynamic-bytes section)
/// [128..160] caller          (sender EVM address, right-aligned in a 32-byte slot)
/// [160..192] length          (uint256, big-endian length of destAddress in bytes)
/// [192..]    destAddress     (raw bytes, right-padded to a 32-byte multiple)
/// ----
/// total = 4 (selector) + 5*32 (head + caller) + 32 (length) + ceil(len/32)*32 (data)
/// ```
///
/// # Caller positioning
///
/// The precompile's decode logic reads:
///   - `caller_20 = decode_address_at(calldata, 128)` — slot 4, low 20 bytes
///   - `dest_address = decode_dynamic_bytes(calldata, 96)` — offset at slot 3
///
/// The 5-slot head + caller-at-[128..160] layout matches that decode exactly,
/// without requiring the EVM runtime to inject a caller slot.
pub fn cross_vm_transfer_calldata(
    token_id: [u8; 32],
    amount: [u8; 32],
    dest_vm: DestVm,
    caller: [u8; 20],
    dest_address: &[u8],
) -> Vec<u8> {
    let len = dest_address.len();
    // Pad the dynamic-bytes payload up to a 32-byte multiple.
    let padded_len = len.div_ceil(32) * 32;

    let mut calldata = Vec::with_capacity(4 + 5 * 32 + 32 + padded_len);
    calldata.extend_from_slice(&CROSS_VM_TRANSFER_SELECTOR);

    // Slot 0: tokenId (bytes32).
    calldata.extend_from_slice(&token_id);

    // Slot 1: amount (uint256, big-endian).
    calldata.extend_from_slice(&amount);

    // Slot 2: destVm (uint8 right-aligned in 32 bytes).
    let mut dest_vm_padded = [0u8; 32];
    dest_vm_padded[31] = dest_vm as u8;
    calldata.extend_from_slice(&dest_vm_padded);

    // Slot 3: offset to dynamic-bytes section = 0xa0 (= 160 bytes from start
    // of args). Skips past the caller slot that follows.
    let mut offset_padded = [0u8; 32];
    offset_padded[31] = 0xa0;
    calldata.extend_from_slice(&offset_padded);

    // Slot 4: caller (sender's EVM address, right-aligned in 32 bytes).
    let mut caller_padded = [0u8; 32];
    caller_padded[12..].copy_from_slice(&caller);
    calldata.extend_from_slice(&caller_padded);

    // Dynamic-bytes header: length (uint256, big-endian).
    let mut length_padded = [0u8; 32];
    length_padded[24..].copy_from_slice(&(len as u64).to_be_bytes());
    calldata.extend_from_slice(&length_padded);

    // Dynamic-bytes payload, right-padded with zeros to a 32-byte multiple.
    calldata.extend_from_slice(dest_address);
    if padded_len > len {
        calldata.extend(std::iter::repeat_n(0u8, padded_len - len));
    }

    calldata
}

/// Build calldata for `GET_VM_BALANCE(uint8 vmType, bytes32 address, bytes32 tokenId)`.
pub fn get_vm_balance_calldata(
    vm_type: DestVm,
    address: [u8; 32],
    token_id: [u8; 32],
) -> Vec<u8> {
    let mut calldata = Vec::with_capacity(4 + 3 * 32);
    calldata.extend_from_slice(&GET_VM_BALANCE_SELECTOR);

    let mut vm_padded = [0u8; 32];
    vm_padded[31] = vm_type as u8;
    calldata.extend_from_slice(&vm_padded);

    calldata.extend_from_slice(&address);
    calldata.extend_from_slice(&token_id);
    calldata
}

/// Build calldata for `GET_SUPPORTED_VMS()`.
pub fn get_supported_vms_calldata() -> Vec<u8> {
    GET_SUPPORTED_VMS_SELECTOR.to_vec()
}

/// Helper: convert a `u128` amount into the 32-byte big-endian ABI form.
pub fn u128_to_abi_amount(amount: u128) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[16..].copy_from_slice(&amount.to_be_bytes());
    out
}

/// Helper: ABI-pad an EVM 20-byte address into a 32-byte right-aligned slot
/// (12 leading zero bytes, then the 20-byte address).
pub fn pad_evm_address(addr: [u8; 20]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[12..].copy_from_slice(&addr);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verifies that `cross_vm_transfer_calldata` emits the exact byte layout
    /// the EVM precompile at `0x1003` decodes for
    /// `crossVmTransfer(bytes32 tokenId, uint256 amount, uint8 destVm, bytes destAddress)`,
    /// with the wallet itself populating the caller slot at [128..160].
    #[test]
    fn cross_vm_transfer_calldata_layout() {
        let token_id = [0xaau8; 32];
        let amount = u128_to_abi_amount(1_000_000_000_000_000_000u128); // 1 TNZO
        let caller: [u8; 20] = [0x77; 20];
        // 20-byte EVM destination — bytes-section length must be exactly 20.
        let dest_address: [u8; 20] = [0x42; 20];
        let calldata =
            cross_vm_transfer_calldata(token_id, amount, DestVm::Evm, caller, &dest_address);

        // Selector + 5 head slots (160) + length slot (32) + 32 bytes of
        // padded dynamic data = 4 + 160 + 32 + 32 = 228.
        assert_eq!(calldata.len(), 4 + 160 + 32 + 32);
        // Selector intact.
        assert_eq!(&calldata[0..4], &CROSS_VM_TRANSFER_SELECTOR);

        let args = &calldata[4..];

        // Slot 0: tokenId.
        assert_eq!(&args[0..32], &token_id);
        // Slot 1: amount.
        assert_eq!(&args[32..64], &amount);
        // Slot 2: destVm — 31 zero bytes then 0x01 (Evm).
        assert!(args[64..95].iter().all(|&b| b == 0));
        assert_eq!(args[95], 0x01);
        // Slot 3: dynamic-bytes offset = 0xa0 (160), pointing past the
        // caller slot at [128..160] to the length slot at [160..192].
        assert!(args[96..126].iter().all(|&b| b == 0));
        assert_eq!(args[126], 0x00);
        assert_eq!(args[127], 0xa0);
        // Slot 4 ([128..160]): caller, right-aligned 20 bytes.
        assert!(args[128..140].iter().all(|&b| b == 0));
        assert_eq!(&args[140..160], &caller);
        // Length slot at [160..192]: big-endian 20.
        assert!(args[160..184].iter().all(|&b| b == 0));
        assert_eq!(&args[184..192], &20u64.to_be_bytes());
        // Dynamic data: 20 bytes of payload + 12 bytes of right-pad.
        assert_eq!(&args[192..212], &dest_address);
        assert!(args[212..224].iter().all(|&b| b == 0));
    }

    /// Cross-check that the wallet's calldata layout matches what the EVM
    /// `cross_vm_bridge` precompile decodes. We can't import the precompile
    /// (would create a circular wallet→vm dependency), so we replicate the
    /// exact decode positions the precompile uses against the post-selector
    /// calldata. A future selector or layout change on either side breaks
    /// this test.
    ///
    /// Decode positions (from `cross_vm_bridge::handle_cross_vm_transfer`):
    ///   tokenId        = calldata[0..32]
    ///   amount         = uint256 at offset 32 (low 16 bytes)
    ///   destVm byte    = calldata[95]
    ///   caller_20      = calldata[140..160]      (decode_address_at offset 128)
    ///   destAddress    = decode_dynamic_bytes(calldata, 96)
    #[test]
    fn cross_vm_transfer_calldata_round_trips_through_precompile_decode() {
        let token_id = {
            let mut t = [0u8; 32];
            t[31] = 0xCC; // arbitrary token id marker
            t
        };
        let amount_u128 = 7_500_000_000_000_000_000u128;
        let amount = u128_to_abi_amount(amount_u128);
        let caller: [u8; 20] = [0xEE; 20];
        let dest_address: [u8; 20] = [0x99; 20];

        let wallet_calldata =
            cross_vm_transfer_calldata(token_id, amount, DestVm::Svm, caller, &dest_address);

        // Strip the 4-byte selector — what the precompile dispatcher hands
        // off as `calldata`.
        let args = &wallet_calldata[4..];

        // Decode tokenId.
        let mut decoded_token_id = [0u8; 32];
        decoded_token_id.copy_from_slice(&args[0..32]);
        assert_eq!(decoded_token_id, token_id);

        // Decode amount (uint256, low 16 bytes is u128).
        let mut amount_bytes = [0u8; 16];
        amount_bytes.copy_from_slice(&args[48..64]);
        assert_eq!(u128::from_be_bytes(amount_bytes), amount_u128);

        // Decode destVm byte (last byte of slot 2).
        assert_eq!(args[95], DestVm::Svm as u8);

        // Decode caller (last 20 bytes of slot 4) — the precompile uses
        // `decode_address_at(calldata, 128)` which reads [140..160].
        let mut decoded_caller = [0u8; 20];
        decoded_caller.copy_from_slice(&args[140..160]);
        assert_eq!(decoded_caller, caller);

        // Decode dynamic-bytes destination address: read offset at slot 3,
        // then [offset..offset+32] = length, then payload.
        let offset_bytes = &args[96..128];
        let mut offset_low = [0u8; 8];
        offset_low.copy_from_slice(&offset_bytes[24..32]);
        let offset = u64::from_be_bytes(offset_low) as usize;
        assert_eq!(offset, 0xa0);

        let mut length_low = [0u8; 8];
        length_low.copy_from_slice(&args[offset + 24..offset + 32]);
        let length = u64::from_be_bytes(length_low) as usize;
        assert_eq!(length, 20);

        let payload = &args[offset + 32..offset + 32 + length];
        assert_eq!(payload, &dest_address);
    }

    /// Dynamic-bytes section must be right-padded to a 32-byte multiple, even
    /// for non-aligned payload sizes (e.g. the SVM 32-byte case is naturally
    /// aligned, but a 20-byte EVM address needs 12 bytes of trailing zero).
    #[test]
    fn cross_vm_transfer_calldata_pads_dynamic_section() {
        let token_id = [0u8; 32];
        let amount = u128_to_abi_amount(1u128);
        let caller: [u8; 20] = [0x33; 20];

        // 20-byte payload → padded to 32 bytes.
        let cd20 = cross_vm_transfer_calldata(token_id, amount, DestVm::Evm, caller, &[0x11; 20]);
        assert_eq!(cd20.len(), 4 + 160 + 32 + 32);

        // 32-byte payload → exactly 32 bytes (no extra padding).
        let cd32 = cross_vm_transfer_calldata(token_id, amount, DestVm::Svm, caller, &[0x22; 32]);
        assert_eq!(cd32.len(), 4 + 160 + 32 + 32);

        // 33-byte payload → padded to 64 bytes.
        let cd33 = cross_vm_transfer_calldata(token_id, amount, DestVm::Daml, caller, &[0x33; 33]);
        assert_eq!(cd33.len(), 4 + 160 + 32 + 64);
    }

    #[test]
    fn pad_evm_address_left_zeroes() {
        let addr = [0xee; 20];
        let padded = pad_evm_address(addr);
        assert!(padded[..12].iter().all(|&b| b == 0));
        assert_eq!(&padded[12..], &addr);
    }

    #[test]
    fn u128_amount_big_endian() {
        let abi = u128_to_abi_amount(0x0102030405060708090a0b0c0d0e0f10u128);
        // Upper 16 bytes zero, lower 16 bytes the big-endian value.
        assert!(abi[..16].iter().all(|&b| b == 0));
        assert_eq!(
            &abi[16..],
            &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
              0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10],
        );
    }

    #[test]
    fn get_supported_vms_calldata_is_selector_only() {
        let calldata = get_supported_vms_calldata();
        assert_eq!(calldata, GET_SUPPORTED_VMS_SELECTOR);
    }

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
