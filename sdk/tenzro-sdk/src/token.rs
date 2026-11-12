//! Token SDK for Tenzro Network
//!
//! This module provides token management functionality including creating tokens,
//! querying token info and balances, wrapping TNZO, and cross-VM transfers.

use crate::error::SdkResult;
use crate::rpc::RpcClient;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// The address of the wTNZO pointer precompile on the EVM (`0x1001`).
/// All VMs (EVM, SVM) share the same underlying native TNZO balance via
/// the Sei V2 pointer model -- this address is the EVM representation.
pub const WTNZO_EVM_ADDRESS: &str = "0x0000000000000000000000000000000000001001";

/// Token client for TNZO token registry and cross-VM operations
///
/// # Example
///
/// ```no_run
/// # use tenzro_sdk::{TenzroClient, config::SdkConfig};
/// # #[tokio::main]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// # let client = tenzro_sdk::network::connect_to_network(&tenzro_sdk::network::NetworkOptions::default()).await?;
/// let token = client.token();
///
/// // List all tokens
/// let result = token.list_tokens(None, None).await?;
/// println!("Found {} tokens", result.count);
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct TokenClient {
    rpc: Arc<RpcClient>,
}

impl TokenClient {
    /// Creates a new token client
    pub(crate) fn new(rpc: Arc<RpcClient>) -> Self {
        Self { rpc }
    }

    /// Whether the token's rules allow `from` to send `amount` to `to` now:
    /// `{allowed}` or `{allowed: false, code, reason}`.
    pub async fn can_transfer(
        &self,
        token_id: &str,
        from: &str,
        to: &str,
        amount: u128,
    ) -> SdkResult<serde_json::Value> {
        self.rpc
            .call(
                "tenzro_canTransfer",
                serde_json::json!([{ "token_id": token_id, "from": from, "to": to, "amount": amount.to_string() }]),
            )
            .await
    }

    /// Gets token information by symbol, EVM address, or token ID
    ///
    /// At least one of `symbol`, `evm_address`, or `token_id` must be provided.
    ///
    /// # Arguments
    ///
    /// * `symbol` - Token symbol (e.g., "TNZO")
    /// * `evm_address` - EVM contract address (hex)
    /// * `token_id` - Token registry ID (hex)
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use tenzro_sdk::{TenzroClient, config::SdkConfig};
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = tenzro_sdk::network::connect_to_network(&tenzro_sdk::network::NetworkOptions::default()).await?;
    /// let token = client.token();
    /// let info = token.get_token_info(Some("TNZO"), None, None).await?;
    /// println!("Total supply: {}", info.total_supply);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn get_token_info(
        &self,
        symbol: Option<&str>,
        evm_address: Option<&str>,
        token_id: Option<&str>,
    ) -> SdkResult<TokenInfo> {
        let mut params = serde_json::Map::new();

        if let Some(s) = symbol {
            params.insert("symbol".to_string(), serde_json::json!(s));
        }
        if let Some(a) = evm_address {
            params.insert("evm_address".to_string(), serde_json::json!(a));
        }
        if let Some(id) = token_id {
            params.insert("token_id".to_string(), serde_json::json!(id));
        }

        self.rpc
            .call(
                "tenzro_getToken",
                serde_json::json!([serde_json::Value::Object(params)]),
            )
            .await
    }

    /// Lists registered tokens with optional VM type filter
    ///
    /// # Arguments
    ///
    /// * `vm_type` - Filter by VM type: "evm", "svm", or "native"
    /// * `limit` - Maximum number of tokens to return (default 50, max 100)
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use tenzro_sdk::{TenzroClient, config::SdkConfig};
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = tenzro_sdk::network::connect_to_network(&tenzro_sdk::network::NetworkOptions::default()).await?;
    /// let token = client.token();
    ///
    /// // List all EVM tokens
    /// let result = token.list_tokens(Some("evm"), Some(20)).await?;
    /// for t in &result.tokens {
    ///     println!("{}: {} (supply: {})", t.symbol, t.name, t.total_supply);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn list_tokens(
        &self,
        vm_type: Option<&str>,
        limit: Option<u64>,
    ) -> SdkResult<TokenList> {
        let mut params = serde_json::Map::new();

        if let Some(vt) = vm_type {
            params.insert("vm_type".to_string(), serde_json::json!(vt));
        }
        if let Some(l) = limit {
            params.insert("limit".to_string(), serde_json::json!(l));
        }

        self.rpc
            .call(
                "tenzro_listTokens",
                serde_json::json!([serde_json::Value::Object(params)]),
            )
            .await
    }

    /// Gets the TNZO token balance for an address across all VMs
    ///
    /// Returns native TNZO balance along with EVM (wTNZO ERC-20) and
    /// SVM (wTNZO SPL with 9 decimals) representations. All share the same underlying balance via the
    /// pointer model.
    ///
    /// # Arguments
    ///
    /// * `address` - Account address (hex, with or without 0x prefix)
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use tenzro_sdk::{TenzroClient, config::SdkConfig};
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = tenzro_sdk::network::connect_to_network(&tenzro_sdk::network::NetworkOptions::default()).await?;
    /// let token = client.token();
    /// let balance = token
    ///     .get_token_balance("0x1234567890abcdef1234567890abcdef12345678")
    ///     .await?;
    /// println!("Native: {} wei", balance.native.balance_wei);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn get_token_balance(&self, address: &str) -> SdkResult<TokenBalance> {
        self.rpc
            .call(
                "tenzro_getTokenBalance",
                serde_json::json!({ "address": address }),
            )
            .await
    }
}

/// Token information returned from `get_token_info`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenInfo {
    /// Token registry ID (hex)
    #[serde(default)]
    pub token_id: String,
    /// Token name
    #[serde(default)]
    pub name: String,
    /// Token symbol
    #[serde(default)]
    pub symbol: String,
    /// Number of decimals
    #[serde(default)]
    pub decimals: u8,
    /// Total supply (decimal string)
    #[serde(default)]
    pub total_supply: String,
    /// Initial supply (decimal string, present on create)
    #[serde(default)]
    pub initial_supply: String,
    /// Token type (e.g., "Erc20")
    #[serde(default)]
    pub token_type: String,
    /// EVM contract address (hex)
    #[serde(default)]
    pub evm_address: String,
    /// SVM mint address (hex)
    #[serde(default)]
    pub svm_mint: String,
    /// Tempo L1 TIP-20 contract address (hex)
    #[serde(default)]
    pub tempo_address: Option<String>,
    /// Creator address (hex)
    #[serde(default)]
    pub creator: String,
    /// Operation status (e.g., "created")
    #[serde(default)]
    pub status: String,
}

/// Result from `list_tokens`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenList {
    /// Number of tokens returned
    #[serde(default)]
    pub count: usize,
    /// Token entries
    #[serde(default)]
    pub tokens: Vec<TokenListEntry>,
}

/// A single token entry in a list result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenListEntry {
    /// Token registry ID (hex)
    #[serde(default)]
    pub token_id: String,
    /// Token name
    #[serde(default)]
    pub name: String,
    /// Token symbol
    #[serde(default)]
    pub symbol: String,
    /// Number of decimals
    #[serde(default)]
    pub decimals: u8,
    /// Total supply (decimal string)
    #[serde(default)]
    pub total_supply: String,
    /// EVM contract address (hex)
    #[serde(default)]
    pub evm_address: String,
    /// SVM mint address (hex)
    #[serde(default)]
    pub svm_mint: Option<String>,
    /// Tempo L1 TIP-20 contract address (hex)
    #[serde(default)]
    pub tempo_address: Option<String>,
}

/// Token balance across all VMs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenBalance {
    /// Account address
    #[serde(default)]
    pub address: String,
    /// Native TNZO balance (`{ balance_wei, decimals: 18 }`)
    #[serde(default)]
    pub native: NativeBalance,
    /// EVM wTNZO ERC-20 view — same wei as native
    #[serde(default)]
    pub evm_wtnzo: EvmBalance,
    /// SVM wTNZO SPL view — 9-decimal truncation
    #[serde(default)]
    pub svm_wtnzo: SvmBalance,
}

/// Native TNZO balance details.
///
/// The RPC handler emits `{ "balance_wei": "...", "decimals": 18 }`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NativeBalance {
    /// Balance in wei (decimal string)
    #[serde(default, rename = "balance_wei")]
    pub balance_wei: String,
    /// Number of decimals (18)
    #[serde(default)]
    pub decimals: u8,
}

/// EVM wTNZO ERC-20 view (same wei as native, 18 decimals).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EvmBalance {
    /// Balance in wei (decimal string)
    #[serde(default, rename = "balance_wei")]
    pub balance_wei: String,
    /// Number of decimals (18)
    #[serde(default)]
    pub decimals: u8,
}

/// SVM wTNZO SPL view — 9-decimal truncation of native balance.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SvmBalance {
    /// Balance in SPL base units (decimal string, 9 decimals)
    #[serde(default, rename = "balance_base_units")]
    pub balance_base_units: String,
    /// Number of decimals (9)
    #[serde(default)]
    pub decimals: u8,
}

impl TokenClient {
    /// Calls `tenzro_readPorReserve`: read por reserve.
    pub async fn read_por_reserve(
        &self,
        asset_id: &str,
    ) -> crate::error::SdkResult<serde_json::Value> {
        self.rpc
            .call(
                "tenzro_readPorReserve",
                serde_json::json!({ "asset_id": asset_id }),
            )
            .await
    }

    /// Calls `tenzro_getReserveFeed`: the Proof-of-Reserve feed governance
    /// installed for `asset_id`, from consensus state (`feed` is null when
    /// none is installed).
    pub async fn get_reserve_feed(
        &self,
        asset_id: &str,
    ) -> crate::error::SdkResult<serde_json::Value> {
        self.rpc
            .call(
                "tenzro_getReserveFeed",
                serde_json::json!({ "asset_id": asset_id }),
            )
            .await
    }
}
