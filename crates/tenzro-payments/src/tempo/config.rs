//! Tempo network configuration

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

/// Tempo network chain ID (mainnet)
pub const TEMPO_CHAIN_ID: u64 = 42431;

/// Tempo testnet (Moderato) RPC URL
pub const TEMPO_TESTNET_RPC: &str = "https://rpc.moderato.tempo.xyz";

/// Tempo mainnet RPC URL
pub const TEMPO_MAINNET_RPC: &str = "https://rpc.tempo.xyz";

/// Configuration for Tempo network participation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TempoConfig {
    /// JSON-RPC URL for Tempo node
    pub rpc_url: String,
    /// Chain ID (42431 for mainnet)
    pub chain_id: u64,
    /// TIP-20 stablecoin contract addresses
    pub stablecoin_addresses: HashMap<String, String>,
    /// Path to Ed25519 validator key (if participating as validator)
    pub validator_key_path: Option<PathBuf>,
    /// MPP endpoint URL (if running MPP server)
    pub mpp_endpoint: Option<String>,
    /// Block confirmation count for finality
    pub finality_confirmations: u64,
}

impl Default for TempoConfig {
    fn default() -> Self {
        let mut stablecoins = HashMap::new();
        stablecoins.insert("USDC".to_string(), String::new());
        stablecoins.insert("USDT".to_string(), String::new());

        Self {
            rpc_url: TEMPO_TESTNET_RPC.to_string(),
            chain_id: TEMPO_CHAIN_ID,
            stablecoin_addresses: stablecoins,
            validator_key_path: None,
            mpp_endpoint: None,
            finality_confirmations: 1,
        }
    }
}

impl TempoConfig {
    /// Creates a mainnet configuration
    pub fn mainnet() -> Self {
        Self {
            rpc_url: TEMPO_MAINNET_RPC.to_string(),
            ..Default::default()
        }
    }

    /// Creates a testnet (Moderato) configuration
    pub fn testnet() -> Self {
        Self::default()
    }

    /// Sets the RPC URL
    pub fn with_rpc_url(mut self, url: impl Into<String>) -> Self {
        self.rpc_url = url.into();
        self
    }

    /// Sets a stablecoin address
    pub fn with_stablecoin(mut self, symbol: impl Into<String>, address: impl Into<String>) -> Self {
        self.stablecoin_addresses
            .insert(symbol.into(), address.into());
        self
    }
}
