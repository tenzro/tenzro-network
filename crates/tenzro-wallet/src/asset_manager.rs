//! Asset management for Tenzro Network wallets.
//!
//! This module manages supported assets, asset metadata, and default assets.

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tenzro_types::{AssetId, AssetInfo, AssetType, StablecoinType};

/// Asset registry for Tenzro Network.
///
/// Maintains a registry of all supported assets with their metadata.
pub struct AssetManager {
    /// Map of asset ID to asset information
    assets: DashMap<AssetId, AssetInfo>,
}

impl AssetManager {
    /// Create a new asset manager with default assets
    pub fn new() -> Self {
        let manager = Self {
            assets: DashMap::new(),
        };

        // Register default assets
        manager.register_default_assets();

        manager
    }

    /// Register default assets (TNZO, USDC, USDT)
    fn register_default_assets(&self) {
        // TNZO - Native token
        self.register_asset(AssetInfo::tnzo());

        // USDT - USD stablecoin
        self.register_asset(AssetInfo::new(
            AssetId::from("USDT"),
            "Tether USD".to_string(),
            "USDT".to_string(),
            6,
            0, // Total supply managed by bridge
            AssetType::Stablecoin(StablecoinType::USD),
        ));

        // USDC - USD stablecoin
        self.register_asset(AssetInfo::new(
            AssetId::from("USDC"),
            "USD Coin".to_string(),
            "USDC".to_string(),
            6,
            0, // Total supply managed by bridge
            AssetType::Stablecoin(StablecoinType::USD),
        ));

        // DAI - Algorithmic stablecoin
        self.register_asset(AssetInfo::new(
            AssetId::from("DAI"),
            "DAI Stablecoin".to_string(),
            "DAI".to_string(),
            18,
            0,
            AssetType::Stablecoin(StablecoinType::Algorithmic),
        ));
    }

    /// Register a new asset
    pub fn register_asset(&self, asset_info: AssetInfo) {
        self.assets.insert(asset_info.asset_id.clone(), asset_info);
    }

    /// Get asset information
    pub fn get_asset(&self, asset_id: &AssetId) -> Option<AssetInfo> {
        self.assets.get(asset_id).map(|entry| entry.value().clone())
    }

    /// Check if an asset is registered
    pub fn is_supported(&self, asset_id: &AssetId) -> bool {
        self.assets.contains_key(asset_id)
    }

    /// Get all registered assets
    pub fn list_assets(&self) -> Vec<AssetInfo> {
        self.assets
            .iter()
            .map(|entry| entry.value().clone())
            .collect()
    }

    /// Get assets by type
    pub fn list_assets_by_type(&self, asset_type: AssetType) -> Vec<AssetInfo> {
        self.assets
            .iter()
            .filter(|entry| entry.value().asset_type == asset_type)
            .map(|entry| entry.value().clone())
            .collect()
    }

    /// Get all stablecoins
    pub fn list_stablecoins(&self) -> Vec<AssetInfo> {
        self.assets
            .iter()
            .filter(|entry| matches!(entry.value().asset_type, AssetType::Stablecoin(_)))
            .map(|entry| entry.value().clone())
            .collect()
    }

    /// Get native token (TNZO)
    pub fn get_native_token(&self) -> AssetInfo {
        self.get_asset(&AssetId::tnzo())
            .expect("TNZO should always be registered")
    }

    /// Remove an asset from the registry
    pub fn unregister_asset(&self, asset_id: &AssetId) -> Option<AssetInfo> {
        self.assets.remove(asset_id).map(|(_, info)| info)
    }

    /// Get asset count
    pub fn asset_count(&self) -> usize {
        self.assets.len()
    }

    /// Clear all assets (for testing)
    pub fn clear(&self) {
        self.assets.clear();
    }
}

impl Default for AssetManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Default asset configuration for new wallets
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefaultAssetConfig {
    /// Default assets to enable for new wallets
    pub default_assets: Vec<AssetId>,
    /// Whether to auto-enable all stablecoins
    pub auto_enable_stablecoins: bool,
}

impl DefaultAssetConfig {
    /// Create default configuration
    pub fn new() -> Self {
        Self {
            default_assets: vec![
                AssetId::tnzo(),
                AssetId::from("USDT"),
                AssetId::from("USDC"),
            ],
            auto_enable_stablecoins: true,
        }
    }

    /// Get the list of default assets
    pub fn get_default_assets(&self) -> &[AssetId] {
        &self.default_assets
    }

    /// Add a default asset
    pub fn add_default_asset(&mut self, asset_id: AssetId) {
        if !self.default_assets.contains(&asset_id) {
            self.default_assets.push(asset_id);
        }
    }

    /// Remove a default asset
    pub fn remove_default_asset(&mut self, asset_id: &AssetId) {
        self.default_assets.retain(|a| a != asset_id);
    }
}

impl Default for DefaultAssetConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// Shared asset manager instance
pub type SharedAssetManager = Arc<AssetManager>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_asset_manager_default_assets() {
        let manager = AssetManager::new();

        // Check default assets are registered
        assert!(manager.is_supported(&AssetId::tnzo()));
        assert!(manager.is_supported(&AssetId::from("USDT")));
        assert!(manager.is_supported(&AssetId::from("USDC")));
        assert!(manager.is_supported(&AssetId::from("DAI")));

        // Should have at least 4 default assets
        assert!(manager.asset_count() >= 4);
    }

    #[test]
    fn test_register_asset() {
        let manager = AssetManager::new();

        let custom_asset = AssetInfo::new(
            AssetId::from("TEST"),
            "Test Token".to_string(),
            "TEST".to_string(),
            18,
            1000000,
            AssetType::Fungible,
        );

        manager.register_asset(custom_asset.clone());

        assert!(manager.is_supported(&AssetId::from("TEST")));

        let retrieved = manager.get_asset(&AssetId::from("TEST")).unwrap();
        assert_eq!(retrieved.name, "Test Token");
        assert_eq!(retrieved.symbol, "TEST");
    }

    #[test]
    fn test_list_assets() {
        let manager = AssetManager::new();

        let assets = manager.list_assets();
        assert!(!assets.is_empty());

        // All default assets should be present
        let asset_ids: Vec<_> = assets.iter().map(|a| &a.asset_id).collect();
        assert!(asset_ids.contains(&&AssetId::tnzo()));
    }

    #[test]
    fn test_list_stablecoins() {
        let manager = AssetManager::new();

        let stablecoins = manager.list_stablecoins();
        assert!(!stablecoins.is_empty());

        // All stablecoins should have Stablecoin type
        for asset in stablecoins {
            assert!(matches!(asset.asset_type, AssetType::Stablecoin(_)));
        }
    }

    #[test]
    fn test_native_token() {
        let manager = AssetManager::new();

        let native = manager.get_native_token();
        assert_eq!(native.asset_id, AssetId::tnzo());
        assert_eq!(native.symbol, "TNZO");
        assert_eq!(native.asset_type, AssetType::Native);
    }

    #[test]
    fn test_unregister_asset() {
        let manager = AssetManager::new();

        let custom_asset = AssetInfo::new(
            AssetId::from("TEST"),
            "Test Token".to_string(),
            "TEST".to_string(),
            18,
            1000000,
            AssetType::Fungible,
        );

        manager.register_asset(custom_asset);
        assert!(manager.is_supported(&AssetId::from("TEST")));

        let removed = manager.unregister_asset(&AssetId::from("TEST"));
        assert!(removed.is_some());
        assert!(!manager.is_supported(&AssetId::from("TEST")));
    }

    #[test]
    fn test_list_assets_by_type() {
        let manager = AssetManager::new();

        let native_assets = manager.list_assets_by_type(AssetType::Native);
        assert_eq!(native_assets.len(), 1);
        assert_eq!(native_assets[0].asset_id, AssetId::tnzo());

        let stablecoins = manager.list_assets_by_type(AssetType::Stablecoin(StablecoinType::USD));
        assert!(!stablecoins.is_empty());
    }

    #[test]
    fn test_default_asset_config() {
        let config = DefaultAssetConfig::new();

        assert!(config.get_default_assets().contains(&AssetId::tnzo()));
        assert!(config.get_default_assets().contains(&AssetId::from("USDT")));
        assert!(config.auto_enable_stablecoins);
    }

    #[test]
    fn test_modify_default_config() {
        let mut config = DefaultAssetConfig::new();

        let custom_asset = AssetId::from("CUSTOM");
        config.add_default_asset(custom_asset.clone());
        assert!(config.get_default_assets().contains(&custom_asset));

        config.remove_default_asset(&custom_asset);
        assert!(!config.get_default_assets().contains(&custom_asset));
    }
}
