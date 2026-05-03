//! Asset types for Tenzro Network
//!
//! This module defines asset representations including TNZO tokens,
//! stablecoins, and other digital assets on the network.

use crate::primitives::Address;
use serde::{Deserialize, Serialize};

/// Unique identifier for an asset on Tenzro Network
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AssetId(pub String);

impl AssetId {
    /// Creates a new AssetId
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// Returns the TNZO native token asset ID
    pub fn tnzo() -> Self {
        Self("TNZO".to_string())
    }

    /// Returns a USD stablecoin asset ID
    pub fn usd_stablecoin() -> Self {
        Self("USDT".to_string())
    }

    /// Returns the asset ID as a string
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<String> for AssetId {
    fn from(id: String) -> Self {
        Self(id)
    }
}

impl From<&str> for AssetId {
    fn from(id: &str) -> Self {
        Self(id.to_string())
    }
}

/// Types of stablecoins supported on Tenzro Network
///
/// Stablecoins are used for stable-value settlements and payments.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum StablecoinType {
    /// US Dollar stablecoin
    USD,
    /// Euro stablecoin
    EUR,
    /// British Pound stablecoin
    GBP,
    /// Japanese Yen stablecoin
    JPY,
    /// Custom algorithmic stablecoin
    Algorithmic,
}

impl StablecoinType {
    /// Returns the asset ID for this stablecoin type
    pub fn asset_id(&self) -> AssetId {
        match self {
            Self::USD => AssetId::new("USDT"),
            Self::EUR => AssetId::new("EURT"),
            Self::GBP => AssetId::new("GBPT"),
            Self::JPY => AssetId::new("JPYT"),
            Self::Algorithmic => AssetId::new("TNZO-STABLE"),
        }
    }

    /// Returns the symbol for this stablecoin
    pub fn symbol(&self) -> &str {
        match self {
            Self::USD => "USDT",
            Self::EUR => "EURT",
            Self::GBP => "GBPT",
            Self::JPY => "JPYT",
            Self::Algorithmic => "TNZO-STABLE",
        }
    }
}

/// Information about an asset on Tenzro Network
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssetInfo {
    /// Unique asset identifier
    pub asset_id: AssetId,
    /// Asset name
    pub name: String,
    /// Asset symbol
    pub symbol: String,
    /// Number of decimal places
    pub decimals: u8,
    /// Total supply (in smallest unit)
    pub total_supply: u64,
    /// Asset type
    pub asset_type: AssetType,
    /// Asset issuer address
    pub issuer: Option<Address>,
    /// Whether the asset is mintable
    pub mintable: bool,
    /// Whether the asset is burnable
    pub burnable: bool,
    /// Asset metadata
    pub metadata: AssetMetadata,
}

impl AssetInfo {
    /// Creates a new AssetInfo
    pub fn new(
        asset_id: AssetId,
        name: String,
        symbol: String,
        decimals: u8,
        total_supply: u64,
        asset_type: AssetType,
    ) -> Self {
        Self {
            asset_id,
            name,
            symbol,
            decimals,
            total_supply,
            asset_type,
            issuer: None,
            mintable: false,
            burnable: false,
            metadata: AssetMetadata::default(),
        }
    }

    /// Returns the TNZO native token info
    pub fn tnzo() -> Self {
        Self {
            asset_id: AssetId::tnzo(),
            name: "Tenzro Network Token".to_string(),
            symbol: "TNZO".to_string(),
            decimals: 18,
            total_supply: 1_000_000_000, // 1 billion TNZO (in whole tokens, decimals applied separately)
            asset_type: AssetType::Native,
            issuer: None,
            mintable: false,
            burnable: true,
            metadata: AssetMetadata::default(),
        }
    }

    /// Sets the issuer address
    pub fn with_issuer(mut self, issuer: Address) -> Self {
        self.issuer = Some(issuer);
        self
    }

    /// Sets mintable flag
    pub fn with_mintable(mut self, mintable: bool) -> Self {
        self.mintable = mintable;
        self
    }

    /// Sets burnable flag
    pub fn with_burnable(mut self, burnable: bool) -> Self {
        self.burnable = burnable;
        self
    }
}

/// The type of asset
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AssetType {
    /// Native TNZO token
    Native,
    /// Stablecoin
    Stablecoin(StablecoinType),
    /// Fungible token
    Fungible,
    /// Non-fungible token (NFT)
    NonFungible,
    /// Synthetic asset
    Synthetic,
}

/// Additional metadata for an asset
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct AssetMetadata {
    /// Asset description
    pub description: Option<String>,
    /// Asset icon URI
    pub icon_uri: Option<String>,
    /// Website URL
    pub website: Option<String>,
    /// Whitepaper URL
    pub whitepaper: Option<String>,
    /// Social media links
    pub social: Option<SocialLinks>,
}

/// Social media links for an asset
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SocialLinks {
    /// Twitter handle
    pub twitter: Option<String>,
    /// Discord server
    pub discord: Option<String>,
    /// Telegram channel
    pub telegram: Option<String>,
    /// GitHub repository
    pub github: Option<String>,
}
