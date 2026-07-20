//! # Tenzro Bridge
//!
//! Cross-chain bridge adapters for Tenzro Network providing interoperability with
//! multiple blockchain ecosystems through various bridge protocols.
//!
//! ## Supported Bridge Protocols
//!
//! - **LayerZero V2**: Omnichain interoperability protocol with configurable security
//!   via independent oracles and relayers. Supports OApp and OFT patterns.
//!
//! - **Chainlink CCIP**: Cross-Chain Interoperability Protocol leveraging Chainlink's
//!   decentralized oracle networks for secure token transfers and messaging.
//!
//! - **deBridge DLN**: Decentralized Liquidity Network using an intent-based maker-taker
//!   model for fast, capital-efficient cross-chain transfers.
//!
//! - **Canton**: Enterprise-grade distributed ledger using Daml 3.x smart contracts with
//!   privacy-preserving cross-domain synchronization for multi-party workflows.
//!
//! ## Architecture
//!
//! The crate uses an adapter pattern where each bridge protocol implements the
//! `BridgeAdapter` trait, providing a consistent interface for cross-chain operations.
//! A `BridgeRouter` intelligently selects the best adapter based on factors like
//! cost, speed, and availability.
//!
//! ## Message Format
//!
//! A standardized `TenzroMessage` format ensures consistent cross-chain communication
//! across all bridge protocols, with support for various message types including:
//! - Token transfers
//! - Data messages
//! - Governance actions
//! - AI model registrations
//! - AI agent messages
//!
//! ## Example
//!
//! ```rust
//! use tenzro_bridge::{
//!     BridgeRouter,
//!     layerzero::{LayerZeroAdapter, LayerZeroConfig},
//!     traits::BridgeTokenRequest,
//! };
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Create a bridge router
//! let router = BridgeRouter::new();
//!
//! // Configure and register LayerZero adapter
//! let lz_config = LayerZeroConfig::new(
//!     "0x1a44076050125825900e736c501f859c50fE728c",
//!     30101,
//!     "0x0000000000000000000000000000000000000001",
//!     "0x0000000000000000000000000000000000000002",
//! );
//! let lz_adapter = LayerZeroAdapter::new(lz_config);
//! router.register_adapter("layerzero", Box::new(lz_adapter)).await;
//!
//! // Bridge tokens
//! let request = BridgeTokenRequest::new(
//!     "ethereum",
//!     "arbitrum",
//!     "USDC",
//!     1000000,
//!     "0xsender...",
//!     "0xreceiver...",
//! );
//!
//! let receipt = router.bridge_tokens(request).await?;
//! println!("Transfer initiated: {}", receipt.transfer_id);
//! # Ok(())
//! # }
//! ```
//!
//! ## Features
//!
//! - **Multi-Protocol Support**: Integrate with LayerZero, Chainlink CCIP, deBridge, and LI.FI
//! - **LI.FI Aggregation**: 58+ chains via LI.FI aggregator (27+ bridges, 31+ DEXes)
//! - **Intelligent Routing**: Automatically select the best bridge based on preferences
//! - **Fee Comparison**: Compare fees across different bridge protocols
//! - **Transfer Tracking**: Monitor cross-chain transfer status in real-time
//! - **Standardized Messaging**: Consistent message format across all bridges
//! - **Async/Await**: Full async support for non-blocking operations

pub mod canton;
pub mod canton_auth;
pub mod chainlink_ccip;
pub mod circuit_breaker;
pub mod debridge;
pub mod error;
pub mod evm_signer;
pub mod layerzero;
pub mod lifi;
pub mod message_format;
pub mod monitor;
pub mod secp256k1_multisig;
pub mod mpc;
pub mod axelar;
pub mod babylon;
pub mod bitvm2;
pub mod hyperbridge;
pub mod hyperlane;
pub mod ibc_eureka;
pub mod near_chain_sig;
pub mod stargate_v2;
pub mod router;
pub mod tenant_idp;
pub mod tnzo_cct;
pub mod traits;
pub mod wormhole;
pub mod wormhole_ntt;
pub mod chainlink_feed;
pub mod chainlink_por;
pub mod fee_oracle;
pub mod fee_sponsor;
pub mod price_oracle;

// Re-export commonly used types
pub use circuit_breaker::CircuitBreaker;
pub use error::{BridgeError, Result};
pub use evm_signer::{EvmTransactionSigner, EvmSignerConfig};
pub use monitor::{TransferMonitor, TransferStatusEvent, MonitorConfig};
pub use chainlink_feed::{
    ChainlinkFeedClient, FeedReading, FeedRegistration, FEED_BTC_USD_MAINNET,
    FEED_ETH_USD_MAINNET, FEED_LINK_USD_MAINNET, QUOTE_CACHE_TTL_SECS,
    SELECTOR_DECIMALS, SELECTOR_LATEST_ROUND_DATA, STALENESS_THRESHOLD_LONGTAIL_SECS,
    STALENESS_THRESHOLD_MAJOR_SECS,
};
pub use chainlink_por::{
    ChainlinkPorAdapter, PorAttestationInput, PorError, PorFeedConfig, PorReading,
    decode_por_round, validate_freshness,
};
pub use fee_oracle::{
    BridgeAdapterId, BridgeFeeOracle, BridgeFeeQuote, ChainlinkFeedFeeOracle,
    GovernanceFeeRow, GovernanceSetFeeOracle, OracleBacking,
};
pub use fee_sponsor::{
    BridgeFeeSponsor, BridgeSponsorshipReceipt, SponsorshipPool, WiredBridgeFeeSurface,
};
pub use price_oracle::{PriceOracle, SymbolFeed, UsdPrice, USD_PRICE_DECIMALS};
pub use router::{BridgeRouter, ChainCoverage};
pub use tnzo_cct::{CctPoolType, TnzoCctBridge, TnzoCctPool, TnzoCctRegistry};
pub use traits::{
    BridgeAdapter, BridgeAdapterClass, BridgeTokenReceipt, BridgeTokenRequest, ChainInfo,
    TransferStatus,
};
pub use wormhole::{TokenBridgePayload, Vaa, WormholeAdapter, WormholeConfig};

/// Bridge crate version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Prelude module for convenient imports
pub mod prelude {
    pub use crate::{
        canton::{CantonAdapter, CantonConfig},
        canton_auth::{CantonAuthConfig, CantonTokenProvider},
        chainlink_ccip::{ChainlinkCcipAdapter, CcipConfig, CcipMessage, FeeToken},
        debridge::{DeBridgeAdapter, DeBridgeConfig, DlnOrder, DlnOrderStatus, DlnHook},
        error::{BridgeError, Result},
        evm_signer::{EvmTransactionSigner, EvmSignerConfig},
        layerzero::{LayerZeroAdapter, LayerZeroConfig},
        lifi::{LiFiAdapter, LiFiConfig},
        message_format::{
            AgentMessagePayload, MessageEnvelope, MessageMetadata, MessageType,
            NonceTracker, TokenTransferPayload, TenzroMessage,
        },
        monitor::{TransferMonitor, TransferStatusEvent, MonitorConfig},
        router::{BridgeRouter, FeeComparison, RouteInfo, RoutingPreferences, RoutingStrategy},
        tnzo_cct::{CctPoolType, TnzoCctBridge, TnzoCctPool, TnzoCctRegistry},
        traits::{
            BridgeAdapter, BridgeAdapterClass, BridgeTokenReceipt, BridgeTokenRequest, ChainInfo,
            TransferStatus,
        },
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        assert!(!VERSION.is_empty());
    }
}
