//! # Tenzro Bridge
//!
//! Moves TNZO between Tenzro and external chains over governed routes.
//!
//! There is one bridge path: the [`route`] framework. A route joins Tenzro to
//! one external chain over one transport, and every route obeys the same
//! rules, enforced by the framework rather than by any adapter: strict
//! canonical decoding, domain-separated and replay-protected attestations,
//! a circuit breaker, per-mint and per-epoch caps, and the on-chain supply
//! invariant (the representation outstanding on a chain never exceeds the
//! TNZO locked on Tenzro for that route).
//!
//! Transports:
//!
//! - **CCIP-compatible envelope** for the EVM family (Ethereum, Base,
//!   Arbitrum) and Solana ([`route::evm`], [`route::solana`]).
//! - **IBC** ICS-20 packets to Cosmos chains ([`route::ibc`]).
//! - **Deposits** to a governed output script on Bitcoin ([`route::bitcoin`]).
//! - **Bridge contracts** on Stellar, Sui, Aptos and TON ([`route::stellar`],
//!   [`route::sui`], [`route::aptos`], [`route::ton`]).
//!
//! The crate also holds the supporting pieces the node needs around the
//! routes: Chainlink price and proof-of-reserve readers, the bridge fee
//! oracle and sponsor, the EVM transaction signer and the committee
//! signature verifier.

pub mod chainlink_feed;
pub mod chainlink_por;
pub mod data_streams;
pub mod error;
pub mod evm_signer;
pub mod fee_oracle;
pub mod route;
pub mod secp256k1_multisig;

pub use chainlink_feed::{
    ChainlinkFeedClient, FEED_BTC_USD_MAINNET, FEED_ETH_USD_MAINNET, FEED_LINK_USD_MAINNET,
    FeedReading, FeedRegistration, QUOTE_CACHE_TTL_SECS, SELECTOR_DECIMALS,
    SELECTOR_LATEST_ROUND_DATA, STALENESS_THRESHOLD_LONGTAIL_SECS, STALENESS_THRESHOLD_MAJOR_SECS,
};
pub use chainlink_por::{
    ChainlinkPorAdapter, PorError, PorReading, decode_por_round, validate_freshness,
};
pub use error::{BridgeError, Result};
pub use evm_signer::EvmTransactionSigner;
pub use fee_oracle::BridgeFeeQuote;
pub use route::{
    AdmittedTransfer, BridgeRoute, BridgeRouteAdapter, ChainFamily, OutboundMessage,
    OutboundTransfer, RouteFramework, RouteMessage,
};

/// Bridge crate version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        assert!(!VERSION.is_empty());
    }
}
