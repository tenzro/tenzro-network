//! Asset USD price oracle over Chainlink Data Feeds.
//!
//! Wraps [`crate::chainlink_feed::ChainlinkFeedClient`] with a `symbol → feed
//! address` map so callers can ask "what is TNZO worth in USD?" by ticker
//! rather than by feed address. Each registered feed is a `SYMBOL/USD` pair;
//! the reading's `answer` is renormalized to a fixed 8-decimal USD scale
//! regardless of the feed's native `decimals()`.
//!
//! This is distinct from [`crate::fee_oracle::ChainlinkFeedFeeOracle`], which
//! derives `dest_native/TNZO` cross-rates for bridge fee quoting. Here the
//! output is a raw per-symbol USD price consumed by wallet portfolio views.

use crate::chainlink_feed::ChainlinkFeedClient;
use crate::error::{BridgeError, Result};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Fixed USD output precision. All prices are returned scaled by `10^8`
/// (matching Chainlink's own USD-pair convention) so integer arithmetic is
/// lossless across the RPC boundary.
pub const USD_PRICE_DECIMALS: u8 = 8;

/// A normalized USD price for one symbol.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UsdPrice {
    /// Upper-cased ticker (e.g. "TNZO", "ETH", "BTC").
    pub symbol: String,
    /// USD price scaled by `10^USD_PRICE_DECIMALS`.
    pub price_usd_8dp: i128,
    /// Feed decimals precision this price is expressed at (always 8).
    pub decimals: u8,
    /// On-chain `updatedAt` of the underlying feed round (unix seconds).
    pub updated_at: u64,
    /// Feed proxy address the price was read from.
    pub feed_address: String,
}

/// Per-symbol feed registration input.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SymbolFeed {
    /// Ticker; matched case-insensitively.
    pub symbol: String,
    /// Chainlink `SYMBOL/USD` aggregator proxy address.
    pub feed_address: String,
    /// Staleness tier: "major" | "longtail".
    pub tier: String,
}

/// Reads renormalized USD prices for a fixed set of symbols.
pub struct PriceOracle {
    client: Arc<ChainlinkFeedClient>,
    /// `symbol_upper → feed_address_lower`.
    symbols: dashmap::DashMap<String, String>,
}

impl PriceOracle {
    /// Build over a shared feed client. Feeds must be registered via
    /// [`Self::register_symbol`] before [`Self::price`] can resolve them.
    pub fn new(client: Arc<ChainlinkFeedClient>) -> Self {
        Self {
            client,
            symbols: dashmap::DashMap::new(),
        }
    }

    /// Register a `SYMBOL/USD` feed. Eagerly registers the feed with the
    /// underlying client (fetches `decimals()`), so the first price read is a
    /// single `latestRoundData()` call.
    pub async fn register_symbol(&self, feed: &SymbolFeed) -> Result<()> {
        let addr = feed.feed_address.to_lowercase();
        self.client.register_feed(addr.clone(), &feed.tier).await?;
        self.symbols.insert(feed.symbol.to_uppercase(), addr);
        Ok(())
    }

    /// Symbols this oracle can price.
    pub fn known_symbols(&self) -> Vec<String> {
        self.symbols.iter().map(|e| e.key().clone()).collect()
    }

    /// Resolve a single symbol's USD price, renormalized to 8 decimals.
    pub async fn price(&self, symbol: &str) -> Result<UsdPrice> {
        let sym = symbol.to_uppercase();
        let addr = self
            .symbols
            .get(&sym)
            .map(|e| e.value().clone())
            .ok_or_else(|| {
                BridgeError::AdapterError(format!("no USD feed registered for symbol {sym}"))
            })?;
        let reading = self.client.read_feed(&addr).await?;
        // read_feed already rejects invalid/stale readings.
        let price_usd_8dp = renormalize_to_8dp(reading.answer, reading.decimals)?;
        Ok(UsdPrice {
            symbol: sym,
            price_usd_8dp,
            decimals: USD_PRICE_DECIMALS,
            updated_at: reading.updated_at,
            feed_address: addr,
        })
    }
}

/// Renormalize a feed answer expressed at `from_decimals` to a fixed 8-decimal
/// USD scale. Chainlink USD pairs are 8dp today, but long-tail feeds can differ.
fn renormalize_to_8dp(answer: i128, from_decimals: u8) -> Result<i128> {
    use std::cmp::Ordering;
    match from_decimals.cmp(&USD_PRICE_DECIMALS) {
        Ordering::Equal => Ok(answer),
        Ordering::Greater => {
            let shift = (from_decimals - USD_PRICE_DECIMALS) as u32;
            Ok(answer / 10i128.pow(shift.min(38)))
        }
        Ordering::Less => {
            let shift = (USD_PRICE_DECIMALS - from_decimals) as u32;
            answer
                .checked_mul(10i128.pow(shift.min(38)))
                .ok_or_else(|| BridgeError::AdapterError("price renormalize overflow".to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renormalize_same_scale_is_identity() {
        assert_eq!(renormalize_to_8dp(123_456_789, 8).unwrap(), 123_456_789);
    }

    #[test]
    fn renormalize_downscales_higher_precision() {
        // 18dp answer of 1.5 USD → 8dp
        let answer = 1_500_000_000_000_000_000; // 1.5 * 10^18
        assert_eq!(renormalize_to_8dp(answer, 18).unwrap(), 150_000_000);
    }

    #[test]
    fn renormalize_upscales_lower_precision() {
        // 6dp answer of 2.0 USD → 8dp
        let answer = 2_000_000; // 2.0 * 10^6
        assert_eq!(renormalize_to_8dp(answer, 6).unwrap(), 200_000_000);
    }
}
