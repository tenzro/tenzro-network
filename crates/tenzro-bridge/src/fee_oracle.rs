//! A destination-native bridge fee, quoted in TNZO.
//!
//! The conversion uses the USD rates validators commit on chain (the
//! stake-weighted median of their `FeeRateSubmit` reports, one per symbol),
//! so every node quotes the same amount for the same state. This module
//! holds the quote envelope; the node fills it from chain state.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tenzro_types::bridge_route::BridgeRouteAdapter;

/// How long a quote is honoured after it is issued.
pub const QUOTE_VALID_MS: u64 = 60_000;

/// A destination-native fee and the TNZO that pays it at committed rates.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BridgeFeeQuote {
    /// SHA-256 over the quote's inputs, `0x` hex.
    pub quote_id_hex: String,
    /// Route transport.
    pub adapter: BridgeRouteAdapter,
    /// Destination chain, CAIP-2.
    pub dest_chain: String,
    /// The destination chain's native asset symbol.
    pub native_symbol: String,
    /// Destination-native fee in the asset's smallest unit.
    #[serde(with = "tenzro_types::primitives::u128_serde")]
    pub native_fee_smallest_unit: u128,
    /// TNZO base units worth the fee at the committed rates, rounded up.
    #[serde(with = "tenzro_types::primitives::u128_serde")]
    pub tnzo_amount_wei: u128,
    /// Committed USD rate of the native asset, nano-USD per whole unit.
    #[serde(with = "tenzro_types::primitives::u128_serde")]
    pub native_rate_nano_usd: u128,
    /// Committed USD rate of TNZO, nano-USD per whole TNZO.
    #[serde(with = "tenzro_types::primitives::u128_serde")]
    pub tnzo_rate_nano_usd: u128,
    /// Epoch the native asset's rate was committed for.
    pub rate_epoch: Option<u64>,
    /// Issue time, ms since the Unix epoch.
    pub issued_at_ms: u64,
    /// Expiry, ms since the Unix epoch.
    pub valid_until_ms: u64,
}

impl BridgeFeeQuote {
    /// A quote over committed rates, its id derived from its inputs.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        adapter: BridgeRouteAdapter,
        dest_chain: &str,
        native_symbol: &str,
        native_fee_smallest_unit: u128,
        tnzo_amount_wei: u128,
        native_rate_nano_usd: u128,
        tnzo_rate_nano_usd: u128,
        rate_epoch: Option<u64>,
        issued_at_ms: u64,
    ) -> Self {
        let mut h = Sha256::new();
        h.update(b"tenzro/bridge-fee-quote/v2");
        h.update(adapter.as_str().as_bytes());
        h.update([0]);
        h.update(dest_chain.as_bytes());
        h.update([0]);
        h.update(native_fee_smallest_unit.to_be_bytes());
        h.update(tnzo_amount_wei.to_be_bytes());
        h.update(native_rate_nano_usd.to_be_bytes());
        h.update(tnzo_rate_nano_usd.to_be_bytes());
        h.update(rate_epoch.unwrap_or(u64::MAX).to_be_bytes());
        h.update(issued_at_ms.to_be_bytes());
        Self {
            quote_id_hex: format!("0x{}", hex::encode(h.finalize())),
            adapter,
            dest_chain: dest_chain.to_string(),
            native_symbol: native_symbol.to_string(),
            native_fee_smallest_unit,
            tnzo_amount_wei,
            native_rate_nano_usd,
            tnzo_rate_nano_usd,
            rate_epoch,
            issued_at_ms,
            valid_until_ms: issued_at_ms.saturating_add(QUOTE_VALID_MS),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quote_id_binds_the_inputs() {
        let a = BridgeFeeQuote::new(
            BridgeRouteAdapter::Ccip,
            "eip155:1",
            "ETH",
            10,
            20,
            3,
            4,
            Some(5),
            6,
        );
        let b = BridgeFeeQuote::new(
            BridgeRouteAdapter::Ccip,
            "eip155:1",
            "ETH",
            10,
            21,
            3,
            4,
            Some(5),
            6,
        );
        assert_ne!(a.quote_id_hex, b.quote_id_hex);
        assert_eq!(a.valid_until_ms, 6 + QUOTE_VALID_MS);
    }
}
