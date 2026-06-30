//! Adapter bridging the VM's [`StableRateOracle`] to the payment gateway's
//! [`ConversionHook`].
//!
//! An agent may spend a stable unit while the payee settles in some token.
//! The gateway calls [`ConversionHook::convert`] between protocol settlement
//! and on-chain settle; this adapter resolves the rate via the oracle and
//! returns the converted amount plus the quote id for the receipt audit
//! trail. The quote's TTL is enforced here so a stale rate can't be replayed
//! across an FX move.

use std::sync::Arc;

use async_trait::async_trait;
use tenzro_payments::{Conversion, ConversionHook, PaymentError};
use tenzro_vm::stable_rate_oracle::{StableRateError, StableRateOracle};

/// Wraps a [`StableRateOracle`] so the payment gateway can convert a payer's
/// stable unit into the payee's asset. `from_asset == to_asset` is an
/// identity (no rate lookup), matching the direct-token settlement path.
pub struct OracleConversionHook {
    oracle: Arc<dyn StableRateOracle>,
}

impl OracleConversionHook {
    pub fn new(oracle: Arc<dyn StableRateOracle>) -> Self {
        Self { oracle }
    }
}

#[async_trait]
impl ConversionHook for OracleConversionHook {
    async fn convert(
        &self,
        from_asset: &str,
        to_asset: &str,
        amount: u128,
    ) -> std::result::Result<Conversion, PaymentError> {
        if from_asset == to_asset {
            return Ok(Conversion {
                amount_out: amount,
                to_asset: to_asset.to_string(),
                quote_ref: String::new(),
            });
        }

        let quote = self
            .oracle
            .quote(from_asset, to_asset, amount)
            .await
            .map_err(|e| match e {
                StableRateError::NoRate { asset, unit } => PaymentError::SettlementError(
                    format!("no conversion rate for {asset} -> {unit}"),
                ),
                StableRateError::Overflow { .. } => {
                    PaymentError::SettlementError(format!("conversion overflow: {e}"))
                }
            })?;

        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        if quote.valid_until_ms != 0 && now_ms > quote.valid_until_ms {
            return Err(PaymentError::SettlementError(format!(
                "stale conversion quote {} (expired at {}ms)",
                quote.quote_id_hex, quote.valid_until_ms
            )));
        }

        Ok(Conversion {
            amount_out: quote.amount_out,
            to_asset: to_asset.to_string(),
            quote_ref: quote.quote_id_hex,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_vm::stable_rate_oracle::{GovernanceSetRateOracle, RateRow};

    const Q18: u128 = 1_000_000_000_000_000_000;

    fn oracle_with_rate() -> Arc<GovernanceSetRateOracle> {
        let o = GovernanceSetRateOracle::new();
        // 1 USDX = 1 USDC, 50 bps spread, 60s validity.
        o.set_rate(RateRow {
            asset: "USDX".into(),
            unit: "USDC".into(),
            rate_q18: Q18,
            spread_bps: 50,
            valid_window_ms: 60_000,
            updated_at_ms: 0,
        });
        Arc::new(o)
    }

    #[tokio::test]
    async fn identity_passes_through_without_lookup() {
        // Oracle has no rate for this pair; identity must not consult it.
        let hook = OracleConversionHook::new(Arc::new(GovernanceSetRateOracle::new()));
        let c = hook.convert("USDC", "USDC", 1_000).await.unwrap();
        assert_eq!(c.amount_out, 1_000);
        assert_eq!(c.to_asset, "USDC");
        assert!(c.quote_ref.is_empty());
    }

    #[tokio::test]
    async fn converts_via_oracle_with_quote_ref() {
        let hook = OracleConversionHook::new(oracle_with_rate());
        let c = hook.convert("USDX", "USDC", 1_000_000).await.unwrap();
        // 50 bps spread off 1:1 → 995_000.
        assert_eq!(c.amount_out, 995_000);
        assert_eq!(c.to_asset, "USDC");
        assert!(c.quote_ref.starts_with("0x"));
    }

    #[tokio::test]
    async fn missing_rate_is_settlement_error() {
        let hook = OracleConversionHook::new(oracle_with_rate());
        let err = hook.convert("DAI", "USDC", 1_000).await.unwrap_err();
        assert!(matches!(err, PaymentError::SettlementError(_)));
    }
}
