//! Settlement assets: the tokens other than TNZO that governance permits
//! payments to settle in.
//!
//! Each entry names the token, the symbol validators price it under, the
//! currency it is pegged to, and its governed limits. A payment in a token
//! with no entry, a disabled entry or a price outside the entry's par band
//! is refused; nothing settles in it until governance changes the entry.

use serde::{Deserialize, Serialize};

/// Least par band an entry may set, bps.
pub const MIN_PAR_BAND_BPS: u64 = 25;
/// Greatest par band an entry may set, bps.
pub const MAX_PAR_BAND_BPS: u64 = 300;
/// Par band a new entry starts with, bps.
pub const DEFAULT_PAR_BAND_BPS: u64 = 100;
/// Greatest value one asset may settle in one epoch, whole units.
pub const MAX_EPOCH_INFLOW_CAP_UNITS: u64 = 100_000_000;
/// Epoch inflow cap a new entry starts with, whole units.
pub const DEFAULT_EPOCH_INFLOW_CAP_UNITS: u64 = 1_000_000;
/// Least treasury share an entry may set, bps.
pub const MIN_TREASURY_SHARE_BPS: u64 = 1_000;
/// Greatest treasury share an entry may set, bps.
pub const MAX_TREASURY_SHARE_BPS: u64 = 7_000;
/// Treasury share a new entry starts with, bps.
pub const DEFAULT_TREASURY_SHARE_BPS: u64 = 5_000;
/// Greatest exposure ceiling an entry may set, bps of the treasury's value.
pub const MAX_EXPOSURE_BPS: u64 = 9_000;
/// Exposure ceiling a new entry starts with, bps of the treasury's value.
pub const DEFAULT_EXPOSURE_BPS: u64 = 7_500;
/// The currency every rate is quoted in, nano-units per whole unit of the
/// priced symbol.
pub const NUMERAIRE: &str = "USD";

/// A token payments may settle in, as governance installs it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementAsset {
    /// The token id, `0x` and 64 hex digits.
    pub token_id: String,
    /// The symbol validators report the token's rate under.
    pub symbol: String,
    /// The currency the token is pegged to (`USD`, `EUR`): its peg is
    /// checked against that currency's rate.
    pub currency: String,
    /// Decimals of the token's smallest unit.
    pub decimals: u8,
    /// Most the token's rate may sit from its currency's rate, bps of the
    /// currency's rate.
    pub par_band_bps: u64,
    /// Most value that may settle in the token in one epoch, whole units of
    /// account.
    pub epoch_inflow_cap_units: u64,
    /// Most of the treasury's stable holdings the token may make up, bps:
    /// the target payout swaps rebalance toward.
    pub max_treasury_share_bps: u64,
    /// Most of the treasury's whole value (TNZO and stable holdings) the
    /// token may make up, bps: past it, nothing that would add the token to
    /// the treasury settles. Above `max_treasury_share_bps`, so the target
    /// is reached long before the ceiling refuses anything.
    #[serde(default = "default_exposure_bps")]
    pub max_exposure_bps: u64,
    /// Whether payments may settle in it.
    pub enabled: bool,
}

impl SettlementAsset {
    /// An enabled entry with the genesis limits.
    pub fn new(token_id: &str, symbol: &str, currency: &str, decimals: u8) -> Self {
        Self {
            token_id: token_id.to_ascii_lowercase(),
            symbol: symbol.to_ascii_uppercase(),
            currency: currency.to_ascii_uppercase(),
            decimals,
            par_band_bps: DEFAULT_PAR_BAND_BPS,
            epoch_inflow_cap_units: DEFAULT_EPOCH_INFLOW_CAP_UNITS,
            max_treasury_share_bps: DEFAULT_TREASURY_SHARE_BPS,
            max_exposure_bps: DEFAULT_EXPOSURE_BPS,
            enabled: true,
        }
    }

    /// Storage key of the entry for the token `id`.
    pub fn storage_key(id: &[u8; 32]) -> String {
        format!("settlement_asset:{}", hex::encode(id))
    }

    /// The token id as bytes, when it is `0x` and 64 hex digits.
    pub fn token_bytes(&self) -> Option<[u8; 32]> {
        let hex_part = self.token_id.strip_prefix("0x")?;
        hex::decode(hex_part).ok()?.try_into().ok()
    }

    /// Whether the entry is usable: a 32-byte token id, symbols of 1 to 16
    /// upper-case letters and digits, at most 36 decimals, and every limit
    /// within its bounds.
    pub fn validate(&self) -> Result<(), String> {
        if self.token_bytes().is_none() {
            return Err(format!(
                "token id {:?} is not 0x and 64 hex digits",
                self.token_id
            ));
        }
        for (what, s) in [("symbol", &self.symbol), ("currency", &self.currency)] {
            if s.is_empty()
                || s.len() > 16
                || !s
                    .bytes()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
            {
                return Err(format!(
                    "{what} {s:?} is not 1 to 16 upper-case letters and digits"
                ));
            }
        }
        if self.symbol == "TNZO" {
            return Err("TNZO settles natively and is not a settlement asset".to_string());
        }
        if self.symbol == self.currency {
            return Err(format!("{} cannot be pegged to itself", self.symbol));
        }
        if self.decimals > 36 {
            return Err(format!("{} decimals is above 36", self.decimals));
        }
        let bounded = [
            (
                "par band",
                self.par_band_bps,
                MIN_PAR_BAND_BPS,
                MAX_PAR_BAND_BPS,
            ),
            (
                "epoch inflow cap",
                self.epoch_inflow_cap_units,
                0,
                MAX_EPOCH_INFLOW_CAP_UNITS,
            ),
            (
                "treasury share",
                self.max_treasury_share_bps,
                MIN_TREASURY_SHARE_BPS,
                MAX_TREASURY_SHARE_BPS,
            ),
            (
                "exposure ceiling",
                self.max_exposure_bps,
                MIN_TREASURY_SHARE_BPS,
                MAX_EXPOSURE_BPS,
            ),
        ];
        for (what, v, lo, hi) in bounded {
            if v < lo || v > hi {
                return Err(format!("{what} {v} is outside {lo}..={hi}"));
            }
        }
        if self.max_exposure_bps <= self.max_treasury_share_bps {
            return Err(format!(
                "exposure ceiling {} is not above the treasury share target {}",
                self.max_exposure_bps, self.max_treasury_share_bps
            ));
        }
        Ok(())
    }
}

fn default_exposure_bps() -> u64 {
    DEFAULT_EXPOSURE_BPS
}

/// Micro-units of a decimal price in the unit of account (`"0.25"` is
/// 250000): digits with at most six after the point, no sign or exponent,
/// greater than zero and within u64.
pub fn parse_price_e6(amount: &str) -> Result<u64, String> {
    let (whole, frac) = amount.split_once('.').unwrap_or((amount, ""));
    let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    if !digits(whole) || (amount.contains('.') && !digits(frac)) || frac.len() > 6 {
        return Err(format!(
            "price {amount:?} is not a decimal with at most six places"
        ));
    }
    let whole: u64 = whole
        .parse()
        .map_err(|_| format!("price {amount:?} is too large"))?;
    let frac: u64 = format!("{frac:0<6}").parse().unwrap_or(0);
    let e6 = whole
        .checked_mul(1_000_000)
        .and_then(|w| w.checked_add(frac))
        .ok_or_else(|| format!("price {amount:?} is too large"))?;
    if e6 == 0 {
        return Err("a price is greater than zero".to_string());
    }
    Ok(e6)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prices_parse_exactly_to_micro_units() {
        for (s, v) in [
            ("0.25", 250_000),
            ("1", 1_000_000),
            ("12.000001", 12_000_001),
            ("0.1", 100_000),
        ] {
            assert_eq!(parse_price_e6(s), Ok(v), "{s}");
        }
        for s in [
            "",
            ".5",
            "1.",
            "0",
            "0.0000001",
            "-1",
            "1e3",
            " 1",
            "1.2.3",
            "18446744073709.551616",
        ] {
            assert!(parse_price_e6(s).is_err(), "{s}");
        }
    }

    fn usdc() -> SettlementAsset {
        SettlementAsset::new(&format!("0x{}", "ab".repeat(32)), "usdc", "usd", 6)
    }

    #[test]
    fn a_new_entry_carries_the_genesis_limits_and_validates() {
        let a = usdc();
        assert_eq!(a.symbol, "USDC");
        assert_eq!(a.currency, "USD");
        assert_eq!(a.par_band_bps, DEFAULT_PAR_BAND_BPS);
        assert_eq!(a.epoch_inflow_cap_units, DEFAULT_EPOCH_INFLOW_CAP_UNITS);
        assert_eq!(a.max_treasury_share_bps, DEFAULT_TREASURY_SHARE_BPS);
        assert_eq!(a.max_exposure_bps, DEFAULT_EXPOSURE_BPS);
        assert!(a.enabled);
        assert_eq!(a.validate(), Ok(()));
        assert_eq!(a.token_bytes(), Some([0xab; 32]));
    }

    #[test]
    fn limits_outside_their_bounds_are_refused() {
        for f in [
            |a: &mut SettlementAsset| a.par_band_bps = MIN_PAR_BAND_BPS - 1,
            |a: &mut SettlementAsset| a.par_band_bps = MAX_PAR_BAND_BPS + 1,
            |a: &mut SettlementAsset| a.epoch_inflow_cap_units = MAX_EPOCH_INFLOW_CAP_UNITS + 1,
            |a: &mut SettlementAsset| a.max_treasury_share_bps = MIN_TREASURY_SHARE_BPS - 1,
            |a: &mut SettlementAsset| a.max_treasury_share_bps = MAX_TREASURY_SHARE_BPS + 1,
            |a: &mut SettlementAsset| a.decimals = 37,
            |a: &mut SettlementAsset| a.token_id = "0x12".into(),
            |a: &mut SettlementAsset| a.symbol = "TNZO".into(),
            |a: &mut SettlementAsset| a.currency = "usd".into(),
            |a: &mut SettlementAsset| a.currency = "USDC".into(),
        ] {
            let mut a = usdc();
            f(&mut a);
            assert!(a.validate().is_err(), "{a:?}");
        }
        let mut edge = usdc();
        edge.par_band_bps = MIN_PAR_BAND_BPS;
        edge.epoch_inflow_cap_units = 0;
        edge.max_treasury_share_bps = MAX_TREASURY_SHARE_BPS;
        assert_eq!(edge.validate(), Ok(()));
    }

    #[test]
    fn the_exposure_ceiling_sits_above_the_share_target_and_defaults_for_old_entries() {
        let mut a = usdc();
        a.max_exposure_bps = a.max_treasury_share_bps;
        assert!(
            a.validate()
                .unwrap_err()
                .contains("not above the treasury share target")
        );
        a.max_exposure_bps = MAX_EXPOSURE_BPS + 1;
        assert!(a.validate().unwrap_err().contains("exposure ceiling"));
        a.max_exposure_bps = MAX_EXPOSURE_BPS;
        assert_eq!(a.validate(), Ok(()));
        let mut old = serde_json::to_value(usdc()).unwrap();
        old.as_object_mut().unwrap().remove("max_exposure_bps");
        let read: SettlementAsset = serde_json::from_value(old).unwrap();
        assert_eq!(read.max_exposure_bps, DEFAULT_EXPOSURE_BPS);
    }
}
