//! TNZO ↔ wei conversion helpers.
//!
//! The Tenzro RPC surface expresses all amounts in **wei** (10^-18 TNZO),
//! matching the standard smallest-unit convention. The CLI accepts
//! human-friendly decimal TNZO input (e.g. `100`, `100.5`, `0.0001`) and
//! converts it to a wei decimal string before dispatching the RPC call.
//!
//! Float-based scaling is rejected — at 18 decimals, anything above ~9 TNZO
//! loses precision through f64. We parse the input as a string, split on the
//! decimal point, and scale exactly.

use anyhow::{anyhow, Result};

const DECIMALS: u32 = 18;

/// Convert a human-friendly TNZO amount string (e.g. `"100"`, `"100.5"`,
/// `"0.0001"`) to a wei decimal string suitable for RPC.
///
/// - Rejects negatives, scientific notation, and >18 fractional digits.
/// - Accepts an optional leading `+`.
/// - Returns the wei value as a decimal string (no leading zeros).
pub fn tnzo_to_wei_string(input: &str) -> Result<String> {
    let s = input.trim();
    let s = s.strip_prefix('+').unwrap_or(s);

    if s.is_empty() {
        return Err(anyhow!("empty amount"));
    }
    if s.starts_with('-') {
        return Err(anyhow!("negative amount: {}", input));
    }
    if s.contains(['e', 'E']) {
        return Err(anyhow!(
            "scientific notation not supported: {} (use plain decimal)",
            input
        ));
    }

    let (whole, frac) = match s.split_once('.') {
        Some((w, f)) => (w, f),
        None => (s, ""),
    };

    if !whole.chars().all(|c| c.is_ascii_digit()) || (whole.is_empty() && frac.is_empty()) {
        return Err(anyhow!("invalid TNZO amount: {}", input));
    }
    if !frac.chars().all(|c| c.is_ascii_digit()) {
        return Err(anyhow!("invalid TNZO amount: {}", input));
    }
    if frac.len() > DECIMALS as usize {
        return Err(anyhow!(
            "too many decimal places (max {}): {}",
            DECIMALS,
            input
        ));
    }

    // Pad fractional part to 18 digits. Then concatenate.
    let padded_frac = format!("{:0<width$}", frac, width = DECIMALS as usize);
    let combined = format!("{}{}", whole, padded_frac);
    // Strip leading zeros, keep at least one digit.
    let trimmed = combined.trim_start_matches('0');
    let result = if trimmed.is_empty() {
        "0".to_string()
    } else {
        trimmed.to_string()
    };

    // Validate the result actually fits u128 by parsing it.
    result
        .parse::<u128>()
        .map_err(|_| anyhow!("amount overflows u128: {}", input))?;

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn whole_tnzo() {
        assert_eq!(tnzo_to_wei_string("1").unwrap(), "1000000000000000000");
        assert_eq!(tnzo_to_wei_string("100").unwrap(), "100000000000000000000");
        assert_eq!(tnzo_to_wei_string("1000").unwrap(), "1000000000000000000000");
    }

    #[test]
    fn fractional_tnzo() {
        assert_eq!(tnzo_to_wei_string("1.5").unwrap(), "1500000000000000000");
        assert_eq!(tnzo_to_wei_string("0.5").unwrap(), "500000000000000000");
        assert_eq!(tnzo_to_wei_string("0.000000000000000001").unwrap(), "1");
    }

    #[test]
    fn zero() {
        assert_eq!(tnzo_to_wei_string("0").unwrap(), "0");
        assert_eq!(tnzo_to_wei_string("0.0").unwrap(), "0");
    }

    #[test]
    fn rejects_invalid() {
        assert!(tnzo_to_wei_string("").is_err());
        assert!(tnzo_to_wei_string("-1").is_err());
        assert!(tnzo_to_wei_string("1e18").is_err());
        assert!(tnzo_to_wei_string("1.0000000000000000001").is_err()); // 19 frac digits
        assert!(tnzo_to_wei_string("abc").is_err());
        assert!(tnzo_to_wei_string("1.2.3").is_err());
    }

    #[test]
    fn no_truncation_above_u64() {
        // 10^23 wei = 100,000 TNZO — well above u64::MAX.
        assert_eq!(
            tnzo_to_wei_string("100000").unwrap(),
            "100000000000000000000000"
        );
    }
}
