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

use anyhow::{Result, anyhow};

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

/// Whole TNZO at or above which a bare integer is refused as probably wei.
///
/// No supply the network will ever hold reaches a trillion TNZO, so a bare
/// integer this large was written in wei. Taking it as TNZO would ask for an
/// amount of 10^30 wei or more; refusing it names the suffix the writer needs.
const BARE_TNZO_CEILING: u128 = 1_000_000_000_000;

/// Parse an amount typed on a command line into wei.
///
/// Accepted forms:
///
/// - `10000` or `10000 TNZO` or `10000tnzo`: whole TNZO.
/// - `0.5` or `0.5tnzo`: fractional TNZO, exact to 18 places.
/// - `250000000000000000wei`: wei, with the `wei` suffix.
///
/// A bare number is TNZO. A bare integer of 10^12 or more is refused rather
/// than guessed at, because it can only be a wei amount written without its
/// suffix.
pub fn parse_amount_wei(input: &str) -> std::result::Result<u128, String> {
    let lowered = input.trim().to_ascii_lowercase();
    if let Some(wei) = lowered.strip_suffix("wei") {
        let wei = wei.trim();
        if wei.is_empty() || !wei.chars().all(|c| c.is_ascii_digit()) {
            return Err(format!("invalid wei amount: {input}"));
        }
        return wei
            .parse::<u128>()
            .map_err(|_| format!("amount overflows u128: {input}"));
    }
    let tnzo = lowered
        .strip_suffix("tnzo")
        .map(str::trim)
        .unwrap_or(&lowered);
    if !tnzo.is_empty()
        && tnzo.chars().all(|c| c.is_ascii_digit())
        && tnzo
            .parse::<u128>()
            .is_ok_and(|whole| whole >= BARE_TNZO_CEILING)
    {
        return Err(format!(
            "{input} is too large to be a TNZO amount; if it is wei, write it as \"{tnzo}wei\""
        ));
    }
    tnzo_to_wei_string(tnzo)
        .map_err(|e| e.to_string())?
        .parse::<u128>()
        .map_err(|_| format!("amount overflows u128: {input}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_amount_typed_back_matches_the_amount_parsed() {
        for a in [
            "5050",
            "0.1",
            "1234.567890123456789",
            "9999.999999999999999999",
            "10000",
        ] {
            let wei = parse_amount_wei(a).unwrap();
            assert!(
                tenzro_types::transfer_policy::amount_confirmation_matches(wei, a),
                "{a}"
            );
        }
        assert_eq!(parse_amount_wei("5050").unwrap(), 5_050 * 10u128.pow(18));
    }

    #[test]
    fn whole_tnzo() {
        assert_eq!(tnzo_to_wei_string("1").unwrap(), "1000000000000000000");
        assert_eq!(tnzo_to_wei_string("100").unwrap(), "100000000000000000000");
        assert_eq!(
            tnzo_to_wei_string("1000").unwrap(),
            "1000000000000000000000"
        );
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

    #[test]
    fn amounts_accept_tnzo_and_wei() {
        let one = 1_000_000_000_000_000_000u128;
        assert_eq!(parse_amount_wei("10000").unwrap(), 10_000 * one);
        assert_eq!(parse_amount_wei("10000 TNZO").unwrap(), 10_000 * one);
        assert_eq!(parse_amount_wei("10000tnzo").unwrap(), 10_000 * one);
        assert_eq!(parse_amount_wei(" 0.5 tnzo ").unwrap(), one / 2);
        assert_eq!(parse_amount_wei("250wei").unwrap(), 250);
        assert_eq!(
            parse_amount_wei("400000000000000000000wei").unwrap(),
            400 * one
        );
    }

    #[test]
    fn a_bare_wei_sized_integer_is_refused_not_guessed() {
        let err = parse_amount_wei("400000000000000000000").unwrap_err();
        assert!(err.contains("400000000000000000000wei"), "{err}");
        assert!(parse_amount_wei("999999999999").is_ok());
    }

    #[test]
    fn amounts_reject_garbage() {
        assert!(parse_amount_wei("").is_err());
        assert!(parse_amount_wei("tnzo").is_err());
        assert!(parse_amount_wei("wei").is_err());
        assert!(parse_amount_wei("-5").is_err());
        assert!(parse_amount_wei("1.5wei").is_err());
        assert!(parse_amount_wei("ten").is_err());
    }
}
