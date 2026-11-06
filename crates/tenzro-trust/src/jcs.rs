//! RFC 8785 JSON Canonicalization Scheme.
//!
//! Signed agent cards and the DID envelope's body digest are computed over
//! the JCS form of a JSON value, so a producer and a verifier written in
//! different languages hash the same bytes. Three rules make the form
//! canonical:
//!
//! - object members are sorted by the UTF-16 code units of their names;
//! - numbers are IEEE-754 doubles rendered with the ECMAScript
//!   `Number.prototype.toString` algorithm (shortest round-trip digits);
//! - strings use the minimal `JSON.stringify` escaping: `\"`, `\\`, the
//!   short forms `\b \f \n \r \t`, `\u00xx` (lowercase) for the remaining
//!   control characters, and every other code point written as itself.
//!
//! Every signed trust document, agent card and DID envelope body is hashed
//! in this form.

use serde_json::Value;

/// A value that has no JCS representation.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum JcsError {
    /// NaN and the infinities are not JSON numbers.
    #[error("number {0} is not finite and has no JSON form")]
    NonFiniteNumber(String),
}

/// Canonical UTF-8 text of `value`.
pub fn canonicalize(value: &Value) -> Result<String, JcsError> {
    let mut out = String::new();
    write_value(value, &mut out)?;
    Ok(out)
}

/// [`canonicalize`] as bytes. Every JSON number `serde_json` parses is
/// finite, so a parsed document always has a canonical form; a value built
/// in code with a non-finite number yields no bytes.
pub fn canonical_json(value: &Value) -> Vec<u8> {
    canonicalize(value)
        .map(String::into_bytes)
        .unwrap_or_default()
}

/// Whether `value` contains a number that is not an integer. Trust documents
/// carry integers only and are refused when they hold anything else.
pub fn has_fractional_number(value: &Value) -> bool {
    match value {
        Value::Number(n) => !(n.is_i64() || n.is_u64()),
        Value::Array(items) => items.iter().any(has_fractional_number),
        Value::Object(map) => map.values().any(has_fractional_number),
        _ => false,
    }
}

fn write_value(value: &Value, out: &mut String) -> Result<(), JcsError> {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(n) => {
            // JCS serialises every number as the double it denotes, including
            // integers that serde_json holds exactly as u64/i64.
            let f = n
                .as_f64()
                .ok_or_else(|| JcsError::NonFiniteNumber(n.to_string()))?;
            out.push_str(&format_number(f)?);
        }
        Value::String(s) => write_string(s, out),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(item, out)?;
            }
            out.push(']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
            out.push('{');
            for (i, key) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_string(key, out);
                out.push(':');
                write_value(&map[*key], out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

fn write_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

/// ECMAScript `Number.prototype.toString` for a finite double.
///
/// Rust's `{:e}` formatting yields the shortest digit string that round-trips
/// to the same double, which is the digit selection ECMAScript specifies; the
/// remaining work is placing the decimal point or choosing exponent form by
/// the ECMAScript thresholds.
fn format_number(f: f64) -> Result<String, JcsError> {
    if !f.is_finite() {
        return Err(JcsError::NonFiniteNumber(f.to_string()));
    }
    if f == 0.0 {
        // Covers negative zero, which ECMAScript renders as "0".
        return Ok("0".to_string());
    }
    let sci = format!("{:e}", f.abs());
    let (mantissa, exponent) = sci
        .split_once('e')
        .expect("LowerExp output always carries an exponent");
    let exponent: i32 = exponent
        .parse()
        .expect("LowerExp exponent is a decimal integer");
    let digits = even_on_tie(
        f.abs(),
        mantissa.chars().filter(|c| *c != '.').collect(),
        exponent,
    );
    let k = digits.len() as i32;
    // `n` is the position of the decimal point relative to the digit string:
    // the value is 0.d1d2...dk x 10^n.
    let n = exponent + 1;

    let mut out = String::new();
    if f < 0.0 {
        out.push('-');
    }
    if k <= n && n <= 21 {
        out.push_str(&digits);
        out.extend(std::iter::repeat_n('0', (n - k) as usize));
    } else if 0 < n && n <= 21 {
        out.push_str(&digits[..n as usize]);
        out.push('.');
        out.push_str(&digits[n as usize..]);
    } else if -6 < n && n <= 0 {
        out.push_str("0.");
        out.extend(std::iter::repeat_n('0', (-n) as usize));
        out.push_str(&digits);
    } else {
        out.push_str(&digits[..1]);
        if k > 1 {
            out.push('.');
            out.push_str(&digits[1..]);
        }
        out.push('e');
        let e = n - 1;
        out.push(if e < 0 { '-' } else { '+' });
        out.push_str(&e.abs().to_string());
    }
    Ok(out)
}

/// ECMAScript's tie rule for the shortest digits.
///
/// When the double lies exactly halfway between two `k`-digit strings that
/// both round-trip, ECMAScript takes the even one; the shortest-digit
/// formatter may return the other. `digits` (with decimal exponent
/// `exponent` of its first digit) is swapped for its even neighbour in
/// that case.
fn even_on_tie(f: f64, digits: String, exponent: i32) -> String {
    let k = digits.len();
    let last = digits.as_bytes()[k - 1] - b'0';
    if last.is_multiple_of(2) {
        return digits;
    }
    // The exact decimal expansion of the double: 767 significant digits
    // cover every finite f64.
    let exact = format!("{:.766e}", f);
    let (exact_mantissa, exact_exp) = exact.split_once('e').expect("LowerExp exponent");
    if exact_exp.parse::<i32>().ok() != Some(exponent) {
        return digits;
    }
    let exact_digits: Vec<u8> = exact_mantissa.bytes().filter(|b| *b != b'.').collect();
    let rest = &exact_digits[k..];
    let is_tie = rest.first() == Some(&b'5') && rest[1..].iter().all(|b| *b == b'0');
    if !is_tie {
        return digits;
    }
    let lower = String::from_utf8(exact_digits[..k].to_vec()).expect("ascii digits");
    let candidate = if lower == digits {
        // Rust returned the lower neighbour, so the even one is above it.
        let mut n: u128 = lower.parse().expect("digits");
        n += 1;
        n.to_string()
    } else {
        lower
    };
    if candidate.len() != k {
        return digits;
    }
    let text = if k == 1 {
        format!("{candidate}e{exponent}")
    } else {
        format!("{}.{}e{}", &candidate[..1], &candidate[1..], exponent)
    };
    if text.parse::<f64>().ok() == Some(f) {
        candidate
    } else {
        digits
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn num(bits: u64) -> String {
        format_number(f64::from_bits(bits)).unwrap()
    }

    /// Number vectors from RFC 8785 Appendix B.
    #[test]
    fn rfc8785_number_vectors() {
        let vectors: &[(u64, &str)] = &[
            (0x0000000000000000, "0"),
            (0x8000000000000000, "0"),
            (0x0000000000000001, "5e-324"),
            (0x8000000000000001, "-5e-324"),
            (0x7fefffffffffffff, "1.7976931348623157e+308"),
            (0xffefffffffffffff, "-1.7976931348623157e+308"),
            (0x4340000000000000, "9007199254740992"),
            (0xc340000000000000, "-9007199254740992"),
            (0x4430000000000000, "295147905179352830000"),
            (0x44b52d02c7e14af5, "9.999999999999997e+22"),
            (0x44b52d02c7e14af6, "1e+23"),
            (0x44b52d02c7e14af7, "1.0000000000000001e+23"),
            (0x444b1ae4d6e2ef4e, "999999999999999700000"),
            (0x444b1ae4d6e2ef4f, "999999999999999900000"),
            (0x444b1ae4d6e2ef50, "1e+21"),
            (0x3eb0c6f7a0b5ed8c, "9.999999999999997e-7"),
            (0x3eb0c6f7a0b5ed8d, "0.000001"),
            (0x41b3de4355555553, "333333333.3333332"),
            (0x41b3de4355555554, "333333333.33333325"),
            (0x41b3de4355555555, "333333333.3333333"),
            (0x41b3de4355555556, "333333333.3333334"),
            (0x41b3de4355555557, "333333333.33333343"),
            (0xbecbf647612f3696, "-0.0000033333333333333333"),
            (0x43143ff3c1cb0959, "1424953923781206.2"),
        ];
        for (bits, expected) in vectors {
            assert_eq!(&num(*bits), expected, "bits {bits:#018x}");
        }
    }

    /// The worked example from RFC 8785 section 3.2.2.
    #[test]
    fn rfc8785_sample_object() {
        let input = r#"{
            "numbers": [333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001],
            "string": "\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"\/",
            "literals": [null, true, false]
        }"#;
        let value: Value = serde_json::from_str(input).unwrap();
        let expected = "{\"literals\":[null,true,false],\
            \"numbers\":[333333333.3333333,1e+30,4.5,0.002,1e-27],\
            \"string\":\"\u{20ac}$\\u000f\\nA'B\\\"\\\\\\\\\\\"/\"}";
        assert_eq!(canonicalize(&value).unwrap(), expected);
    }

    /// Member ordering by UTF-16 code units, from RFC 8785 section 3.2.3: the
    /// astral-plane key sorts by its high surrogate, ahead of U+FB33.
    #[test]
    fn rfc8785_utf16_member_ordering() {
        let input = "{\"\u{20ac}\":\"Euro Sign\",\"\\r\":\"Carriage Return\",\
            \"\u{fb33}\":\"Hebrew Letter Dalet With Dagesh\",\"1\":\"One\",\
            \"\u{1f600}\":\"Emoji: Grinning Face\",\"\u{0080}\":\"Control\",\
            \"\u{00f6}\":\"Latin Small Letter O With Diaeresis\"}";
        let value: Value = serde_json::from_str(input).unwrap();
        let canon = canonicalize(&value).unwrap();
        let order: Vec<&str> = [
            "Carriage Return",
            "One",
            "Control",
            "Latin Small Letter O With Diaeresis",
            "Euro Sign",
            "Emoji: Grinning Face",
            "Hebrew Letter Dalet With Dagesh",
        ]
        .to_vec();
        let mut last = 0;
        for label in order {
            let pos = canon.find(label).unwrap();
            assert!(pos >= last, "{label} out of order in {canon}");
            last = pos;
        }
    }

    #[test]
    fn integers_are_serialised_as_doubles() {
        // 2^53 + 1 has no double; it is written as the double it rounds to.
        let value = serde_json::json!({"a": 1, "b": -7, "c": 9_007_199_254_740_993u64, "d": 10_000_000_000_000_000_000u64});
        assert_eq!(
            canonicalize(&value).unwrap(),
            "{\"a\":1,\"b\":-7,\"c\":9007199254740992,\"d\":10000000000000000000}"
        );
    }

    #[test]
    fn whitespace_and_order_do_not_change_the_canonical_form() {
        let a: Value = serde_json::from_str(r#"{ "b" : [1, 2], "a" : "x" }"#).unwrap();
        let b: Value = serde_json::from_str(r#"{"a":"x","b":[1,2]}"#).unwrap();
        assert_eq!(canonicalize(&a).unwrap(), canonicalize(&b).unwrap());
    }

    #[test]
    fn keys_are_sorted_and_whitespace_dropped() {
        let v = serde_json::json!({"b": [1, {"d": true, "c": null}], "a": "x"});
        assert_eq!(
            canonical_json(&v),
            br#"{"a":"x","b":[1,{"c":null,"d":true}]}"#.to_vec()
        );
    }

    #[test]
    fn key_order_of_the_input_does_not_matter() {
        let a: Value = serde_json::from_str(r#"{"z":1,"y":{"q":2,"p":3}}"#).unwrap();
        let b: Value = serde_json::from_str(r#"{ "y" : { "p":3, "q":2 }, "z":1 }"#).unwrap();
        assert_eq!(canonical_json(&a), canonical_json(&b));
    }

    #[test]
    fn fractional_numbers_are_detected() {
        assert!(has_fractional_number(&serde_json::json!({"a": [1, 2.5]})));
        assert!(!has_fractional_number(&serde_json::json!({"a": [1, -2]})));
    }
}
