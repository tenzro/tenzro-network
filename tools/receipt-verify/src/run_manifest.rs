//! The digest of a harness run manifest, implemented from
//! `docs/standards/run-manifest.md`.

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

/// Domain tag the preimage starts with.
pub const RUN_MANIFEST_DOMAIN: &[u8] = b"tenzro/run-manifest/v1";

const MAX_BYTES: usize = 65_536;
const MAX_INPUTS: usize = 64;
const MAX_OUTPUTS: usize = 64;
const MAX_CLAIMS: usize = 32;
const MAX_INTERACTIONS: usize = 256;
const MAX_TEXT: usize = 256;

/// Why a manifest has no digest.
#[derive(Debug, PartialEq, Eq)]
pub enum RunManifestError {
    /// A member is missing, has the wrong type or breaks a rule.
    Malformed(String),
    /// A bound is passed.
    TooLarge(String),
    /// `outputs` is empty: the manifest states no useful output.
    NoOutput,
}

impl RunManifestError {
    /// The reason as the vectors name it.
    pub fn reason(&self) -> &'static str {
        match self {
            RunManifestError::Malformed(_) => "malformed",
            RunManifestError::TooLarge(_) => "too_large",
            RunManifestError::NoOutput => "no_output",
        }
    }
}

impl std::fmt::Display for RunManifestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RunManifestError::Malformed(why) | RunManifestError::TooLarge(why) => {
                write!(f, "not a run manifest: {why}")
            }
            RunManifestError::NoOutput => write!(f, "not a run manifest: `outputs` is empty"),
        }
    }
}

impl std::error::Error for RunManifestError {}

fn malformed(why: impl Into<String>) -> RunManifestError {
    RunManifestError::Malformed(why.into())
}

fn object<'a>(v: &'a Value, what: &str) -> Result<&'a Map<String, Value>, RunManifestError> {
    v.as_object()
        .ok_or_else(|| malformed(format!("{what} is not an object")))
}

fn text<'a>(
    at: &'a Map<String, Value>,
    key: &str,
    what: &str,
    non_empty: bool,
) -> Result<&'a str, RunManifestError> {
    let s = at
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| malformed(format!("`{what}` is not a string")))?;
    if non_empty && s.is_empty() {
        return Err(malformed(format!("`{what}` is empty")));
    }
    if s.len() > MAX_TEXT {
        return Err(RunManifestError::TooLarge(format!(
            "`{what}` is longer than {MAX_TEXT} bytes"
        )));
    }
    Ok(s)
}

fn digest(v: Option<&Value>, what: &str) -> Result<[u8; 32], RunManifestError> {
    let bad = || malformed(format!("`{what}` is not a non-zero lower-case hex digest"));
    let s = v.and_then(Value::as_str).ok_or_else(bad)?;
    if s.len() != 64
        || !s
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(bad());
    }
    let mut out = [0u8; 32];
    hex::decode_to_slice(s, &mut out).map_err(|_| bad())?;
    if out == [0u8; 32] {
        return Err(bad());
    }
    Ok(out)
}

fn whole(v: Option<&Value>, max: u64, what: &str) -> Result<u64, RunManifestError> {
    v.and_then(Value::as_u64)
        .filter(|n| *n <= max)
        .ok_or_else(|| malformed(format!("`{what}` is not a whole number")))
}

fn list<'a>(
    at: &'a Map<String, Value>,
    key: &str,
    max: usize,
) -> Result<&'a Vec<Value>, RunManifestError> {
    let v = at
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| malformed(format!("`{key}` is not a list")))?;
    if v.len() > max {
        return Err(RunManifestError::TooLarge(format!(
            "`{key}` has more than {max} entries"
        )));
    }
    Ok(v)
}

fn field(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(bytes);
}

fn named(
    out: &mut Vec<u8>,
    entries: &[Value],
    what: &str,
    with_bytes: bool,
) -> Result<(), RunManifestError> {
    out.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    let mut seen = std::collections::BTreeSet::new();
    for (i, entry) in entries.iter().enumerate() {
        let e = object(entry, &format!("{what}[{i}]"))?;
        let name = text(e, "name", &format!("{what}[{i}].name"), true)?;
        if !seen.insert(name) {
            return Err(malformed(format!("`{what}` names `{name}` twice")));
        }
        field(out, name.as_bytes());
        field(
            out,
            &digest(e.get("digest"), &format!("{what}[{i}].digest"))?,
        );
        if with_bytes {
            let bytes = whole(e.get("bytes"), u64::MAX, &format!("{what}[{i}].bytes"))?;
            out.extend_from_slice(&bytes.to_le_bytes());
        }
    }
    Ok(())
}

fn is_decimal(s: &str) -> bool {
    let (int, frac) = match s.split_once('.') {
        Some((i, f)) => (i, Some(f)),
        None => (s, None),
    };
    let int_ok = int == "0"
        || (!int.is_empty() && !int.starts_with('0') && int.bytes().all(|b| b.is_ascii_digit()));
    int_ok && frac.is_none_or(|f| !f.is_empty() && f.bytes().all(|b| b.is_ascii_digit()))
}

/// The bytes the digest is taken over, from the manifest's JSON text.
pub fn run_manifest_preimage(raw: &str) -> Result<Vec<u8>, RunManifestError> {
    if raw.len() > MAX_BYTES {
        return Err(RunManifestError::TooLarge(format!(
            "the manifest is longer than {MAX_BYTES} bytes"
        )));
    }
    let value: Value =
        serde_json::from_str(raw).map_err(|e| malformed(format!("not JSON: {e}")))?;
    let m = object(&value, "the manifest")?;
    let started = whole(m.get("started_at_ms"), i64::MAX as u64, "started_at_ms")?;
    let ended = whole(m.get("ended_at_ms"), i64::MAX as u64, "ended_at_ms")?;
    if ended < started {
        return Err(malformed("`ended_at_ms` is before `started_at_ms`"));
    }
    let inputs = list(m, "inputs", MAX_INPUTS)?;
    let outputs = list(m, "outputs", MAX_OUTPUTS)?;
    let claims = list(m, "claims", MAX_CLAIMS)?;
    let interactions = list(m, "interactions", MAX_INTERACTIONS)?;
    if outputs.is_empty() {
        return Err(RunManifestError::NoOutput);
    }
    let mut out = RUN_MANIFEST_DOMAIN.to_vec();
    field(&mut out, text(m, "run_id", "run_id", true)?.as_bytes());
    field(
        &mut out,
        text(m, "operator_did", "operator_did", true)?.as_bytes(),
    );
    field(
        &mut out,
        &digest(m.get("harness_module"), "harness_module")?,
    );
    out.extend_from_slice(&started.to_le_bytes());
    out.extend_from_slice(&ended.to_le_bytes());
    named(&mut out, inputs, "inputs", false)?;
    named(&mut out, outputs, "outputs", true)?;
    out.extend_from_slice(&(claims.len() as u32).to_le_bytes());
    for (i, claim) in claims.iter().enumerate() {
        let c = object(claim, &format!("claims[{i}]"))?;
        let metric = text(c, "metric", &format!("claims[{i}].metric"), true)?;
        let value = text(c, "value", &format!("claims[{i}].value"), true)?;
        if !is_decimal(value) {
            return Err(malformed(format!(
                "`claims[{i}].value` is not a decimal number"
            )));
        }
        let unit = text(c, "unit", &format!("claims[{i}].unit"), false)?;
        for part in [metric, value, unit] {
            field(&mut out, part.as_bytes());
        }
    }
    out.extend_from_slice(&(interactions.len() as u32).to_le_bytes());
    for (i, d) in interactions.iter().enumerate() {
        field(&mut out, &digest(Some(d), &format!("interactions[{i}]"))?);
    }
    Ok(out)
}

/// The manifest's digest, lowercase hex: the registry anchor of its run.
pub fn run_manifest_digest(raw: &str) -> Result<String, RunManifestError> {
    Ok(hex::encode(Sha256::digest(run_manifest_preimage(raw)?)))
}

#[cfg(test)]
mod tests {
    use super::is_decimal;

    #[test]
    fn a_claim_value_is_a_plain_decimal() {
        for ok in ["0", "12", "0.5", "1200", "3.14"] {
            assert!(is_decimal(ok), "{ok}");
        }
        for bad in ["", "01", "1.", ".5", "+1", "-1", "1e3", "1.2.3"] {
            assert!(!is_decimal(bad), "{bad}");
        }
    }
}
