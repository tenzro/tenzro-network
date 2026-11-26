//! The digest of a Tenzro interaction record, implemented from
//! `docs/standards/interaction-receipt.md`.

use serde_json::Value;
use sha2::{Digest, Sha256};

/// Domain tag the preimage starts with.
pub const INTERACTION_DOMAIN: &[u8] = b"tenzro/interaction-attestation/v2";

const KINDS: [&str; 9] = [
    "inference",
    "rental",
    "storage",
    "database",
    "hosting",
    "security",
    "marketplace",
    "rpc_brokerage",
    "access",
];

/// Why a record has no digest.
#[derive(Debug, PartialEq, Eq)]
pub enum InteractionError {
    /// A field is missing, has the wrong JSON type or an unknown value.
    Malformed(String),
    /// The record is well formed but cannot be attested: it names no payer,
    /// attester or interaction, or its charge contradicts its amount.
    NotAttestable(String),
}

impl std::fmt::Display for InteractionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InteractionError::Malformed(why) => write!(f, "not an interaction record: {why}"),
            InteractionError::NotAttestable(why) => write!(f, "the record has no digest: {why}"),
        }
    }
}

impl std::error::Error for InteractionError {}

fn malformed(why: impl Into<String>) -> InteractionError {
    InteractionError::Malformed(why.into())
}

fn text<'a>(v: &'a Value, path: &str) -> Result<&'a str, InteractionError> {
    let mut at = v;
    for key in path.split('.') {
        at = at
            .get(key)
            .ok_or_else(|| malformed(format!("`{path}` is missing")))?;
    }
    at.as_str()
        .ok_or_else(|| malformed(format!("`{path}` is not a string")))
}

/// The amount in wei: a JSON number up to 2^64 - 1, or a string of decimal
/// digits for any value (writers use the string only above 2^64 - 1).
fn amount(record: &Value) -> Result<u128, InteractionError> {
    match record.get("amount_charged") {
        Some(Value::Number(n)) => n
            .as_u64()
            .map(u128::from)
            .ok_or_else(|| malformed("`amount_charged` is not a whole number")),
        Some(Value::String(s)) if !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) => s
            .parse()
            .map_err(|_| malformed("`amount_charged` does not fit 128 bits")),
        Some(_) => Err(malformed(
            "`amount_charged` is not a number or a decimal string",
        )),
        None => Err(malformed("`amount_charged` is missing")),
    }
}

/// The bytes the digest is taken over.
pub fn interaction_preimage(record: &Value) -> Result<Vec<u8>, InteractionError> {
    let kind = text(record, "kind")?;
    if !KINDS.contains(&kind) {
        return Err(malformed(format!("`{kind}` is not an interaction kind")));
    }
    let on_behalf_of = match record.get("on_behalf_of") {
        None | Some(Value::Null) => "",
        Some(Value::String(s)) => s,
        Some(_) => return Err(malformed("`on_behalf_of` is not a string")),
    };
    let authority_kind = text(record, "authority.kind")?;
    let authority_value = match authority_kind {
        "delegation" => text(record, "authority.controller_did")?,
        "x402_payment" => text(record, "authority.scheme")?,
        "credential" => text(record, "authority.digest")?,
        "open" => "",
        other => return Err(malformed(format!("`{other}` is not an authority kind"))),
    };
    let charge_kind = text(record, "charge.kind")?;
    let charge_value = match charge_kind {
        "settlement" => text(record, "charge.settlement_id")?.to_string(),
        "channel" => {
            let nonce = record["charge"]
                .get("nonce")
                .and_then(Value::as_u64)
                .ok_or_else(|| malformed("`charge.nonce` is not a whole number"))?;
            format!("{}:{nonce}", text(record, "charge.channel_id")?)
        }
        "accrued" => text(record, "charge.accrued_wei")?.to_string(),
        "free" => String::new(),
        other => return Err(malformed(format!("`{other}` is not a charge kind"))),
    };
    let amount = amount(record)?;
    let occurred_at = record
        .get("occurred_at")
        .and_then(Value::as_i64)
        .ok_or_else(|| malformed("`occurred_at` is not an integer"))?;
    let (interaction_id, payer_did, attester_did) = (
        text(record, "interaction_id")?,
        text(record, "payer_did")?,
        text(record, "attester_did")?,
    );
    for (name, value) in [
        ("payer_did", payer_did),
        ("attester_did", attester_did),
        ("interaction_id", interaction_id),
    ] {
        if value.is_empty() {
            return Err(InteractionError::NotAttestable(format!(
                "`{name}` is empty"
            )));
        }
    }
    if (charge_kind == "free") != (amount == 0) {
        return Err(InteractionError::NotAttestable(format!(
            "a `{charge_kind}` charge of {amount} wei"
        )));
    }
    let amount = amount.to_string();
    let occurred_at = occurred_at.to_le_bytes();
    let mut out = INTERACTION_DOMAIN.to_vec();
    for field in [
        interaction_id.as_bytes(),
        kind.as_bytes(),
        payer_did.as_bytes(),
        on_behalf_of.as_bytes(),
        attester_did.as_bytes(),
        text(record, "resource_id")?.as_bytes(),
        authority_kind.as_bytes(),
        authority_value.as_bytes(),
        charge_kind.as_bytes(),
        charge_value.as_bytes(),
        amount.as_bytes(),
        text(record, "settled_asset")?.as_bytes(),
        &occurred_at,
    ] {
        out.extend_from_slice(&(field.len() as u32).to_le_bytes());
        out.extend_from_slice(field);
    }
    Ok(out)
}

/// The record's digest, lowercase hex.
pub fn interaction_digest(record: &Value) -> Result<String, InteractionError> {
    Ok(hex::encode(Sha256::digest(interaction_preimage(record)?)))
}
