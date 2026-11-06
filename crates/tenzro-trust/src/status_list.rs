//! Revocation: per-issuer Bitstring Status Lists and issuer key revocation.
//!
//! Only an issuer can revoke its own credentials: a revocation is a document
//! naming status list indices, signed by the same key that signed the
//! credentials. Revocation is permanent (a set bit never clears), so records
//! can be applied in any order and every holder converges on the same list.
//!
//! An issuer whose key is compromised signs an issuer revocation with that
//! key. From then on nothing that key signed is accepted, because a stolen
//! key could have back-dated anything.

use std::collections::BTreeSet;
use std::io::Write;

use base64::Engine;
use serde_json::{Value, json};

use crate::credential::{MAX_STATUS_INDEX, STATUS_LIST_PREFIX, VC_CONTEXT};
use crate::{Result, has_type, invalid, str_field, time_field, verify_signed_by};

pub const REVOCATION_TYPE: &str = "TenzroRevocation";
pub const ISSUER_REVOCATION_TYPE: &str = "TenzroIssuerRevocation";
/// The W3C minimum list length (entries), which keeps a single revocation
/// from being identifiable by the list's size.
pub const MIN_LIST_BITS: usize = 131_072;

/// Signed revocation of some of an issuer's status list entries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Revocation {
    pub issuer: String,
    pub indices: BTreeSet<u32>,
    pub revoked_at: chrono::DateTime<chrono::Utc>,
    pub document: Value,
}

impl Revocation {
    pub fn unsigned(
        issuer: &str,
        indices: &[u32],
        revoked_at: chrono::DateTime<chrono::Utc>,
    ) -> Value {
        json!({
            "type": [REVOCATION_TYPE],
            "issuer": issuer,
            "statusListIndex": indices.iter().map(|i| i.to_string()).collect::<Vec<_>>(),
            "revokedAt": revoked_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        })
    }

    pub fn parse(document: &Value) -> Result<Self> {
        if !has_type(document, REVOCATION_TYPE) {
            return Err(invalid(format!("not a {REVOCATION_TYPE}")));
        }
        let issuer = str_field(document, "/issuer")?.to_string();
        verify_signed_by(document, &issuer)?;
        let list = document
            .get("statusListIndex")
            .and_then(Value::as_array)
            .filter(|a| !a.is_empty() && a.len() <= 4096)
            .ok_or_else(|| invalid("statusListIndex must list 1-4096 indices"))?;
        let mut indices = BTreeSet::new();
        for i in list {
            let idx = i
                .as_str()
                .and_then(|s| s.parse::<u32>().ok())
                .filter(|i| *i < MAX_STATUS_INDEX)
                .ok_or_else(|| invalid("statusListIndex entries are decimal strings below 2^20"))?;
            indices.insert(idx);
        }
        Ok(Revocation {
            issuer,
            indices,
            revoked_at: time_field(document, "/revokedAt")?,
            document: document.clone(),
        })
    }
}

/// Signed revocation of an issuer's key, by that key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuerRevocation {
    pub issuer: String,
    pub revoked_at: chrono::DateTime<chrono::Utc>,
    pub reason: String,
    pub document: Value,
}

impl IssuerRevocation {
    pub fn unsigned(
        issuer: &str,
        revoked_at: chrono::DateTime<chrono::Utc>,
        reason: &str,
    ) -> Value {
        json!({
            "type": [ISSUER_REVOCATION_TYPE],
            "issuer": issuer,
            "revokedAt": revoked_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            "reason": reason,
        })
    }

    pub fn parse(document: &Value) -> Result<Self> {
        if !has_type(document, ISSUER_REVOCATION_TYPE) {
            return Err(invalid(format!("not a {ISSUER_REVOCATION_TYPE}")));
        }
        let issuer = str_field(document, "/issuer")?.to_string();
        verify_signed_by(document, &issuer)?;
        let reason = document
            .get("reason")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        if reason.len() > 1024 {
            return Err(invalid("reason is longer than 1024 characters"));
        }
        Ok(IssuerRevocation {
            issuer,
            revoked_at: time_field(document, "/revokedAt")?,
            reason,
            document: document.clone(),
        })
    }
}

/// The bitstring with `revoked` set: index 0 is the most significant bit of
/// the first byte, and the length is at least [`MIN_LIST_BITS`].
pub fn bitstring(revoked: &BTreeSet<u32>) -> Vec<u8> {
    let highest = revoked.iter().next_back().map_or(0, |i| *i as usize + 1);
    let bits = highest.max(MIN_LIST_BITS).div_ceil(8) * 8;
    let mut out = vec![0u8; bits / 8];
    for i in revoked {
        let i = *i as usize;
        out[i / 8] |= 0x80 >> (i % 8);
    }
    out
}

/// Whether `index` is set in a bitstring.
#[cfg(test)]
pub fn bit_is_set(bits: &[u8], index: u32) -> bool {
    let i = index as usize;
    bits.get(i / 8).is_some_and(|b| b & (0x80 >> (i % 8)) != 0)
}

/// `encodedList`: multibase base64url (prefix `u`, no padding) of the GZIP
/// of the bitstring.
pub fn encode_list(bits: &[u8]) -> String {
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    let _ = gz.write_all(bits);
    let compressed = gz.finish().unwrap_or_default();
    format!(
        "u{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(compressed)
    )
}

/// Inverse of [`encode_list`].
#[cfg(test)]
pub fn decode_list(encoded: &str) -> Result<Vec<u8>> {
    use std::io::Read;
    let b64 = encoded
        .strip_prefix('u')
        .ok_or_else(|| invalid("encodedList is not multibase base64url"))?;
    let compressed = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(b64)
        .map_err(|_| invalid("encodedList is not base64url"))?;
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(compressed.as_slice())
        .take(64 * 1024 * 1024)
        .read_to_end(&mut out)
        .map_err(|_| invalid("encodedList is not GZIP"))?;
    Ok(out)
}

/// The issuer's status list in the `BitstringStatusListCredential` shape,
/// with the signed statements it was computed from so any reader can
/// recompute every bit. The ledger renders it; the issuer's signatures are on
/// the statements.
pub fn status_list_document(
    issuer: &str,
    revoked: &BTreeSet<u32>,
    statements: &[Value],
    issuer_revocation: Option<&Value>,
) -> Value {
    json!({
        "@context": [VC_CONTEXT],
        "id": format!("{STATUS_LIST_PREFIX}{issuer}"),
        "type": ["BitstringStatusListCredential"],
        "issuer": issuer,
        "credentialSubject": {
            "id": format!("{STATUS_LIST_PREFIX}{issuer}#list"),
            "type": "BitstringStatusList",
            "statusPurpose": "revocation",
            "encodedList": encode_list(&bitstring(revoked)),
        },
        "revocations": statements,
        "issuerRevocation": issuer_revocation,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proof::testkit::TestKey;

    #[test]
    fn bits_round_trip_through_the_encoded_list() {
        let revoked: BTreeSet<u32> = [0, 7, 8, 131_071, 200_000].into_iter().collect();
        let bits = bitstring(&revoked);
        assert_eq!(bits.len() * 8, 200_008);
        let decoded = decode_list(&encode_list(&bits)).unwrap();
        for i in [0u32, 7, 8, 131_071, 200_000] {
            assert!(bit_is_set(&decoded, i));
        }
        for i in [1u32, 6, 9, 131_070, 199_999] {
            assert!(!bit_is_set(&decoded, i));
        }
        assert_eq!(bitstring(&BTreeSet::new()).len() * 8, MIN_LIST_BITS);
    }

    #[test]
    fn index_zero_is_the_leftmost_bit() {
        let bits = bitstring(&[0u32].into_iter().collect());
        assert_eq!(bits[0], 0x80);
    }

    #[test]
    fn a_revocation_verifies_only_under_the_issuers_key() {
        let issuer = TestKey::new(1);
        let now = chrono::Utc::now();
        let r = Revocation::parse(&issuer.sign(Revocation::unsigned(&issuer.did(), &[4, 9], now)))
            .unwrap();
        assert_eq!(r.indices.into_iter().collect::<Vec<_>>(), vec![4, 9]);

        let attacker = TestKey::new(2);
        let forged = attacker.sign(Revocation::unsigned(&issuer.did(), &[4], now));
        assert!(Revocation::parse(&forged).is_err());
    }

    #[test]
    fn an_issuer_revocation_verifies_only_under_the_issuers_key() {
        let issuer = TestKey::new(1);
        let now = chrono::Utc::now();
        assert!(
            IssuerRevocation::parse(&issuer.sign(IssuerRevocation::unsigned(
                &issuer.did(),
                now,
                "key lost"
            )))
            .is_ok()
        );
        let forged = TestKey::new(2).sign(IssuerRevocation::unsigned(
            &issuer.did(),
            now,
            "silence them",
        ));
        assert!(IssuerRevocation::parse(&forged).is_err());
    }
}
