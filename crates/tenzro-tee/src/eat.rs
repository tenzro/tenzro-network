//! The Entity Attestation Token claims (RFC 9711) a verifier reads from a
//! token whose signature it has already checked against a pinned key.
//!
//! An EAT is a JWT or a CWT carrying attestation claims. The services this
//! crate verifies answer in the JWT form: Intel Tiber Trust Authority and
//! NVIDIA's attestation service. Each also carries claims of its own, which
//! its verifier reads beside these. This module reads the claims RFC 9711
//! defines and that a relying party acts on: the nonce the token answers,
//! the entity's identifier (`ueid`), its debug status (`dbgstat`), the
//! profile the token follows (`eat_profile`) and the measurements it carries
//! (`measurements`), and records them on an [`AttestationResult`].
//!
//! It reads claims only; it never decides a token is genuine. A caller
//! passes the claims set of a token it verified.

use serde_json::Value;
use tenzro_types::tee::{AttestationResult, Measurement};

use crate::error::{Result, TeeError};

/// The debug status of the attested entity (RFC 9711, section 4.2.9).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DebugStatus {
    /// Debug is enabled.
    Enabled,
    /// Debug is disabled now; it may have been enabled earlier.
    Disabled,
    /// Debug has been disabled since the entity booted.
    DisabledSinceBoot,
    /// Debug is disabled and cannot be enabled again.
    DisabledPermanently,
    /// Debug is disabled for the entity and every part of it, for good.
    DisabledFullyAndPermanently,
}

impl DebugStatus {
    /// The status named by the JSON form of the claim.
    fn from_json(name: &str) -> Option<Self> {
        Some(match name {
            "enabled" => Self::Enabled,
            "disabled" => Self::Disabled,
            "disabled-since-boot" => Self::DisabledSinceBoot,
            "disabled-permanently" => Self::DisabledPermanently,
            "disabled-fully-and-permanently" => Self::DisabledFullyAndPermanently,
            _ => return None,
        })
    }

    /// The JSON name of the status.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Enabled => "enabled",
            Self::Disabled => "disabled",
            Self::DisabledSinceBoot => "disabled-since-boot",
            Self::DisabledPermanently => "disabled-permanently",
            Self::DisabledFullyAndPermanently => "disabled-fully-and-permanently",
        }
    }
}

/// The RFC 9711 claims of one token.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EatClaims {
    /// The nonces the token answers (`eat_nonce`, one or several).
    pub nonces: Vec<String>,
    /// The entity's identifier (`ueid`), as the token carries it.
    pub ueid: Option<String>,
    /// The entity's debug status (`dbgstat`).
    pub dbgstat: Option<DebugStatus>,
    /// The profile the token follows (`eat_profile`).
    pub profile: Option<String>,
    /// The measurements the token carries (`measurements`): each a CoAP
    /// content format and the bytes in that format.
    pub measurements: Vec<(u64, Vec<u8>)>,
}

fn malformed(claim: &str) -> TeeError {
    TeeError::AttestationVerificationFailed(format!("EAT claim {claim} is malformed"))
}

fn text(claims: &Value, name: &str) -> Result<Option<String>> {
    match claims.get(name) {
        None => Ok(None),
        Some(v) => v
            .as_str()
            .map(|s| Some(s.to_string()))
            .ok_or_else(|| malformed(name)),
    }
}

/// The most nonces and measurements one token may carry: a verified token is
/// still data from outside, and each entry is copied onto the result.
const MAX_NONCES: usize = 8;
const MAX_MEASUREMENTS: usize = 64;

impl EatClaims {
    /// Read the claims from the JSON claims set of a verified JWT. A claim
    /// that is absent stays empty; one that is present in the wrong form is
    /// refused, so a token cannot pass by mis-typing a claim it relies on.
    pub fn from_json(claims: &Value) -> Result<Self> {
        let nonces = match claims.get("eat_nonce") {
            None => Vec::new(),
            Some(Value::String(n)) => vec![n.clone()],
            Some(Value::Array(ns)) if !ns.is_empty() && ns.len() <= MAX_NONCES => ns
                .iter()
                .map(|n| n.as_str().map(str::to_string))
                .collect::<Option<_>>()
                .ok_or_else(|| malformed("eat_nonce"))?,
            Some(_) => return Err(malformed("eat_nonce")),
        };
        let dbgstat = match text(claims, "dbgstat")? {
            None => None,
            Some(s) => Some(DebugStatus::from_json(&s).ok_or_else(|| malformed("dbgstat"))?),
        };
        let measurements = match claims.get("measurements") {
            None => Vec::new(),
            Some(Value::Array(ms)) if ms.len() <= MAX_MEASUREMENTS => ms
                .iter()
                .map(|m| {
                    let pair = m.as_array().filter(|p| p.len() == 2)?;
                    let format = pair[0].as_u64()?;
                    let bytes = pair[1].as_str().and_then(|b| b64url(b).ok())?;
                    Some((format, bytes))
                })
                .collect::<Option<_>>()
                .ok_or_else(|| malformed("measurements"))?,
            Some(_) => return Err(malformed("measurements")),
        };
        Ok(Self {
            nonces,
            ueid: text(claims, "ueid")?,
            dbgstat,
            profile: text(claims, "eat_profile")?,
            measurements,
        })
    }

    /// The token answers `nonce` (compared without regard to letter case,
    /// as a hex nonce may be written either way).
    pub fn answers(&self, nonce: &str) -> bool {
        self.nonces.iter().any(|n| n.eq_ignore_ascii_case(nonce))
    }

    /// The token reports exactly `disabled`, the status the Tiber and
    /// NVIDIA verifiers require. The other disabled statuses are not taken
    /// for it: which of them a verifier accepts is a policy decision this
    /// reader does not make.
    pub fn debug_disabled(&self) -> bool {
        self.dbgstat == Some(DebugStatus::Disabled)
    }

    /// Record the claims on `result`: the identifier, debug status and
    /// profile among its details, each measurement as a measurement entry
    /// whose algorithm names its content format, numbered after the entries
    /// `result` already holds.
    pub fn record(&self, result: &mut AttestationResult) {
        let first = result.measurements.len() as u32;
        if let Some(ueid) = &self.ueid {
            result.details.insert("ueid".into(), ueid.clone());
        }
        if let Some(dbgstat) = self.dbgstat {
            result
                .details
                .insert("dbgstat".into(), dbgstat.as_str().into());
        }
        if let Some(profile) = &self.profile {
            result.details.insert("eat_profile".into(), profile.clone());
        }
        for (i, (format, bytes)) in self.measurements.iter().enumerate() {
            result.measurements.push(Measurement {
                index: first + i as u32,
                algorithm: format!("coap-content-format:{format}"),
                value: bytes.clone(),
                register: "eat:measurements".into(),
                description: None,
            });
        }
    }
}

fn b64url(s: &str) -> std::result::Result<Vec<u8>, base64::DecodeError> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s.trim_end_matches('='))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn the_rfc_9711_claims_are_read_and_recorded() {
        let c = EatClaims::from_json(&json!({
            "eat_nonce": ["AbCd", "ef01"],
            "ueid": "AgAEizrK3Q",
            "dbgstat": "disabled-since-boot",
            "eat_profile": "https://example.com/profile",
            "measurements": [[258, "3q2-7w"]],
            "x-vendor": true,
        }))
        .unwrap();
        assert!(c.answers("abcd") && c.answers("EF01") && !c.answers("00"));
        let mut r = AttestationResult::default();
        r.measurements.push(Measurement::default());
        c.record(&mut r);
        assert_eq!(r.details["ueid"], "AgAEizrK3Q");
        assert_eq!(r.details["dbgstat"], "disabled-since-boot");
        assert_eq!(r.details["eat_profile"], "https://example.com/profile");
        assert_eq!(r.measurements.len(), 2);
        assert_eq!(r.measurements[1].index, 1, "numbered after what was there");
        assert_eq!(r.measurements[1].algorithm, "coap-content-format:258");
        assert_eq!(r.measurements[1].value, vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn debug_counts_as_off_only_for_exactly_disabled() {
        let read = |s: &str| EatClaims::from_json(&json!({"dbgstat": s})).unwrap();
        assert!(read("disabled").debug_disabled());
        for s in [
            "enabled",
            "disabled-since-boot",
            "disabled-permanently",
            "disabled-fully-and-permanently",
        ] {
            assert!(!read(s).debug_disabled(), "{s}");
            assert_eq!(read(s).dbgstat.map(DebugStatus::as_str), Some(s));
        }
        assert!(!EatClaims::from_json(&json!({})).unwrap().debug_disabled());
    }

    #[test]
    fn a_claim_in_the_wrong_form_is_refused() {
        for bad in [
            json!({"dbgstat": "off"}),
            json!({"dbgstat": 1}),
            json!({"eat_nonce": 7}),
            json!({"eat_nonce": []}),
            json!({"eat_nonce": vec!["a"; MAX_NONCES + 1]}),
            json!({"measurements": vec![json!([258, "3q2-7w"]); MAX_MEASUREMENTS + 1]}),
            json!({"ueid": 5}),
            json!({"measurements": [[258]]}),
            json!({"measurements": [["x", "3q2-7w"]]}),
            json!({"measurements": [[258, "not base64!"]]}),
        ] {
            assert!(EatClaims::from_json(&bad).is_err(), "{bad}");
        }
    }
}
