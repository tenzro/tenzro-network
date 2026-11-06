//! Carrying Tenzro payment challenges over the x402 headers.
//!
//! A node gate mints a [`PaymentChallenge`] per request. On the wire that
//! challenge becomes a `PAYMENT-REQUIRED` requirement whose `extra` names the
//! challenge (`challengeId`), and the buyer's `PAYMENT-SIGNATURE` payload
//! becomes a [`PaymentCredential`] the gateway verifies and settles like any
//! other:
//!
//! - under a Tenzro scheme the payload *is* the signed credential;
//! - under an EVM scheme the credential carries the payload, and the scheme
//!   backend verifies it against the requirement rebuilt from the challenge,
//!   never against the requirement the buyer echoed back.

use std::collections::HashMap;

use crate::error::{PaymentError, Result};
use crate::types::{PaymentChallenge, PaymentCredential};
use crate::x402::payment_payload::X402PaymentPayload;
use crate::x402::payment_required::{ResourceInfo, X402PaymentRequired, X402PaymentRequirement};
use crate::x402::scheme::{BATCH_SETTLEMENT_SCHEME, DEFAULT_SCHEME, UPTO_SCHEME};

/// Requirement `extra` key naming the challenge a payment answers.
pub const CHALLENGE_ID_KEY: &str = "challengeId";

/// Scheme: escrows locked by the hash of a sealed delivery's key.
pub const DVP_SCHEME: &str = "dvp";

/// Credential `extra` key carrying an EVM-scheme payment payload.
pub const X402_PAYLOAD_KEY: &str = "x402_payload";

/// Challenge `extra` keys that describe the challenge itself rather than the
/// payment option, and so are not copied into the requirement.
const CHALLENGE_ONLY_KEYS: [&str; 3] = ["scheme", "network", OFFERED_SCHEMES_KEY];

/// Key in `challenge.extra` listing every scheme the challenge accepts (the
/// pinned one first), when it offers more than one.
pub const OFFERED_SCHEMES_KEY: &str = "schemes";

/// Every scheme a challenge accepts: its own, and any it offers beside it.
pub fn offered_schemes(challenge: &PaymentChallenge) -> Vec<String> {
    match challenge
        .extra
        .get(OFFERED_SCHEMES_KEY)
        .and_then(|v| v.as_array())
    {
        Some(list) => list
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect(),
        None => vec![challenge_scheme(challenge).to_string()],
    }
}

/// Whether `scheme` pays with a signed Tenzro credential.
pub fn is_tenzro_scheme(scheme: &str) -> bool {
    [
        DEFAULT_SCHEME,
        UPTO_SCHEME,
        BATCH_SETTLEMENT_SCHEME,
        DVP_SCHEME,
    ]
    .iter()
    .any(|s| s.eq_ignore_ascii_case(scheme))
}

/// The scheme a challenge was minted under.
pub fn challenge_scheme(challenge: &PaymentChallenge) -> &str {
    challenge
        .extra
        .get("scheme")
        .and_then(|v| v.as_str())
        .unwrap_or(DEFAULT_SCHEME)
}

/// The CAIP-2 network a challenge settles on.
pub fn challenge_network(challenge: &PaymentChallenge) -> &str {
    challenge
        .extra
        .get("network")
        .and_then(|v| v.as_str())
        .unwrap_or(&challenge.chain)
}

/// The payment option a challenge offers, as it appears in
/// `PAYMENT-REQUIRED`.
pub fn requirement_for(challenge: &PaymentChallenge) -> X402PaymentRequirement {
    let remaining = (challenge.expires_at - chrono::Utc::now())
        .num_seconds()
        .max(0) as u64;
    let mut extra = serde_json::Map::new();
    for (k, v) in &challenge.extra {
        if !CHALLENGE_ONLY_KEYS.contains(&k.as_str()) {
            extra.insert(k.clone(), v.clone());
        }
    }
    extra.insert(
        CHALLENGE_ID_KEY.to_string(),
        serde_json::json!(challenge.challenge_id),
    );
    X402PaymentRequirement::new(
        challenge_scheme(challenge),
        challenge_network(challenge),
        challenge.amount.to_string(),
        challenge.recipient.clone(),
        challenge.asset.clone(),
        remaining,
    )
    .with_extra(serde_json::Value::Object(extra))
}

/// The option a challenge offers under `scheme` beside its pinned one. The
/// signed offer and the meter key belong to the pinned option and are not
/// repeated here.
fn other_requirement(challenge: &PaymentChallenge, scheme: &str) -> X402PaymentRequirement {
    let mut r = requirement_for(challenge);
    r.scheme = scheme.to_string();
    if let Some(extra) = r.extra.as_object_mut() {
        for key in [
            crate::x402::offer::OFFER_COMMITMENT_KEY,
            crate::x402::offer::OFFER_SIG_KEY,
            crate::x402::offer::OFFER_SIGNER_KEY,
            crate::metering::METER_KEY,
        ] {
            extra.remove(key);
        }
    }
    r
}

/// The `PAYMENT-REQUIRED` body for a challenge: one option per scheme it
/// accepts.
pub fn payment_required_for(challenge: &PaymentChallenge) -> X402PaymentRequired {
    let pinned = challenge_scheme(challenge).to_string();
    let accepts = offered_schemes(challenge)
        .iter()
        .map(|s| {
            if *s == pinned {
                requirement_for(challenge)
            } else {
                other_requirement(challenge, s)
            }
        })
        .collect();
    X402PaymentRequired::new(ResourceInfo::new(challenge.resource.clone()), accepts)
}

/// The chain id of a `tenzro:<chain id>` network.
pub fn tenzro_chain_id(network: &str) -> Option<u64> {
    network.strip_prefix("tenzro:")?.parse().ok()
}

/// The challenge a Tenzro-scheme requirement describes, as the payer signs
/// it: the challenge id from `extra`, the chain from the network, the payee,
/// amount and asset from the requirement.
pub fn challenge_from_requirement(
    requirement: &X402PaymentRequirement,
    resource: &str,
) -> Result<PaymentChallenge> {
    let challenge_id = requirement.extra_str(CHALLENGE_ID_KEY).ok_or_else(|| {
        PaymentError::VerificationFailed(format!("the requirement names no {CHALLENGE_ID_KEY}"))
    })?;
    let chain_id = tenzro_chain_id(&requirement.network).ok_or_else(|| {
        PaymentError::VerificationFailed(format!("{} is not a Tenzro network", requirement.network))
    })?;
    let mut extra = HashMap::new();
    extra.insert("scheme".to_string(), serde_json::json!(requirement.scheme));
    extra.insert(
        "network".to_string(),
        serde_json::json!(requirement.network),
    );
    extra.insert(
        crate::payer_auth::CHAIN_ID_KEY.to_string(),
        serde_json::json!(chain_id),
    );
    Ok(PaymentChallenge {
        challenge_id: challenge_id.to_string(),
        protocol: "x402".to_string(),
        resource: resource.to_string(),
        amount: requirement.amount_u128()?,
        asset: requirement.asset.clone(),
        recipient: requirement.pay_to.clone(),
        chain: "tenzro".to_string(),
        expires_at: chrono::Utc::now()
            + chrono::Duration::seconds(requirement.max_timeout_seconds.max(1) as i64),
        extra,
    })
}

/// The EVM-scheme payload a credential carries.
pub fn credential_payload(credential: &PaymentCredential) -> Result<X402PaymentPayload> {
    let value = credential.extra.get(X402_PAYLOAD_KEY).ok_or_else(|| {
        PaymentError::CredentialError(format!(
            "credential carries no x402 payload under extra.{X402_PAYLOAD_KEY}"
        ))
    })?;
    serde_json::from_value(value.clone())
        .map_err(|e| PaymentError::CredentialError(format!("x402 payload: {e}")))
}

/// The credential a `PAYMENT-SIGNATURE` payload presents.
pub fn credential_from_payload(payload: &X402PaymentPayload) -> Result<PaymentCredential> {
    let challenge_id = payload
        .accepted
        .extra_str(CHALLENGE_ID_KEY)
        .ok_or_else(|| {
            PaymentError::CredentialError(format!(
                "the accepted requirement names no {CHALLENGE_ID_KEY}"
            ))
        })?
        .to_string();

    if is_tenzro_scheme(payload.scheme()) {
        let mut credential: PaymentCredential = serde_json::from_value(payload.payload.clone())
            .map_err(|e| {
                PaymentError::CredentialError(format!(
                    "{} payload is not a signed credential: {e}",
                    payload.scheme()
                ))
            })?;
        if credential.challenge_id != challenge_id {
            return Err(PaymentError::CredentialError(format!(
                "the credential answers challenge {} but the payload names {}",
                credential.challenge_id, challenge_id
            )));
        }
        if !credential.protocol.eq_ignore_ascii_case("x402") {
            return Err(PaymentError::CredentialError(format!(
                "a {} credential cannot be presented as an x402 payment",
                credential.protocol
            )));
        }
        // The option the payer answered: the verifier checks it was offered.
        credential
            .extra
            .entry("scheme".to_string())
            .or_insert_with(|| serde_json::json!(payload.scheme()));
        return Ok(credential);
    }

    let exact = payload.exact_payload()?;
    let payload_value = serde_json::to_value(payload)
        .map_err(|e| PaymentError::SerializationError(e.to_string()))?;
    let mut extra = HashMap::new();
    extra.insert(X402_PAYLOAD_KEY.to_string(), payload_value);
    Ok(PaymentCredential {
        credential_id: exact.authorization.nonce.clone(),
        challenge_id,
        protocol: "x402".to_string(),
        payer_did: String::new(),
        payer_address: exact.authorization.from.clone(),
        amount: payload.accepted.amount_u128()?,
        asset: payload.accepted.asset.clone(),
        signature: None,
        extra,
    })
}

/// The credential in a `PAYMENT-SIGNATURE` header value.
pub fn credential_from_header(value: &str) -> Result<PaymentCredential> {
    credential_from_payload(&X402PaymentPayload::from_base64(value)?)
}

/// The `PAYMENT-SIGNATURE` payload for a signed Tenzro credential.
pub fn payload_for_credential(
    challenge: &PaymentChallenge,
    credential: &PaymentCredential,
) -> Result<X402PaymentPayload> {
    let value = serde_json::to_value(credential)
        .map_err(|e| PaymentError::SerializationError(e.to_string()))?;
    Ok(X402PaymentPayload::new(requirement_for(challenge), value)
        .with_resource(ResourceInfo::new(challenge.resource.clone())))
}

/// Refuse an EVM payload whose chosen option differs from the one the
/// challenge offers. The EIP-3009 signature covers only the transfer, so the
/// option the buyer echoes is never trusted for scheme or network.
pub fn check_accepted_matches(
    payload: &X402PaymentPayload,
    offered: &X402PaymentRequirement,
) -> Result<()> {
    let a = &payload.accepted;
    if !a.scheme.eq_ignore_ascii_case(&offered.scheme) || a.network != offered.network {
        return Err(PaymentError::VerificationFailed(format!(
            "payload chose {} on {} but the challenge offers {} on {}",
            a.scheme, a.network, offered.scheme, offered.network
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::x402::payment_payload::{ExactAuthorization, ExactSchemePayload};

    fn challenge(scheme: &str) -> PaymentChallenge {
        let mut extra = HashMap::new();
        extra.insert("scheme".to_string(), serde_json::json!(scheme));
        extra.insert("network".to_string(), serde_json::json!("tenzro:1337"));
        extra.insert("chain_id".to_string(), serde_json::json!(1337));
        PaymentChallenge {
            challenge_id: "ch-1".into(),
            protocol: "x402".into(),
            resource: "/paid".into(),
            amount: 500,
            asset: "TNZO".into(),
            recipient: "09".repeat(20),
            chain: "tenzro".into(),
            expires_at: chrono::Utc::now() + chrono::Duration::seconds(120),
            extra,
        }
    }

    #[test]
    fn a_challenge_becomes_a_requirement_naming_it() {
        let req = requirement_for(&challenge(DEFAULT_SCHEME));
        assert_eq!(req.scheme, DEFAULT_SCHEME);
        assert_eq!(req.network, "tenzro:1337");
        assert_eq!(req.amount, "500");
        assert_eq!(req.extra_str(CHALLENGE_ID_KEY), Some("ch-1"));
        assert_eq!(req.extra["chain_id"], 1337);
        assert!(req.extra.get("scheme").is_none());
        assert!(req.max_timeout_seconds > 100 && req.max_timeout_seconds <= 120);
    }

    fn credential(challenge_id: &str, protocol: &str) -> PaymentCredential {
        PaymentCredential {
            credential_id: "k".into(),
            challenge_id: challenge_id.into(),
            protocol: protocol.into(),
            payer_did: String::new(),
            payer_address: "ab".repeat(20),
            amount: 500,
            asset: "TNZO".into(),
            signature: None,
            extra: HashMap::new(),
        }
    }

    #[test]
    fn a_tenzro_payload_yields_its_credential() {
        let ch = challenge(DEFAULT_SCHEME);
        let cred = credential("ch-1", "x402");
        let payload = payload_for_credential(&ch, &cred).unwrap();
        let back = credential_from_header(&payload.to_base64().unwrap()).unwrap();
        assert_eq!(back.challenge_id, "ch-1");
        assert_eq!(back.signature, cred.signature);
    }

    #[test]
    fn a_credential_for_another_challenge_or_protocol_is_refused() {
        let ch = challenge(DEFAULT_SCHEME);
        let payload = payload_for_credential(&ch, &credential("ch-2", "x402")).unwrap();
        assert!(credential_from_payload(&payload).is_err());
        let payload = payload_for_credential(&ch, &credential("ch-1", "mpp")).unwrap();
        assert!(credential_from_payload(&payload).is_err());
    }

    #[test]
    fn an_evm_payload_is_carried_for_its_backend() {
        let mut ch = challenge("exact-eip3009");
        ch.extra
            .insert("network".to_string(), serde_json::json!("eip155:8453"));
        let exact = ExactSchemePayload {
            signature: "0x00".into(),
            authorization: ExactAuthorization {
                from: "0xfrom".into(),
                to: "0xto".into(),
                value: "500".into(),
                valid_after: 0,
                valid_before: 10,
                nonce: "0xn".into(),
            },
        };
        let payload = X402PaymentPayload::exact(requirement_for(&ch), &exact).unwrap();
        let cred = credential_from_payload(&payload).unwrap();
        assert_eq!(cred.challenge_id, "ch-1");
        assert_eq!(cred.payer_address, "0xfrom");
        assert_eq!(credential_payload(&cred).unwrap(), payload);

        let mut other = payload.clone();
        other.accepted.network = "eip155:1".into();
        assert!(check_accepted_matches(&other, &requirement_for(&ch)).is_err());
        assert!(check_accepted_matches(&payload, &requirement_for(&ch)).is_ok());
    }
}
