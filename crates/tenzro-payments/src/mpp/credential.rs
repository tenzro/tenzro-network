//! The HTTP Payment authentication credential.
//!
//! A payer answers a `WWW-Authenticate: Payment` challenge with
//! `Authorization: Payment <base64url JSON>`, the JSON being
//! `{challenge: {id, ...}, source?, payload}`. For a Tenzro payment the
//! payload is the signed [`PaymentCredential`]; the echoed challenge id must
//! be the one it answers.

use base64::Engine as _;
use serde::{Deserialize, Serialize};

use crate::error::{PaymentError, Result};
use crate::types::PaymentCredential;

/// The body of `Authorization: Payment`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IetfPaymentBody {
    /// The echoed challenge parameters; `id` names the challenge.
    pub challenge: serde_json::Value,
    /// The payer, as a DID, when it names one.
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub source: String,
    /// The method's proof: the signed credential.
    pub payload: serde_json::Value,
}

impl IetfPaymentBody {
    /// The body presenting `credential`.
    pub fn for_credential(credential: &PaymentCredential) -> Result<Self> {
        Ok(Self {
            challenge: serde_json::json!({ "id": credential.challenge_id }),
            source: credential.payer_did.clone(),
            payload: serde_json::to_value(credential)
                .map_err(|e| PaymentError::SerializationError(e.to_string()))?,
        })
    }

    /// The `Authorization` header value.
    pub fn to_header(&self) -> Result<String> {
        let json = serde_json::to_vec(self)
            .map_err(|e| PaymentError::SerializationError(e.to_string()))?;
        Ok(format!(
            "Payment {}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json)
        ))
    }

    /// Parse the base64url part of an `Authorization: Payment` value.
    pub fn from_base64url(data: &str) -> Result<Self> {
        let json = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(data.trim())
            .map_err(|e| PaymentError::CredentialError(format!("Payment credential: {e}")))?;
        serde_json::from_slice(&json)
            .map_err(|e| PaymentError::CredentialError(format!("Payment credential: {e}")))
    }

    /// The credential presented, which must answer the echoed challenge.
    pub fn into_credential(self) -> Result<PaymentCredential> {
        let echoed = self
            .challenge
            .get("id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                PaymentError::CredentialError(
                    "the Payment credential echoes no challenge id".into(),
                )
            })?
            .to_string();
        let credential: PaymentCredential = serde_json::from_value(self.payload)
            .map_err(|e| PaymentError::CredentialError(format!("Payment payload: {e}")))?;
        if credential.challenge_id != echoed {
            return Err(PaymentError::CredentialError(format!(
                "the payload answers challenge {} but the credential echoes {}",
                credential.challenge_id, echoed
            )));
        }
        Ok(credential)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn credential(challenge_id: &str) -> PaymentCredential {
        PaymentCredential {
            credential_id: "k".into(),
            challenge_id: challenge_id.into(),
            protocol: "mpp".into(),
            payer_did: "did:tenzro:human:x".into(),
            payer_address: "ab".repeat(20),
            amount: 5,
            asset: "TNZO".into(),
            signature: None,
            extra: HashMap::new(),
        }
    }

    #[test]
    fn a_credential_round_trips_through_the_header() {
        let body = IetfPaymentBody::for_credential(&credential("ch-1")).unwrap();
        let header = body.to_header().unwrap();
        let data = header.strip_prefix("Payment ").unwrap();
        let back = IetfPaymentBody::from_base64url(data).unwrap();
        assert_eq!(back.source, "did:tenzro:human:x");
        assert_eq!(back.into_credential().unwrap().challenge_id, "ch-1");
    }

    #[test]
    fn a_payload_for_another_challenge_is_refused() {
        let mut body = IetfPaymentBody::for_credential(&credential("ch-1")).unwrap();
        body.challenge = serde_json::json!({ "id": "ch-2" });
        assert!(body.into_credential().is_err());
    }
}
