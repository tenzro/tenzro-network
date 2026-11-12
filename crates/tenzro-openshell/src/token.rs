//! The short-lived credential a sandbox presents to Tenzro.
//!
//! `tzs1.<claims>.<signature>`: base64url JSON claims naming the agent, the
//! provider and credential key it was minted for, the scope and the expiry,
//! and the base64url JSON [`RecordSignature`] of the serving node over the
//! claims. Nothing in it is a key: it names an agent whose Terms the
//! verifier reads, and it is worthless after its expiry or once the agent is
//! revoked, which the verifier checks on every use.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use serde::{Deserialize, Serialize};
use tenzro_crypto::batch::{RecordSignature, RecordSigner};
use tenzro_crypto::composite::CompositePublicKey;

const PREFIX: &str = "tzs1";
const DOMAIN: &[u8] = b"tenzro/openshell/credential/v1";

/// What a credential grants.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Claims {
    /// The agent the credential acts for.
    pub agent: String,
    /// The OpenShell provider instance it was minted for.
    pub provider: String,
    /// The credential key (environment variable) it fills.
    pub key: String,
    /// The operation its Terms must allow on use.
    pub scope: String,
    /// Issued, ms since the Unix epoch.
    pub iat_ms: u64,
    /// Expires, ms since the Unix epoch.
    pub exp_ms: u64,
    /// Unique id.
    pub jti: String,
}

fn message(claims_json: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(DOMAIN.len() + claims_json.len());
    m.extend_from_slice(DOMAIN);
    m.extend_from_slice(claims_json);
    m
}

/// Mint a credential for `claims`.
pub fn mint(signer: &dyn RecordSigner, claims: &Claims) -> Result<String, String> {
    let json = serde_json::to_vec(claims).map_err(|e| e.to_string())?;
    let sig = signer
        .sign_record(&message(&json))
        .map_err(|e| e.to_string())?;
    let sig = serde_json::to_vec(&sig).map_err(|e| e.to_string())?;
    Ok(format!("{PREFIX}.{}.{}", B64.encode(json), B64.encode(sig)))
}

/// Check a credential's signature under `identity` and its expiry at
/// `now_ms`; returns its claims.
pub fn verify(identity: &CompositePublicKey, token: &str, now_ms: u64) -> Result<Claims, String> {
    let mut parts = token.split('.');
    let (Some(PREFIX), Some(claims), Some(sig), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err("not a Tenzro credential".to_string());
    };
    let json = B64
        .decode(claims)
        .map_err(|_| "credential claims are not base64url")?;
    let sig = B64
        .decode(sig)
        .map_err(|_| "credential signature is not base64url")?;
    let sig: RecordSignature =
        serde_json::from_slice(&sig).map_err(|e| format!("credential signature: {e}"))?;
    let claims: Claims =
        serde_json::from_slice(&json).map_err(|e| format!("credential claims: {e}"))?;
    sig.verify_record_at(identity, &message(&json), claims.iat_ms)
        .map_err(|e| format!("credential signature: {e}"))?;
    if now_ms >= claims.exp_ms {
        return Err("credential expired".to_string());
    }
    Ok(claims)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tenzro_crypto::composite::HybridSigner;
    use tenzro_crypto::composite::testing::TestHybridSigner;

    fn claims(exp_ms: u64) -> Claims {
        Claims {
            agent: "did:tenzro:machine:a:b".into(),
            provider: "tenzro".into(),
            key: "TENZRO_AGENT_TOKEN".into(),
            scope: "inference".into(),
            iat_ms: crate::now_ms(),
            exp_ms,
            jti: "j".into(),
        }
    }

    #[test]
    fn a_minted_credential_verifies_until_it_expires() {
        let id = Arc::new(TestHybridSigner::p256_only(3));
        let signer = tenzro_crypto::batch::ImmediateRecordSigner::new(id.clone());
        let now = crate::now_ms();
        let t = mint(&signer, &claims(now + 1000)).unwrap();
        assert_eq!(verify(id.public_key(), &t, now).unwrap().scope, "inference");
        assert_eq!(
            verify(id.public_key(), &t, now + 1000).unwrap_err(),
            "credential expired"
        );
    }

    #[test]
    fn a_widened_scope_is_refused() {
        let id = Arc::new(TestHybridSigner::p256_only(3));
        let signer = tenzro_crypto::batch::ImmediateRecordSigner::new(id.clone());
        let now = crate::now_ms();
        let t = mint(&signer, &claims(now + 1000)).unwrap();
        let mut c = claims(now + 1000);
        c.scope = "pay".into();
        let forged = format!(
            "tzs1.{}.{}",
            B64.encode(serde_json::to_vec(&c).unwrap()),
            t.rsplit('.').next().unwrap()
        );
        assert!(verify(id.public_key(), &forged, now).is_err());
    }

    #[test]
    fn another_nodes_credential_is_refused() {
        let id = Arc::new(TestHybridSigner::p256_only(3));
        let other = TestHybridSigner::p256_only(4);
        let signer = tenzro_crypto::batch::ImmediateRecordSigner::new(id);
        let now = crate::now_ms();
        let t = mint(&signer, &claims(now + 1000)).unwrap();
        assert!(verify(other.public_key(), &t, now).is_err());
    }

    #[test]
    fn a_batched_credential_verifies_and_a_forged_one_does_not() {
        let signer = crate::testing::Immediate::new(9);
        let now = crate::now_ms();
        let t = mint(&signer, &claims(now + 1000)).unwrap();
        // The signature part is the JSON of the batched form.
        let sig = B64.decode(t.rsplit('.').next().unwrap()).unwrap();
        assert!(String::from_utf8(sig).unwrap().contains("batched"));
        assert_eq!(
            verify(signer.identity(), &t, now).unwrap().scope,
            "inference"
        );
        let other = crate::testing::Immediate::new(10);
        assert!(verify(other.identity(), &t, now).is_err());
        let mut c = claims(now + 1000);
        c.scope = "pay".into();
        let forged = format!(
            "tzs1.{}.{}",
            B64.encode(serde_json::to_vec(&c).unwrap()),
            t.rsplit('.').next().unwrap()
        );
        assert!(verify(signer.identity(), &forged, now).is_err());
    }
}
