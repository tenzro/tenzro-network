//! Trusted agent request signatures over RFC 9421, as a card network's agent
//! program has a merchant check them.
//!
//! An agent a payment network registered signs each request it sends a
//! merchant with a key that network publishes: `Signature-Input` names the
//! key (`keyid`), the purpose (`tag`: `agent-browser-auth` while browsing,
//! `agent-payer-auth` when paying), a single-use `nonce`, and a `created` and
//! `expires` time, and covers at least `@authority` and `@path`. A merchant
//! that holds the network's key set checks the signature, the window and the
//! nonce, and learns which registered agent is asking and for what.
//!
//! The result is a signal for the merchant's own gate, never a payment: a
//! verified agent still pays through the gate like any caller. A request that
//! carries such a signature and fails the check is refused rather than served
//! as if unsigned, so a forged or replayed signature never passes as one that
//! was simply absent.
//!
//! Keys are Ed25519 (`OKP`/`Ed25519` JWKs); the operator supplies the key set
//! of each network it accepts.

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD as BASE64, URL_SAFE_NO_PAD as B64URL};
use serde_json::Value;
use std::collections::HashMap;

use super::nonce::NonceCache;
use super::signature::{
    RequestParts, SignatureAlgorithm, SignedHeaders, parse_signature_input, verify_http_signature,
};
use crate::error::{PaymentError, Result};

/// `tag` of a signature an agent makes while browsing.
pub const TAG_BROWSING: &str = "agent-browser-auth";
/// `tag` of a signature an agent makes when it pays.
pub const TAG_PAYMENT: &str = "agent-payer-auth";
/// Components every trusted agent signature covers.
pub const REQUIRED_COMPONENTS: [&str; 2] = ["@authority", "@path"];
/// Longest `expires - created` accepted: eight minutes.
pub const MAX_LIFETIME_SECS: u64 = 480;
/// Seconds a `created` time may lie ahead of this clock.
pub const CLOCK_SKEW_SECS: u64 = 30;

/// What a trusted agent signature is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TapPurpose {
    /// The agent is browsing for its user.
    Browsing,
    /// The agent is paying for its user.
    Payment,
}

/// A request whose trusted agent signature verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TapAgent {
    /// The key that signed, as its network names it.
    pub key_id: String,
    /// What the signature is for.
    pub purpose: TapPurpose,
}

fn refuse(msg: impl Into<String>) -> PaymentError {
    PaymentError::Rfc9421Error(msg.into())
}

/// The key sets of the payment networks a merchant accepts agents from, and
/// the nonces already seen.
pub struct TapVerifier {
    keys: HashMap<String, Vec<u8>>,
    nonces: NonceCache,
}

impl TapVerifier {
    /// A verifier over the Ed25519 keys among `jwks` (each a JWK, or a JWK
    /// set with a `keys` array). A key without a `kid`, or of another type,
    /// is skipped; a set holding no usable key is refused.
    pub fn from_jwks(jwks: &[Value]) -> Result<Self> {
        let mut keys = HashMap::new();
        let flat = jwks
            .iter()
            .flat_map(|v| match v.get("keys").and_then(Value::as_array) {
                Some(set) => set.clone(),
                None => vec![v.clone()],
            });
        for jwk in flat {
            let (Some("OKP"), Some("Ed25519"), Some(kid), Some(x)) = (
                jwk.get("kty").and_then(Value::as_str),
                jwk.get("crv").and_then(Value::as_str),
                jwk.get("kid").and_then(Value::as_str),
                jwk.get("x").and_then(Value::as_str),
            ) else {
                continue;
            };
            let bytes = B64URL
                .decode(x)
                .ok()
                .filter(|b| b.len() == 32)
                .ok_or_else(|| refuse(format!("key {kid} is not an Ed25519 public key")))?;
            keys.insert(kid.to_string(), bytes);
        }
        if keys.is_empty() {
            return Err(refuse("the trusted agent key sets hold no Ed25519 key"));
        }
        Ok(Self {
            keys,
            nonces: NonceCache::with_ttl(MAX_LIFETIME_SECS + CLOCK_SKEW_SECS),
        })
    }

    /// Whether `parts` carries a trusted agent signature at all: a
    /// `Signature-Input` whose `tag` is one of the two purposes.
    pub fn is_tap_request(parts: &RequestParts) -> bool {
        parts
            .headers
            .get("signature-input")
            .and_then(|h| parse_signature_input(h).ok())
            .and_then(|i| i.params.tag)
            .is_some_and(|t| t == TAG_BROWSING || t == TAG_PAYMENT)
    }

    /// Check the trusted agent signature on `parts` at unix time `now`.
    pub fn verify(&self, parts: &RequestParts, now: u64) -> Result<TapAgent> {
        let header = |name: &str| {
            parts
                .headers
                .get(name)
                .ok_or_else(|| refuse(format!("no {name} header")))
        };
        let raw_input = header("signature-input")?;
        let input = parse_signature_input(raw_input)?;
        let purpose = match input.params.tag.as_deref() {
            Some(TAG_BROWSING) => TapPurpose::Browsing,
            Some(TAG_PAYMENT) => TapPurpose::Payment,
            _ => return Err(refuse("not a trusted agent signature")),
        };
        if input.params.alg != SignatureAlgorithm::Ed25519 {
            return Err(refuse("a trusted agent signature is ed25519"));
        }
        for required in REQUIRED_COMPONENTS {
            if !input.covered_components.iter().any(|c| c == required) {
                return Err(refuse(format!("the signature does not cover {required}")));
            }
        }
        let created = input
            .params
            .created
            .ok_or_else(|| refuse("no created time"))?;
        let expires = input.params.expires.ok_or_else(|| refuse("no expiry"))?;
        if expires < created || expires - created > MAX_LIFETIME_SECS {
            return Err(refuse("the signature's lifetime is too long"));
        }
        if created > now + CLOCK_SKEW_SECS || now > expires {
            return Err(refuse("the signature is not valid now"));
        }
        let key = self.keys.get(&input.params.keyid).ok_or_else(|| {
            refuse(format!(
                "key {} is not in an accepted key set",
                input.params.keyid
            ))
        })?;
        let raw = header("signature")?;
        let b64 = raw
            .strip_prefix(&format!("{}=:", input.label))
            .and_then(|s| s.strip_suffix(':'))
            .ok_or_else(|| refuse("malformed Signature header"))?;
        let signature_bytes = BASE64
            .decode(b64)
            .map_err(|_| refuse("Signature is not base64"))?;
        let nonce = input
            .params
            .nonce
            .clone()
            .ok_or_else(|| refuse("no nonce"))?;
        let key_id = input.params.keyid.clone();
        let signed = SignedHeaders {
            signature_input_raw: raw_input.clone(),
            signature_bytes,
            parsed: input,
        };
        verify_http_signature(parts, &signed, key, &SignatureAlgorithm::Ed25519)?;
        // Only a verified signature spends its nonce, so a forger cannot
        // burn the nonce of a request still to come.
        self.nonces.check_and_store(&format!("{key_id}:{nonce}"))?;
        Ok(TapAgent { key_id, purpose })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rfc9421::signature::{RawKeySigner, create_http_signature};
    use serde_json::json;

    const KID: &str = "network-key-1";

    fn seed() -> [u8; 32] {
        [7u8; 32]
    }

    fn jwk() -> Value {
        let pair = tenzro_crypto::keys::KeyPair::from_bytes(
            tenzro_crypto::keys::KeyType::Ed25519,
            &seed(),
        )
        .unwrap();
        let public = pair.public_key().as_bytes().to_vec();
        json!({ "keys": [{ "kty": "OKP", "crv": "Ed25519", "kid": KID, "x": B64URL.encode(public) }] })
    }

    fn signed(tag: &str, created: u64, expires: u64, nonce: &str, path: &str) -> RequestParts {
        let header = format!(
            "sig2=(\"@authority\" \"@path\");created={created};expires={expires};keyid=\"{KID}\";alg=\"ed25519\";nonce=\"{nonce}\";tag=\"{tag}\""
        );
        let parts = RequestParts::for_request("GET", "shop.example", "/checkout");
        let input = parse_signature_input(&header).unwrap();
        let signer = RawKeySigner::new(&seed(), &SignatureAlgorithm::Ed25519);
        let sig = create_http_signature(&parts, &input, &signer).unwrap();
        RequestParts::for_request("GET", "shop.example", path)
            .with_header("signature-input", header)
            .with_header("signature", format!("sig2=:{}:", BASE64.encode(sig)))
    }

    /// A signature by a key in the accepted set, inside its window, verifies
    /// once and names its purpose; a replay, another path, a stale or
    /// too-long window, and an unknown key are refused.
    #[test]
    fn a_trusted_agent_signature_verifies_once_inside_its_window() {
        let v = TapVerifier::from_jwks(&[jwk()]).unwrap();
        let now = 1_800_000_000;
        let paying = signed(TAG_PAYMENT, now, now + 60, "n1", "/checkout");
        assert!(TapVerifier::is_tap_request(&paying));
        assert_eq!(
            v.verify(&paying, now).unwrap(),
            TapAgent {
                key_id: KID.into(),
                purpose: TapPurpose::Payment
            }
        );
        assert!(v.verify(&paying, now).is_err(), "a nonce is spent once");

        let browsing = signed(TAG_BROWSING, now, now + 60, "n2", "/checkout");
        assert_eq!(
            v.verify(&browsing, now).unwrap().purpose,
            TapPurpose::Browsing
        );

        for (bad, why) in [
            (
                signed(TAG_PAYMENT, now, now + 60, "n3", "/elsewhere"),
                "path",
            ),
            (
                signed(TAG_PAYMENT, now - 600, now - 300, "n4", "/checkout"),
                "stale",
            ),
            (
                signed(
                    TAG_PAYMENT,
                    now,
                    now + MAX_LIFETIME_SECS + 1,
                    "n5",
                    "/checkout",
                ),
                "long",
            ),
        ] {
            assert!(v.verify(&bad, now).is_err(), "{why}");
        }
        let other = TapVerifier::from_jwks(&[json!({
            "kty": "OKP", "crv": "Ed25519", "kid": "another", "x": B64URL.encode([9u8; 32])
        })])
        .unwrap();
        assert!(
            other
                .verify(&signed(TAG_PAYMENT, now, now + 60, "n6", "/checkout"), now)
                .is_err()
        );
        assert!(TapVerifier::from_jwks(&[json!({ "kty": "RSA", "kid": "r" })]).is_err());
        assert!(!TapVerifier::is_tap_request(&RequestParts::for_request(
            "GET", "a", "/"
        )));
    }
}
