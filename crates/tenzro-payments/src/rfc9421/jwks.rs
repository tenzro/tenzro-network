//! JWK / JWK Set publication for Tenzro agent keys (RFC 7517 / RFC 7518).
//!
//! This is the **producer** side that complements [`crate::visa_tap::registry`]
//! (which is a JWKS *consumer* for external Visa registries). Tenzro itself
//! publishes its agent keys at `/.well-known/jwks.json` so that external
//! verifiers (Visa TAP, Mastercard, Stripe MPP, AP2 facilitators, x402
//! settlement nodes, generic RFC 9421 clients) can fetch a public key by
//! `kid` and verify HTTP message signatures created by Tenzro agents.
//!
//! # Encoding
//!
//! Each [`AgentPublicKeyInfo`] is converted to a [`Jwk`] using the
//! algorithm-specific encoding rules of RFC 7518:
//!
//! - **Ed25519** → `{kty: "OKP", crv: "Ed25519", alg: "EdDSA", x: <base64url(32B raw)>}`
//! - **ECDSA P-256** → `{kty: "EC", crv: "P-256", alg: "ES256", x: <base64url(X)>, y: <base64url(Y)>}`
//!   from raw SEC1 uncompressed (`0x04 || X(32) || Y(32)`).
//! - **ECDSA P-384** → `{kty: "EC", crv: "P-384", alg: "ES384", x: <base64url(X)>, y: <base64url(Y)>}`
//!   from raw SEC1 uncompressed (`0x04 || X(48) || Y(48)`).
//! - **RSA-PSS-SHA256** / **RSA-PSS-SHA512** / **RSA-v1.5-SHA256** →
//!   `{kty: "RSA", alg: "PS256"/"PS512"/"RS256", n: <base64url(modulus)>, e: <base64url(exponent)>}`
//!   from SPKI DER (`SubjectPublicKeyInfo` per RFC 5280).
//! - **HMAC-SHA-256** is intentionally **not published** — symmetric keys
//!   must never be exposed in a public JWKS.
//!
//! # JSON shape
//!
//! ```json
//! {
//!   "keys": [
//!     {
//!       "kty": "OKP",
//!       "crv": "Ed25519",
//!       "alg": "EdDSA",
//!       "kid": "did:tenzro:machine:0xabc",
//!       "use": "sig",
//!       "key_ops": ["verify"],
//!       "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
//!     }
//!   ]
//! }
//! ```

use crate::error::{PaymentError, Result};
use crate::rfc9421::{AgentPublicKeyInfo, SignatureAlgorithm};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};

/// A single JWK (RFC 7517 §4) covering the four key types needed for
/// RFC 9421 verification: `OKP` (Ed25519), `EC` (NIST curves), `RSA`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Jwk {
    /// Key type. One of `"OKP"`, `"EC"`, `"RSA"`.
    pub kty: String,
    /// Curve name. `"Ed25519"` for OKP; `"P-256"` / `"P-384"` for EC.
    /// Omitted for RSA.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crv: Option<String>,
    /// JWA algorithm identifier (RFC 7518 §3.1).
    /// `"EdDSA"`, `"ES256"`, `"ES384"`, `"PS256"`, `"PS512"`, `"RS256"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
    /// Key ID. We use the agent DID (with optional `#fragment`) so that
    /// RFC 9421 `keyid` parameters resolve directly here.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    /// Public-key use, RFC 7517 §4.2. Always `"sig"` for our keys.
    #[serde(rename = "use", skip_serializing_if = "Option::is_none")]
    pub use_: Option<String>,
    /// Key operations, RFC 7517 §4.3. Always `["verify"]` since we publish
    /// only the public half.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_ops: Option<Vec<String>>,
    /// X coordinate / Ed25519 raw public key bytes (base64url, no padding).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x: Option<String>,
    /// Y coordinate (EC only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,
    /// RSA modulus (base64url).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub n: Option<String>,
    /// RSA exponent (base64url).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub e: Option<String>,
    /// Tenzro extension: agent DID. Lets external verifiers resolve a
    /// Tenzro identity from a JWKS entry without an extra round-trip.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_did: Option<String>,
    /// Tenzro extension: identity-status flag. Set to `false` when the
    /// agent has been suspended/revoked. Verifiers SHOULD reject signatures
    /// from inactive keys.
    #[serde(default = "default_active")]
    pub active: bool,
}

fn default_active() -> bool {
    true
}

/// JWK Set (RFC 7517 §5) — the wire format served at `/.well-known/jwks.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwkSet {
    pub keys: Vec<Jwk>,
}

impl JwkSet {
    /// Build a JWK Set from agent records, skipping any that fail to
    /// encode (HMAC keys, malformed key bytes). Errors are logged and
    /// the bad entry is dropped — a single bad key must not break the
    /// whole set.
    pub fn from_agents(records: &[AgentPublicKeyInfo]) -> Self {
        let mut keys = Vec::with_capacity(records.len());
        for rec in records {
            match Jwk::try_from_agent(rec) {
                Ok(jwk) => keys.push(jwk),
                Err(e) => tracing::warn!(
                    key_id = %rec.key_id,
                    algorithm = ?rec.algorithm,
                    "skipping JWK encode: {}",
                    e
                ),
            }
        }
        JwkSet { keys }
    }
}

impl Jwk {
    /// Convert an agent public-key record to a JWK using RFC 7518 §6
    /// encoding rules. Symmetric (HMAC) keys are explicitly rejected —
    /// they MUST NOT appear in a public JWKS.
    pub fn try_from_agent(rec: &AgentPublicKeyInfo) -> Result<Self> {
        let base = JwkBase {
            kid: Some(rec.key_id.clone()),
            use_: Some("sig".to_string()),
            key_ops: Some(vec!["verify".to_string()]),
            agent_did: rec.agent_did.clone(),
            active: rec.is_active,
        };

        match rec.algorithm {
            SignatureAlgorithm::Ed25519 => encode_ed25519(&rec.public_key_bytes, base),
            SignatureAlgorithm::EcdsaP256Sha256 => {
                encode_ec(&rec.public_key_bytes, "P-256", "ES256", 32, base)
            }
            SignatureAlgorithm::EcdsaP384Sha384 => {
                encode_ec(&rec.public_key_bytes, "P-384", "ES384", 48, base)
            }
            SignatureAlgorithm::RsaPssSha256 => encode_rsa(&rec.public_key_bytes, "PS256", base),
            SignatureAlgorithm::RsaPssSha512 => encode_rsa(&rec.public_key_bytes, "PS512", base),
            SignatureAlgorithm::RsaV15Sha256 => encode_rsa(&rec.public_key_bytes, "RS256", base),
            SignatureAlgorithm::HmacSha256 => Err(PaymentError::Rfc9421Error(
                "HMAC keys MUST NOT be published in JWKS (symmetric)".to_string(),
            )),
        }
    }
}

/// Common JWK metadata fields that don't depend on algorithm.
struct JwkBase {
    kid: Option<String>,
    use_: Option<String>,
    key_ops: Option<Vec<String>>,
    agent_did: Option<String>,
    active: bool,
}

fn encode_ed25519(bytes: &[u8], base: JwkBase) -> Result<Jwk> {
    if bytes.len() != 32 {
        return Err(PaymentError::Rfc9421Error(format!(
            "Ed25519 public key must be 32 bytes, got {}",
            bytes.len()
        )));
    }
    Ok(Jwk {
        kty: "OKP".to_string(),
        crv: Some("Ed25519".to_string()),
        alg: Some("EdDSA".to_string()),
        kid: base.kid,
        use_: base.use_,
        key_ops: base.key_ops,
        x: Some(URL_SAFE_NO_PAD.encode(bytes)),
        y: None,
        n: None,
        e: None,
        agent_did: base.agent_did,
        active: base.active,
    })
}

fn encode_ec(bytes: &[u8], crv: &str, alg: &str, coord_len: usize, base: JwkBase) -> Result<Jwk> {
    // SEC1 uncompressed: 0x04 || X || Y. SPKI parsing is done by the
    // consumer (rfc9421::signature) — for the JWKS we accept either
    // raw SEC1 (preferred) or DER-wrapped SPKI.
    let (x_bytes, y_bytes) = if bytes.len() == 1 + 2 * coord_len && bytes[0] == 0x04 {
        // raw SEC1 uncompressed
        (&bytes[1..1 + coord_len], &bytes[1 + coord_len..])
    } else {
        // Try SPKI: extract subjectPublicKey BIT STRING and treat as SEC1.
        let extracted = extract_spki_subject_public_key(bytes)?;
        if extracted.len() != 1 + 2 * coord_len || extracted[0] != 0x04 {
            return Err(PaymentError::Rfc9421Error(format!(
                "{} key not in SEC1 uncompressed form (expected {} bytes, 0x04 prefix)",
                crv,
                1 + 2 * coord_len
            )));
        }
        // Borrowed slices need to outlive the function — return owned bytes
        // via a separate path. We re-extract here into a Vec and split.
        return Ok(Jwk {
            kty: "EC".to_string(),
            crv: Some(crv.to_string()),
            alg: Some(alg.to_string()),
            kid: base.kid,
            use_: base.use_,
            key_ops: base.key_ops,
            x: Some(URL_SAFE_NO_PAD.encode(&extracted[1..1 + coord_len])),
            y: Some(URL_SAFE_NO_PAD.encode(&extracted[1 + coord_len..])),
            n: None,
            e: None,
            agent_did: base.agent_did,
            active: base.active,
        });
    };

    Ok(Jwk {
        kty: "EC".to_string(),
        crv: Some(crv.to_string()),
        alg: Some(alg.to_string()),
        kid: base.kid,
        use_: base.use_,
        key_ops: base.key_ops,
        x: Some(URL_SAFE_NO_PAD.encode(x_bytes)),
        y: Some(URL_SAFE_NO_PAD.encode(y_bytes)),
        n: None,
        e: None,
        agent_did: base.agent_did,
        active: base.active,
    })
}

fn encode_rsa(bytes: &[u8], alg: &str, base: JwkBase) -> Result<Jwk> {
    use rsa::RsaPublicKey;
    use rsa::pkcs8::DecodePublicKey;
    use rsa::traits::PublicKeyParts;

    let pk = RsaPublicKey::from_public_key_der(bytes)
        .map_err(|e| PaymentError::Rfc9421Error(format!("RSA SPKI parse failed: {}", e)))?;

    let n_bytes = pk.n().to_bytes_be();
    let e_bytes = pk.e().to_bytes_be();

    Ok(Jwk {
        kty: "RSA".to_string(),
        crv: None,
        alg: Some(alg.to_string()),
        kid: base.kid,
        use_: base.use_,
        key_ops: base.key_ops,
        x: None,
        y: None,
        n: Some(URL_SAFE_NO_PAD.encode(&n_bytes)),
        e: Some(URL_SAFE_NO_PAD.encode(&e_bytes)),
        agent_did: base.agent_did,
        active: base.active,
    })
}

/// Extract the `subjectPublicKey` BIT STRING from a SubjectPublicKeyInfo DER
/// blob using the `spki` crate. Returns the raw SEC1-encoded EC public key.
fn extract_spki_subject_public_key(spki_der: &[u8]) -> Result<Vec<u8>> {
    use spki::SubjectPublicKeyInfoRef;

    let spki: SubjectPublicKeyInfoRef = SubjectPublicKeyInfoRef::try_from(spki_der)
        .map_err(|e| PaymentError::Rfc9421Error(format!("SPKI decode failed: {}", e)))?;
    Ok(spki
        .subject_public_key
        .as_bytes()
        .ok_or_else(|| {
            PaymentError::Rfc9421Error("SPKI subjectPublicKey not byte-aligned".to_string())
        })?
        .to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ed25519_record(active: bool) -> AgentPublicKeyInfo {
        AgentPublicKeyInfo {
            key_id: "did:tenzro:machine:abc".to_string(),
            algorithm: SignatureAlgorithm::Ed25519,
            public_key_bytes: vec![0x42; 32],
            agent_did: Some("did:tenzro:machine:abc".to_string()),
            is_active: active,
        }
    }

    #[test]
    fn test_ed25519_jwk_encoding() {
        let rec = ed25519_record(true);
        let jwk = Jwk::try_from_agent(&rec).unwrap();
        assert_eq!(jwk.kty, "OKP");
        assert_eq!(jwk.crv.as_deref(), Some("Ed25519"));
        assert_eq!(jwk.alg.as_deref(), Some("EdDSA"));
        assert_eq!(jwk.kid.as_deref(), Some("did:tenzro:machine:abc"));
        assert_eq!(jwk.use_.as_deref(), Some("sig"));
        assert_eq!(jwk.key_ops.as_deref(), Some(&["verify".to_string()][..]));
        assert!(jwk.x.is_some());
        assert!(jwk.y.is_none());
        assert!(jwk.n.is_none());
        assert!(jwk.e.is_none());
        assert!(jwk.active);
        // Decode roundtrip
        let decoded = URL_SAFE_NO_PAD.decode(jwk.x.as_ref().unwrap()).unwrap();
        assert_eq!(decoded, vec![0x42; 32]);
    }

    #[test]
    fn test_ed25519_wrong_length_rejected() {
        let mut rec = ed25519_record(true);
        rec.public_key_bytes = vec![0u8; 16];
        let result = Jwk::try_from_agent(&rec);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("32 bytes"));
    }

    #[test]
    fn test_inactive_agent_jwk_marked_inactive() {
        let rec = ed25519_record(false);
        let jwk = Jwk::try_from_agent(&rec).unwrap();
        assert!(!jwk.active);
    }

    #[test]
    fn test_p256_sec1_uncompressed_round_trip() {
        // Build a valid P-256 key from scratch using the p256 crate, then
        // serialize as SEC1 uncompressed and feed through our encoder.
        use ::p256::elliptic_curve::Generate;
        use getrandom_0_4::{SysRng, rand_core::UnwrapErr};
        use p256::ecdsa::SigningKey as P256Sk;
        let sk = P256Sk::generate_from_rng(&mut UnwrapErr(SysRng));
        let vk = sk.verifying_key();
        let encoded = vk.to_sec1_point(false); // uncompressed
        let sec1 = encoded.as_bytes().to_vec();
        assert_eq!(sec1.len(), 65);
        assert_eq!(sec1[0], 0x04);

        let rec = AgentPublicKeyInfo {
            key_id: "did:tenzro:machine:p256".to_string(),
            algorithm: SignatureAlgorithm::EcdsaP256Sha256,
            public_key_bytes: sec1.clone(),
            agent_did: Some("did:tenzro:machine:p256".to_string()),
            is_active: true,
        };

        let jwk = Jwk::try_from_agent(&rec).unwrap();
        assert_eq!(jwk.kty, "EC");
        assert_eq!(jwk.crv.as_deref(), Some("P-256"));
        assert_eq!(jwk.alg.as_deref(), Some("ES256"));
        let x = URL_SAFE_NO_PAD.decode(jwk.x.as_ref().unwrap()).unwrap();
        let y = URL_SAFE_NO_PAD.decode(jwk.y.as_ref().unwrap()).unwrap();
        assert_eq!(x.len(), 32);
        assert_eq!(y.len(), 32);
        assert_eq!(x, sec1[1..33]);
        assert_eq!(y, sec1[33..]);
    }

    #[test]
    fn test_p384_sec1_uncompressed_round_trip() {
        use ::p384::elliptic_curve::Generate;
        use getrandom_0_4::{SysRng, rand_core::UnwrapErr};
        use p384::ecdsa::SigningKey as P384Sk;
        let sk = P384Sk::generate_from_rng(&mut UnwrapErr(SysRng));
        let vk = sk.verifying_key();
        let encoded = vk.to_sec1_point(false);
        let sec1 = encoded.as_bytes().to_vec();
        assert_eq!(sec1.len(), 97); // 1 + 48 + 48
        assert_eq!(sec1[0], 0x04);

        let rec = AgentPublicKeyInfo {
            key_id: "did:tenzro:machine:p384".to_string(),
            algorithm: SignatureAlgorithm::EcdsaP384Sha384,
            public_key_bytes: sec1.clone(),
            agent_did: Some("did:tenzro:machine:p384".to_string()),
            is_active: true,
        };

        let jwk = Jwk::try_from_agent(&rec).unwrap();
        assert_eq!(jwk.crv.as_deref(), Some("P-384"));
        assert_eq!(jwk.alg.as_deref(), Some("ES384"));
        let x = URL_SAFE_NO_PAD.decode(jwk.x.as_ref().unwrap()).unwrap();
        assert_eq!(x.len(), 48);
    }

    #[test]
    fn test_rsa_pss_sha256_jwk_encoding() {
        use rsa::RsaPrivateKey;
        use rsa::pkcs8::EncodePublicKey;
        let mut rng = rand::rngs::OsRng;
        let sk = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let pk = sk.to_public_key();
        let spki_der = pk.to_public_key_der().unwrap().as_bytes().to_vec();

        let rec = AgentPublicKeyInfo {
            key_id: "did:tenzro:machine:rsa".to_string(),
            algorithm: SignatureAlgorithm::RsaPssSha256,
            public_key_bytes: spki_der,
            agent_did: Some("did:tenzro:machine:rsa".to_string()),
            is_active: true,
        };

        let jwk = Jwk::try_from_agent(&rec).unwrap();
        assert_eq!(jwk.kty, "RSA");
        assert_eq!(jwk.alg.as_deref(), Some("PS256"));
        assert!(jwk.n.is_some());
        assert!(jwk.e.is_some());
        let n = URL_SAFE_NO_PAD.decode(jwk.n.as_ref().unwrap()).unwrap();
        // 2048-bit modulus is 256 bytes
        assert_eq!(n.len(), 256);
    }

    #[test]
    fn test_hmac_jwk_rejected() {
        let rec = AgentPublicKeyInfo {
            key_id: "did:tenzro:machine:hmac".to_string(),
            algorithm: SignatureAlgorithm::HmacSha256,
            public_key_bytes: vec![0u8; 32],
            agent_did: None,
            is_active: true,
        };
        let result = Jwk::try_from_agent(&rec);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("HMAC"));
    }

    #[test]
    fn test_jwkset_from_agents_skips_invalid() {
        let valid = ed25519_record(true);
        let invalid_hmac = AgentPublicKeyInfo {
            key_id: "hmac-id".to_string(),
            algorithm: SignatureAlgorithm::HmacSha256,
            public_key_bytes: vec![0u8; 32],
            agent_did: None,
            is_active: true,
        };
        let mut wrong_len = ed25519_record(true);
        wrong_len.public_key_bytes = vec![1u8; 8];

        let set = JwkSet::from_agents(&[valid, invalid_hmac, wrong_len]);
        assert_eq!(set.keys.len(), 1);
        assert_eq!(set.keys[0].kty, "OKP");
    }

    #[test]
    fn test_jwkset_serializes_to_keys_array() {
        let set = JwkSet::from_agents(&[ed25519_record(true)]);
        let json = serde_json::to_value(&set).unwrap();
        assert!(json.get("keys").is_some());
        assert!(json["keys"].is_array());
        assert_eq!(json["keys"][0]["kty"], "OKP");
        assert_eq!(json["keys"][0]["crv"], "Ed25519");
    }
}
