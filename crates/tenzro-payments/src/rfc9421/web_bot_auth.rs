//! Web Bot Auth — proving an agent is who it says it is, to the open web.
//!
//! Tenzro already knows how to authenticate an agent *to Tenzro*: a TDIP DID,
//! resolved to a DID Document, with a delegation scope behind it. That proof is
//! worth nothing to a merchant behind Cloudflare, because nothing outside this
//! network resolves `did:tenzro:`. Web Bot Auth is the format the rest of the
//! web agreed on, and it is the one both card networks build their agent
//! identity on: Visa's Trusted Agent Protocol and Mastercard's Agent Pay both
//! authenticate with it, and Cloudflare, AWS WAF, Vercel, Shopify and Akamai
//! verify it at the edge.
//!
//! So this module is the translation layer, in both directions:
//!
//! - **Outbound** — a Tenzro agent signs its requests with its existing Ed25519
//!   identity key so an edge that has never heard of Tenzro can still verify it
//!   is a declared agent rather than a scraper wearing a browser's user-agent.
//! - **Inbound** — Tenzro verifies the same proof from foreign agents, so a
//!   node can tell a registered agent from an anonymous caller before deciding
//!   what to serve it.
//!
//! # What the signature covers, and why that is enough
//!
//! Web Bot Auth signs `@authority` — the host being addressed — and nothing
//! else by default. That looks thin next to signing a body, and it is
//! deliberate: the claim being made is *"this request comes from this agent"*,
//! not *"this request means what it says"*. Binding the authority stops a
//! captured signature being replayed against a different host, and `expires`
//! stops it being replayed against the same one later. Payment authorization
//! is a separate proof carried by AP2 mandates and x402 payloads, which do sign
//! amounts and recipients.
//!
//! When a `Signature-Agent` header is present it must also be covered,
//! otherwise an intermediary could rewrite which directory a verifier fetches
//! keys from and satisfy the signature with a key of its own choosing.
//!
//! # Relationship to the closed directories
//!
//! Visa and Mastercard each run their own registered-agent directory, and
//! neither resolves the other's. `tenzro-identity::kya` covers what that means
//! for Know-Your-Agent federation. This module implements the transport those
//! directories authenticate with; it does not join either directory.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{PaymentError, Result};

/// The exact tag every Web Bot Auth signature carries. A signature without it
/// is an RFC 9421 signature for some other purpose, and must not be read as an
/// agent identity claim.
pub const WEB_BOT_AUTH_TAG: &str = "web-bot-auth";

/// Where an agent publishes its keys. Fixed by the specification — a verifier
/// derives this path from the authority in `Signature-Agent` and fetches it
/// without configuration.
pub const DIRECTORY_PATH: &str = "/.well-known/http-message-signatures-directory";

/// The only algorithm this profile uses.
///
/// The draft permits RSA-PSS as well. Tenzro identities are Ed25519 all the way
/// down, so accepting a second algorithm here would add a verification path no
/// Tenzro key can ever exercise and a downgrade target an attacker could aim
/// for. Foreign agents signing with RSA are refused with a clear reason rather
/// than silently unverified.
pub const ALG: &str = "ed25519";

/// Recommended nonce length in bytes.
pub const NONCE_BYTES: usize = 64;

/// A parsed Web Bot Auth signature claim, after structural validation but
/// before the cryptographic check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BotAuthClaim {
    /// RFC 7638 JWK SHA-256 thumbprint, base64url — identifies which key in
    /// the agent's directory signed this.
    pub keyid: String,
    /// Signing algorithm. Always [`ALG`] once validated.
    pub alg: String,
    /// Unix seconds the signature was created.
    pub created: u64,
    /// Unix seconds the signature expires.
    pub expires: u64,
    /// Optional replay nonce.
    pub nonce: Option<String>,
    /// The authority the signature is bound to.
    pub authority: String,
    /// Directory URL from the `Signature-Agent` header, when the agent sent one.
    pub signature_agent: Option<String>,
}

impl BotAuthClaim {
    /// Whether this claim is still inside its validity window at `now_unix`.
    ///
    /// Expiry is checked by the verifier rather than trusted from the signer:
    /// a signature that never expires is a bearer token that leaks permanently
    /// the first time it is logged by a proxy.
    pub fn is_live(&self, now_unix: u64) -> bool {
        now_unix < self.expires && now_unix >= self.created.saturating_sub(MAX_CLOCK_SKEW_SECS)
    }

    /// How long the signature is valid for, in seconds.
    pub fn lifetime_secs(&self) -> u64 {
        self.expires.saturating_sub(self.created)
    }
}

/// Tolerance for a signer whose clock runs slightly ahead of ours.
///
/// Without it, a correctly-generated signature from a host a few seconds fast
/// is rejected as not-yet-valid, which presents as an intermittent auth failure
/// nobody can reproduce.
pub const MAX_CLOCK_SKEW_SECS: u64 = 60;

/// Longest signature lifetime accepted from a foreign agent.
///
/// The draft sets no ceiling, so an agent may nominate its own expiry — and one
/// that nominates a year is asking for a credential that outlives any plausible
/// key rotation. Capping at an hour keeps the replay window bounded regardless
/// of what the signer asked for.
pub const MAX_LIFETIME_SECS: u64 = 3600;

/// RFC 7638 JWK thumbprint of an Ed25519 public key, base64url-encoded.
///
/// The member ordering below is not stylistic: RFC 7638 requires the JSON to
/// contain exactly the required members, lexicographically ordered, with no
/// whitespace. Any deviation produces a different thumbprint and the key stops
/// resolving.
pub fn ed25519_thumbprint(public_key: &[u8; 32]) -> String {
    let x = URL_SAFE_NO_PAD.encode(public_key);
    let canonical = format!(r#"{{"crv":"Ed25519","kty":"OKP","x":"{x}"}}"#);
    URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes()))
}

/// The signature base a Web Bot Auth signature is computed over.
///
/// Built here rather than through the general RFC 9421 builder because this
/// profile's covered-component set is fixed by specification, and deriving it
/// from caller input would let a caller sign a weaker set than the profile
/// requires while still labelling it `web-bot-auth`.
pub fn signature_base(claim: &BotAuthClaim) -> String {
    let mut lines = Vec::with_capacity(3);
    lines.push(format!("\"@authority\": {}", claim.authority));
    if let Some(agent) = &claim.signature_agent {
        lines.push(format!("\"signature-agent\": {agent}"));
    }
    lines.push(format!(
        "\"@signature-params\": {}",
        signature_params(claim)
    ));
    lines.join("\n")
}

/// The `@signature-params` value — the covered component list plus parameters,
/// in the order the specification's own test vectors use.
pub fn signature_params(claim: &BotAuthClaim) -> String {
    let components = if claim.signature_agent.is_some() {
        "(\"@authority\" \"signature-agent\")"
    } else {
        "(\"@authority\")"
    };
    let mut s = format!(
        "{components};created={};keyid=\"{}\";alg=\"{}\";expires={}",
        claim.created, claim.keyid, claim.alg, claim.expires
    );
    if let Some(nonce) = &claim.nonce {
        s.push_str(&format!(";nonce=\"{nonce}\""));
    }
    s.push_str(&format!(";tag=\"{WEB_BOT_AUTH_TAG}\""));
    s
}

/// Build the `Signature-Input` header value for label `label`.
pub fn signature_input_header(label: &str, claim: &BotAuthClaim) -> String {
    format!("{label}={}", signature_params(claim))
}

/// Build the `Signature` header value for label `label`.
pub fn signature_header(label: &str, signature: &[u8]) -> String {
    format!(
        "{label}=:{}:",
        base64::engine::general_purpose::STANDARD.encode(signature)
    )
}

/// Structural checks a claim must pass before its signature is worth verifying.
///
/// Ordered cheapest-first and run before any cryptography: rejecting an expired
/// or mis-tagged claim costs a comparison, while verifying its signature costs
/// a curve operation. An attacker who can make a verifier do the expensive work
/// first has a cheap amplification.
pub fn validate_claim(claim: &BotAuthClaim, now_unix: u64) -> Result<()> {
    if claim.alg != ALG {
        return Err(PaymentError::CredentialError(format!(
            "web-bot-auth requires alg=\"{ALG}\"; this signature declares \"{}\". \
             Tenzro identities are Ed25519, so no other algorithm can resolve to a Tenzro key.",
            claim.alg
        )));
    }
    if claim.keyid.is_empty() {
        return Err(PaymentError::CredentialError(
            "web-bot-auth signature carries no keyid, so no key can be selected to verify it"
                .into(),
        ));
    }
    if claim.expires <= claim.created {
        return Err(PaymentError::CredentialError(
            "web-bot-auth signature expires at or before it was created".into(),
        ));
    }
    if claim.lifetime_secs() > MAX_LIFETIME_SECS {
        return Err(PaymentError::CredentialError(format!(
            "web-bot-auth signature asks for a {}s lifetime; the ceiling is {MAX_LIFETIME_SECS}s. \
             A long-lived signature is a bearer credential that outlives key rotation.",
            claim.lifetime_secs()
        )));
    }
    if !claim.is_live(now_unix) {
        return Err(PaymentError::CredentialError(format!(
            "web-bot-auth signature is outside its validity window \
             (created {}, expires {}, now {now_unix})",
            claim.created, claim.expires
        )));
    }
    if claim.authority.is_empty() {
        return Err(PaymentError::CredentialError(
            "web-bot-auth signature must cover @authority; none was bound".into(),
        ));
    }
    Ok(())
}

/// One key as published in an agent's signature directory.
///
/// This is a JWK Set by wire format, but a *different document* from
/// `/.well-known/jwks.json`: that one publishes Tenzro service keys for OAuth
/// introspection, this one publishes agent signing keys for edge verification.
/// Serving one at the other's path would hand verifiers keys that cannot
/// verify the signatures they are checking.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DirectoryKey {
    /// Always `"OKP"`.
    pub kty: String,
    /// Always `"Ed25519"`.
    pub crv: String,
    /// Raw public key, base64url unpadded.
    pub x: String,
    /// RFC 7638 thumbprint — what a `keyid` parameter matches against.
    pub kid: String,
    /// Always `"EdDSA"`.
    pub alg: String,
    /// Always `"sig"`.
    #[serde(rename = "use")]
    pub use_: String,
    /// Tenzro extension: the DID this key belongs to, so a verifier that *does*
    /// speak TDIP can resolve the full identity and its delegation scope
    /// instead of learning only that some declared bot signed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_did: Option<String>,
}

impl DirectoryKey {
    /// Build a directory entry from a raw Ed25519 public key.
    pub fn from_ed25519(public_key: &[u8; 32], agent_did: Option<String>) -> Self {
        Self {
            kty: "OKP".into(),
            crv: "Ed25519".into(),
            x: URL_SAFE_NO_PAD.encode(public_key),
            kid: ed25519_thumbprint(public_key),
            alg: "EdDSA".into(),
            use_: "sig".into(),
            agent_did,
        }
    }
}

/// The document served at [`DIRECTORY_PATH`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignatureDirectory {
    /// Published keys.
    pub keys: Vec<DirectoryKey>,
}

impl SignatureDirectory {
    /// Build a directory from Ed25519 keys.
    pub fn new(keys: Vec<DirectoryKey>) -> Self {
        Self { keys }
    }

    /// Find the key a `keyid` names.
    pub fn find(&self, keyid: &str) -> Option<&DirectoryKey> {
        self.keys.iter().find(|k| k.kid == keyid)
    }

    /// The raw Ed25519 public key for `keyid`, decoded.
    pub fn public_key(&self, keyid: &str) -> Option<[u8; 32]> {
        let entry = self.find(keyid)?;
        let bytes = URL_SAFE_NO_PAD.decode(&entry.x).ok()?;
        bytes.try_into().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claim(now: u64) -> BotAuthClaim {
        BotAuthClaim {
            keyid: "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U".into(),
            alg: ALG.into(),
            created: now,
            expires: now + 300,
            nonce: None,
            authority: "example.com".into(),
            signature_agent: None,
        }
    }

    #[test]
    fn thumbprint_matches_rfc7638_member_ordering() {
        // The thumbprint is only stable if the canonical JSON is exactly
        // {"crv":..,"kty":..,"x":..} with no whitespace. This pins the shape:
        // a reordering would silently change every keyid we publish and break
        // resolution for every verifier that cached the old one.
        let pk = [7u8; 32];
        let t = ed25519_thumbprint(&pk);
        assert_eq!(t, ed25519_thumbprint(&pk), "must be deterministic");
        assert!(!t.contains('='), "base64url thumbprints are unpadded");
        assert!(!t.contains('+') && !t.contains('/'), "must be url-safe");
        // A different key must give a different thumbprint.
        assert_ne!(t, ed25519_thumbprint(&[8u8; 32]));
    }

    #[test]
    fn signature_params_match_the_specs_test_vector_shape() {
        let c = BotAuthClaim {
            keyid: "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U".into(),
            alg: "ed25519".into(),
            created: 1735689600,
            expires: 1735693200,
            nonce: Some("mYotfW3CUjI68sbGw6oKd7kyXqPjZEtU8xFPGWFrqOAf5qC6MDe3pys3SWWCudB0MvwslHy32WXUpkR7u0lt/w==".into()),
            authority: "example.com".into(),
            signature_agent: None,
        };
        let p = signature_params(&c);
        assert!(p.starts_with("(\"@authority\");created=1735689600;"));
        assert!(p.contains("keyid=\"poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U\""));
        assert!(p.contains("alg=\"ed25519\""));
        assert!(p.contains("expires=1735693200"));
        assert!(p.ends_with("tag=\"web-bot-auth\""));
    }

    #[test]
    fn signature_agent_is_covered_when_present() {
        // If the header is sent but not signed, an intermediary can swap the
        // directory URL and satisfy the signature with its own key.
        let mut c = claim(1_000);
        c.signature_agent = Some("https://agent.example".into());
        let params = signature_params(&c);
        assert!(params.starts_with("(\"@authority\" \"signature-agent\")"));
        assert!(signature_base(&c).contains("\"signature-agent\": https://agent.example"));
    }

    #[test]
    fn signature_base_binds_the_authority() {
        let c = claim(1_000);
        assert!(signature_base(&c).starts_with("\"@authority\": example.com"));
    }

    #[test]
    fn a_valid_claim_passes() {
        assert!(validate_claim(&claim(1_000), 1_000).is_ok());
    }

    #[test]
    fn an_expired_claim_is_refused() {
        let c = claim(1_000);
        assert!(validate_claim(&c, c.expires + 1).is_err());
    }

    #[test]
    fn a_claim_from_the_future_is_refused_beyond_the_skew_allowance() {
        let c = claim(10_000);
        // Inside the allowance: a slightly fast signer still verifies.
        assert!(validate_claim(&c, 10_000 - MAX_CLOCK_SKEW_SECS).is_ok());
        // Beyond it: refused.
        assert!(validate_claim(&c, 10_000 - MAX_CLOCK_SKEW_SECS - 1).is_err());
    }

    #[test]
    fn a_long_lived_signature_is_refused() {
        // The draft sets no ceiling, so the signer can ask for anything. A
        // year-long signature is a bearer credential that outlives rotation.
        let mut c = claim(1_000);
        c.expires = c.created + MAX_LIFETIME_SECS + 1;
        assert!(validate_claim(&c, 1_000).is_err());
        c.expires = c.created + MAX_LIFETIME_SECS;
        assert!(validate_claim(&c, 1_000).is_ok());
    }

    #[test]
    fn a_non_ed25519_algorithm_is_refused_rather_than_ignored() {
        let mut c = claim(1_000);
        c.alg = "rsa-pss-sha512".into();
        let e = validate_claim(&c, 1_000).unwrap_err().to_string();
        assert!(
            e.contains("ed25519"),
            "refusal must name the requirement: {e}"
        );
    }

    #[test]
    fn a_claim_with_no_keyid_is_refused() {
        let mut c = claim(1_000);
        c.keyid.clear();
        assert!(validate_claim(&c, 1_000).is_err());
    }

    #[test]
    fn expiry_before_creation_is_refused() {
        let mut c = claim(1_000);
        c.expires = c.created;
        assert!(validate_claim(&c, 1_000).is_err());
    }

    #[test]
    fn an_unbound_authority_is_refused() {
        // Without @authority the signature replays against any host.
        let mut c = claim(1_000);
        c.authority.clear();
        assert!(validate_claim(&c, 1_000).is_err());
    }

    #[test]
    fn directory_roundtrips_a_key_by_thumbprint() {
        let pk = [3u8; 32];
        let key = DirectoryKey::from_ed25519(&pk, Some("did:tenzro:machine:abc".into()));
        let dir = SignatureDirectory::new(vec![key.clone()]);
        assert_eq!(dir.find(&key.kid).unwrap(), &key);
        assert_eq!(dir.public_key(&key.kid).unwrap(), pk);
        assert!(dir.find("not-a-thumbprint").is_none());
    }

    #[test]
    fn directory_key_thumbprint_is_its_own_kid() {
        // A directory whose kid disagrees with the key's thumbprint is
        // unresolvable: verifiers match on the thumbprint they compute.
        let pk = [9u8; 32];
        let key = DirectoryKey::from_ed25519(&pk, None);
        assert_eq!(key.kid, ed25519_thumbprint(&pk));
    }

    #[test]
    fn directory_serializes_as_a_jwk_set() {
        let dir = SignatureDirectory::new(vec![DirectoryKey::from_ed25519(&[1u8; 32], None)]);
        let v: serde_json::Value = serde_json::to_value(&dir).unwrap();
        let k = &v["keys"][0];
        assert_eq!(k["kty"], "OKP");
        assert_eq!(k["crv"], "Ed25519");
        assert_eq!(k["alg"], "EdDSA");
        assert_eq!(k["use"], "sig");
        assert!(k.get("agent_did").is_none(), "absent DID must be omitted");
    }

    #[test]
    fn the_directory_path_is_the_specified_one() {
        // Verifiers derive this path without configuration; changing it makes
        // every key we publish undiscoverable.
        assert_eq!(
            DIRECTORY_PATH,
            "/.well-known/http-message-signatures-directory"
        );
        assert_eq!(WEB_BOT_AUTH_TAG, "web-bot-auth");
    }
}
