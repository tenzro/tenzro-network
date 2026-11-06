//! Tenzro agent request signatures over RFC 9421.
//!
//! A node serving an agent signs each HTTP request the agent sends with the
//! agent's key on that node: a P-256 key the node's TPM holds, which the
//! agent's controller approved in the agent's on-chain terms. The signature
//! covers the request line, the body digest, the agent's identity and the
//! mandate it acts under (the approval digest of its current terms), so a
//! server that has never seen the agent can check, per request:
//!
//! - who the agent is and that the key belongs to it ([`AgentKeyResolution`],
//!   read from chain state through `tenzro_resolveAgentKey`);
//! - that its controller has not revoked or quarantined it, and that it acts
//!   under the terms in force now;
//! - that the request is fresh and unaltered.
//!
//! The signature follows the Web Bot Auth profile: `tag="web-bot-auth"`,
//! the `keyid` is the key's JWK SHA-256 thumbprint (RFC 7638), and the
//! covered `Signature-Agent` header names the key directory
//! (`/.well-known/http-message-signatures-directory`) a verifier fetches the
//! key from. Every node serves the same directory for an agent, derived
//! from the agent's terms in consensus state at the current height: a
//! revoked, quarantined or expired agent's directory is empty from the next
//! block on.
//!
//! [`sign_agent_request`] produces the headers; [`verify_agent_request`]
//! checks them against a resolution; [`directory`] renders a directory.

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::signature::{
    HttpSigner, RequestParts, SignatureAlgorithm, SignatureInput, SignatureParams, SignedHeaders,
    create_http_signature, parse_signature_input, verify_http_signature,
};
use crate::error::{PaymentError, Result};

/// Label of the signature in `Signature-Input` and `Signature`.
pub const AGENT_SIGNATURE_LABEL: &str = "tenzro";
/// `tag` parameter naming this profile.
pub const AGENT_SIGNATURE_TAG: &str = "web-bot-auth";
/// Header naming the key directory, as a structured-field string.
pub const SIGNATURE_AGENT_HEADER: &str = "signature-agent";
/// Path of the key directory on any node.
pub const DIRECTORY_PATH: &str = "/.well-known/http-message-signatures-directory";
/// Media type of a key directory.
pub const DIRECTORY_MEDIA_TYPE: &str = "application/http-message-signatures-directory+json";
/// Longest validity the profile allows any signature, seconds.
pub const PROFILE_MAX_LIFETIME_SECS: u64 = 86_400;
/// Header carrying the agent's DID.
pub const AGENT_HEADER: &str = "tenzro-agent";
/// Header carrying the mandate reference: the approval digest of the terms
/// the agent acts under, hex.
pub const MANDATE_HEADER: &str = "tenzro-mandate";
/// Longest validity a signature may declare, seconds.
pub const MAX_SIGNATURE_LIFETIME_SECS: u64 = 300;
/// Clock skew tolerated on `created`, seconds.
pub const CLOCK_SKEW_SECS: u64 = 30;

/// Components every agent signature covers.
const REQUIRED_COMPONENTS: &[&str] = &[
    "@method",
    "@authority",
    "@path",
    SIGNATURE_AGENT_HEADER,
    AGENT_HEADER,
    MANDATE_HEADER,
];

/// What chain state says about an agent's signing key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentKeyResolution {
    /// The agent.
    pub agent_did: String,
    /// The agent's root identity.
    pub root: String,
    /// RFC 7638 thumbprint of the key, the signature's `keyid`.
    pub keyid: String,
    /// The P-256 key, `x || y`, hex.
    pub public_key: String,
    /// The machine whose TPM holds the key.
    pub machine_did: String,
    /// The TPM's certification of the key, hex.
    pub key_certification: String,
    /// Approval digest of the agent's terms in force, hex.
    pub mandate: String,
    /// Version of those terms.
    pub terms_version: u64,
    /// When the terms expire, unix ms.
    pub expires_at_ms: Option<u64>,
    /// The controller revoked the agent.
    pub revoked: bool,
    /// The agent is quarantined.
    pub quarantined: bool,
}

/// A request that passed [`verify_agent_request`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAgentRequest {
    pub agent_did: String,
    pub root: String,
    pub mandate: String,
    pub created: u64,
}

/// `Content-Digest` value of a body (RFC 9530, SHA-256).
pub fn content_digest(body: &[u8]) -> String {
    format!("sha-256=:{}:", BASE64.encode(Sha256::digest(body)))
}

fn refuse(msg: impl Into<String>) -> PaymentError {
    PaymentError::Rfc9421Error(msg.into())
}

/// The directory URL for `agent_did` under the HTTPS origin `origin`.
pub fn directory_url(origin: &str, agent_did: &str) -> String {
    format!(
        "{}{DIRECTORY_PATH}?agent={}",
        origin.trim_end_matches('/'),
        agent_did
            .replace('%', "%25")
            .replace('&', "%26")
            .replace('#', "%23")
    )
}

/// The `Signature-Agent` value naming `directory`, a structured-field
/// string.
fn signature_agent_value(directory: &str) -> Result<String> {
    if !directory.starts_with("https://") || directory.contains('"') || directory.contains('\\') {
        return Err(refuse("Signature-Agent names an https directory"));
    }
    Ok(format!("\"{directory}\""))
}

/// The headers that sign `parts` (with `body`, when it has one) for
/// `agent_did`, acting under `mandate`, with `signer`, the key `keyid`
/// names, whose key directory is `directory`. Returns `(name, value)` pairs
/// to add to the request.
#[allow(clippy::too_many_arguments)]
pub fn sign_agent_request(
    mut parts: RequestParts,
    body: Option<&[u8]>,
    agent_did: &str,
    mandate: &str,
    keyid: &str,
    directory: &str,
    created: u64,
    nonce: &str,
    signer: &dyn HttpSigner,
) -> Result<Vec<(String, String)>> {
    let mut headers = vec![
        (
            SIGNATURE_AGENT_HEADER.to_string(),
            signature_agent_value(directory)?,
        ),
        (AGENT_HEADER.to_string(), agent_did.to_string()),
        (MANDATE_HEADER.to_string(), mandate.to_string()),
    ];
    let mut components: Vec<String> = REQUIRED_COMPONENTS.iter().map(|c| c.to_string()).collect();
    if !parts.query.is_empty() {
        components.insert(3, "@query".to_string());
    }
    if let Some(body) = body.filter(|b| !b.is_empty()) {
        headers.push(("content-digest".to_string(), content_digest(body)));
        components.push("content-digest".to_string());
    }
    for (k, v) in &headers {
        parts = parts.with_header(k.clone(), v.clone());
    }
    let expires = created + MAX_SIGNATURE_LIFETIME_SECS;
    let input = SignatureInput {
        label: AGENT_SIGNATURE_LABEL.to_string(),
        covered_components: components.clone(),
        params: SignatureParams {
            label: AGENT_SIGNATURE_LABEL.to_string(),
            created: Some(created),
            expires: Some(expires),
            nonce: Some(nonce.to_string()),
            keyid: keyid.to_string(),
            alg: SignatureAlgorithm::EcdsaP256Sha256,
            tag: Some(AGENT_SIGNATURE_TAG.to_string()),
        },
    };
    let signature = create_http_signature(&parts, &input, signer)?;
    let quoted: Vec<String> = components.iter().map(|c| format!("\"{c}\"")).collect();
    headers.push((
        "signature-input".to_string(),
        format!(
            "{AGENT_SIGNATURE_LABEL}=({});created={created};expires={expires};nonce=\"{nonce}\";keyid=\"{keyid}\";alg=\"ecdsa-p256-sha256\";tag=\"{AGENT_SIGNATURE_TAG}\"",
            quoted.join(" ")
        ),
    ));
    headers.push((
        "signature".to_string(),
        format!("{AGENT_SIGNATURE_LABEL}=:{}:", BASE64.encode(signature)),
    ));
    Ok(headers)
}

/// The `keyid` and agent DID a signed request names, so the verifier can
/// resolve the key before checking the signature.
pub fn agent_key_of(parts: &RequestParts) -> Result<(String, String)> {
    let input = parse_signature_input(
        parts
            .headers
            .get("signature-input")
            .ok_or_else(|| refuse("no Signature-Input header"))?,
    )?;
    let agent = parts
        .headers
        .get(AGENT_HEADER)
        .ok_or_else(|| refuse("no Tenzro-Agent header"))?;
    Ok((input.params.keyid, agent.clone()))
}

/// Check a request signed with [`sign_agent_request`]. `parts` carries the
/// request's headers (lower-case names), `body` its body, `resolution` what
/// chain state says about the key the signature names, and `now` the
/// verifier's clock, unix seconds. Replay protection beyond the signature's
/// short lifetime is the caller's: remember the nonce until `expires`.
pub fn verify_agent_request(
    parts: &RequestParts,
    body: Option<&[u8]>,
    resolution: &AgentKeyResolution,
    now: u64,
) -> Result<VerifiedAgentRequest> {
    let header = |name: &str| {
        parts
            .headers
            .get(name)
            .ok_or_else(|| refuse(format!("no {name} header")))
    };
    let input = parse_signature_input(header("signature-input")?)?;
    if input.label != AGENT_SIGNATURE_LABEL
        || input.params.tag.as_deref() != Some(AGENT_SIGNATURE_TAG)
    {
        return Err(refuse("not a web-bot-auth agent signature"));
    }
    let directory = header(SIGNATURE_AGENT_HEADER)?;
    if !directory.starts_with("\"https://") || !directory.ends_with('"') {
        return Err(refuse("Signature-Agent does not name an https directory"));
    }
    if input.params.alg != SignatureAlgorithm::EcdsaP256Sha256 {
        return Err(refuse("an agent signature is ecdsa-p256-sha256"));
    }
    for required in REQUIRED_COMPONENTS {
        if !input.covered_components.iter().any(|c| c == required) {
            return Err(refuse(format!("the signature does not cover {required}")));
        }
    }
    if !parts.query.is_empty() && !input.covered_components.iter().any(|c| c == "@query") {
        return Err(refuse("the signature does not cover the query"));
    }
    if let Some(body) = body.filter(|b| !b.is_empty()) {
        if !input
            .covered_components
            .iter()
            .any(|c| c == "content-digest")
        {
            return Err(refuse("the signature does not cover the body"));
        }
        if *header("content-digest")? != content_digest(body) {
            return Err(refuse("the body does not match its Content-Digest"));
        }
    }
    let created = input
        .params
        .created
        .ok_or_else(|| refuse("no created time"))?;
    let expires = input.params.expires.ok_or_else(|| refuse("no expiry"))?;
    if expires < created
        || expires - created > MAX_SIGNATURE_LIFETIME_SECS.min(PROFILE_MAX_LIFETIME_SECS)
    {
        return Err(refuse("the signature's lifetime is too long"));
    }
    if created > now + CLOCK_SKEW_SECS || now > expires {
        return Err(refuse("the signature is not valid now"));
    }
    if input.params.keyid != resolution.keyid {
        return Err(refuse(
            "the key the signature names is not the resolved key",
        ));
    }
    let agent = header(AGENT_HEADER)?;
    if *agent != resolution.agent_did {
        return Err(refuse(
            "the key does not belong to the agent the request names",
        ));
    }
    if resolution.revoked {
        return Err(refuse("the agent's controller revoked it"));
    }
    if resolution.quarantined {
        return Err(refuse("the agent is quarantined"));
    }
    if resolution
        .expires_at_ms
        .is_some_and(|t| now.saturating_mul(1000) > t)
    {
        return Err(refuse("the agent's terms have expired"));
    }
    let mandate = header(MANDATE_HEADER)?;
    if !mandate.eq_ignore_ascii_case(&resolution.mandate) {
        return Err(refuse(
            "the request was made under terms no longer in force",
        ));
    }
    let raw = header("signature")?;
    let b64 = raw
        .strip_prefix(&format!("{AGENT_SIGNATURE_LABEL}=:"))
        .and_then(|s| s.strip_suffix(':'))
        .ok_or_else(|| refuse("malformed Signature header"))?;
    let signature_bytes = BASE64
        .decode(b64)
        .map_err(|_| refuse("Signature is not base64"))?;
    let xy =
        hex::decode(&resolution.public_key).map_err(|_| refuse("the resolved key is not hex"))?;
    let mut sec1 = vec![0x04];
    sec1.extend_from_slice(&xy);
    let signed = SignedHeaders {
        signature_input_raw: header("signature-input")?.clone(),
        signature_bytes,
        parsed: input,
    };
    verify_http_signature(parts, &signed, &sec1, &SignatureAlgorithm::EcdsaP256Sha256)?;
    Ok(VerifiedAgentRequest {
        agent_did: resolution.agent_did.clone(),
        root: resolution.root.clone(),
        mandate: resolution.mandate.clone(),
        created,
    })
}

/// The JWK of a P-256 key given as `x || y` hex, with its RFC 7638
/// thumbprint as `kid`.
pub fn jwk(public_key_xy_hex: &str) -> Result<serde_json::Value> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
    let xy = hex::decode(public_key_xy_hex).map_err(|_| refuse("the key is not hex"))?;
    if xy.len() != 64 {
        return Err(refuse("a P-256 key is 64 bytes, x || y"));
    }
    let (x, y) = (B64URL.encode(&xy[..32]), B64URL.encode(&xy[32..]));
    // RFC 7638: the required members, lexicographic, no whitespace.
    let canonical = format!(r#"{{"crv":"P-256","kty":"EC","x":"{x}","y":"{y}"}}"#);
    let kid = B64URL.encode(Sha256::digest(canonical.as_bytes()));
    Ok(serde_json::json!({ "kty": "EC", "crv": "P-256", "x": x, "y": y, "kid": kid }))
}

/// A key directory holding the keys of `live` resolutions: the keys of a
/// revoked, quarantined or expired agent are left out, so its directory is
/// empty. `now_ms` is the time of the state the resolutions were read at.
pub fn directory(resolutions: &[AgentKeyResolution], now_ms: u64) -> Result<serde_json::Value> {
    let mut keys = Vec::new();
    for r in resolutions {
        if r.revoked || r.quarantined || r.expires_at_ms.is_some_and(|t| now_ms >= t) {
            continue;
        }
        keys.push(jwk(&r.public_key)?);
    }
    Ok(serde_json::json!({ "keys": keys }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{Signature, SigningKey};
    use signature::Signer as _;

    struct TestKey(SigningKey);

    impl HttpSigner for TestKey {
        fn sign(&self, base: &[u8]) -> Result<Vec<u8>> {
            let sig: Signature = self.0.sign(base);
            Ok(sig.to_bytes().to_vec())
        }
    }

    const AGENT: &str = "did:tenzro:machine:alice:shopper";
    const MANDATE: &str = "ab12";
    const DIRECTORY: &str = "https://node.example/.well-known/http-message-signatures-directory?agent=did:tenzro:machine:alice:shopper";

    fn setup() -> (TestKey, AgentKeyResolution) {
        let key = SigningKey::from_slice(&[7u8; 32]).unwrap();
        let point = key.verifying_key().to_sec1_point(false);
        let resolution = AgentKeyResolution {
            agent_did: AGENT.into(),
            root: "did:tenzro:human:alice".into(),
            keyid: "jkt-1".into(),
            public_key: hex::encode(&point.as_bytes()[1..]),
            machine_did: "did:tenzro:machine:m1".into(),
            key_certification: String::new(),
            mandate: MANDATE.into(),
            terms_version: 1,
            expires_at_ms: None,
            revoked: false,
            quarantined: false,
        };
        (TestKey(key), resolution)
    }

    fn signed(key: &TestKey, body: &[u8], created: u64) -> RequestParts {
        let parts = RequestParts::for_request("POST", "shop.example", "/checkout");
        let headers = sign_agent_request(
            parts.clone(),
            Some(body),
            AGENT,
            MANDATE,
            "jkt-1",
            DIRECTORY,
            created,
            "n1",
            key,
        )
        .unwrap();
        headers
            .into_iter()
            .fold(parts, |p, (k, v)| p.with_header(k, v))
    }

    #[test]
    fn a_signed_agent_request_verifies_and_every_forgery_is_refused() {
        let (key, res) = setup();
        let now = 1_000_000;
        let body = br#"{"item":"x"}"#;
        let parts = signed(&key, body, now);
        let ok = verify_agent_request(&parts, Some(body), &res, now).unwrap();
        assert_eq!(ok.root, "did:tenzro:human:alice");
        assert_eq!(
            agent_key_of(&parts).unwrap(),
            ("jkt-1".to_string(), AGENT.to_string())
        );

        // A changed body, path or agent header no longer verifies.
        assert!(verify_agent_request(&parts, Some(b"{}"), &res, now).is_err());
        let mut moved = parts.clone();
        moved.path = "/refund".into();
        assert!(verify_agent_request(&moved, Some(body), &res, now).is_err());
        let other = parts
            .clone()
            .with_header(AGENT_HEADER, "did:tenzro:machine:alice:other");
        assert!(verify_agent_request(&other, Some(body), &res, now).is_err());

        // Chain state decides: revoked, quarantined, new terms, expired terms.
        for change in [
            AgentKeyResolution {
                revoked: true,
                ..res.clone()
            },
            AgentKeyResolution {
                quarantined: true,
                ..res.clone()
            },
            AgentKeyResolution {
                mandate: "cd34".into(),
                ..res.clone()
            },
            AgentKeyResolution {
                expires_at_ms: Some(now * 1000 - 1),
                ..res.clone()
            },
        ] {
            assert!(verify_agent_request(&parts, Some(body), &change, now).is_err());
        }

        // Another key under the same keyid fails the signature.
        let stranger = SigningKey::from_slice(&[9u8; 32]).unwrap();
        let p = stranger.verifying_key().to_sec1_point(false);
        let forged = AgentKeyResolution {
            public_key: hex::encode(&p.as_bytes()[1..]),
            ..res.clone()
        };
        assert!(verify_agent_request(&parts, Some(body), &forged, now).is_err());

        // A stale signature is refused.
        assert!(
            verify_agent_request(
                &parts,
                Some(body),
                &res,
                now + MAX_SIGNATURE_LIFETIME_SECS + 1
            )
            .is_err()
        );
    }

    #[test]
    fn the_signature_agent_header_is_required_and_covered() {
        let (key, res) = setup();
        let now = 1_000_000;
        let body = b"{}";
        let parts = signed(&key, body, now);
        let input = parts.headers.get("signature-input").unwrap();
        assert!(input.contains("\"signature-agent\"") && input.contains("tag=\"web-bot-auth\""));
        assert_eq!(
            parts.headers.get(SIGNATURE_AGENT_HEADER).unwrap(),
            &format!("\"{DIRECTORY}\"")
        );
        // Re-pointed at another directory: the signature no longer verifies.
        let moved = parts.clone().with_header(
            SIGNATURE_AGENT_HEADER,
            "\"https://evil.example/.well-known/http-message-signatures-directory\"",
        );
        assert!(verify_agent_request(&moved, Some(body), &res, now).is_err());
        // Without it: refused.
        let mut bare = parts.clone();
        bare.headers.remove(SIGNATURE_AGENT_HEADER);
        assert!(verify_agent_request(&bare, Some(body), &res, now).is_err());
        // A signer cannot name a directory that is not https.
        let p = RequestParts::for_request("GET", "shop.example", "/");
        assert!(
            sign_agent_request(p, None, AGENT, MANDATE, "jkt-1", "http://x", now, "n", &key)
                .is_err()
        );
    }

    #[test]
    fn a_directory_lists_only_live_keys() {
        let (_, res) = setup();
        let live = directory(std::slice::from_ref(&res), 10).unwrap();
        assert_eq!(live["keys"].as_array().unwrap().len(), 1);
        let k = &live["keys"][0];
        assert_eq!(k["kty"], "EC");
        assert_eq!(k["crv"], "P-256");
        assert_eq!(k["kid"].as_str().unwrap().len(), 43);
        for dead in [
            AgentKeyResolution {
                revoked: true,
                ..res.clone()
            },
            AgentKeyResolution {
                quarantined: true,
                ..res.clone()
            },
            AgentKeyResolution {
                expires_at_ms: Some(10),
                ..res.clone()
            },
        ] {
            assert_eq!(
                directory(&[dead], 10).unwrap()["keys"]
                    .as_array()
                    .unwrap()
                    .len(),
                0
            );
        }
        assert!(directory_url("https://n.example/", "did:x&y").ends_with("?agent=did:x%26y"));
    }
}

#[cfg(test)]
mod vector {
    use super::*;
    use p256::ecdsa::{Signature, SigningKey};
    use signature::Signer as _;

    struct Fixed(SigningKey);

    impl HttpSigner for Fixed {
        fn sign(&self, base: &[u8]) -> Result<Vec<u8>> {
            let sig: Signature = self.0.sign(base);
            Ok(sig.to_bytes().to_vec())
        }
    }

    /// The request the TypeScript SDK's verifier checks against the same
    /// headers: both implementations agree on the signature base.
    #[test]
    fn cross_implementation_vector() {
        let key = SigningKey::from_slice(&[0x11u8; 32]).unwrap();
        let xy = hex::encode(&key.verifying_key().to_sec1_point(false).as_bytes()[1..]);
        let parts = RequestParts::for_request("POST", "shop.example", "/buy").with_query("sku=1");
        let headers = sign_agent_request(
            parts,
            Some(b"{\"qty\":1}"),
            "did:tenzro:machine:alice:shopper",
            "beef",
            "jkt-vector",
            "https://node.example/.well-known/http-message-signatures-directory?agent=did:tenzro:machine:alice:shopper",
            1_700_000_000,
            "n1",
            &Fixed(key),
        )
        .unwrap();
        assert_eq!(xy, PUBLIC_KEY);
        let sig = headers.iter().find(|(k, _)| k == "signature").unwrap();
        assert_eq!(sig.1, EXPECTED_SIGNATURE);
    }

    const PUBLIC_KEY: &str = "0217e617f0b6443928278f96999e69a23a4f2c152bdf6d6cdf66e5b80282d4ed194a7debcb97712d2dda3ca85aa8765a56f45fc758599652f2897c65306e5794";

    const EXPECTED_SIGNATURE: &str = "tenzro=:4QIEap6tQ39GNiJ6idvGjehPECBALHDkmZxn9+PsBiVumLqx5ZLOrHaUoLv/4wyZbNOgiWF5mkNgU1J/uLcrRQ==:";
}
