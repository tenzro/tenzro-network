//! Small utilities shared across `tenzro-auth` callers.
//!
//! These are intentionally non-cryptographic: their callers (HTTP
//! revocation handlers, audit-log decoders) need to peek at a JWT's
//! payload to extract a `jti` *before* the engine validates the
//! signature. Revocation is idempotent — the worst case for an attacker
//! who submits a forged JWT is that the engine "revokes" a `jti` that
//! doesn't exist in the audit index, which is a no-op.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// Extract the `jti` claim from a JWT *without* verifying its
/// signature.
///
/// Returns `None` if the token is not three dot-separated segments,
/// the middle segment is not valid base64url, the payload is not JSON,
/// or the payload has no `jti` field. The caller can treat any `None`
/// as "this is not something we minted; ignore it" — the auth engine
/// itself will reject malformed tokens at the validation layer.
///
/// Used by the HTTP `/oauth/revoke` and `/oauth/introspect` handlers
/// in `tenzro-node::web::oauth` and the legacy `/revoke` handler in
/// `tenzro-node::mcp::oauth`. Both call this to map a token to its
/// `jti` and then look the `jti` up in the audit index.
pub fn peek_unverified_jti(token: &str) -> Option<String> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return None;
    }
    let payload_bytes = URL_SAFE_NO_PAD.decode(parts[1]).ok()?;
    let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).ok()?;
    payload
        .get("jti")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peek_jti_happy_path() {
        // Header (irrelevant), payload {"jti":"abc"}, signature (irrelevant).
        let payload = URL_SAFE_NO_PAD.encode(br#"{"jti":"abc"}"#);
        let token = format!("eyJhbGciOiJIUzI1NiJ9.{}.sig", payload);
        assert_eq!(peek_unverified_jti(&token), Some("abc".to_string()));
    }

    #[test]
    fn peek_jti_returns_none_for_non_jwt() {
        assert!(peek_unverified_jti("").is_none());
        assert!(peek_unverified_jti("just.two").is_none());
        assert!(peek_unverified_jti("a.b.c.d").is_none());
    }

    #[test]
    fn peek_jti_returns_none_for_unparseable_payload() {
        let payload = URL_SAFE_NO_PAD.encode(b"not-json");
        let token = format!("h.{}.s", payload);
        assert!(peek_unverified_jti(&token).is_none());
    }

    #[test]
    fn peek_jti_returns_none_when_jti_absent() {
        let payload = URL_SAFE_NO_PAD.encode(br#"{"sub":"foo"}"#);
        let token = format!("h.{}.s", payload);
        assert!(peek_unverified_jti(&token).is_none());
    }
}
