//! RFC 7662 OAuth 2.0 Token Introspection — response shape + helpers.
//!
//! Token introspection is a resource-server-facing endpoint that
//! answers "is this token active right now, and what are its claims?"
//! without requiring the RS to validate the JWT signature itself.
//! Introspection is the canonical way for downstream services
//! (e.g., a Tenzro-aware MCP server, a third-party RS) to make a
//! single call to the AS and get back a machine-readable description
//! of a bearer token.
//!
//! ## What we return
//!
//! Per RFC 7662 §2.2, an active token's response MUST include
//! `active: true` and SHOULD include the standard claim names that
//! correspond to the token's content. We return:
//!
//! - **`active`** — `true` iff the token validates *and* its
//!   `controller_did` (and transitive controllers) are not revoked.
//! - **`token_type`** — always `"DPoP"` (RFC 9449) for tokens with a
//!   `cnf.jkt`; absent otherwise.
//! - **`sub`, `iss`, `aud`, `iat`, `nbf`, `exp`, `jti`** — copied
//!   verbatim from the JWT body.
//! - **`cnf`** — `{ "jkt": "..." }` for DPoP-bound tokens. Resource
//!   servers compare `cnf.jkt` against the inbound `DPoP` proof's
//!   thumbprint to bind the call to the holder.
//! - **`authorization_details`** — full RAR envelope (RFC 9396 §11
//!   recommends including this in introspection responses).
//! - **`controller_did`** — the authorizing DID; useful for RS-side
//!   logging.
//! - **`aap_*`** — every AAP claim present on the token. RSes that
//!   honor AAP (purpose binding, oversight, delegation depth) read
//!   them straight from this response.
//!
//! Inactive responses are minimal per RFC 7662 §2.2: just
//! `{"active": false}`. The AS deliberately does not leak whether
//! the token was ever valid, the reason it's inactive, or any of
//! its content — only that it is not currently valid.
//!
//! ## What we don't do
//!
//! - **No bulk introspection.** RFC 7662 has no batch endpoint;
//!   neither do we.
//! - **No `username`, `client_id`, `scope`.** Tenzro tokens have no
//!   `scope` (we use RAR exclusively) and no separate `client_id`
//!   (the bearer DID is the identifier). The `username` field is
//!   intentionally omitted — DIDs are not human-readable.
//!
//! ## Authentication of the introspection request
//!
//! RFC 7662 requires the introspection endpoint itself be
//! authenticated. Tenzro's HTTP layer (in
//! `tenzro-node::web::oauth::handle_introspect`) requires the
//! caller to present a DPoP-bound JWT with the
//! `aap_capabilities` action `"auth.introspect"`. This module is
//! protocol-agnostic — it just builds the response struct.

use crate::aap::{
    AapAgentClaim, AapAuditClaim, AapCapabilityClaim, AapContextClaim, AapDelegationClaim,
    AapOversightClaim, AapTaskClaim,
};
use crate::claims::{AuthClaims, Cnf};
use crate::rar::AuthorizationDetails;
use serde::{Deserialize, Serialize};

/// Response body for `POST /oauth/introspect` per RFC 7662 §2.2.
///
/// All fields except `active` are skipped from JSON when the token
/// is inactive — RFC 7662 §2.2 mandates a minimal `{"active": false}`
/// response in that case. The same struct represents both shapes; the
/// active path populates the optional fields, the inactive path
/// constructs via [`Self::inactive`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntrospectionResponse {
    /// `true` iff the token validates and its controller chain is not
    /// revoked. Always present.
    pub active: bool,

    /// `"DPoP"` for tokens with a `cnf.jkt` claim; absent otherwise.
    /// Per RFC 9449 §6 there is no other valid token type for
    /// proof-of-possession tokens.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_type: Option<String>,

    /// Subject — bearer DID (mirror of `claims.sub`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,

    /// Issuer — node DID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,

    /// Audience — typically the resource server URL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aud: Option<String>,

    /// Issued-at, Unix seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iat: Option<u64>,

    /// Not-before, Unix seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nbf: Option<u64>,

    /// Expires-at, Unix seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exp: Option<u64>,

    /// JWT id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,

    /// RFC 7800 confirmation claim — present iff the token is
    /// DPoP-bound.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cnf: Option<Cnf>,

    /// The authorizing DID (parent of `sub` in the act-chain). Equal
    /// to `sub` for autonomous-agent tokens.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub controller_did: Option<String>,

    /// RFC 9396 typed scope envelope. RFC 9396 §11 recommends
    /// including this in introspection responses.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_details: Option<AuthorizationDetails>,

    /// AAP `aap_agent` claim if present on the token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aap_agent: Option<AapAgentClaim>,

    /// AAP `aap_task` claim — purpose binding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aap_task: Option<AapTaskClaim>,

    /// AAP `aap_capabilities` claim — per-action constraints layered
    /// over RAR.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aap_capabilities: Option<Vec<AapCapabilityClaim>>,

    /// AAP `aap_oversight` claim — which actions require approval.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aap_oversight: Option<AapOversightClaim>,

    /// AAP `aap_delegation` claim — position in the act-chain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aap_delegation: Option<AapDelegationClaim>,

    /// AAP `aap_context` claim — operational context.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aap_context: Option<AapContextClaim>,

    /// AAP `aap_audit` claim — observability hooks.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aap_audit: Option<AapAuditClaim>,
}

impl IntrospectionResponse {
    /// Build the minimal `{"active": false}` response for an unknown,
    /// expired, or revoked token. Per RFC 7662 §2.2 this MUST NOT
    /// leak any other claim — the AS withholds even the issuer.
    pub fn inactive() -> Self {
        Self {
            active: false,
            token_type: None,
            sub: None,
            iss: None,
            aud: None,
            iat: None,
            nbf: None,
            exp: None,
            jti: None,
            cnf: None,
            controller_did: None,
            authorization_details: None,
            aap_agent: None,
            aap_task: None,
            aap_capabilities: None,
            aap_oversight: None,
            aap_delegation: None,
            aap_context: None,
            aap_audit: None,
        }
    }

    /// Build an `active: true` response from a validated
    /// [`AuthClaims`]. The caller is responsible for having
    /// already validated the token (signature, controller chain,
    /// and DPoP if applicable) — this constructor does not check
    /// anything; it only formats.
    pub fn from_claims(claims: &AuthClaims) -> Self {
        Self {
            active: true,
            token_type: claims.cnf.as_ref().map(|_| "DPoP".to_string()),
            sub: Some(claims.sub.clone()),
            iss: Some(claims.iss.clone()),
            aud: Some(claims.aud.clone()),
            iat: Some(claims.iat),
            nbf: Some(claims.nbf),
            exp: Some(claims.exp),
            jti: Some(claims.jti.clone()),
            cnf: claims.cnf.clone(),
            controller_did: Some(claims.controller_did.clone()),
            authorization_details: Some(claims.authorization_details.clone()),
            aap_agent: claims.aap_agent.clone(),
            aap_task: claims.aap_task.clone(),
            aap_capabilities: claims.aap_capabilities.clone(),
            aap_oversight: claims.aap_oversight.clone(),
            aap_delegation: claims.aap_delegation.clone(),
            aap_context: claims.aap_context.clone(),
            aap_audit: claims.aap_audit.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rar::{AuthorizationDetail, AuthorizationDetails};
    use tenzro_types::AssetId;

    fn sample_claims(with_cnf: bool) -> AuthClaims {
        AuthClaims {
            sub: "did:tenzro:human:abc".into(),
            iss: "did:tenzro:node:1".into(),
            aud: "https://rpc.tenzro.xyz".into(),
            iat: 1_700_000_000,
            nbf: 1_700_000_000,
            exp: 1_700_003_600,
            jti: "abc123".into(),
            cnf: if with_cnf {
                Some(Cnf {
                    jkt: "jkt-thumbprint-base64".into(),
                })
            } else {
                None
            },
            controller_did: "did:tenzro:human:abc".into(),
            authorization_details: AuthorizationDetails::single(AuthorizationDetail::Transfer {
                asset: AssetId::tnzo(),
                max_amount: 1000,
                max_daily_amount: None,
                allowed_counterparties: None,
            }),
            aap_agent: None,
            aap_task: None,
            aap_capabilities: None,
            aap_oversight: None,
            aap_delegation: None,
            aap_context: None,
            aap_audit: None,
        }
    }

    #[test]
    fn inactive_is_minimal() {
        let r = IntrospectionResponse::inactive();
        assert!(!r.active);
        let json = serde_json::to_value(&r).unwrap();
        // Only `active` should be present (everything else is
        // skip_serializing_if None).
        assert_eq!(json.as_object().unwrap().len(), 1);
        assert_eq!(json["active"], false);
    }

    #[test]
    fn from_claims_dpop_bound_sets_token_type() {
        let claims = sample_claims(true);
        let r = IntrospectionResponse::from_claims(&claims);
        assert!(r.active);
        assert_eq!(r.token_type.as_deref(), Some("DPoP"));
        assert_eq!(r.sub.as_deref(), Some("did:tenzro:human:abc"));
        assert!(r.cnf.is_some());
        assert!(r.authorization_details.is_some());
    }

    #[test]
    fn from_claims_no_cnf_omits_token_type() {
        let claims = sample_claims(false);
        let r = IntrospectionResponse::from_claims(&claims);
        assert!(r.active);
        assert!(r.token_type.is_none());
        assert!(r.cnf.is_none());
    }

    #[test]
    fn json_round_trip() {
        let claims = sample_claims(true);
        let r = IntrospectionResponse::from_claims(&claims);
        let json = serde_json::to_string(&r).unwrap();
        let back: IntrospectionResponse = serde_json::from_str(&json).unwrap();
        assert!(back.active);
        assert_eq!(back.sub, r.sub);
        assert_eq!(back.jti, r.jti);
        assert_eq!(back.exp, r.exp);
    }
}
