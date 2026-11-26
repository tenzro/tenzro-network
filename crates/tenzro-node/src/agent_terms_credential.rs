//! An agent's consensus Terms as documents other systems read.
//!
//! - an unsigned W3C Verifiable Credential 2.0 whose issuer is the agent's
//!   controller: the controller signs it with its own key, on its own device,
//!   and a relying party that never reads this chain checks what the agent
//!   may do from that signature;
//! - the claims of an OAuth on-behalf-of token (RFC 8693 `act`, with the
//!   payment limits as RFC 9396 authorization details), for an authorization
//!   server that issues the agent a token for its controller;
//! - the agent registration data a payment network's agent program asks for:
//!   who the agent is, who answers for it, and what it may spend.
//!
//! The node signs none of them: what the Terms authorize is the controller's
//! statement, never the node's.

use serde_json::{Value, json};
use tenzro_vm::native::StoredAgentTerms;

/// The credential type of an exported Terms credential.
pub const TERMS_CREDENTIAL_TYPE: &str = "TenzroAgentTermsCredential";

fn rfc3339_ms(ms: i64) -> Option<String> {
    chrono::DateTime::from_timestamp_millis(ms)
        .map(|t| t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
}

/// The three documents for `agent_did` under `stored`.
pub fn documents(agent_did: &str, stored: &StoredAgentTerms) -> Value {
    let terms = &stored.terms;
    let scope = &terms.delegation_scope;
    let expires_ms = terms.expires_at_ms.map(|e| e.min(i64::MAX as u64) as i64);

    let mut credential = json!({
        "@context": [tenzro_trust::credential::VC_CONTEXT],
        "type": ["VerifiableCredential", TERMS_CREDENTIAL_TYPE],
        "issuer": terms.controller_did,
        "validFrom": rfc3339_ms(stored.updated_at_ms),
        "credentialSubject": {
            "id": agent_did,
            "name": terms.agent_name,
            "terms": terms,
            "termsVersion": stored.version,
            "approvalDigest": stored.approval_digest,
            "root": stored.root,
        },
    });
    if let Some(until) = expires_ms.and_then(rfc3339_ms) {
        credential["validUntil"] = json!(until);
    }

    let mut oauth = json!({
        "sub": terms.controller_did,
        "act": { "sub": agent_did },
        "scope": scope.allowed_operations.join(" "),
        "authorization_details": [{
            "type": "tenzro_agent_terms",
            "max_transaction_value": scope.max_transaction_value,
            "max_daily_spend": scope.max_daily_spend,
            "payment_protocols": scope.allowed_payment_protocols,
            "chains": scope.allowed_chains,
            "counterparties": scope.allowed_counterparties,
        }],
    });
    if let Some(ms) = expires_ms {
        oauth["exp"] = json!(ms / 1000);
    }

    let registration = json!({
        "agent_id": agent_did,
        "agent_name": terms.agent_name,
        "operator_id": terms.controller_did,
        "payment_protocols": scope.allowed_payment_protocols,
        "spend_limits": {
            "per_transaction": scope.max_transaction_value,
            "per_day": scope.max_daily_spend,
        },
        "valid_until": expires_ms.and_then(rfc3339_ms),
    });

    json!({
        "credential": credential,
        "oauth_claims": oauth,
        "registration": registration,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_types::agent_terms::{AgentTerms, RootKind, TermsScope};

    /// The credential names the controller as issuer and the agent as
    /// subject and carries the Terms whole; the OAuth claims make the
    /// controller the subject the agent acts for.
    #[test]
    fn terms_export_as_a_credential_the_controller_issues() {
        let stored = StoredAgentTerms {
            terms: AgentTerms {
                controller_did: "did:tenzro:human:root".into(),
                agent_name: "buyer".into(),
                delegation_scope: TermsScope {
                    max_transaction_value: Some("5000000".into()),
                    max_daily_spend: Some("20000000".into()),
                    allowed_operations: vec!["payment".into(), "inference".into()],
                    allowed_payment_protocols: vec!["x402".into()],
                    ..Default::default()
                },
                capabilities: Vec::new(),
                serving_nodes: Vec::new(),
                min_distinct_operators: 1,
                expires_at_ms: Some(1_900_000_000_000),
                trifecta_exception: false,
                auto_approve: None,
                credentials: Vec::new(),
            },
            root: RootKind::Passkey,
            version: 3,
            approval_digest: "ab".repeat(32),
            updated_at_ms: 1_800_000_000_000,
            renewed_at_ms: None,
        };
        let d = documents("did:tenzro:machine:root:agent", &stored);
        let vc = &d["credential"];
        assert_eq!(vc["issuer"], "did:tenzro:human:root");
        assert_eq!(vc["type"][1], TERMS_CREDENTIAL_TYPE);
        assert_eq!(
            vc["credentialSubject"]["id"],
            "did:tenzro:machine:root:agent"
        );
        assert_eq!(vc["credentialSubject"]["termsVersion"], 3);
        assert_eq!(
            vc["credentialSubject"]["terms"],
            serde_json::to_value(&stored.terms).unwrap()
        );
        assert_eq!(vc["validFrom"], "2027-01-15T08:00:00Z");
        assert_eq!(vc["validUntil"], "2030-03-17T17:46:40Z");
        assert!(vc.get("proof").is_none(), "the node signs nothing");

        let oauth = &d["oauth_claims"];
        assert_eq!(oauth["sub"], "did:tenzro:human:root");
        assert_eq!(oauth["act"]["sub"], "did:tenzro:machine:root:agent");
        assert_eq!(oauth["scope"], "payment inference");
        assert_eq!(oauth["exp"], 1_900_000_000);
        assert_eq!(
            oauth["authorization_details"][0]["max_transaction_value"],
            "5000000"
        );

        assert_eq!(d["registration"]["operator_id"], "did:tenzro:human:root");
        assert_eq!(d["registration"]["spend_limits"]["per_day"], "20000000");
    }
}
