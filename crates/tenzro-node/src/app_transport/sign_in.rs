//! Signing in to the app transport with this node's access tokens.

use std::sync::{Arc, OnceLock, Weak};

use tenzro_types::node_access::{MethodClass, Surface};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use tenzro_iroh::app_stream::WELCOME_PQ_CONTEXT;
use tenzro_types::did_derivation::MACHINE_KEY_LABEL;

use tenzro_iroh::relay::RelayDevices;

use super::{Admitted, Refusal, SignIn, Vouch};
use crate::access::{Caller, Decision, evaluate};
use crate::node::TenzroNode;
use crate::rpc::AuthContext;

/// What a delegated agent's terms are asked about when it signs in.
const APP_STREAM: &str = "app_stream";

/// Admits the bearers of this node's DPoP-bound access tokens, under its
/// access policy: the `iroh` surface's rule for the `read` class decides,
/// and a caller with no token is never admitted whatever that rule says.
#[derive(Clone)]
pub struct NodeSignIn {
    node: Arc<OnceLock<Weak<TenzroNode>>>,
}

impl NodeSignIn {
    /// Sign-in against the node `node` comes to hold.
    pub fn new(node: Arc<OnceLock<Weak<TenzroNode>>>) -> Self {
        Self { node }
    }

    /// Admits the bearer of the DPoP-bound access token `auth` carries.
    fn admit_with(&self, auth: AuthContext) -> Result<Admitted, Refusal> {
        let no = Refusal::No;
        let node = self
            .node
            .get()
            .and_then(Weak::upgrade)
            .ok_or_else(|| no("this node is not serving".to_string()))?;
        let claims = crate::access::proved_token(&node, &auth)
            .map_err(|e| no(e.message))?
            .ok_or_else(|| no("sign in with an access token of this node".to_string()))?;
        let did = claims.sub;
        if node.agent_audit().is_revoked(&did) {
            return Err(no(format!("{did} was revoked by its controller")));
        }
        if node.agent_audit().is_quarantined(&did) {
            return Err(no(format!("{did} is quarantined")));
        }
        crate::agent_guardrails::counted(crate::agent_delegation::check_agent_key_request(
            &node, &did, APP_STREAM, None,
        ))
        .map_err(no)?;
        let device = claims
            .cnf
            .map(|cnf| cnf.jkt)
            .ok_or_else(|| no("the access token is bound to no key".to_string()))?;
        let admitted = Admitted {
            did: did.clone(),
            device,
            expires_at: claims.exp,
        };
        let policy = node.access().policy();
        let caller = Caller {
            did: Some(did.clone()),
            ip: None,
        };
        match evaluate(&node, &policy, &caller, Surface::Iroh, MethodClass::Read) {
            Decision::Allow { tier: None, .. } => Ok(admitted),
            Decision::Allow {
                tier: Some(tier), ..
            } => {
                node.access()
                    .charge_tier(&policy, &tier, &did)
                    .map_err(no)?;
                Ok(admitted)
            }
            Decision::Pay { price, asset, .. } => Err(Refusal::Pay {
                admitted,
                price,
                asset,
            }),
            Decision::Refuse(why) => Err(no(why)),
        }
    }
}

impl SignIn for NodeSignIn {
    fn admit(&self, htu: &str, access_token: &str, dpop: &str) -> Result<Admitted, Refusal> {
        self.admit_with(AuthContext::from_mcp(
            Some(format!("DPoP {access_token}")),
            Some(dpop.to_string()),
            "POST".to_string(),
            htu.to_string(),
        ))
    }

    fn vouch(&self, digest: &[u8; 32]) -> Result<Vouch, String> {
        let node = self
            .node
            .get()
            .and_then(Weak::upgrade)
            .ok_or_else(|| "this node is not serving".to_string())?;
        let engine = node
            .auth_engine()
            .ok_or_else(|| "this node issues no access tokens".to_string())?;
        let signature = engine.signer().sign_prehash(digest)?;
        let pq_signature = tenzro_device_key::DerivationRoot::open_or_create()
            .and_then(|root| root.ml_dsa65_sign(MACHINE_KEY_LABEL, WELCOME_PQ_CONTEXT, digest))
            .map_err(|e| format!("the machine's ML-DSA-65 key: {e}"))?;
        Ok(Vouch {
            signature: URL_SAFE_NO_PAD.encode(signature),
            pq_signature: URL_SAFE_NO_PAD.encode(pq_signature),
        })
    }
}

/// App devices signed in to this node, as its relay sees them: a request
/// carrying an access token of this node and a DPoP proof made for the relay
/// URL (`GET`), judged as a sign-in to the app transport is.
pub struct NodeRelayDevices {
    sign_in: NodeSignIn,
    htu: String,
}

impl NodeRelayDevices {
    /// Devices proving for the relay at `htu` to `sign_in`.
    pub fn new(sign_in: NodeSignIn, htu: String) -> Self {
        Self { sign_in, htu }
    }
}

/// The access token and proof a relay request carries: in the
/// `Authorization: DPoP` and `DPoP` headers, or as the `token` and `dpop`
/// query parameters a client that sets no headers can use.
fn relay_credential(
    uri: &axum::http::Uri,
    headers: &axum::http::HeaderMap,
) -> Option<(String, String)> {
    let header = |name: &str| headers.get(name).and_then(|v| v.to_str().ok());
    if let Some(token) = header("authorization").and_then(|a| a.strip_prefix("DPoP "))
        && let Some(proof) = header("dpop")
    {
        return Some((token.trim().to_string(), proof.to_string()));
    }
    let query = uri.query()?;
    let mut token = None;
    let mut proof = None;
    for (name, value) in url::form_urlencoded::parse(query.as_bytes()) {
        match name.as_ref() {
            "token" => token = Some(value.into_owned()),
            "dpop" => proof = Some(value.into_owned()),
            _ => {}
        }
    }
    Some((token?, proof?))
}

impl RelayDevices for NodeRelayDevices {
    fn signed_in(&self, uri: &axum::http::Uri, headers: &axum::http::HeaderMap) -> Option<String> {
        let (token, proof) = relay_credential(uri, headers)?;
        self.sign_in
            .admit_with(AuthContext::from_mcp(
                Some(format!("DPoP {token}")),
                Some(proof),
                "GET".to_string(),
                self.htu.clone(),
            ))
            .ok()
            .map(|admitted| admitted.did)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_relay_request_carries_its_credential_in_headers_or_the_query() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("authorization", "DPoP tok".parse().unwrap());
        headers.insert("dpop", "proof".parse().unwrap());
        let plain: axum::http::Uri = "/relay".parse().unwrap();
        assert_eq!(
            relay_credential(&plain, &headers),
            Some(("tok".to_string(), "proof".to_string()))
        );
        let query: axum::http::Uri = "/relay?token=t%2B1&dpop=p".parse().unwrap();
        assert_eq!(
            relay_credential(&query, &axum::http::HeaderMap::new()),
            Some(("t+1".to_string(), "p".to_string()))
        );
        let half: axum::http::Uri = "/relay?token=t".parse().unwrap();
        assert_eq!(relay_credential(&half, &axum::http::HeaderMap::new()), None);
        let mut bearer = axum::http::HeaderMap::new();
        bearer.insert("authorization", "Bearer tok".parse().unwrap());
        assert_eq!(relay_credential(&plain, &bearer), None);
    }
}
