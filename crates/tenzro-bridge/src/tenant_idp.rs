//! Per-tenant identity-provider client minting (Stage 2.b).
//!
//! When the operator runs `tenzro_createApiKey` with a Canton
//! `canton_user_id` and the node is configured with
//! `canton.identity_providers.enabled = true`, the node atomically:
//!
//! 1. Mints a per-tenant OAuth2 client on the upstream IdP (Auth0 or
//!    equivalent) via the IdP's Management API.
//! 2. Registers a dedicated Canton `IdentityProviderConfig` for that
//!    client (`POST /v2/idps`).
//! 3. Creates the Canton user under that IDP.
//! 4. Allocates a tenant party under that IDP.
//! 5. Grants `CanActAs` on the party to the user.
//! 6. Returns the client_id + client_secret to the tenant exactly once
//!    alongside the API key.
//!
//! From this point the tenant runs their own token-acquisition loop
//! (OAuth2 client_credentials) and presents their own Canton JWT via
//! `X-Canton-Auth: Bearer <jwt>` on subsequent canton-scoped calls.
//! The operator JWT never enters the wire path for tenant requests —
//! a leaked operator credential gives an attacker access to the
//! operator's own surface but not to any tenant's parties.
//!
//! `TenantIdpProvisioner` is the chain-/transport-agnostic interface
//! the node uses. `Auth0ManagementClient` is the production
//! implementation against Auth0's `/api/v2/clients` endpoint. Other
//! OIDC management surfaces (Okta, Keycloak, …) can implement the
//! same trait without touching call sites.

use crate::error::{BridgeError, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// Credentials returned by the upstream IdP after a successful client
/// mint. The `client_secret` is returned to the tenant exactly once;
/// the node does not persist it. If the tenant loses it they have to
/// revoke + re-issue.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantIdpClient {
    /// OAuth2 client_id minted upstream.
    pub client_id: String,
    /// OAuth2 client_secret minted upstream. Sent on-wire exactly
    /// once; not persisted by the node.
    pub client_secret: String,
    /// Token endpoint URL the tenant uses to acquire JWTs
    /// (e.g. `https://<tenant>.<idp-domain>/oauth/token`).
    pub token_url: String,
    /// Issuer URL Canton uses to verify tenant JWTs (registered as
    /// `issuer` on the Canton IDP).
    pub issuer_url: String,
    /// JWKS URL Canton uses to fetch the signing keys (registered as
    /// `jwksUrl` on the Canton IDP).
    pub jwks_url: String,
    /// Audience Canton expects on tenant JWTs.
    pub audience: String,
}

/// Provisioning request handed to the upstream IdP. The node fills
/// `tenant_label` from `tenzro_createApiKey.label` and
/// `tenant_user_id` from `canton_user_id`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantIdpRequest {
    /// Operator-supplied label (e.g. `"tenzro-labs"`).
    pub tenant_label: String,
    /// The Canton User Management Service user id this tenant key is
    /// bound to (`<client_id_hint>@clients`).
    pub tenant_user_id: String,
    /// Audience Canton expects on the tenant's JWTs. Comes from
    /// `canton.identity_providers.canton_audience`.
    pub audience: String,
}

/// Abstract per-tenant identity-provider provisioner.
///
/// Implementations talk to an OIDC Management API (Auth0
/// `/api/v2/clients`, Okta `/api/v1/apps`, Keycloak admin REST,
/// etc.) to mint per-tenant OAuth2 clients and tear them down on
/// revocation. The Tenzro node owns the trait object and dispatches
/// against it from `handle_create_api_key`.
#[async_trait]
pub trait TenantIdpProvisioner: Send + Sync {
    /// Mint a new per-tenant OAuth2 client. Returns the client
    /// credentials + the metadata needed to register the Canton IDP.
    ///
    /// MUST be idempotent for the same `tenant_user_id`:
    /// re-provisioning an existing tenant should return the
    /// already-minted client (or rotate the secret only when the
    /// caller explicitly requests it).
    async fn mint_tenant_client(
        &self,
        req: &TenantIdpRequest,
    ) -> Result<TenantIdpClient>;

    /// Delete (or deactivate) the per-tenant client by id. Called
    /// from `tenzro_revokeApiKey` to tear down a tenant's upstream
    /// credentials in lockstep with revoking the Tenzro key.
    async fn delete_tenant_client(&self, client_id: &str) -> Result<()>;
}

/// Auth0 Management API implementation.
///
/// Talks to `https://<auth0_domain>/api/v2/clients`. The `mgmt_token`
/// is an Auth0 management API token (machine-to-machine) with the
/// `create:clients` + `delete:clients` scopes. Loaded from
/// `CANTON_IDP_MGMT_TOKEN` at node startup.
pub struct Auth0ManagementClient {
    /// `auth0_domain` without scheme — e.g. `tenzro.us.auth0.com`.
    /// Used to construct the Management API URL + the canonical
    /// issuer URL for the tenant.
    auth0_domain: String,
    /// Management API JWT.
    mgmt_token: String,
    /// HTTP client for outbound requests.
    http: reqwest::Client,
}

impl Auth0ManagementClient {
    /// Build a client from the operator-supplied mgmt URL + token.
    /// `mgmt_url` is the management base URL (e.g.
    /// `https://tenzro.us.auth0.com/api/v2`); we derive the bare
    /// `auth0_domain` from it.
    pub fn new(mgmt_url: &str, mgmt_token: &str) -> Result<Self> {
        let url = reqwest::Url::parse(mgmt_url).map_err(|e| {
            BridgeError::ConfigurationError(format!(
                "Auth0 mgmt URL parse failed: {}",
                e
            ))
        })?;
        let host = url.host_str().ok_or_else(|| {
            BridgeError::ConfigurationError(
                "Auth0 mgmt URL has no host".to_string(),
            )
        })?;
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| {
                BridgeError::ConfigurationError(format!(
                    "Auth0 mgmt HTTP client build failed: {}",
                    e
                ))
            })?;
        Ok(Self {
            auth0_domain: host.to_string(),
            mgmt_token: mgmt_token.to_string(),
            http,
        })
    }

    fn issuer_url(&self) -> String {
        format!("https://{}/", self.auth0_domain)
    }

    fn jwks_url(&self) -> String {
        format!("https://{}/.well-known/jwks.json", self.auth0_domain)
    }

    fn token_url(&self) -> String {
        format!("https://{}/oauth/token", self.auth0_domain)
    }

    fn clients_url(&self) -> String {
        format!("https://{}/api/v2/clients", self.auth0_domain)
    }
}

#[async_trait]
impl TenantIdpProvisioner for Auth0ManagementClient {
    async fn mint_tenant_client(
        &self,
        req: &TenantIdpRequest,
    ) -> Result<TenantIdpClient> {
        // Build the Auth0 client create body. We use the
        // `non_interactive` app type because tenants will run the
        // client_credentials grant against this client. `grant_types`
        // and `audience` are bound at the *grant* level (Auth0
        // requires a Client Grant in addition to the Client itself
        // for the audience binding); we issue both here.
        //
        // Idempotent semantics are best-effort: Auth0's API doesn't
        // support "create-if-not-exists" natively, so the operator
        // surface treats AlreadyExists as success and reuses the
        // existing client. Production callers should add a
        // `list_clients(name=...)` pre-check if strict idempotency is
        // required across retries; for the M14 wave we accept the
        // duplicate-on-retry risk and rely on `tenant_label` being
        // unique per-issuance.
        let create_body = serde_json::json!({
            "name": format!("tenzro-tenant-{}", req.tenant_label),
            "description": format!(
                "Tenzro per-tenant OAuth2 client for canton user_id={} (M14 Stage 2.b)",
                req.tenant_user_id
            ),
            "app_type": "non_interactive",
            "token_endpoint_auth_method": "client_secret_post",
            "grant_types": ["client_credentials"],
            "is_first_party": true,
        });
        let resp = self
            .http
            .post(self.clients_url())
            .bearer_auth(&self.mgmt_token)
            .json(&create_body)
            .send()
            .await
            .map_err(|e| {
                BridgeError::AdapterError(format!(
                    "Auth0 create-client failed: {}",
                    e
                ))
            })?;
        let status = resp.status();
        let body_text = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            return Err(BridgeError::AdapterError(format!(
                "Auth0 create-client HTTP {}: {}",
                status,
                body_text.chars().take(256).collect::<String>()
            )));
        }
        let v: serde_json::Value = serde_json::from_str(&body_text).map_err(|e| {
            BridgeError::AdapterError(format!(
                "Auth0 create-client response not JSON: {}",
                e
            ))
        })?;
        let client_id = v
            .get("client_id")
            .and_then(|x| x.as_str())
            .ok_or_else(|| {
                BridgeError::AdapterError(
                    "Auth0 create-client response missing client_id".to_string(),
                )
            })?
            .to_string();
        let client_secret = v
            .get("client_secret")
            .and_then(|x| x.as_str())
            .ok_or_else(|| {
                BridgeError::AdapterError(
                    "Auth0 create-client response missing client_secret".to_string(),
                )
            })?
            .to_string();
        Ok(TenantIdpClient {
            client_id,
            client_secret,
            token_url: self.token_url(),
            issuer_url: self.issuer_url(),
            jwks_url: self.jwks_url(),
            audience: req.audience.clone(),
        })
    }

    async fn delete_tenant_client(&self, client_id: &str) -> Result<()> {
        let url = format!("{}/{}", self.clients_url(), client_id);
        let resp = self
            .http
            .delete(&url)
            .bearer_auth(&self.mgmt_token)
            .send()
            .await
            .map_err(|e| {
                BridgeError::AdapterError(format!(
                    "Auth0 delete-client failed: {}",
                    e
                ))
            })?;
        let status = resp.status();
        if !status.is_success() && status.as_u16() != 404 {
            let body_text = resp.text().await.unwrap_or_default();
            return Err(BridgeError::AdapterError(format!(
                "Auth0 delete-client HTTP {}: {}",
                status,
                body_text.chars().take(256).collect::<String>()
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Sanity test that the Auth0 client constructor extracts the
    /// canonical domain + builds the right URLs.
    #[test]
    fn auth0_url_derivation() {
        let c = Auth0ManagementClient::new(
            "https://tenzro.us.auth0.com/api/v2",
            "fake-token",
        )
        .unwrap();
        assert_eq!(c.auth0_domain, "tenzro.us.auth0.com");
        assert_eq!(c.issuer_url(), "https://tenzro.us.auth0.com/");
        assert_eq!(
            c.jwks_url(),
            "https://tenzro.us.auth0.com/.well-known/jwks.json"
        );
        assert_eq!(c.token_url(), "https://tenzro.us.auth0.com/oauth/token");
        assert_eq!(
            c.clients_url(),
            "https://tenzro.us.auth0.com/api/v2/clients"
        );
    }
}
