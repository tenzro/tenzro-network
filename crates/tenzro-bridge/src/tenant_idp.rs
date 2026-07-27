//! Per-tenant identity-provider client minting (Stage 2.b).
//!
//! When the operator runs `tenzro_createApiKey` with a Canton
//! `canton_user_id` and the node is configured with
//! `canton.identity_providers.enabled = true`, the node atomically:
//!
//! 1. Mints a per-tenant OAuth2 client (plus its client-grant for the
//!    Canton audience) on the upstream IdP (Auth0 or equivalent) via
//!    the IdP's Management API.
//! 2. Creates the Canton user `<client_id>@clients` in the DEFAULT
//!    identity provider (matching the `sub` claim Auth0 puts on
//!    client_credentials tokens). Canton consults its static
//!    config-file auth services before any dynamic
//!    `IdentityProviderConfig` and short-circuits at the first
//!    non-Unauthenticated claim; since tenant clients share the
//!    operator's upstream issuer, tenant JWTs are always claimed by
//!    the static auth service and scoped to the default IDP — a
//!    dynamic IDP with the same issuer is unreachable. Isolation
//!    comes from per-tenant OAuth clients (distinct `sub` → distinct
//!    Canton user) + per-user CanActAs rights, not IDP scoping.
//! 3. Allocates a tenant party in the default IDP.
//! 4. Grants `CanActAs` on the party to the user.
//! 5. Stores the client credentials on the `ApiKeyRecord` — the tenant
//!    never sees them. The Tenzro API key is the single credential a
//!    tenant holds.
//!
//! On every canton-scoped call the node mints (and caches) the tenant
//! JWT itself via the stored client credentials and forwards it to
//! Canton. The operator JWT never enters the wire path for tenant
//! requests, and the tenant never touches OAuth at all — a leaked
//! tenant API key is revocable in one `tenzro_revokeApiKey` call
//! without any upstream IdP coordination. `X-Canton-Auth: Bearer
//! <jwt>` remains supported only as a BYO-issuer escape hatch for
//! keys provisioned without stored credentials.
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
/// mint. Persisted on the tenant's `ApiKeyRecord` by the node; never
/// returned to the tenant — the Tenzro API key is the tenant's only
/// credential.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantIdpClient {
    /// OAuth2 client_id minted upstream.
    pub client_id: String,
    /// OAuth2 client_secret minted upstream. Stored on the
    /// `ApiKeyRecord` so the node can mint tenant JWTs server-side.
    /// Never logged, never returned over RPC.
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
    /// Scopes granted to the tenant client for `audience` (e.g.
    /// `["daml_ledger_api"]`). Bound at the client-grant level on
    /// Auth0 — without the grant, the tenant's client_credentials
    /// token request is refused by the IdP.
    pub scopes: Vec<String>,
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

    /// Mint a JWT for the given tenant client via the OAuth2
    /// client_credentials grant. Called by the node on every
    /// canton-scoped request from a key with stored credentials; the
    /// implementation MUST cache tokens per client_id and refresh
    /// before expiry so this is cheap on the hot path.
    async fn mint_tenant_jwt(
        &self,
        client_id: &str,
        client_secret: &str,
        audience: &str,
        scopes: &[String],
    ) -> Result<String>;
}

/// Cached OAuth2 access token (Management API or tenant JWT). Tokens
/// are refreshed 60s before expiry so a long-running node never
/// presents a stale token.
struct CachedToken {
    token: String,
    expires_at: std::time::Instant,
}

/// OAuth2 token endpoint response (client_credentials grant).
#[derive(Deserialize)]
struct OauthTokenResponse {
    access_token: String,
    expires_in: u64,
}

/// Auth0 Management API implementation.
///
/// Talks to `https://<auth0_domain>/api/v2/clients` +
/// `/api/v2/client-grants`. Authenticates by minting its own
/// Management API token via the OAuth2 `client_credentials` grant
/// against the `https://<auth0_domain>/api/v2/` audience — the
/// configured M2M client must hold the `create:clients` +
/// `delete:clients` + `create:client_grants` scopes. Credentials are
/// loaded from `CANTON_IDP_MGMT_CLIENT_ID` /
/// `CANTON_IDP_MGMT_CLIENT_SECRET` at node startup. Tokens are cached
/// in-memory and refreshed 60s before their 24h expiry, so the
/// provisioner stays valid for the life of the process (a static
/// boot-minted token would silently break tenant provisioning a day
/// after every boot).
pub struct Auth0ManagementClient {
    /// `auth0_domain` without scheme — e.g. `tenzro.us.auth0.com`.
    /// Used to construct the Management API URL + the canonical
    /// issuer URL for the tenant.
    auth0_domain: String,
    /// M2M client id authorized for the Management API audience.
    mgmt_client_id: String,
    /// M2M client secret. Never logged.
    mgmt_client_secret: String,
    /// Cached Management API token.
    mgmt_token_cache: parking_lot::RwLock<Option<CachedToken>>,
    /// Per-tenant-client JWT cache keyed by client_id. Tenant JWTs
    /// are minted server-side on canton-scoped requests; caching
    /// keeps the hot path to one map read instead of an Auth0
    /// round-trip per call.
    tenant_token_cache: dashmap::DashMap<String, CachedToken>,
    /// HTTP client for outbound requests.
    http: reqwest::Client,
}

impl Auth0ManagementClient {
    /// Build a client from the operator-supplied mgmt URL + M2M
    /// client credentials. `mgmt_url` is the management base URL
    /// (e.g. `https://tenzro.us.auth0.com/api/v2`); we derive the
    /// bare `auth0_domain` from it.
    pub fn new(mgmt_url: &str, mgmt_client_id: &str, mgmt_client_secret: &str) -> Result<Self> {
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
            mgmt_client_id: mgmt_client_id.to_string(),
            mgmt_client_secret: mgmt_client_secret.to_string(),
            mgmt_token_cache: parking_lot::RwLock::new(None),
            tenant_token_cache: dashmap::DashMap::new(),
            http,
        })
    }

    /// Auth0 Management API audience — always `https://<domain>/api/v2/`
    /// (trailing slash significant; Auth0 registers it that way).
    fn mgmt_audience(&self) -> String {
        format!("https://{}/api/v2/", self.auth0_domain)
    }

    /// Returns a currently-valid Management API bearer token, minting
    /// via client_credentials when the cache is empty or within 60s
    /// of expiry. Concurrent refreshes are harmless — Auth0 issues
    /// independent tokens; last writer wins.
    async fn mgmt_bearer(&self) -> Result<String> {
        if let Some(t) = self.mgmt_token_cache.read().as_ref()
            && t.expires_at > std::time::Instant::now() + std::time::Duration::from_secs(60)
        {
            return Ok(t.token.clone());
        }

        let body = serde_json::json!({
            "client_id": self.mgmt_client_id,
            "client_secret": self.mgmt_client_secret,
            "audience": self.mgmt_audience(),
            "grant_type": "client_credentials",
        });
        let resp = self
            .http
            .post(self.token_url())
            .json(&body)
            .send()
            .await
            .map_err(|e| {
                BridgeError::AdapterError(format!("Auth0 mgmt token request failed: {}", e))
            })?;
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            return Err(BridgeError::AdapterError(format!(
                "Auth0 mgmt token endpoint HTTP {}: {}",
                status,
                text.chars().take(256).collect::<String>()
            )));
        }
        let tok: OauthTokenResponse = serde_json::from_str(&text).map_err(|e| {
            BridgeError::AdapterError(format!("Auth0 mgmt token response not JSON: {}", e))
        })?;
        *self.mgmt_token_cache.write() = Some(CachedToken {
            token: tok.access_token.clone(),
            expires_at: std::time::Instant::now()
                + std::time::Duration::from_secs(tok.expires_in),
        });
        Ok(tok.access_token)
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

    fn client_grants_url(&self) -> String {
        format!("https://{}/api/v2/client-grants", self.auth0_domain)
    }

    /// Body for `POST /api/v2/client-grants` — binds the freshly
    /// minted client to the Canton audience with the tenant scopes.
    fn client_grant_body(client_id: &str, req: &TenantIdpRequest) -> serde_json::Value {
        serde_json::json!({
            "client_id": client_id,
            "audience": req.audience,
            "scope": req.scopes,
        })
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
        // client_credentials grant against this client. The audience
        // binding lives at the *grant* level (Auth0 requires a Client
        // Grant in addition to the Client itself), so we issue both:
        // POST /api/v2/clients then POST /api/v2/client-grants. If
        // the grant fails we best-effort delete the freshly-minted
        // client so retries don't accumulate orphans.
        //
        // Idempotent semantics are best-effort: Auth0's API doesn't
        // support "create-if-not-exists" natively, so the operator
        // surface treats AlreadyExists as success and reuses the
        // existing client. Production callers should add a
        // `list_clients(name=...)` pre-check if strict idempotency is
        // required across retries. This path accepts the duplicate-on-retry
        // risk and relies on `tenant_label` being unique per-issuance.
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
        let mgmt_bearer = self.mgmt_bearer().await?;
        let resp = self
            .http
            .post(self.clients_url())
            .bearer_auth(&mgmt_bearer)
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

        // Client Grant: authorize the new client for the Canton
        // audience with the requested scopes. Without this, Auth0
        // refuses the tenant's client_credentials token request with
        // "access_denied: Client is not authorized to access ...".
        let grant_body = Self::client_grant_body(&client_id, req);
        let grant_resp = self
            .http
            .post(self.client_grants_url())
            .bearer_auth(&mgmt_bearer)
            .json(&grant_body)
            .send()
            .await;
        let grant_err = match grant_resp {
            Ok(r) => {
                let status = r.status();
                if status.is_success() {
                    None
                } else {
                    let body = r.text().await.unwrap_or_default();
                    Some(format!(
                        "Auth0 create-client-grant HTTP {}: {}",
                        status,
                        body.chars().take(256).collect::<String>()
                    ))
                }
            }
            Err(e) => Some(format!("Auth0 create-client-grant failed: {}", e)),
        };
        if let Some(err) = grant_err {
            // Roll back the orphaned client so a retry starts clean.
            if let Err(del_err) = self.delete_tenant_client(&client_id).await {
                tracing::warn!(
                    client_id = %client_id,
                    error = %del_err,
                    "Auth0 rollback delete-client failed after grant failure"
                );
            }
            return Err(BridgeError::AdapterError(err));
        }

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
        let mgmt_bearer = self.mgmt_bearer().await?;
        let resp = self
            .http
            .delete(&url)
            .bearer_auth(&mgmt_bearer)
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
        // Drop any cached JWT for the revoked client.
        self.tenant_token_cache.remove(client_id);
        Ok(())
    }

    async fn mint_tenant_jwt(
        &self,
        client_id: &str,
        client_secret: &str,
        audience: &str,
        scopes: &[String],
    ) -> Result<String> {
        if let Some(t) = self.tenant_token_cache.get(client_id)
            && t.expires_at > std::time::Instant::now() + std::time::Duration::from_secs(60)
        {
            return Ok(t.token.clone());
        }

        let body = serde_json::json!({
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
            "audience": audience,
            "scope": scopes.join(" "),
        });
        let resp = self
            .http
            .post(self.token_url())
            .json(&body)
            .send()
            .await
            .map_err(|e| {
                BridgeError::AdapterError(format!(
                    "Auth0 tenant token request failed: {}",
                    e
                ))
            })?;
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            return Err(BridgeError::AdapterError(format!(
                "Auth0 tenant token endpoint HTTP {}: {}",
                status,
                text.chars().take(256).collect::<String>()
            )));
        }
        let tok: OauthTokenResponse = serde_json::from_str(&text).map_err(|e| {
            BridgeError::AdapterError(format!(
                "Auth0 tenant token response not JSON: {}",
                e
            ))
        })?;
        self.tenant_token_cache.insert(
            client_id.to_string(),
            CachedToken {
                token: tok.access_token.clone(),
                expires_at: std::time::Instant::now()
                    + std::time::Duration::from_secs(tok.expires_in),
            },
        );
        Ok(tok.access_token)
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
            "fake-client-id",
            "fake-client-secret",
        )
        .unwrap();
        assert_eq!(c.auth0_domain, "tenzro.us.auth0.com");
        assert_eq!(c.mgmt_audience(), "https://tenzro.us.auth0.com/api/v2/");
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
        assert_eq!(
            c.client_grants_url(),
            "https://tenzro.us.auth0.com/api/v2/client-grants"
        );
    }

    /// The client-grant body must bind client_id + audience + scope —
    /// the exact shape Auth0's `POST /api/v2/client-grants` expects.
    #[test]
    fn client_grant_body_shape() {
        let req = TenantIdpRequest {
            tenant_label: "tenzro-labs".to_string(),
            tenant_user_id: "abc123@clients".to_string(),
            audience: "https://canton.network.global".to_string(),
            scopes: vec!["daml_ledger_api".to_string()],
        };
        let body = Auth0ManagementClient::client_grant_body("abc123", &req);
        assert_eq!(
            body,
            serde_json::json!({
                "client_id": "abc123",
                "audience": "https://canton.network.global",
                "scope": ["daml_ledger_api"],
            })
        );
    }
}
