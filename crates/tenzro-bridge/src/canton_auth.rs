//! Canton OAuth2 client-credentials token provider.
//!
//! Canton 3.x Ledger API (both gRPC and JSON) authenticates via JWT bearer
//! tokens issued by an external IdP. The Tenzro-operated Canton devnet
//! (`https://json.devnet.tenzro.network/v2`) issues tokens via Auth0 using
//! the OAuth2 `client_credentials` grant.
//!
//! This module owns the token lifecycle: it exchanges a client_id /
//! client_secret pair for a short-lived JWT, caches it in-memory, and
//! refreshes 60 seconds before expiry. Callers obtain a fresh `Bearer`
//! string via [`CantonTokenProvider::bearer`].
//!
//! The provider is shared (`Arc<CantonTokenProvider>`) by both the
//! `CantonAdapter` HTTP bridge and the Canton MCP server, so a single
//! cached token covers the whole process.
//!
//! Secrets are never logged. The `Debug` impl deliberately omits the
//! client secret.

use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

use crate::error::{BridgeError, Result};

/// Configuration for the Canton OAuth2 token provider.
#[derive(Clone)]
pub struct CantonAuthConfig {
    /// Token endpoint (e.g. `https://dev-x0gilg1n7mhbxz5r.us.auth0.com/oauth/token`).
    pub token_url: String,
    /// OAuth2 client ID.
    pub client_id: String,
    /// OAuth2 client secret. Never logged.
    pub client_secret: String,
    /// JWT audience claim (e.g. `https://canton.network.global`).
    pub audience: String,
    /// OAuth2 scope (e.g. `daml_ledger_api`).
    pub scope: String,
}

impl std::fmt::Debug for CantonAuthConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CantonAuthConfig")
            .field("token_url", &self.token_url)
            .field("client_id", &self.client_id)
            .field("client_secret", &"<redacted>")
            .field("audience", &self.audience)
            .field("scope", &self.scope)
            .finish()
    }
}

impl CantonAuthConfig {
    /// Returns the verified devnet configuration. The `client_secret` must
    /// be supplied by the caller — typically read from the
    /// `CANTON_DEVNET_CLIENT_SECRET` env var.
    pub fn devnet(client_secret: impl Into<String>) -> Self {
        Self {
            token_url: "https://dev-x0gilg1n7mhbxz5r.us.auth0.com/oauth/token".to_string(),
            client_id: "anF8xBKNJmNhuGjWWBfwJHeR9L7YGY3H".to_string(),
            client_secret: client_secret.into(),
            audience: "https://canton.network.global".to_string(),
            scope: "daml_ledger_api".to_string(),
        }
    }
}

#[derive(Serialize)]
struct ClientCredentialsRequest<'a> {
    client_id: &'a str,
    client_secret: &'a str,
    audience: &'a str,
    grant_type: &'a str,
    scope: &'a str,
}

#[derive(Deserialize)]
struct ClientCredentialsResponse {
    access_token: String,
    /// Lifetime in seconds (Auth0 returns this).
    expires_in: u64,
}

#[derive(Clone)]
struct CachedToken {
    token: String,
    /// Wall-clock instant after which the token must be refreshed.
    expires_at: Instant,
}

/// Shared, thread-safe OAuth2 client-credentials token provider.
pub struct CantonTokenProvider {
    config: CantonAuthConfig,
    http: reqwest::Client,
    cache: RwLock<Option<CachedToken>>,
}

impl std::fmt::Debug for CantonTokenProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CantonTokenProvider")
            .field("config", &self.config)
            .field("cached", &self.cache.read().is_some())
            .finish()
    }
}

impl CantonTokenProvider {
    /// Construct a new token provider. Does not fetch a token eagerly;
    /// the first call to [`bearer`] triggers the exchange.
    pub fn new(config: CantonAuthConfig) -> Arc<Self> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .expect("reqwest client builder must not fail");
        Arc::new(Self {
            config,
            http,
            cache: RwLock::new(None),
        })
    }

    /// Returns a currently-valid bearer JWT, refreshing from the IdP when
    /// the cache is empty or within 60s of expiry.
    pub async fn bearer(&self) -> Result<String> {
        // Fast path: cached and not near expiry.
        if let Some(t) = self.cache.read().as_ref() {
            if t.expires_at > Instant::now() + Duration::from_secs(60) {
                return Ok(t.token.clone());
            }
        }

        // Slow path: refresh. Multiple concurrent refreshes are fine —
        // Auth0 will issue independent tokens; whichever writes last wins.
        let body = ClientCredentialsRequest {
            client_id: &self.config.client_id,
            client_secret: &self.config.client_secret,
            audience: &self.config.audience,
            grant_type: "client_credentials",
            scope: &self.config.scope,
        };

        let resp = self
            .http
            .post(&self.config.token_url)
            .json(&body)
            .send()
            .await
            .map_err(|e| {
                BridgeError::AdapterError(format!("canton auth: token request failed: {}", e))
            })?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(BridgeError::AdapterError(format!(
                "canton auth: token endpoint returned {}: {}",
                status, text
            )));
        }

        let body: ClientCredentialsResponse = resp.json().await.map_err(|e| {
            BridgeError::AdapterError(format!("canton auth: invalid token response: {}", e))
        })?;

        let cached = CachedToken {
            token: body.access_token.clone(),
            expires_at: Instant::now() + Duration::from_secs(body.expires_in),
        };
        *self.cache.write() = Some(cached);

        Ok(body.access_token)
    }
}
