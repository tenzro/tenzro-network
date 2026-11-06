//! OAuth Client ID Metadata Documents for the MCP authorization server.
//!
//! An MCP client with no prior relationship to this node identifies itself
//! with an `https://` URL as its `client_id`. That URL serves a JSON document
//! naming the client and the redirect URIs it may use. The authorization
//! server fetches the document, checks it names itself (`client_id` equals
//! the URL exactly), and accepts an authorization request only for a
//! redirect URI the document lists. Nothing is registered: a client is
//! whoever controls the URL, and the node keeps no client table of its own.

use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use dashmap::DashMap;
use serde::Deserialize;

/// Largest metadata document the server reads. Real documents are a few
/// hundred bytes; the cap bounds what an arbitrary URL can make the node
/// buffer.
pub const MAX_DOCUMENT_BYTES: usize = 64 * 1024;

/// How long a fetched document is reused when the response carried no
/// `Cache-Control: max-age`.
const DEFAULT_CACHE_TTL: Duration = Duration::from_secs(300);

/// Upper bound on a cached document's lifetime, whatever `max-age` says,
/// so a client that changes its redirect URIs is picked up within the hour.
const MAX_CACHE_TTL: Duration = Duration::from_secs(3600);

/// A validated client metadata document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientMetadata {
    pub client_id: String,
    pub client_name: String,
    pub redirect_uris: Vec<String>,
}

impl ClientMetadata {
    /// Exact-string redirect URI match against the document's list. No
    /// prefix, case or normalisation leeway: a URI that is not listed
    /// verbatim is not the client's.
    pub fn allows_redirect(&self, redirect_uri: &str) -> bool {
        self.redirect_uris.iter().any(|r| r == redirect_uri)
    }
}

/// A fetched document body and the lifetime its response allowed.
pub struct FetchedDocument {
    pub body: Vec<u8>,
    pub max_age: Option<Duration>,
}

/// Retrieves a client metadata document. Production uses [`HttpsFetcher`];
/// tests substitute a local fixture server.
#[async_trait]
pub trait ClientMetadataFetcher: Send + Sync {
    async fn fetch(&self, url: &url::Url) -> Result<FetchedDocument, String>;
}

/// Fetches metadata documents over HTTPS with the node's shared client.
pub struct HttpsFetcher {
    http: reqwest::Client,
}

impl Default for HttpsFetcher {
    fn default() -> Self {
        Self::new()
    }
}

impl HttpsFetcher {
    pub fn new() -> Self {
        Self {
            http: crate::http_client::shared().clone(),
        }
    }
}

#[async_trait]
impl ClientMetadataFetcher for HttpsFetcher {
    async fn fetch(&self, url: &url::Url) -> Result<FetchedDocument, String> {
        let resp = self
            .http
            .get(url.as_str())
            .header("Accept", "application/json")
            .timeout(Duration::from_secs(10))
            .send()
            .await
            .map_err(|e| format!("fetching {url}: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!("fetching {url}: HTTP {}", resp.status()));
        }
        let max_age = resp
            .headers()
            .get(reqwest::header::CACHE_CONTROL)
            .and_then(|v| v.to_str().ok())
            .and_then(parse_max_age);
        if resp
            .content_length()
            .is_some_and(|n| n as usize > MAX_DOCUMENT_BYTES)
        {
            return Err(format!(
                "{url} serves a document over {MAX_DOCUMENT_BYTES} bytes"
            ));
        }
        let body = resp
            .bytes()
            .await
            .map_err(|e| format!("reading {url}: {e}"))?;
        if body.len() > MAX_DOCUMENT_BYTES {
            return Err(format!(
                "{url} serves a document over {MAX_DOCUMENT_BYTES} bytes"
            ));
        }
        Ok(FetchedDocument {
            body: body.to_vec(),
            max_age,
        })
    }
}

fn parse_max_age(cache_control: &str) -> Option<Duration> {
    cache_control.split(',').find_map(|directive| {
        let directive = directive.trim();
        if directive.eq_ignore_ascii_case("no-store") || directive.eq_ignore_ascii_case("no-cache")
        {
            return Some(Duration::ZERO);
        }
        directive
            .strip_prefix("max-age=")
            .and_then(|v| v.trim().parse::<u64>().ok())
            .map(Duration::from_secs)
    })
}

/// A `client_id` is a metadata document URL only when it is `https`, has a
/// path beyond `/`, and carries no fragment or userinfo.
pub fn parse_client_id_url(client_id: &str) -> Result<url::Url, String> {
    let url =
        url::Url::parse(client_id).map_err(|e| format!("client_id must be an https URL: {e}"))?;
    if url.scheme() != "https" {
        return Err("client_id must use the https scheme".to_string());
    }
    if url.host_str().is_none_or(str::is_empty) {
        return Err("client_id names no host".to_string());
    }
    if url.path().is_empty() || url.path() == "/" {
        return Err("client_id must contain a path component".to_string());
    }
    if url.fragment().is_some() {
        return Err("client_id must not contain a fragment".to_string());
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("client_id must not carry credentials".to_string());
    }
    Ok(url)
}

#[derive(Deserialize)]
struct RawDocument {
    client_id: String,
    client_name: String,
    redirect_uris: Vec<String>,
    token_endpoint_auth_method: Option<String>,
    response_types: Option<Vec<String>>,
    grant_types: Option<Vec<String>>,
}

/// Validate a fetched document for `client_id`.
pub fn parse_document(client_id: &str, body: &[u8]) -> Result<ClientMetadata, String> {
    let raw: RawDocument = serde_json::from_slice(body)
        .map_err(|e| format!("client metadata document is not valid: {e}"))?;
    if raw.client_id != client_id {
        return Err(format!(
            "client metadata document names client_id '{}', but it was fetched from '{}'",
            raw.client_id, client_id
        ));
    }
    if raw.client_name.trim().is_empty() {
        return Err("client metadata document has an empty client_name".to_string());
    }
    if raw.redirect_uris.is_empty() {
        return Err("client metadata document lists no redirect_uris".to_string());
    }
    for uri in &raw.redirect_uris {
        let parsed = url::Url::parse(uri).map_err(|e| format!("redirect_uri '{uri}': {e}"))?;
        if parsed.fragment().is_some() {
            return Err(format!("redirect_uri '{uri}' contains a fragment"));
        }
    }
    // This server issues only public-client authorization codes.
    if let Some(m) = raw.token_endpoint_auth_method.as_deref()
        && m != "none"
    {
        return Err(format!(
            "token_endpoint_auth_method '{m}' is not supported; this server serves public clients"
        ));
    }
    if let Some(rt) = &raw.response_types
        && rt.iter().any(|t| t != "code")
    {
        return Err("only the 'code' response type is supported".to_string());
    }
    if let Some(gt) = &raw.grant_types
        && gt
            .iter()
            .any(|g| g != "authorization_code" && g != "refresh_token")
    {
        return Err("only authorization_code and refresh_token grants are supported".to_string());
    }
    Ok(ClientMetadata {
        client_id: raw.client_id,
        client_name: raw.client_name,
        redirect_uris: raw.redirect_uris,
    })
}

/// Resolves `client_id`s to validated metadata, caching each document for
/// the lifetime its response allowed.
pub struct ClientResolver {
    fetcher: Arc<dyn ClientMetadataFetcher>,
    cache: DashMap<String, (ClientMetadata, Instant)>,
}

impl ClientResolver {
    pub fn new(fetcher: Arc<dyn ClientMetadataFetcher>) -> Self {
        Self {
            fetcher,
            cache: DashMap::new(),
        }
    }

    pub async fn resolve(&self, client_id: &str) -> Result<ClientMetadata, String> {
        if let Some(entry) = self.cache.get(client_id)
            && entry.1 > Instant::now()
        {
            return Ok(entry.0.clone());
        }
        let url = parse_client_id_url(client_id)?;
        let doc = self.fetcher.fetch(&url).await?;
        if doc.body.len() > MAX_DOCUMENT_BYTES {
            return Err(format!(
                "{url} serves a document over {MAX_DOCUMENT_BYTES} bytes"
            ));
        }
        let metadata = parse_document(client_id, &doc.body)?;
        let ttl = doc.max_age.unwrap_or(DEFAULT_CACHE_TTL).min(MAX_CACHE_TTL);
        if ttl > Duration::ZERO {
            self.cache.insert(
                client_id.to_string(),
                (metadata.clone(), Instant::now() + ttl),
            );
        } else {
            self.cache.remove(client_id);
        }
        Ok(metadata)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Serves fixed documents keyed by URL, standing in for a client's
    /// metadata host.
    pub(crate) struct FixtureFetcher {
        pub docs: DashMap<String, (String, Option<Duration>)>,
        pub hits: AtomicUsize,
    }

    impl FixtureFetcher {
        pub(crate) fn with(url: &str, body: serde_json::Value) -> Arc<Self> {
            let f = Self {
                docs: DashMap::new(),
                hits: AtomicUsize::new(0),
            };
            f.docs.insert(url.to_string(), (body.to_string(), None));
            Arc::new(f)
        }
    }

    #[async_trait]
    impl ClientMetadataFetcher for FixtureFetcher {
        async fn fetch(&self, url: &url::Url) -> Result<FetchedDocument, String> {
            self.hits.fetch_add(1, Ordering::SeqCst);
            self.docs
                .get(url.as_str())
                .map(|d| FetchedDocument {
                    body: d.0.clone().into_bytes(),
                    max_age: d.1,
                })
                .ok_or_else(|| format!("404 {url}"))
        }
    }

    pub(crate) const CLIENT: &str = "https://app.example.com/oauth/client.json";

    pub(crate) fn good_doc() -> serde_json::Value {
        serde_json::json!({
            "client_id": CLIENT,
            "client_name": "Example MCP Client",
            "redirect_uris": ["http://127.0.0.1:3000/callback"],
            "token_endpoint_auth_method": "none",
        })
    }

    #[test]
    fn client_id_url_rules() {
        assert!(parse_client_id_url(CLIENT).is_ok());
        for bad in [
            "http://app.example.com/client.json",
            "https://app.example.com",
            "https://app.example.com/",
            "https://app.example.com/c.json#frag",
            "https://user:pw@app.example.com/c.json",
            "client_abc123",
        ] {
            assert!(parse_client_id_url(bad).is_err(), "{bad} must be refused");
        }
    }

    #[test]
    fn document_must_name_the_url_it_was_fetched_from() {
        let mut doc = good_doc();
        doc["client_id"] = serde_json::json!("https://evil.example/client.json");
        let err = parse_document(CLIENT, doc.to_string().as_bytes()).unwrap_err();
        assert!(err.contains("fetched from"), "{err}");
    }

    #[test]
    fn document_requires_name_and_redirects() {
        let mut doc = good_doc();
        doc["redirect_uris"] = serde_json::json!([]);
        assert!(parse_document(CLIENT, doc.to_string().as_bytes()).is_err());
        let mut doc = good_doc();
        doc.as_object_mut().unwrap().remove("client_name");
        assert!(parse_document(CLIENT, doc.to_string().as_bytes()).is_err());
        let mut doc = good_doc();
        doc["token_endpoint_auth_method"] = serde_json::json!("client_secret_basic");
        assert!(parse_document(CLIENT, doc.to_string().as_bytes()).is_err());
    }

    #[test]
    fn redirect_match_is_exact() {
        let m = parse_document(CLIENT, good_doc().to_string().as_bytes()).unwrap();
        assert!(m.allows_redirect("http://127.0.0.1:3000/callback"));
        for bad in [
            "http://127.0.0.1:3000/callback/",
            "http://127.0.0.1:3000/callback?x=1",
            "http://127.0.0.1:3000/CALLBACK",
            "https://attacker.example/callback",
        ] {
            assert!(!m.allows_redirect(bad), "{bad} must not match");
        }
    }

    #[test]
    fn max_age_parsing() {
        assert_eq!(
            parse_max_age("public, max-age=60"),
            Some(Duration::from_secs(60))
        );
        assert_eq!(parse_max_age("no-store"), Some(Duration::ZERO));
        assert_eq!(parse_max_age("public"), None);
    }

    #[tokio::test]
    async fn resolver_caches_and_honours_no_store() {
        let fetcher = FixtureFetcher::with(CLIENT, good_doc());
        let resolver = ClientResolver::new(fetcher.clone());
        resolver.resolve(CLIENT).await.unwrap();
        resolver.resolve(CLIENT).await.unwrap();
        assert_eq!(fetcher.hits.load(Ordering::SeqCst), 1);

        fetcher.docs.insert(
            CLIENT.to_string(),
            (good_doc().to_string(), Some(Duration::ZERO)),
        );
        let resolver = ClientResolver::new(fetcher.clone());
        resolver.resolve(CLIENT).await.unwrap();
        resolver.resolve(CLIENT).await.unwrap();
        assert_eq!(fetcher.hits.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn resolver_refuses_non_url_client_ids_without_fetching() {
        let fetcher = FixtureFetcher::with(CLIENT, good_doc());
        let resolver = ClientResolver::new(fetcher.clone());
        assert!(resolver.resolve("client_1234").await.is_err());
        assert_eq!(fetcher.hits.load(Ordering::SeqCst), 0);
    }
}
