//! Web-app hosting: proving the owner gate is the *right* gate.
//!
//! Every mutating site, function, machine, alias, placement and domain RPC is
//! guarded by a signed DID envelope. It is easy to test that a *missing*
//! envelope is refused and conclude the surface is protected — and that
//! conclusion would have been wrong here. "Requires a signature" is not
//! "requires the right signature": the envelope commits to a method and a hash
//! of the parameters precisely so one signature cannot be replayed as another,
//! and checking only the signature would mean any envelope an owner ever
//! produced for any site operation authorizes every other one, for as long as
//! it stays inside the freshness window.
//!
//! So the tests here are all about *valid signatures used wrongly*: the right
//! owner signing the wrong method, the right method naming the wrong resource,
//! and a correct envelope presented twice.

use ed25519_dalek::{Signer, SigningKey};
use serde_json::{Value, json};
use std::sync::Arc;
use tenzro_identity::envelope::{TenzroDidEnvelope, canonical_preimage, params_hash};
use tenzro_node::{NodeConfig, RpcServer, TenzroNode};
use tokio::sync::broadcast;

struct TestNode {
    base_url: String,
    node: Arc<TenzroNode>,
    shutdown: broadcast::Sender<()>,
    handle: tokio::task::JoinHandle<tenzro_node::Result<()>>,
    _tmp: tempfile::TempDir,
    client: reqwest::Client,
}

impl TestNode {
    async fn boot() -> Self {
        let tmp = tempfile::tempdir().expect("temp dir");
        let config = NodeConfig {
            data_dir: tmp.path().to_path_buf(),
            ..Default::default()
        };
        let mut node = TenzroNode::new(config).await.expect("node creation");
        node.start().await.expect("node start");
        let node = Arc::new(node);

        let (shutdown, shutdown_rx) = broadcast::channel::<()>(1);
        let (addr_tx, addr_rx) = tokio::sync::oneshot::channel();
        let rpc = RpcServer::new(node.clone(), "127.0.0.1:0".to_string());
        let handle =
            tokio::spawn(
                async move { rpc.start_with_shutdown_and_addr(shutdown_rx, addr_tx).await },
            );
        let addr = addr_rx.await.expect("bound address");

        Self {
            base_url: format!("http://{addr}"),
            node,
            shutdown,
            handle,
            _tmp: tmp,
            client: reqwest::Client::new(),
        }
    }

    async fn rpc(&self, method: &str, params: Value) -> Value {
        self.request(method, params, None).await
    }

    /// The same call, presenting an API key. Site RPCs do not *require* one —
    /// the envelope is what authenticates them — but a key that is presented
    /// still attenuates what the call may reach.
    async fn rpc_with_key(&self, method: &str, params: Value, key: &str) -> Value {
        self.request(method, params, Some(key)).await
    }

    async fn request(&self, method: &str, params: Value, key: Option<&str>) -> Value {
        let mut req = self
            .client
            .post(&self.base_url)
            .json(&json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}));
        if let Some(key) = key {
            req = req.header("X-Tenzro-Api-Key", key);
        }
        req.send()
            .await
            .expect("HTTP request")
            .json::<Value>()
            .await
            .expect("JSON parse")
    }

    /// Publish a real site owned by `owner`, returning its `site_id`.
    async fn publish(&self, owner: &Owner, name: &str) -> String {
        let hash = "c".repeat(64);
        self.node
            .site_registry()
            .blob_cache()
            .insert(&hash, bytes::Bytes::from_static(b"<!doctype html>"));
        let env = owner.envelope("tenzro_sitePublish", name.as_bytes());
        let resp = self
            .rpc(
                "tenzro_sitePublish",
                json!({
                    "name": name,
                    "owner_did": owner.did,
                    "did_envelope": env,
                    "routes": [
                        {"path": "/index.html", "blob_hash": hash,
                         "content_type": "text/html", "size": 15},
                    ],
                }),
            )
            .await;
        resp["result"]["site_id"]
            .as_str()
            .unwrap_or_else(|| panic!("publish failed: {resp}"))
            .to_string()
    }

    /// A key narrowed to exactly the sites named.
    fn key_for_sites(&self, subject: &str, sites: Vec<String>) -> String {
        use tenzro_node::api_key::{AgentDelegation, ApiKeyScope, KeyClass};
        self.node
            .api_key_manager()
            .expect("api key manager")
            .issue_with_delegation(
                Some(subject.to_string()),
                "narrowed",
                // Site RPCs carry no scope of their own; issuance just requires
                // at least one, and which is irrelevant to the allow-list.
                vec![ApiKeyScope::Storage],
                KeyClass::Subject,
                None,
                None,
                None,
                None,
                AgentDelegation {
                    allowed_sites: sites,
                    ..Default::default()
                },
            )
            .expect("issue")
            .key
    }

    async fn shutdown(self) {
        let _ = self.shutdown.send(());
        let _ = self.handle.await;
    }
}

/// An owner who can sign. `did:key:` resolves from the identifier itself, so no
/// registry round-trip is needed to make a real, verifiable signature.
struct Owner {
    did: String,
    key: SigningKey,
}

impl Owner {
    fn new(seed: u8) -> Self {
        let key = SigningKey::from_bytes(&[seed; 32]);
        let mut multicodec = vec![0xed, 0x01];
        multicodec.extend_from_slice(key.verifying_key().as_bytes());
        let did = format!("did:key:z{}", bs58::encode(multicodec).into_string());
        Self { did, key }
    }

    /// A genuinely valid envelope: correct signature, by this owner, over the
    /// given method and canonical params.
    fn envelope(&self, method: &str, canonical: &[u8]) -> String {
        self.envelope_with_nonce(method, canonical, rand_nonce())
    }

    fn envelope_with_nonce(&self, method: &str, canonical: &[u8], nonce: [u8; 16]) -> String {
        let mut env = TenzroDidEnvelope {
            did: self.did.clone(),
            method: method.to_string(),
            params_hash: params_hash(canonical),
            timestamp: now_ms(),
            nonce,
            signature: vec![],
        };
        env.signature = self.key.sign(&canonical_preimage(&env)).to_bytes().to_vec();
        env.to_header_value()
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_millis() as u64
}

/// Nonces only need to differ within a run; deriving one from the clock keeps
/// the test free of a random-number dependency.
fn rand_nonce() -> [u8; 16] {
    let mut n = [0u8; 16];
    n[..8].copy_from_slice(&now_ms().to_le_bytes());
    n[8..].copy_from_slice(&std::time::Instant::now().elapsed().as_nanos().to_le_bytes()[..8]);
    // An all-zero nonce is rejected outright as providing no replay entropy.
    n[15] |= 1;
    n
}

fn error_message(resp: &Value) -> String {
    resp.get("error")
        .and_then(|e| e.get("message"))
        .and_then(|m| m.as_str())
        .unwrap_or_default()
        .to_string()
}

// ---------------------------------------------------------------------------
// The easy half: no envelope at all
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_mutation_without_an_envelope_is_refused() {
    let n = TestNode::boot().await;
    let owner = Owner::new(1);
    let resp = n
        .rpc(
            "tenzro_siteRemove",
            json!({ "site_id": "some-site", "owner_did": owner.did }),
        )
        .await;
    assert!(
        error_message(&resp).contains("Missing did_envelope"),
        "{resp}"
    );
    n.shutdown().await;
}

#[tokio::test]
async fn an_envelope_from_a_different_owner_is_refused() {
    let n = TestNode::boot().await;
    let owner = Owner::new(1);
    let attacker = Owner::new(2);
    // A perfectly valid envelope — signed by the wrong person.
    let env = attacker.envelope("tenzro_siteRemove", b"some-site");
    let resp = n
        .rpc(
            "tenzro_siteRemove",
            json!({ "site_id": "some-site", "owner_did": owner.did, "did_envelope": env }),
        )
        .await;
    assert!(
        error_message(&resp).contains("does not match owner_did"),
        "{resp}"
    );
    n.shutdown().await;
}

// ---------------------------------------------------------------------------
// The half that matters: a valid signature, used wrongly
// ---------------------------------------------------------------------------

/// The owner signed something — just not this. An envelope minted for a
/// placement change must not authorize deleting the site.
#[tokio::test]
async fn an_envelope_for_another_method_is_refused() {
    let n = TestNode::boot().await;
    let owner = Owner::new(3);
    let env = owner.envelope("tenzro_siteSetPlacement", b"some-site");
    let resp = n
        .rpc(
            "tenzro_siteRemove",
            json!({ "site_id": "some-site", "owner_did": owner.did, "did_envelope": env }),
        )
        .await;
    let msg = error_message(&resp);
    assert!(
        msg.contains("authorizes method"),
        "a valid signature over a different method was accepted: {resp}"
    );
    n.shutdown().await;
}

/// The owner signed the right method — for a different site. Without a params
/// binding, one envelope would delete any of their sites.
#[tokio::test]
async fn an_envelope_for_another_resource_is_refused() {
    let n = TestNode::boot().await;
    let owner = Owner::new(4);
    let env = owner.envelope("tenzro_siteRemove", b"the-site-they-meant");
    let resp = n
        .rpc(
            "tenzro_siteRemove",
            json!({
                "site_id": "a-different-site",
                "owner_did": owner.did,
                "did_envelope": env,
            }),
        )
        .await;
    let msg = error_message(&resp);
    assert!(
        msg.contains("params_hash"),
        "a valid signature over a different site was accepted: {resp}"
    );
    n.shutdown().await;
}

/// Same shape, on the alias surface: an envelope pointing a hostname at one
/// site must not repoint it at another.
#[tokio::test]
async fn an_alias_envelope_is_bound_to_its_target_site() {
    let n = TestNode::boot().await;
    let owner = Owner::new(5);
    let env = owner.envelope("tenzro_siteSetAlias", b"app.example.com:intended-site");
    let resp = n
        .rpc(
            "tenzro_siteSetAlias",
            json!({
                "hostname": "app.example.com",
                "site_id": "attackers-site",
                "owner_did": owner.did,
                "did_envelope": env,
            }),
        )
        .await;
    assert!(
        error_message(&resp).contains("params_hash"),
        "an alias envelope was reusable against a different site: {resp}"
    );
    n.shutdown().await;
}

/// And on the domain surface, where the consequence is handing someone else's
/// hostname away.
#[tokio::test]
async fn a_domain_envelope_is_bound_to_its_hostname() {
    let n = TestNode::boot().await;
    let owner = Owner::new(6);
    let env = owner.envelope("tenzro_siteRemoveDomain", b"mine.example.com");
    let resp = n
        .rpc(
            "tenzro_siteRemoveDomain",
            json!({
                "hostname": "theirs.example.com",
                "owner_did": owner.did,
                "did_envelope": env,
            }),
        )
        .await;
    assert!(
        error_message(&resp).contains("params_hash"),
        "a domain envelope was reusable against a different hostname: {resp}"
    );
    n.shutdown().await;
}

/// A correct envelope, presented twice. The method and params bindings narrow a
/// captured envelope to exactly one call; the nonce is what stops that one call
/// being made twice.
#[tokio::test]
async fn a_correct_envelope_cannot_be_replayed() {
    let n = TestNode::boot().await;
    let owner = Owner::new(7);
    let nonce = rand_nonce();
    let env = owner.envelope_with_nonce("tenzro_siteRemove", b"no-such-site", nonce);

    let params = json!({
        "site_id": "no-such-site",
        "owner_did": owner.did,
        "did_envelope": env,
    });

    // The site does not exist, so the first call fails on lookup — but it fails
    // *past* the envelope check, which is what burns the nonce. An envelope
    // error here would mean this test is not exercising what it claims to.
    let first = n.rpc("tenzro_siteRemove", params.clone()).await;
    let first_msg = error_message(&first);
    assert!(
        !first_msg.contains("did_envelope"),
        "the first call was rejected by the envelope gate, so the replay check below \
         proves nothing: {first}"
    );

    let second = n.rpc("tenzro_siteRemove", params).await;
    assert!(
        error_message(&second).contains("replayed"),
        "the same envelope was accepted twice: {second}"
    );
    n.shutdown().await;
}

// ---------------------------------------------------------------------------
// The gate is not simply closed
// ---------------------------------------------------------------------------

/// A gate that refused everything would pass every test above and host nothing.
/// A correctly-bound envelope must get past the gate and reach the handler.
#[tokio::test]
async fn a_correctly_bound_envelope_reaches_the_handler() {
    let n = TestNode::boot().await;
    let owner = Owner::new(8);
    let env = owner.envelope("tenzro_siteRemove", b"absent-site");
    let resp = n
        .rpc(
            "tenzro_siteRemove",
            json!({ "site_id": "absent-site", "owner_did": owner.did, "did_envelope": env }),
        )
        .await;
    let msg = error_message(&resp);
    // It gets past authentication and fails on the site not existing, which is
    // the handler's own error — proof the envelope was accepted.
    assert!(
        !msg.contains("did_envelope") && !msg.contains("params_hash"),
        "a correctly-bound envelope was refused by the gate: {resp}"
    );
    assert!(
        !msg.is_empty(),
        "expected the handler's own not-found error: {resp}"
    );
    n.shutdown().await;
}

/// Reads are not gated — a tenant's site has to be servable, and a published
/// site's manifest is public by construction.
#[tokio::test]
async fn reads_do_not_require_an_envelope() {
    let n = TestNode::boot().await;
    let resp = n.rpc("tenzro_listSites", json!({})).await;
    assert!(
        resp.get("result").is_some(),
        "listing sites must not require an envelope: {resp}"
    );
    n.shutdown().await;
}

// ---------------------------------------------------------------------------
// The other axis: which of an owner's own sites a credential may reach
// ---------------------------------------------------------------------------
//
// The envelope proves *who* is calling. `allowed_sites` narrows *what* one
// credential of theirs may touch — an owner with two sites can hand out a key
// that reaches only one. Both checks run; neither substitutes for the other,
// so these tests sign correctly throughout and vary only the key.

/// A narrowed key reaches the site it names and is refused on the one it does
/// not — including through the alias surface, where the site is reached by
/// hostname rather than by id.
#[tokio::test]
async fn a_narrowed_key_reaches_only_the_site_it_names() {
    let n = TestNode::boot().await;
    let owner = Owner::new(20);
    let mine = n.publish(&owner, "narrow-mine").await;
    let other = n.publish(&owner, "narrow-other").await;
    let key = n.key_for_sites(&owner.did, vec![mine.clone()]);

    let resp = n
        .rpc_with_key("tenzro_siteGet", json!({ "site_id": mine }), &key)
        .await;
    assert!(
        resp.get("result").is_some(),
        "the key was refused on the site it names: {resp}"
    );

    let resp = n
        .rpc_with_key("tenzro_siteGet", json!({ "site_id": other }), &key)
        .await;
    assert!(
        error_message(&resp).contains("not authorized for site"),
        "the key reached a site outside its allow-list: {resp}"
    );

    // Aliases name a hostname, not a site. Resolving it first is what keeps
    // the allow-list from being sidestepped by pointing at the target
    // indirectly.
    let env = owner.envelope("tenzro_siteSetAlias", format!("a.example:{other}").as_bytes());
    let resp = n
        .rpc_with_key(
            "tenzro_siteSetAlias",
            json!({ "hostname": "a.example", "site_id": other,
                    "owner_did": owner.did, "did_envelope": env }),
            &key,
        )
        .await;
    assert!(
        error_message(&resp).contains("not authorized for site"),
        "a narrowed key re-pointed a hostname at a site it may not touch: {resp}"
    );
    n.shutdown().await;
}

/// A listing must not name what a `get` would refuse. Otherwise the allow-list
/// hides the contents of a site while still disclosing that it exists.
#[tokio::test]
async fn a_listing_names_nothing_the_key_cannot_open() {
    let n = TestNode::boot().await;
    let owner = Owner::new(21);
    let mine = n.publish(&owner, "listing-mine").await;
    let other = n.publish(&owner, "listing-other").await;
    let key = n.key_for_sites(&owner.did, vec![mine.clone()]);

    let resp = n.rpc_with_key("tenzro_listSites", json!({}), &key).await;
    let listed: Vec<String> = resp["result"]["sites"]
        .as_array()
        .expect("sites array")
        .iter()
        .filter_map(|s| s["site_id"].as_str().map(str::to_string))
        .collect();
    assert!(listed.contains(&mine), "the key's own site was hidden: {resp}");
    assert!(
        !listed.contains(&other),
        "the listing disclosed a site the key cannot open: {resp}"
    );

    // The same call without a key is unnarrowed, so this is a property of the
    // credential and not of the listing having quietly stopped working.
    let resp = n.rpc("tenzro_listSites", json!({})).await;
    let all: Vec<String> = resp["result"]["sites"]
        .as_array()
        .expect("sites array")
        .iter()
        .filter_map(|s| s["site_id"].as_str().map(str::to_string))
        .collect();
    assert!(
        all.contains(&mine) && all.contains(&other),
        "an unnarrowed caller should still see both: {resp}"
    );
    n.shutdown().await;
}

/// Narrowing must also stop a key creating its way out of the allow-list. A
/// key that could publish a *new* site would simply own one the list does not
/// name.
#[tokio::test]
async fn a_narrowed_key_cannot_publish_a_new_site() {
    let n = TestNode::boot().await;
    let owner = Owner::new(22);
    let mine = n.publish(&owner, "escape-mine").await;
    let key = n.key_for_sites(&owner.did, vec![mine]);

    let hash = "c".repeat(64);
    n.node
        .site_registry()
        .blob_cache()
        .insert(&hash, bytes::Bytes::from_static(b"<!doctype html>"));
    let env = owner.envelope("tenzro_sitePublish", b"escape-new");
    let resp = n
        .rpc_with_key(
            "tenzro_sitePublish",
            json!({
                "name": "escape-new",
                "owner_did": owner.did,
                "did_envelope": env,
                "routes": [
                    {"path": "/index.html", "blob_hash": hash,
                     "content_type": "text/html", "size": 15},
                ],
            }),
            &key,
        )
        .await;
    assert!(
        error_message(&resp).contains("not authorized for site"),
        "a narrowed key published a site outside its allow-list: {resp}"
    );
    n.shutdown().await;
}

// ---------------------------------------------------------------------------
// Hosting, end to end
// ---------------------------------------------------------------------------

/// Publish a site through the real RPC with a correctly-bound envelope, then
/// fetch its pages back over HTTP from the real serving handler.
///
/// The gate tests above prove nobody else can touch a tenant's site. This
/// proves the tenant gets a working one — which is the actual product, and the
/// thing a suite of refusal tests can quietly stop delivering.
#[tokio::test]
async fn a_published_site_is_served_over_http() {
    use axum::Router;
    use axum::routing::get;

    let tmp = tempfile::tempdir().expect("temp dir");
    let config = NodeConfig {
        data_dir: tmp.path().to_path_buf(),
        ..Default::default()
    };
    let mut node = TenzroNode::new(config).await.expect("node creation");
    node.start().await.expect("node start");
    let node = Arc::new(node);

    let (shutdown, shutdown_rx) = broadcast::channel::<()>(1);
    let (addr_tx, addr_rx) = tokio::sync::oneshot::channel();
    let rpc = RpcServer::new(node.clone(), "127.0.0.1:0".to_string());
    let rpc_handle =
        tokio::spawn(async move { rpc.start_with_shutdown_and_addr(shutdown_rx, addr_tx).await });
    let rpc_addr = addr_rx.await.expect("bound address");
    let client = reqwest::Client::new();

    // Seed the blob layer directly. Publishing addresses content by hash and
    // the fetch path falls back to iroh on a cache miss; pre-seeding keeps this
    // test about hosting rather than about blob transport, which
    // `tenzro-iroh` covers on its own.
    let index_html = b"<!doctype html><title>tenant app</title><h1>hello</h1>";
    let app_js = b"console.log('bundle');";
    let index_hash = "a".repeat(64);
    let js_hash = "b".repeat(64);
    let cache = node.site_registry().blob_cache();
    cache.insert(&index_hash, bytes::Bytes::from_static(index_html));
    cache.insert(&js_hash, bytes::Bytes::from_static(app_js));

    let owner = Owner::new(9);
    let env = owner.envelope("tenzro_sitePublish", b"tenant-app");
    let published: Value = client
        .post(format!("http://{rpc_addr}"))
        .json(&json!({
            "jsonrpc": "2.0", "id": 1, "method": "tenzro_sitePublish",
            "params": {
                "name": "tenant-app",
                "owner_did": owner.did,
                "did_envelope": env,
                "spa": true,
                "routes": [
                    {"path": "/index.html", "blob_hash": index_hash,
                     "content_type": "text/html", "size": index_html.len()},
                    {"path": "/app.js", "blob_hash": js_hash,
                     "content_type": "application/javascript", "size": app_js.len()},
                ],
            }
        }))
        .send()
        .await
        .expect("HTTP request")
        .json()
        .await
        .expect("JSON parse");
    let site_id = published["result"]["site_id"]
        .as_str()
        .unwrap_or_else(|| panic!("publish failed: {published}"))
        .to_string();

    // Stand up the real serving handlers against the real node state.
    let web_state = Arc::new(tenzro_node::web::handlers::WebState::new().with_node(node.clone()));
    let app = Router::new()
        .route(
            "/sites/:site_id",
            get(tenzro_node::web::sites::serve_site_index),
        )
        .route(
            "/sites/:site_id/*path",
            get(tenzro_node::web::sites::serve_site_asset),
        )
        .with_state(web_state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let web_addr = listener.local_addr().expect("addr");
    let web_handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    // The index, by site id.
    let resp = client
        .get(format!("http://{web_addr}/sites/{site_id}"))
        .send()
        .await
        .expect("HTTP request");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok()),
        Some("text/html")
    );
    let etag = resp
        .headers()
        .get("etag")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
        .expect("an ETag, so a browser can revalidate");
    assert_eq!(resp.bytes().await.expect("body"), &index_html[..]);

    // An asset.
    let js = client
        .get(format!("http://{web_addr}/sites/{site_id}/app.js"))
        .send()
        .await
        .expect("HTTP request");
    assert_eq!(js.status(), reqwest::StatusCode::OK);
    assert_eq!(js.bytes().await.expect("body"), &app_js[..]);

    // Revalidation: the ETag is the content hash, so an unchanged deploy costs
    // a tenant's visitors nothing.
    let cached = client
        .get(format!("http://{web_addr}/sites/{site_id}"))
        .header("if-none-match", &etag)
        .send()
        .await
        .expect("HTTP request");
    assert_eq!(cached.status(), reqwest::StatusCode::NOT_MODIFIED);

    // SPA fallback: a client-side route serves the index at 200 so the app's
    // own router can handle it.
    let deep = client
        .get(format!(
            "http://{web_addr}/sites/{site_id}/settings/profile"
        ))
        .send()
        .await
        .expect("HTTP request");
    assert_eq!(deep.status(), reqwest::StatusCode::OK);
    assert_eq!(deep.bytes().await.expect("body"), &index_html[..]);

    // But a missing *asset* is a 404, not the index — masking a missing bundle
    // chunk as an HTML page is how a broken deploy looks fine and fails in the
    // browser console.
    let missing = client
        .get(format!("http://{web_addr}/sites/{site_id}/missing.js"))
        .send()
        .await
        .expect("HTTP request");
    assert_eq!(missing.status(), reqwest::StatusCode::NOT_FOUND);

    web_handle.abort();
    let _ = shutdown.send(());
    let _ = rpc_handle.await;
}
