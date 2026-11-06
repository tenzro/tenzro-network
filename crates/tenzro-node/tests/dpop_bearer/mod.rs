//! An onboarded human with a DPoP-bound bearer, for tests that call
//! authenticated RPCs. Declared next to `passkey_holder`, which it uses.

// Each test binary that declares this module uses a different part of it.
#![allow(dead_code)]

use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use serde_json::{Value, json};
use tenzro_auth::DpopProof;
use tenzro_types::Address;

use crate::passkey_holder::PasskeyHolder;

/// A DPoP proof holder: the key a bearer token is bound to.
pub struct DpopHolder {
    key: SigningKey,
    jwk_json: String,
    pub jkt: String,
}

impl DpopHolder {
    pub fn new() -> Self {
        let key = SigningKey::generate(&mut OsRng);
        let x = URL_SAFE_NO_PAD.encode(key.verifying_key().to_bytes());
        let jwk_json = format!(r#"{{"crv":"Ed25519","kty":"OKP","x":"{}"}}"#, x);
        let jkt = DpopProof::compute_jkt(&jwk_json).expect("jkt");
        Self { key, jwk_json, jkt }
    }

    pub fn sign_proof(&self, htm: &str, htu: &str, access_token: Option<&str>) -> String {
        let jwk: Value = serde_json::from_str(&self.jwk_json).unwrap();
        let header = json!({ "typ": "dpop+jwt", "alg": "EdDSA", "jwk": jwk });
        let jti: [u8; 16] = rand::random();
        let mut payload = json!({
            "htm": htm,
            "htu": htu,
            "iat": SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            "jti": URL_SAFE_NO_PAD.encode(jti),
        });
        if let Some(token) = access_token {
            use sha2::Digest as _;
            payload["ath"] = json!(URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(token.as_bytes())));
        }
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header.to_string()),
            URL_SAFE_NO_PAD.encode(payload.to_string())
        );
        let sig = self.key.sign(input.as_bytes());
        format!("{}.{}", input, URL_SAFE_NO_PAD.encode(sig.to_bytes()))
    }
}

/// An onboarded human: wallet address and a DPoP-bound bearer.
pub struct Bearer {
    pub address: Address,
    pub token: String,
    pub holder: DpopHolder,
}

fn parse_addr(hex_str: &str) -> Address {
    let bytes = hex::decode(hex_str.trim_start_matches("0x")).expect("hex address");
    let mut arr = [0u8; 32];
    if bytes.len() <= 20 {
        arr[32 - bytes.len()..].copy_from_slice(&bytes);
    } else {
        arr[..bytes.len()].copy_from_slice(&bytes);
    }
    Address::new(arr)
}

async fn call(client: &reqwest::Client, url: &str, method: &str, params: Value) -> Value {
    client
        .post(url)
        .json(&json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params }))
        .send()
        .await
        .expect("HTTP")
        .json()
        .await
        .expect("JSON")
}

impl Bearer {
    /// Onboard a human with a fresh passkey at the node serving `url`.
    pub async fn onboard(client: &reqwest::Client, url: &str, name: &str) -> Self {
        let holder = DpopHolder::new();
        let passkey = PasskeyHolder::generate();
        let issued = call(
            client,
            url,
            "tenzro_createCustodyChallenge",
            passkey.challenge_params(),
        )
        .await;
        let resp = call(
            client,
            url,
            "tenzro_onboardHuman",
            passkey.onboard_params(
                json!({ "display_name": name, "dpop_jkt": holder.jkt }),
                passkey.authorize(&issued["result"]),
            ),
        )
        .await;
        let r = &resp["result"];
        assert!(
            r["identity"]["did"].is_string(),
            "onboarding failed: {resp}"
        );
        Self {
            address: parse_addr(r["wallet"]["address"].as_str().expect("address")),
            token: r["access_token"].as_str().expect("token").to_string(),
            holder,
        }
    }

    /// Attach this bearer's token and a fresh DPoP proof for a `POST` to the
    /// JSON-RPC root at `url`.
    pub fn authorize(&self, req: reqwest::RequestBuilder, url: &str) -> reqwest::RequestBuilder {
        req.header("Authorization", format!("DPoP {}", self.token))
            .header(
                "DPoP",
                self.holder
                    .sign_proof("POST", &format!("{url}/"), Some(&self.token)),
            )
    }

    /// Attach this bearer's token and a fresh DPoP proof for `htm` on the full
    /// route `route_url`.
    pub fn authorize_method(
        &self,
        req: reqwest::RequestBuilder,
        htm: &str,
        route_url: &str,
    ) -> reqwest::RequestBuilder {
        req.header("Authorization", format!("DPoP {}", self.token))
            .header(
                "DPoP",
                self.holder.sign_proof(htm, route_url, Some(&self.token)),
            )
    }

    /// Attach this bearer's token and a fresh DPoP proof for a `POST` to the
    /// full route `route_url`.
    pub fn authorize_route(
        &self,
        req: reqwest::RequestBuilder,
        route_url: &str,
    ) -> reqwest::RequestBuilder {
        req.header("Authorization", format!("DPoP {}", self.token))
            .header(
                "DPoP",
                self.holder.sign_proof("POST", route_url, Some(&self.token)),
            )
    }

    /// Call `method` at `url` as this bearer.
    pub async fn call(
        &self,
        client: &reqwest::Client,
        url: &str,
        method: &str,
        params: Value,
    ) -> Value {
        let proof = self
            .holder
            .sign_proof("POST", &format!("{url}/"), Some(&self.token));
        client
            .post(url)
            .header("Authorization", format!("DPoP {}", self.token))
            .header("DPoP", proof)
            .json(&json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params }))
            .send()
            .await
            .expect("HTTP")
            .json()
            .await
            .expect("JSON")
    }
}

/// A node operator signing in with a P-256 hardware-style key. The DID the
/// key derives is what a test node names as its `operator_did`.
pub struct OperatorKey {
    key: p256::ecdsa::SigningKey,
}

impl OperatorKey {
    pub fn new() -> Self {
        loop {
            let secret: [u8; 32] = rand::random();
            if let Ok(key) = p256::ecdsa::SigningKey::from_slice(&secret) {
                return Self { key };
            }
        }
    }

    /// The SEC1 uncompressed public key.
    pub fn public_key(&self) -> Vec<u8> {
        self.key
            .verifying_key()
            .to_sec1_point(false)
            .as_bytes()
            .to_vec()
    }

    /// The machine DID the key derives.
    pub fn did(&self) -> String {
        tenzro_identity::TenzroDid::from_device_key(&self.public_key())
            .expect("device DID")
            .to_string()
    }

    /// Sign in at the node serving `url` and return the operator's bearer.
    pub async fn sign_in(&self, client: &reqwest::Client, url: &str) -> Bearer {
        use p256::ecdsa::signature::Signer as _;
        let holder = DpopHolder::new();
        let issued = call(
            client,
            url,
            "tenzro_accessChallenge",
            json!({ "did": self.did(), "dpop_jkt": holder.jkt }),
        )
        .await;
        let r = &issued["result"];
        let digest = hex::decode(
            r["device_digest"]
                .as_str()
                .unwrap_or_else(|| panic!("challenge: {issued}")),
        )
        .expect("digest hex");
        let sig: p256::ecdsa::Signature = self.key.sign(&digest);
        let resp = call(
            client,
            url,
            "tenzro_issueAccessToken",
            json!({
                "challenge_id": r["challenge_id"],
                "proof": {
                    "kind": "device",
                    "public_key": hex::encode(self.public_key()),
                    "signature": hex::encode(sig.to_bytes()),
                },
            }),
        )
        .await;
        Bearer {
            address: Address::new([0u8; 32]),
            token: resp["result"]["access_token"]
                .as_str()
                .unwrap_or_else(|| panic!("sign-in failed: {resp}"))
                .to_string(),
            holder,
        }
    }
}

/// Name `did` an administrator of the node whose data directory is
/// `data_dir`, in the access policy it loads at start.
pub fn admit_operator(data_dir: &std::path::Path, did: &str) {
    let mut policy = tenzro_types::node_access::NodeAccessPolicy::default();
    policy.admins.push(did.to_string());
    write_policy(data_dir, &policy);
}

/// Write the access policy the node whose data directory is `data_dir` loads
/// at start.
pub fn write_policy(
    data_dir: &std::path::Path,
    policy: &tenzro_types::node_access::NodeAccessPolicy,
) {
    std::fs::write(
        data_dir.join("access.toml"),
        toml::to_string(policy).expect("policy toml"),
    )
    .expect("write access.toml");
}
