//! Changing an account's session keys, spending limits or hardware signers
//! requires proving you already control it.
//!
//! The account address is a public identifier, so "knows the address" is not
//! a credential. Every such change needs a WebAuthn assertion from a passkey
//! the account's keystore links (for an account with no keystore on chain
//! yet, its first passkey), over a challenge the node issued, bound to the
//! operation and its target, and consumed single-use. Linking and unlinking
//! passkeys and recovery are keystore changes in consensus state instead.

use serde_json::{Value, json};
use std::sync::Arc;
use tenzro_node::{NodeConfig, RpcServer, TenzroNode};
use tokio::sync::broadcast;

struct TestNode {
    base_url: String,
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
            // A loopback endpoint on a port of its own, so the test does not
            // contend with a node already running on the host.
            iroh: tenzro_iroh::TenzroIrohConfig {
                bind_addr: free_udp_port(),
                ..Default::default()
            },
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
            shutdown,
            handle,
            _tmp: tmp,
            client: reqwest::Client::new(),
        }
    }

    async fn rpc(&self, method: &str, params: Value) -> Value {
        self.client
            .post(&self.base_url)
            .json(&json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}))
            .send()
            .await
            .expect("HTTP request")
            .json::<Value>()
            .await
            .expect("JSON parse")
    }

    /// Enroll a passkey account and return `(account_address, credential_id)`.
    ///
    /// Enrolment is authorized the way a browser does it: a custody challenge
    /// binding the credential to its ML-DSA-65 key, asserted by the passkey
    /// and co-signed by that key.
    async fn enroll(&self, name: &str, cred: u8) -> (String, String) {
        let passkey = tenzro_crypto::p256::P256KeyPair::generate();
        let resp = self.enroll_key(name, &passkey, cred, 0).await;
        let account = resp["result"]["smart_account_address"]
            .as_str()
            .unwrap_or_else(|| panic!("enroll failed: {resp}"))
            .to_string();
        (account, hex::encode(vec![cred; 16]))
    }

    /// Enroll `passkey` with credential id `[cred; 16]` and `salt`, returning
    /// the raw JSON-RPC response.
    async fn enroll_key(
        &self,
        name: &str,
        passkey: &tenzro_crypto::p256::P256KeyPair,
        cred: u8,
        salt: u64,
    ) -> Value {
        use sha2::Digest as _;

        let xy = passkey.public_key_bytes().to_vec();
        let credential_id = vec![cred; 16];

        let issued = self
            .rpc(
                "tenzro_createCustodyChallenge",
                json!({
                    "account_address": hex::encode(&xy),
                    "operation": "enroll_passkey",
                    "target_hex": hex::encode(&credential_id),
                }),
            )
            .await;
        let challenge_id = issued["result"]["challenge_id"]
            .as_str()
            .unwrap_or_else(|| panic!("no challenge: {issued}"))
            .to_string();
        let challenge = issued["result"]["webauthn_challenge"]
            .as_str()
            .expect("webauthn_challenge")
            .to_string();

        let rp_id = tenzro_node::config::DEFAULT_WEBAUTHN_RP_ID;
        let cdj = format!(
            r#"{{"type":"webauthn.get","challenge":"{}","origin":"https://{}","crossOrigin":false}}"#,
            challenge,
            rp_id
        )
        .into_bytes();
        let mut authenticator_data = sha2::Sha256::digest(rp_id.as_bytes()).to_vec();
        authenticator_data.push(0x01 | tenzro_crypto::webauthn::AUTH_DATA_FLAG_UV);
        authenticator_data.extend_from_slice(&0u32.to_be_bytes());
        let signer = tenzro_crypto::p256::P256Signer::from_keypair(passkey);
        let signature = signer.sign_prehash(&tenzro_crypto::webauthn::webauthn_signed_hash(
            &authenticator_data,
            &cdj,
        ));

        self.rpc(
            "tenzro_enrollPasskey",
            json!({
                "display_name": name,
                "passkey_public_key_hex": format!("04{}", hex::encode(&xy)),
                "credential_id_hex": hex::encode(&credential_id),
                "registration_authenticator_data_hex": hex::encode(
                    registration_authenticator_data(rp_id, &credential_id, &xy)
                ),
                "salt": salt,
                "ml_dsa_public_key_hex": hex::encode(enrolment_pq_key(&xy).verifying_key_bytes()),
                "authorization": {
                    "challenge_id": challenge_id,
                    "credential_id_hex": hex::encode(&credential_id),
                    "ml_dsa_signature_hex": enrolment_pq_leg(
                        &xy,
                        issued["result"]["challenge_hex"].as_str().expect("challenge_hex"),
                    ),
                    "assertion": {
                        "authenticator_data": authenticator_data,
                        "client_data_json": cdj,
                        "signature": signature.as_bytes().to_vec(),
                        "user_handle": null,
                    },
                },
            }),
        )
        .await
    }

    async fn shutdown(self) {
        let _ = self.shutdown.send(());
        let _ = self.handle.await;
    }
}

/// The ML-DSA-65 key the hardware holding the passkey `xy` enrols with it.
fn enrolment_pq_key(xy: &[u8]) -> tenzro_crypto::pq::MlDsaSigningKey {
    use sha2::Digest as _;
    tenzro_crypto::pq::MlDsaSigningKey::from_seed(&sha2::Sha256::digest(xy)).expect("pq key")
}

/// The ML-DSA-65 leg of an enrolment authorization over the custody
/// challenge `challenge_hex`, hex.
fn enrolment_pq_leg(xy: &[u8], challenge_hex: &str) -> String {
    let digest = hex::decode(challenge_hex.trim_start_matches("0x")).expect("challenge hex");
    hex::encode(enrolment_pq_key(xy).sign(
        tenzro_crypto::composite::LABEL_MLDSA65_P256,
        &tenzro_crypto::composite::message_representative(
            tenzro_crypto::composite::SignatureContext::AccountOwner,
            &digest,
        ),
    ))
}

/// A device-bound registration's `authenticatorData` for `rp_id`, carrying
/// `credential_id` and the P-256 key `xy` as its attested credential.
fn registration_authenticator_data(rp_id: &str, credential_id: &[u8], xy: &[u8]) -> Vec<u8> {
    use sha2::Digest as _;
    let mut data = sha2::Sha256::digest(rp_id.as_bytes()).to_vec();
    data.push(0x01 | tenzro_crypto::webauthn::AUTH_DATA_FLAG_UV | 0x40);
    data.extend_from_slice(&0u32.to_be_bytes());
    data.extend_from_slice(&[0xcb; 16]);
    data.extend_from_slice(&(credential_id.len() as u16).to_be_bytes());
    data.extend_from_slice(credential_id);
    data.extend_from_slice(&[0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20]);
    data.extend_from_slice(&xy[..32]);
    data.extend_from_slice(&[0x22, 0x58, 0x20]);
    data.extend_from_slice(&xy[32..]);
    data
}

fn hex_of(byte: u8, len: usize) -> String {
    std::iter::repeat_n(format!("{byte:02x}"), len).collect()
}

// ---------------------------------------------------------------------------
// The challenge itself
// ---------------------------------------------------------------------------

/// A challenge is scoped to one account, one operation, one target. Issuing is
/// open by design — a challenge is worthless without an enrolled credential to
/// sign it, and gating issuance would only stop a legitimate owner starting.
#[tokio::test]
async fn a_custody_challenge_is_issued_and_scoped() {
    let n = TestNode::boot().await;
    let (account, _) = n.enroll("Owner", 0x91).await;

    let issued = n
        .rpc(
            "tenzro_createCustodyChallenge",
            json!({
                "account_address": account,
                "operation": "bind_device",
                "target_hex": hex_of(0xee, 16),
            }),
        )
        .await;
    let result = &issued["result"];
    assert!(
        result["challenge_id"]
            .as_str()
            .is_some_and(|s| !s.is_empty()),
        "{issued}"
    );
    let digest = result["challenge_hex"].as_str().expect("a digest");
    assert_eq!(digest.len(), 66, "a 32-byte digest as 0x-prefixed hex");
    assert_eq!(result["operation"], "bind_device");
    assert!(result["expires_in_secs"].as_u64().unwrap_or(0) > 0);

    // A challenge for a different target is a different challenge — that
    // binding is what stops one authorization being spent on another change.
    let other = n
        .rpc(
            "tenzro_createCustodyChallenge",
            json!({
                "account_address": account,
                "operation": "bind_device",
                "target_hex": hex_of(0xdd, 16),
            }),
        )
        .await;
    assert_ne!(
        other["result"]["challenge_hex"], result["challenge_hex"],
        "two different targets produced the same challenge"
    );
    n.shutdown().await;
}

// ---------------------------------------------------------------------------
// Enrollment itself stays open
// ---------------------------------------------------------------------------

/// The gate must not break onboarding. Creating a *new* account has nothing to
/// prove control of yet — the passkey being enrolled becomes the proof for
/// everything after it.
#[tokio::test]
async fn enrolling_a_brand_new_account_still_works() {
    let n = TestNode::boot().await;
    let (account, _credential) = n.enroll("Fresh device", 0xb1).await;
    assert!(account.starts_with("0x"));

    // Nothing is stored: the account's keystore is its first passkey alone,
    // and the anchor its first keystore change will carry comes back.
    let keystore = n
        .rpc("tenzro_getKeystore", json!({ "account": account }))
        .await;
    assert_eq!(keystore["result"]["on_chain"], false, "{keystore}");
    n.shutdown().await;
}

/// One passkey is one identity. The DID derives from the key, so enrolling the
/// same key again returns the same DID: at salt 0 the identity's own account
/// and nothing new; at a higher salt one further wallet, once, which enrolling
/// that salt again returns.
#[tokio::test]
async fn re_enrolling_a_passkey_returns_its_identity_and_creates_nothing() {
    let n = TestNode::boot().await;
    let passkey = tenzro_crypto::p256::P256KeyPair::generate();

    let first = n.enroll_key("Owner", &passkey, 0xa7, 0).await;
    let did = first["result"]["did"]
        .as_str()
        .unwrap_or_else(|| panic!("{first}"))
        .to_string();
    let account = first["result"]["smart_account_address"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(
        first["result"]["keystore"]["credentials"]
            .as_array()
            .map(Vec::len),
        Some(1),
        "{first}"
    );
    assert!(first["result"]["anchor"].is_object(), "{first}");
    let commitment = first["result"]["keystore_commitment"].clone();

    let again = n.enroll_key("Owner again", &passkey, 0xa7, 0).await;
    assert_eq!(again["result"]["did"], did.as_str(), "{again}");
    assert_eq!(
        again["result"]["smart_account_address"],
        account.as_str(),
        "{again}"
    );
    assert_eq!(
        again["result"]["keystore_commitment"], commitment,
        "re-enrolling salt 0 changed nothing"
    );

    let further = n.enroll_key("Owner again", &passkey, 0xa7, 9).await;
    assert_eq!(
        further["result"]["did"],
        did.as_str(),
        "same identity: {further}"
    );
    let wallet9 = further["result"]["smart_account_address"]
        .as_str()
        .unwrap_or_else(|| panic!("{further}"))
        .to_string();
    assert_ne!(wallet9, account, "salt 9 is a further wallet");
    let repeat = n.enroll_key("Owner again", &passkey, 0xa7, 9).await;
    assert_eq!(
        repeat["result"]["smart_account_address"],
        wallet9.as_str(),
        "{repeat}"
    );
    n.shutdown().await;
}

// ---------------------------------------------------------------------------
// The legitimate path still works
// ---------------------------------------------------------------------------

/// A UDP port on loopback that was free a moment ago.
fn free_udp_port() -> std::net::SocketAddr {
    std::net::UdpSocket::bind("127.0.0.1:0")
        .and_then(|s| s.local_addr())
        .expect("a free loopback port")
}
