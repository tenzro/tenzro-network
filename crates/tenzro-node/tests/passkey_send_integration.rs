//! A passkey account can send.
//!
//! `tenzro_enrollPasskey` returns the account a passkey derives. The account
//! sends native transactions from itself, each signed by a passkey its
//! keystore in consensus state links, and spends once it holds two
//! independent roots.
//!
//! Each transaction below is signed the way a browser signs it: a WebAuthn
//! assertion over the transaction digest.

use serde_json::{Value, json};
use sha2::Digest as _;
use std::path::Path;
use std::sync::Arc;
use tenzro_node::{NodeConfig, RpcServer, TenzroNode};
use tokio::sync::broadcast;

struct TestNode {
    base_url: String,
    shutdown: broadcast::Sender<()>,
    handle: tokio::task::JoinHandle<tenzro_node::Result<()>>,
    node: Arc<TenzroNode>,
    client: reqwest::Client,
}

impl TestNode {
    async fn boot(data_dir: &Path) -> Self {
        let config = NodeConfig {
            data_dir: data_dir.to_path_buf(),
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
            node,
            client: reqwest::Client::new(),
        }
    }

    /// Stops the RPC server and the node and releases its storage, so another
    /// node can open the same data directory.
    async fn stop(self) {
        let _ = self.shutdown.send(());
        let _ = self.handle.await;
        let mut node = Arc::try_unwrap(self.node).unwrap_or_else(|_| {
            panic!("the node is still referenced after the RPC server stopped")
        });
        node.stop().await.expect("node stop");
        drop(node);
    }

    /// Credits `account` with gas money. On the network an account is funded by
    /// a transfer; here the balance is written to the state transactions
    /// are charged from, which is what these tests need and nothing more.
    fn fund(&self, account: &str, amount: u128) {
        use tenzro_vm::traits::VmState as _;
        let address = hex::decode(account.trim_start_matches("0x")).expect("account hex");
        let storage = self.node.storage().expect("node storage").clone();
        let mut state = tenzro_vm::StateAdapter::with_storage(storage);
        state.set_balance(&address, amount);
        state.commit().expect("commit funded balance");
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
}

/// A passkey: its P-256 key signs alone, as no ML-DSA-65 key is enrolled.
struct Passkey {
    p256: tenzro_crypto::p256::P256KeyPair,
    credential_id: Vec<u8>,
    /// The AAGUID its registration reports.
    aaguid: [u8; 16],
    /// Whether it is synced (BE and BS set).
    synced: bool,
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

/// The relying party a node verifies passkeys against when none is configured.
fn rp_id() -> String {
    tenzro_node::config::DEFAULT_WEBAUTHN_RP_ID.to_string()
}

const BE_BS: u8 = 0x08 | 0x10;

/// Authenticator flags with the user present and verified, plus the backup
/// flags when `synced`.
fn flags_for(synced: bool) -> u8 {
    let base = 0x01 | tenzro_crypto::webauthn::AUTH_DATA_FLAG_UV;
    if synced { base | BE_BS } else { base }
}

impl Passkey {
    /// A device-bound passkey, such as a security key.
    fn new(cred: u8) -> Self {
        Self {
            p256: tenzro_crypto::p256::P256KeyPair::generate(),
            credential_id: vec![cred; 16],
            aaguid: [0xcb; 16],
            synced: false,
        }
    }

    /// A passkey synced by the provider `provider` names.
    fn synced(cred: u8, provider: u8) -> Self {
        Self {
            aaguid: [provider; 16],
            synced: true,
            ..Self::new(cred)
        }
    }

    fn flags(&self) -> u8 {
        flags_for(self.synced)
    }

    fn xy(&self) -> Vec<u8> {
        self.p256.public_key_bytes().to_vec()
    }

    /// The registration's `authenticatorData`: this node's RP ID, the flags,
    /// and this credential with its AAGUID and COSE key.
    fn registration(&self) -> Vec<u8> {
        self.registration_claiming(self.synced, &self.credential_id)
    }

    /// A registration for this key that claims `synced` backup flags and the
    /// credential id `credential_id`, whatever the passkey really is.
    fn registration_claiming(&self, synced: bool, credential_id: &[u8]) -> Vec<u8> {
        let xy = self.xy();
        let mut data = sha2::Sha256::digest(rp_id().as_bytes()).to_vec();
        data.push(flags_for(synced) | 0x40);
        data.extend_from_slice(&0u32.to_be_bytes());
        data.extend_from_slice(&self.aaguid);
        data.extend_from_slice(&(credential_id.len() as u16).to_be_bytes());
        data.extend_from_slice(credential_id);
        data.extend_from_slice(&[0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20]);
        data.extend_from_slice(&xy[..32]);
        data.extend_from_slice(&[0x22, 0x58, 0x20]);
        data.extend_from_slice(&xy[32..]);
        data
    }

    /// A WebAuthn assertion over the WebAuthn `challenge`, as an
    /// authenticator for this node's RP ID returns it.
    fn assert(&self, challenge: &str) -> tenzro_crypto::webauthn::WebAuthnAssertion {
        let client_data_json = format!(
            r#"{{"type":"webauthn.get","challenge":"{}","origin":"https://{}","crossOrigin":false}}"#,
            challenge,
            rp_id()
        )
        .into_bytes();
        let mut authenticator_data = sha2::Sha256::digest(rp_id().as_bytes()).to_vec();
        authenticator_data.push(self.flags());
        authenticator_data.extend_from_slice(&0u32.to_be_bytes());
        let signature = tenzro_crypto::p256::P256Signer::from_keypair(&self.p256).sign_prehash(
            &tenzro_crypto::webauthn::webauthn_signed_hash(&authenticator_data, &client_data_json),
        );
        tenzro_crypto::webauthn::WebAuthnAssertion {
            authenticator_data,
            client_data_json,
            signature: signature.as_bytes().to_vec(),
            user_handle: None,
        }
    }
}

/// A custody authorization from `owner` for `operation` on `account` over
/// `target`, signed the way a browser signs it.
async fn authorize(
    n: &TestNode,
    account: &str,
    owner: &Passkey,
    operation: &str,
    target: &[u8],
) -> Value {
    authorize_over(n, account, owner, operation, target).await.0
}

/// [`authorize`], also returning the WebAuthn challenge, for a second
/// signature over the same challenge.
async fn authorize_over(
    n: &TestNode,
    account: &str,
    owner: &Passkey,
    operation: &str,
    target: &[u8],
) -> (Value, String) {
    let issued = n
        .rpc(
            "tenzro_createCustodyChallenge",
            json!({
                "account_address": account,
                "operation": operation,
                "target_hex": hex::encode(target),
            }),
        )
        .await;
    let challenge_id = issued["result"]["challenge_id"]
        .as_str()
        .unwrap_or_else(|| panic!("no challenge: {issued}"))
        .to_string();
    let digest = issued["result"]["webauthn_challenge"]
        .as_str()
        .expect("webauthn_challenge")
        .to_string();
    let assertion = owner.assert(&digest);
    let mut authorization = json!({
        "challenge_id": challenge_id,
        "credential_id_hex": hex::encode(&owner.credential_id),
        "assertion": {
            "authenticator_data": assertion.authenticator_data,
            "client_data_json": assertion.client_data_json,
            "signature": assertion.signature,
            "user_handle": null,
        },
    });
    if operation == "enroll_passkey" {
        authorization["ml_dsa_signature_hex"] = json!(enrolment_pq_leg(
            &owner.xy(),
            issued["result"]["challenge_hex"]
                .as_str()
                .expect("challenge_hex"),
        ));
    }
    (authorization, digest)
}

/// Enrolls `passkey` presenting `registration` as its registration's
/// `authenticatorData`, and returns the raw response.
async fn enroll_with_registration(n: &TestNode, passkey: &Passkey, registration: &[u8]) -> Value {
    let xy = passkey.xy();
    let authorization = authorize(
        n,
        &hex::encode(&xy),
        passkey,
        "enroll_passkey",
        &passkey.credential_id,
    )
    .await;
    n.rpc(
        "tenzro_enrollPasskey",
        json!({
            "display_name": "Sender",
            "passkey_public_key_hex": format!("04{}", hex::encode(&xy)),
            "credential_id_hex": hex::encode(&passkey.credential_id),
            "registration_authenticator_data_hex": hex::encode(registration),
            "ml_dsa_public_key_hex": hex::encode(enrolment_pq_key(&xy).verifying_key_bytes()),
            "authorization": authorization,
        }),
    )
    .await
}

/// Enrolls `passkey` at `salt` and returns the raw response.
async fn enroll_at_salt(n: &TestNode, passkey: &Passkey, salt: u64) -> Value {
    let xy = passkey.xy();
    let authorization = authorize(
        n,
        &hex::encode(&xy),
        passkey,
        "enroll_passkey",
        &passkey.credential_id,
    )
    .await;
    n.rpc(
        "tenzro_enrollPasskey",
        json!({
            "display_name": "Sender",
            "passkey_public_key_hex": format!("04{}", hex::encode(&xy)),
            "credential_id_hex": hex::encode(&passkey.credential_id),
            "registration_authenticator_data_hex": hex::encode(passkey.registration()),
            "ml_dsa_public_key_hex": hex::encode(enrolment_pq_key(&xy).verifying_key_bytes()),
            "authorization": authorization,
            "salt": salt,
        }),
    )
    .await
}

/// Enrolls `passkey`, authorized the way a browser does it, and returns the
/// smart account address.
async fn enroll(n: &TestNode, passkey: &Passkey) -> String {
    let resp = enroll_with_registration(n, passkey, &passkey.registration()).await;
    resp["result"]["smart_account_address"]
        .as_str()
        .unwrap_or_else(|| panic!("enroll failed: {resp}"))
        .to_string()
}

/// Links `new` to `account` in the node's chain state, as an applied
/// `KeystoreUpdate` leaves it (the consensus rules for linking are the VM's
/// own tests); it counts as a root from `counts_from_secs` (0: at once).
fn link(n: &TestNode, account: &str, first: &Passkey, new: &Passkey, counts_from_secs: u64) {
    let v = n.node.webauthn_validator().expect("webauthn validator");
    let account = hex::decode(account.trim_start_matches("0x")).expect("account hex");
    let mut state = v.state();
    let previous = tenzro_vm::keystore::read_record(&state, &account);
    let mut next = previous.clone().unwrap_or_else(|| {
        tenzro_types::keystore::KeystoreRecord::genesis(&tenzro_types::keystore::KeystoreAnchor {
            rp_id: rp_id(),
            credential_id: first.credential_id.clone(),
            public_key: first.xy(),
            aaguid: first.aaguid.to_vec(),
            backup_eligible: first.synced,
            backup_state: first.synced,
            salt: 0,
        })
    });
    next.credentials
        .push(tenzro_types::keystore::KeystoreCredential {
            rp_id: rp_id(),
            credential_id: new.credential_id.clone(),
            public_key: new.xy(),
            aaguid: new.aaguid.to_vec(),
            backup_eligible: new.synced,
            backup_state: new.synced,
            counts_as_root_from_ms: counts_from_secs * 1000,
            label: String::new(),
            added_at_ms: 0,
        });
    next.version += 1;
    tenzro_vm::keystore::write_record(&mut state, previous.as_ref(), &next, &mut Vec::new())
        .expect("link");
    state.commit().expect("commit");
}

/// The account's keystore as any node reports it.
async fn keystore(n: &TestNode, account: &str) -> Value {
    n.rpc("tenzro_getKeystore", json!({ "account": account }))
        .await["result"]
        .clone()
}

/// Enrolls `passkey` and links a device-bound security key beside it, so the
/// account holds the two independent roots spending needs.
async fn enroll_with_second_root(n: &TestNode, passkey: &Passkey) -> String {
    let account = enroll(n, passkey).await;
    let backup = Passkey::new(passkey.credential_id[0] ^ 0xff);
    link(n, &account, passkey, &backup, 0);
    assert_eq!(keystore(n, &account).await["independent_roots"], 2);
    account
}

fn hex_u64(v: &Value) -> u64 {
    u64::from_str_radix(v.as_str().expect("hex string").trim_start_matches("0x"), 16)
        .expect("hex quantity")
}

/// Signs and submits a zero-value transfer from `account` with nonce `seq`.
/// `tamper` corrupts the passkey's signature after signing.
/// A transaction sent to the node: the node's answer, and the signed
/// transaction it was built from.
struct Sent {
    resp: Value,
    tx: tenzro_types::transaction::SignedTransaction,
}

impl std::fmt::Display for Sent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.resp)
    }
}

async fn send(n: &TestNode, passkey: &Passkey, account: &str, seq: u64, tamper: bool) -> Sent {
    send_transfer(n, passkey, account, seq, tamper, &[0x11; 20], 1).await
}

async fn balance(n: &TestNode, address: &[u8]) -> u128 {
    let resp = n
        .rpc(
            "eth_getBalance",
            json!([format!("0x{}", hex::encode(address)), "latest"]),
        )
        .await;
    u128::from_str_radix(
        resp["result"]
            .as_str()
            .expect("balance")
            .trim_start_matches("0x"),
        16,
    )
    .expect("hex balance")
}

/// A native transfer from the passkey account, signed by `passkey` as a
/// WebAuthn assertion over the transaction digest the node reports.
async fn send_transfer(
    n: &TestNode,
    passkey: &Passkey,
    account: &str,
    seq: u64,
    tamper: bool,
    to: &[u8; 20],
    value: u128,
) -> Sent {
    send_transfer_on(n, passkey, account, seq, tamper, to, value, None).await
}

/// As [`send_transfer`], signed for `chain` instead of the node's own chain id.
#[allow(clippy::too_many_arguments)]
async fn send_transfer_on(
    n: &TestNode,
    passkey: &Passkey,
    account: &str,
    seq: u64,
    tamper: bool,
    to: &[u8; 20],
    value: u128,
    chain: Option<u64>,
) -> Sent {
    let chain_id = match chain {
        Some(c) => c,
        None => hex_u64(&n.rpc("eth_chainId", json!([])).await["result"]),
    };
    let gas_price = u128::from(hex_u64(&n.rpc("eth_gasPrice", json!([])).await["result"]));
    // The time block execution sees, which a test may move forward.
    let now = n
        .node
        .webauthn_validator()
        .expect("webauthn validator")
        .now()
        * 1000;
    let mut from = hex::decode(account.trim_start_matches("0x")).expect("account hex");
    from.resize(32, 0);
    // A refused transaction may already have consumed a nonce; ask the node.
    let _ = seq;
    let seq = hex_u64(
        &n.rpc(
            "tenzro_getNonce",
            json!([format!("0x{}", hex::encode(&from))]),
        )
        .await["result"],
    );
    let mut recipient = to.to_vec();
    recipient.resize(32, 0);
    let fields = json!({
        "from": format!("0x{}", hex::encode(&from)),
        "to": format!("0x{}", hex::encode(&recipient)),
        "nonce": seq,
        "chain_id": chain_id,
        "gas_limit": 100_000,
        "gas_price": gas_price,
        "timestamp": now,
        "valid_until": now + 300_000,
        "tx_type": { "Transfer": { "amount": value } },
    });
    let payload = n.rpc("tenzro_getSigningPayload", fields.clone()).await;
    let digest = hex::decode(
        payload["result"]["digest"]
            .as_str()
            .unwrap_or_else(|| panic!("payload: {payload}")),
    )
    .expect("digest hex");
    let mut assertion = passkey.assert(&tenzro_crypto::composite::webauthn_challenge(
        tenzro_crypto::composite::SignatureContext::Transaction,
        &digest,
    ));
    if tamper {
        let last = assertion.signature.len() - 1;
        assertion.signature[last] ^= 0x01;
    }
    let signature = tenzro_crypto::composite::CompositeSignature::classical(
        tenzro_crypto::composite::ClassicalProof::WebAuthn {
            authenticator_data: assertion.authenticator_data,
            client_data_json: assertion.client_data_json,
            signature: assertion.signature,
        },
    );
    let mut params = fields;
    params["public_key"] = json!(hex::encode(passkey.xy()));
    params["signature"] = serde_json::to_value(&signature).expect("signature JSON");
    let tx = tenzro_types::transaction::Transaction {
        chain_id: tenzro_types::primitives::ChainId(chain_id),
        from: tenzro_types::primitives::Address::new(from.try_into().expect("32 bytes")),
        to: tenzro_types::primitives::Address::new(recipient.try_into().expect("32 bytes")),
        nonce: tenzro_types::primitives::Nonce(seq),
        tx_type: tenzro_types::transaction::TransactionType::Transfer { amount: value },
        gas_limit: 100_000,
        gas_price: gas_price as u64,
        timestamp: tenzro_types::primitives::Timestamp::new(now as i64),
        valid_until: tenzro_types::primitives::Timestamp::new(now as i64 + 300_000),
        memo: None,
    };
    assert_eq!(
        tx.hash().as_bytes(),
        &digest[..],
        "the transaction the node reported the digest of"
    );
    let tx = tenzro_types::transaction::SignedTransaction::new(
        tx,
        passkey.xy(),
        serde_json::from_value(params["signature"].clone()).expect("signature"),
    );
    let resp = n.rpc("tenzro_sendRawTransaction", params).await;
    Sent { resp, tx }
}

/// One TNZO: far above the most gas any operation below can be charged.
const GAS_MONEY: u128 = 1_000_000_000_000_000_000;

/// What consensus makes of a transaction the node admitted: it is executed
/// against the node's state the way block execution runs it, and its writes
/// are kept when it succeeds. A passkey account's
/// signature, its keystore and its spending rule are checked here, in
/// execution, not at admission.
async fn executed(n: &TestNode, sent: &Sent) -> Result<(), String> {
    let admitted = sent.resp["result"]
        .as_str()
        .is_some_and(|h| h.trim_start_matches("0x").len() == 64);
    if !admitted {
        return Err(format!("not admitted: {}", sent.resp));
    }
    let now_ms = n
        .node
        .webauthn_validator()
        .expect("webauthn validator")
        .now() as i64
        * 1000;
    let tx = tenzro_node::event_loop::vm_transaction(&sent.tx).with_block_timestamp_ms(now_ms);
    let runtime = tenzro_vm::MultiVmRuntime::new(tenzro_vm::VmConfig::default())
        .await
        .expect("runtime");
    let mut state =
        tenzro_vm::StateAdapter::with_storage(n.node.storage().expect("node storage").clone());
    let outcome = runtime
        .execute_transaction(&tx, &mut state)
        .await
        .map_err(|e| e.to_string())?;
    if !outcome.success {
        return Err(outcome
            .revert_reason
            .unwrap_or_else(|| "reverted".to_string()));
    }
    state.commit().map_err(|e| e.to_string())?;
    Ok(())
}

#[tokio::test]
async fn an_enrolled_passkey_account_can_send_again_and_again() {
    let dir = tempfile::tempdir().expect("temp dir");
    let passkey = Passkey::new(0x51);

    let n = TestNode::boot(dir.path()).await;
    let account = enroll_with_second_root(&n, &passkey).await;
    n.fund(&account, GAS_MONEY);
    let first = send(&n, &passkey, &account, 0, false).await;
    executed(&n, &first)
        .await
        .expect("a freshly enrolled account must be able to send");
    let second = send(&n, &passkey, &account, 1, false).await;
    executed(&n, &second)
        .await
        .expect("the account must be able to send again");

    // And what it sends arrives.
    let recipient = [0x7au8; 20];
    let amount = 250_000_000_000_000_000u128;
    let third = send_transfer(&n, &passkey, &account, 2, false, &recipient, amount).await;
    executed(&n, &third)
        .await
        .expect("the account must be able to send TNZO");
    assert_eq!(
        balance(&n, &recipient).await,
        amount,
        "the recipient must receive what was sent"
    );
    n.stop().await;
}

#[tokio::test]
async fn an_operation_with_a_forged_passkey_signature_is_refused() {
    let dir = tempfile::tempdir().expect("temp dir");
    let passkey = Passkey::new(0x52);
    let n = TestNode::boot(dir.path()).await;
    let account = enroll_with_second_root(&n, &passkey).await;
    n.fund(&account, GAS_MONEY);

    let forged = send(&n, &passkey, &account, 0, true).await;
    assert!(
        executed(&n, &forged).await.is_err(),
        "a tampered signature must be refused: {forged}"
    );

    // The refusal did not consume the nonce: the genuine operation still goes through.
    let genuine = send(&n, &passkey, &account, 0, false).await;
    executed(&n, &genuine).await.expect("the genuine operation");
    n.stop().await;
}

/// An approval is bound to the network it was signed for: a transfer the
/// passkey signed for another chain id is refused at submission, and the
/// same transfer signed for this network goes through.
#[tokio::test]
async fn a_transfer_signed_for_another_chain_is_refused_at_submission() {
    let dir = tempfile::tempdir().expect("temp dir");
    let passkey = Passkey::new(0x5e);
    let n = TestNode::boot(dir.path()).await;
    let account = enroll_with_second_root(&n, &passkey).await;
    n.fund(&account, GAS_MONEY);
    let own = hex_u64(&n.rpc("eth_chainId", json!([])).await["result"]);

    let other = send_transfer_on(
        &n,
        &passkey,
        &account,
        0,
        false,
        &[0x11; 20],
        1,
        Some(own + 1),
    )
    .await;
    let refused = other.resp["error"]["message"].as_str().unwrap_or_default();
    assert!(
        refused.contains(&format!("signed for chain id {}", own + 1)),
        "a transfer signed for another chain must be refused at submission: {other}"
    );

    let genuine = send(&n, &passkey, &account, 0, false).await;
    executed(&n, &genuine)
        .await
        .expect("the transfer signed for this chain");
    n.stop().await;
}

#[tokio::test]
async fn another_passkey_cannot_send_from_the_account() {
    let dir = tempfile::tempdir().expect("temp dir");
    let owner = Passkey::new(0x53);
    let stranger = Passkey::new(0x53);
    let n = TestNode::boot(dir.path()).await;
    let account = enroll_with_second_root(&n, &owner).await;
    // Funded, and holding two roots, so a refusal can only be the signature's.
    n.fund(&account, GAS_MONEY);

    // Same credential id, different keys: the enrolled key does not verify it.
    let resp = send(&n, &stranger, &account, 0, false).await;
    assert!(
        executed(&n, &resp).await.is_err(),
        "a passkey that is not enrolled must not send: {resp}"
    );
    n.stop().await;
}

/// Spending is high-risk: one root of control is not enough, however valid
/// its signature. A second, independent root unlocks it.
#[tokio::test]
async fn a_single_root_cannot_spend_until_an_independent_one_is_added() {
    let dir = tempfile::tempdir().expect("temp dir");
    let phone = Passkey::synced(0x61, 0xea);
    let n = TestNode::boot(dir.path()).await;
    let account = enroll(&n, &phone).await;
    n.fund(&account, GAS_MONEY);

    let refused = send(&n, &phone, &account, 0, false).await;
    assert!(
        executed(&n, &refused).await.is_err(),
        "one root must not spend: {refused}"
    );

    // Adding a device is low-risk: the one synced passkey approves it. Below
    // two roots it waits, so a stolen passkey cannot add its own "second root"
    // and spend before the holder can remove it.
    let key = Passkey::new(0x62);
    let v = n.node.webauthn_validator().expect("webauthn validator");
    let counts_from = v.now() + 48 * 60 * 60;
    link(&n, &account, &phone, &key, counts_from);
    assert_eq!(keystore(&n, &account).await["independent_roots"], 1);
    let waiting = send(&n, &phone, &account, 0, false).await;
    assert!(
        executed(&n, &waiting).await.is_err(),
        "a waiting passkey must not enable spending: {waiting}"
    );

    v.set_clock_override(Some(counts_from + 1));
    let allowed = send(&n, &phone, &account, 0, false).await;
    executed(&n, &allowed).await.expect("two roots may spend");
    n.stop().await;
}

/// Two passkeys one provider syncs share one sync account: one root, no
/// spending. A passkey from a second provider is a second root.
#[tokio::test]
async fn two_passkeys_from_one_sync_provider_cannot_spend() {
    let dir = tempfile::tempdir().expect("temp dir");
    let laptop = Passkey::synced(0x71, 0x00);
    let n = TestNode::boot(dir.path()).await;
    let account = enroll(&n, &laptop).await;
    n.fund(&account, GAS_MONEY);

    let phone = Passkey::synced(0x72, 0x00);
    link(&n, &account, &laptop, &phone, 0);
    assert_eq!(keystore(&n, &account).await["independent_roots"], 1);
    let refused = send(&n, &laptop, &account, 0, false).await;
    assert!(
        executed(&n, &refused).await.is_err(),
        "one provider is one root: {refused}"
    );

    let other_provider = Passkey::synced(0x73, 0xea);
    link(&n, &account, &laptop, &other_provider, 0);
    assert_eq!(keystore(&n, &account).await["independent_roots"], 2);
    let allowed = send(&n, &laptop, &account, 0, false).await;
    executed(&n, &allowed)
        .await
        .expect("two providers may spend");

    let record = keystore(&n, &account).await;
    assert_eq!(
        record["keystore"]["credentials"].as_array().map(Vec::len),
        Some(3),
        "{record}"
    );
    n.stop().await;
}

/// One passkey is one identity, which can hold several wallets: a higher salt
/// is a further account under the same DID, and enrolling any salt again
/// returns the account it already has.
#[tokio::test]
async fn one_identity_holds_several_wallets_by_salt() {
    let dir = tempfile::tempdir().expect("temp dir");
    let passkey = Passkey::synced(0x91, 0xea);
    let n = TestNode::boot(dir.path()).await;

    let first = enroll_at_salt(&n, &passkey, 0).await;
    let second = enroll_at_salt(&n, &passkey, 1).await;
    let did = first["result"]["did"]
        .as_str()
        .unwrap_or_else(|| panic!("{first}"));
    assert_eq!(second["result"]["did"].as_str(), Some(did), "{second}");
    let a0 = first["result"]["smart_account_address"]
        .as_str()
        .expect("account 0")
        .to_string();
    let a1 = second["result"]["smart_account_address"]
        .as_str()
        .expect("account 1")
        .to_string();
    assert_ne!(a0, a1, "salt 1 must be its own wallet");

    let again = enroll_at_salt(&n, &passkey, 1).await;
    assert_eq!(
        again["result"]["smart_account_address"].as_str(),
        Some(a1.as_str()),
        "{again}"
    );
    let primary = enroll_at_salt(&n, &passkey, 0).await;
    assert_eq!(
        primary["result"]["smart_account_address"].as_str(),
        Some(a0.as_str()),
        "{primary}"
    );

    // The identity still names its own account.
    let identity = n.rpc("tenzro_resolveIdentity", json!({ "did": did })).await;
    assert_eq!(
        identity["result"]["metadata"]["smart_account_address"].as_str(),
        Some(a0.as_str()),
        "{identity}"
    );
    n.stop().await;
}

/// A UDP port on loopback that was free a moment ago.
fn free_udp_port() -> std::net::SocketAddr {
    std::net::UdpSocket::bind("127.0.0.1:0")
        .and_then(|s| s.local_addr())
        .expect("a free loopback port")
}
