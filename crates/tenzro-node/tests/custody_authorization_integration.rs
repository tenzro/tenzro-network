//! Changing who can spend from a wallet requires proving you already control it.
//!
//! # The hole these tests close
//!
//! Six of the eight custody-mutating RPCs took only a smart-account address and
//! did as they were told. The account address is a *public identifier* — it is
//! returned by `tenzro_enrollPasskey`, listed by `tenzro_listSmartAccounts`, and
//! visible on-chain — so "knows the address" was being treated as a credential.
//!
//! Chained, two of them were a complete, unauthenticated wallet takeover,
//! reachable over the open RPC port with no key, no token and no signature:
//!
//! 1. `tenzro_addPasskey` — the attacker enrolls their own passkey on the
//!    victim's account, becoming an authorized signer.
//! 2. `tenzro_removePasskey` — the attacker removes the victim's credential,
//!    leaving themselves in sole control.
//!
//! Both were confirmed against a live node before the fix. The tests below are
//! those exact sequences, now asserting refusal — a regression here is an
//! account-takeover regression, so it is worth its own file and its own
//! narrative.
//!
//! # What the fix requires
//!
//! A WebAuthn assertion from a credential *already enrolled on that account*,
//! over a challenge the node issued, bound to the specific operation and its
//! specific target. Issued server-side and consumed single-use, so a captured
//! assertion cannot be replayed; bound to the operation, so an assertion
//! collected for "add my phone" cannot be replayed as "remove the owner's
//! laptop".

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
    async fn enroll(&self, name: &str, seed: u8, cred: u8) -> (String, String) {
        let x = hex_of(seed, 32);
        let y = hex_of(seed.wrapping_add(1), 32);
        let ml_dsa = hex_of(seed.wrapping_add(2), 1952);
        let credential = hex_of(cred, 16);
        let resp = self
            .rpc(
                "tenzro_enrollPasskey",
                json!({
                    "display_name": name,
                    "passkey_public_key_hex": format!("04{x}{y}"),
                    "credential_id_hex": credential,
                    "ml_dsa_public_key_hex": ml_dsa,
                }),
            )
            .await;
        let account = resp["result"]["smart_account_address"]
            .as_str()
            .unwrap_or_else(|| panic!("enroll failed: {resp}"))
            .to_string();
        (account, credential)
    }

    async fn shutdown(self) {
        let _ = self.shutdown.send(());
        let _ = self.handle.await;
    }
}

fn hex_of(byte: u8, len: usize) -> String {
    std::iter::repeat_n(format!("{byte:02x}"), len).collect()
}

fn error_message(resp: &Value) -> String {
    resp.get("error")
        .and_then(|e| e.get("message"))
        .and_then(|m| m.as_str())
        .unwrap_or_default()
        .to_string()
}

fn is_refusal(resp: &Value) -> bool {
    resp.get("result").is_none() && resp.get("error").is_some()
}

// ---------------------------------------------------------------------------
// The takeover chain
// ---------------------------------------------------------------------------

/// Step one of the confirmed takeover: enrolling your own passkey on a
/// stranger's wallet.
#[tokio::test]
async fn a_stranger_cannot_add_their_passkey_to_someone_elses_wallet() {
    let n = TestNode::boot().await;
    let (victim, victim_cred) = n.enroll("Victim laptop", 0x11, 0xab).await;

    let attack = n
        .rpc(
            "tenzro_addPasskey",
            json!({
                "account_address": victim,
                "new_passkey_public_key_hex": format!("04{}{}", hex_of(0x99, 32), hex_of(0xaa, 32)),
                "new_credential_id_hex": hex_of(0xee, 16),
                "label": "attacker phone",
            }),
        )
        .await;
    assert!(
        is_refusal(&attack),
        "an unauthenticated caller enrolled a passkey on another account: {attack}"
    );
    assert!(
        error_message(&attack).contains("proof you already control it"),
        "{attack}"
    );

    // And the victim's credential set is untouched.
    let listed = n
        .rpc("tenzro_listPasskeys", json!({ "account_address": victim }))
        .await;
    let ids = listed["result"]["credential_ids"]
        .as_array()
        .expect("credential list");
    assert_eq!(ids.len(), 1, "credential set was modified: {listed}");
    assert!(ids[0].as_str().unwrap_or_default().contains(&victim_cred));
    n.shutdown().await;
}

/// Step two: locking the owner out of their own wallet.
#[tokio::test]
async fn a_stranger_cannot_remove_someone_elses_credential() {
    let n = TestNode::boot().await;
    let (victim, victim_cred) = n.enroll("Victim laptop", 0x21, 0xcd).await;

    let attack = n
        .rpc(
            "tenzro_removePasskey",
            json!({
                "account_address": victim,
                "credential_id_hex": format!("0x{victim_cred}"),
            }),
        )
        .await;
    assert!(
        is_refusal(&attack),
        "an unauthenticated caller removed another account's credential: {attack}"
    );

    let listed = n
        .rpc("tenzro_listPasskeys", json!({ "account_address": victim }))
        .await;
    assert_eq!(
        listed["result"]["count"], 1,
        "the owner was locked out: {listed}"
    );
    n.shutdown().await;
}

/// The remaining six mutations are the same class — each changes who can spend
/// or how much. Checked together because the fix is one shared gate, and a
/// handler that skipped it would be the one that gets found.
#[tokio::test]
async fn every_custody_mutation_refuses_an_unauthenticated_caller() {
    let n = TestNode::boot().await;
    let (victim, victim_cred) = n.enroll("Victim", 0x31, 0x77).await;

    let attempts: Vec<(&str, Value)> = vec![
        (
            "tenzro_setPasskeyPolicy",
            json!({ "account_address": victim, "policy": "single_credential" }),
        ),
        (
            "tenzro_grantSessionKey",
            json!({
                "account_address": victim,
                "session_pubkey_hex": hex_of(0x55, 32),
                "allowed_selectors_hex": [],
                "valid_until": 9_999_999_999u64,
            }),
        ),
        (
            "tenzro_revokeSessionKey",
            json!({ "account_address": victim, "session_pubkey_hex": hex_of(0x55, 32) }),
        ),
        (
            "tenzro_setSpendingLimit",
            json!({ "account_address": victim, "max_per_tx": "1", "max_daily": "1" }),
        ),
        (
            "tenzro_addHardwareSigner",
            json!({
                "account_address": victim,
                "vendor": "ledger",
                "pubkey_hex": hex_of(0x66, 32),
            }),
        ),
        (
            "tenzro_addGuardian",
            json!({
                "account_address": victim,
                "guardian_ed25519_pubkey_hex": hex_of(0x44, 32),
                "guardian_ml_dsa_pubkey_hex": hex_of(0x45, 1952),
            }),
        ),
    ];

    for (method, params) in attempts {
        let resp = n.rpc(method, params).await;
        assert!(
            is_refusal(&resp),
            "{method} accepted an unauthenticated custody change: {resp}"
        );
        // A parameter-shape complaint is not a refusal to authorize. The gate
        // must be what rejected it, or this test proves nothing.
        let msg = error_message(&resp);
        assert!(
            msg.contains("proof you already control it") || msg.contains("Invalid params"),
            "{method} was refused for an unexpected reason: {msg}"
        );
    }

    // Nothing moved.
    let listed = n
        .rpc("tenzro_listPasskeys", json!({ "account_address": victim }))
        .await;
    assert_eq!(listed["result"]["count"], 1);
    assert!(
        listed["result"]["credential_ids"][0]
            .as_str()
            .unwrap_or_default()
            .contains(&victim_cred)
    );
    n.shutdown().await;
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
    let (account, _) = n.enroll("Owner", 0x41, 0x91).await;

    let issued = n
        .rpc(
            "tenzro_createCustodyChallenge",
            json!({
                "account_address": account,
                "operation": "add_passkey",
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
    assert_eq!(result["operation"], "add_passkey");
    assert!(result["expires_in_secs"].as_u64().unwrap_or(0) > 0);

    // A challenge for a different target is a different challenge — that
    // binding is what stops one authorization being spent on another change.
    let other = n
        .rpc(
            "tenzro_createCustodyChallenge",
            json!({
                "account_address": account,
                "operation": "add_passkey",
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

/// Presenting a challenge without a credential enrolled on the account is
/// refused — otherwise a caller could sign the challenge with any key they
/// like, which is the original hole wearing a ceremony.
#[tokio::test]
async fn a_challenge_signed_by_an_unenrolled_credential_is_refused() {
    let n = TestNode::boot().await;
    let (victim, _) = n.enroll("Victim", 0x51, 0xa1).await;

    let issued = n
        .rpc(
            "tenzro_createCustodyChallenge",
            json!({
                "account_address": victim,
                "operation": "add_passkey",
                "target_hex": hex_of(0xee, 16),
            }),
        )
        .await;
    let challenge_id = issued["result"]["challenge_id"]
        .as_str()
        .expect("challenge id")
        .to_string();

    // The attacker holds the challenge but no enrolled credential.
    let attack = n
        .rpc(
            "tenzro_addPasskey",
            json!({
                "account_address": victim,
                "new_passkey_public_key_hex": format!("04{}{}", hex_of(0x99, 32), hex_of(0xaa, 32)),
                "new_credential_id_hex": hex_of(0xee, 16),
                "authorization": {
                    "challenge_id": challenge_id,
                    "credential_id_hex": hex_of(0xff, 16),
                    // A syntactically valid but cryptographically meaningless
                    // assertion: the point is that it never gets that far,
                    // because the credential is not enrolled on this account.
                    "assertion": {
                        "authenticator_data": [0],
                        "client_data_json": [0],
                        "signature": [0],
                    },
                },
            }),
        )
        .await;
    assert!(
        is_refusal(&attack),
        "an unenrolled credential authorized a custody change: {attack}"
    );
    assert!(
        error_message(&attack).contains("not enrolled"),
        "expected the enrollment check to reject it: {}",
        error_message(&attack)
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
    let (account, credential) = n.enroll("Fresh device", 0x61, 0xb1).await;
    assert!(account.starts_with("0x"));

    let listed = n
        .rpc("tenzro_listPasskeys", json!({ "account_address": account }))
        .await;
    assert_eq!(listed["result"]["count"], 1);
    assert!(
        listed["result"]["credential_ids"][0]
            .as_str()
            .unwrap_or_default()
            .contains(&credential)
    );
    n.shutdown().await;
}

/// Reads stay open: the account address is public, and so is the set of
/// credential *ids* enrolled on it. Neither lets anyone spend.
#[tokio::test]
async fn reading_an_accounts_credentials_needs_no_authorization() {
    let n = TestNode::boot().await;
    let (account, _) = n.enroll("Owner", 0x71, 0xc1).await;
    let listed = n
        .rpc("tenzro_listPasskeys", json!({ "account_address": account }))
        .await;
    assert!(listed.get("result").is_some(), "{listed}");
    n.shutdown().await;
}

// ---------------------------------------------------------------------------
// The legitimate path still works
// ---------------------------------------------------------------------------

/// A gate that refused everything would pass every test above and ship a wallet
/// nobody can add a device to. This proves the authorized path reaches the
/// verifier — the challenge is issued, matched to its account and operation,
/// and consumed.
///
/// It stops at the cryptographic check, because producing a genuine P-256
/// assertion needs an authenticator. What it does prove is that the *plumbing*
/// is right: the same request that failed with "requires proof you already
/// control it" now fails with a signature error instead, which is the gate
/// admitting the shape and rejecting only the crypto.
#[tokio::test]
async fn an_authorized_add_reaches_the_signature_check() {
    let n = TestNode::boot().await;
    let (account, credential) = n.enroll("Owner laptop", 0x81, 0xd1).await;

    // The owner asks for a challenge, exactly as the browser page does.
    let issued = n
        .rpc(
            "tenzro_createCustodyChallenge",
            // The challenge must name the key it authorizes: `addPasskey`
            // binds the target to the new passkey's public key, normalised
            // to raw P-256 X||Y (the SEC1 `04` prefix dropped). A challenge
            // with no target authorizes nothing in particular, which is the
            // whole point of the binding.
            json!({
                "account_address": account,
                "operation": "add_passkey",
                "target_hex": format!("{}{}", hex_of(0x31, 32), hex_of(0x32, 32)),
            }),
        )
        .await;
    let challenge_id = issued["result"]["challenge_id"]
        .as_str()
        .unwrap_or_else(|| panic!("no challenge: {issued}"))
        .to_string();

    let resp = n
        .rpc(
            "tenzro_addPasskey",
            json!({
                "account_address": account,
                "new_passkey_public_key_hex": format!("04{}{}", hex_of(0x31, 32), hex_of(0x32, 32)),
                "new_credential_id_hex": hex_of(0x41, 16),
                "authorization": {
                    "challenge_id": challenge_id,
                    // The owner's real, enrolled credential.
                    "credential_id_hex": credential,
                    "assertion": {
                        "authenticator_data": [0],
                        "client_data_json": [0],
                        "signature": [0],
                    },
                },
            }),
        )
        .await;

    let msg = error_message(&resp);
    assert!(
        !msg.contains("requires proof you already control it"),
        "an authorized request was still treated as unauthenticated: {msg}"
    );
    assert!(
        !msg.contains("not enrolled"),
        "the owner's own enrolled credential was rejected as unenrolled: {msg}"
    );
    assert!(
        !msg.contains("custody challenge is unknown"),
        "the freshly-issued challenge did not match its own account/operation/target — the two \
         issue sites disagree: {msg}"
    );
    assert!(
        msg.contains("custody authorization failed"),
        "expected to reach and fail the signature check, got: {msg}"
    );
    n.shutdown().await;
}

/// A challenge is single-use. Presenting it twice must fail the second time,
/// or a captured assertion is a standing authorization.
#[tokio::test]
async fn a_custody_challenge_cannot_be_spent_twice() {
    let n = TestNode::boot().await;
    let (account, credential) = n.enroll("Owner", 0x91, 0xe1).await;

    let issued = n
        .rpc(
            "tenzro_createCustodyChallenge",
            // The challenge must name the key it authorizes: `addPasskey`
            // binds the target to the new passkey's public key, normalised
            // to raw P-256 X||Y (the SEC1 `04` prefix dropped). A challenge
            // with no target authorizes nothing in particular, which is the
            // whole point of the binding.
            json!({
                "account_address": account,
                "operation": "add_passkey",
                "target_hex": format!("{}{}", hex_of(0x31, 32), hex_of(0x32, 32)),
            }),
        )
        .await;
    let challenge_id = issued["result"]["challenge_id"]
        .as_str()
        .expect("challenge")
        .to_string();

    let attempt = |cred_id: String, chal: String| {
        json!({
            "account_address": account,
            "new_passkey_public_key_hex": format!("04{}{}", hex_of(0x31, 32), hex_of(0x32, 32)),
            "new_credential_id_hex": hex_of(0x42, 16),
            "authorization": {
                "challenge_id": chal,
                "credential_id_hex": cred_id,
                "assertion": {
                    "authenticator_data": [0],
                    "client_data_json": [0],
                    "signature": [0],
                },
            },
        })
    };

    let first = n
        .rpc(
            "tenzro_addPasskey",
            attempt(credential.clone(), challenge_id.clone()),
        )
        .await;
    assert!(
        error_message(&first).contains("custody authorization failed"),
        "expected the first attempt to reach the signature check: {first}"
    );

    // Consumed on the first presentation, even though it failed after — a
    // challenge someone has already shown is a challenge they have observed.
    let second = n
        .rpc("tenzro_addPasskey", attempt(credential, challenge_id))
        .await;
    assert!(
        error_message(&second).contains("unknown, expired, or already used"),
        "a custody challenge was accepted twice: {second}"
    );
    n.shutdown().await;
}

/// A challenge issued for one operation must not authorize another. Without
/// this, an assertion collected to add a phone would remove the owner's laptop.
#[tokio::test]
async fn a_challenge_for_one_operation_does_not_authorize_another() {
    let n = TestNode::boot().await;
    let (account, credential) = n.enroll("Owner", 0xa1, 0xf1).await;

    let issued = n
        .rpc(
            "tenzro_createCustodyChallenge",
            json!({ "account_address": account, "operation": "add_passkey" }),
        )
        .await;
    let challenge_id = issued["result"]["challenge_id"]
        .as_str()
        .expect("challenge")
        .to_string();

    // Spend the add-challenge on a removal.
    let resp = n
        .rpc(
            "tenzro_removePasskey",
            json!({
                "account_address": account,
                "credential_id_hex": credential.clone(),
                "authorization": {
                    "challenge_id": challenge_id,
                    "credential_id_hex": credential,
                    "assertion": {
                        "authenticator_data": [0],
                        "client_data_json": [0],
                        "signature": [0],
                    },
                },
            }),
        )
        .await;
    let msg = error_message(&resp);
    assert!(
        msg.contains("authorizes") || msg.contains("different target"),
        "an add-passkey challenge authorized a removal: {msg}"
    );
    n.shutdown().await;
}

/// A challenge issued for one account must not authorize a change to another.
#[tokio::test]
async fn a_challenge_for_one_account_does_not_authorize_another() {
    let n = TestNode::boot().await;
    let (alice, alice_cred) = n.enroll("Alice", 0xb1, 0x11).await;
    let (bob, _) = n.enroll("Bob", 0xc1, 0x22).await;

    // Alice legitimately gets a challenge for her own account…
    let issued = n
        .rpc(
            "tenzro_createCustodyChallenge",
            json!({ "account_address": alice, "operation": "add_passkey" }),
        )
        .await;
    let challenge_id = issued["result"]["challenge_id"]
        .as_str()
        .expect("challenge")
        .to_string();

    // …and tries to spend it on Bob's.
    let resp = n
        .rpc(
            "tenzro_addPasskey",
            json!({
                "account_address": bob,
                "new_passkey_public_key_hex": format!("04{}{}", hex_of(0x33, 32), hex_of(0x34, 32)),
                "new_credential_id_hex": hex_of(0x43, 16),
                "authorization": {
                    "challenge_id": challenge_id,
                    "credential_id_hex": alice_cred,
                    "assertion": {
                        "authenticator_data": [0],
                        "client_data_json": [0],
                        "signature": [0],
                    },
                },
            }),
        )
        .await;
    assert!(
        error_message(&resp).contains("not enrolled")
            || error_message(&resp).contains("different account"),
        "a challenge for one account authorized a change to another: {}",
        error_message(&resp)
    );
    n.shutdown().await;
}
