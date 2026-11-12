//! HTTP-402 settlement on a live node, end to end.
//!
//! A real `TenzroNode` runs as a solo validator (single-node validator set,
//! threshold 1), so its own consensus loop proposes and finalizes blocks. Each
//! test drives the path a paying agent takes: mint a challenge through the
//! gateway, sign the canonical payment authorization with the payer's own key,
//! settle through the gateway, and read the balances the VM committed.
//!
//! What is asserted:
//!
//! - a signed payment moves the payer's TNZO to the payee and the network
//!   share to the treasury, and the receipt exists only once the settlement
//!   transaction executed (no polling after `verify_and_settle` returns);
//! - a credential signed by one key cannot debit another account, through
//!   the gateway or by submitting a `PayerSettle` directly;
//! - a payer who cannot cover the amount gets an error, not a receipt;
//! - concurrent submissions of one credential settle once;
//! - a paid tool called through the MCP compact listing settles once, and
//!   the same call again charges nothing;
//! - an escrow funded by the payer backs a session paid with vouchers, and
//!   the claimed voucher pays the payee on-chain;
//! - a hash-locked escrow pays a sealed delivery's seller only against the
//!   content key, which a wrong key cannot stand in for.

#[path = "passkey_holder/mod.rs"]
mod passkey_holder;

use std::sync::Arc;
use tokio::sync::broadcast;

use tenzro_consensus::ConsensusConfig;
use tenzro_crypto::composite::testing::TestHybridSigner;
use tenzro_crypto::composite::{HybridSigner, SignatureContext};
use tenzro_node::{NodeConfig, RpcServer, TenzroNode};
use tenzro_payments::gateway::PaymentExpectation;
use tenzro_payments::payer_auth::sign_credential;
use tenzro_payments::traits::PaymentGateway;
use tenzro_types::RoleSet;
use tenzro_types::payment_authorization::{
    EscrowClaim, EscrowVoucher, PaymentAuthorization, escrow_voucher_preimage,
    payment_authorization_preimage,
};
use tenzro_types::primitives::{Address, ChainId, Nonce};
use tenzro_types::transaction::{SignedTransaction, Transaction, TransactionType};

const CHAIN_ID: u64 = 1337;
/// Five TNZO (18 decimals).
const AMOUNT: u128 = 5_000_000_000_000_000_000;
/// One TNZO, for gas.
const ONE_TNZO: u128 = 1_000_000_000_000_000_000;
/// Open-lane fee floor the fixtures sign at: four times the genesis base fee.
const GAS_PRICE: u64 = 40_000_000_000;

fn test_config() -> (NodeConfig, tempfile::TempDir) {
    let tmp = tempfile::tempdir().expect("create temp dir");
    let config = NodeConfig {
        data_dir: tmp.path().to_path_buf(),
        roles: RoleSet::validator_only(),
        consensus: Some(ConsensusConfig::default()),
        // Loopback, on a port the operating system picks when the node
        // binds, so any number of nodes run in one process.
        iroh: tenzro_iroh::TenzroIrohConfig {
            bind_addr: (std::net::Ipv4Addr::LOCALHOST, 0).into(),
            port_mapping: false,
            ..Default::default()
        },
        genesis: Some(tenzro_node::config::GenesisConfig {
            protocol: None,
            consensus: Default::default(),
            validator_registry: Default::default(),
            version: tenzro_node::config::GENESIS_SCHEMA_VERSION,
            chain_id: CHAIN_ID,
            timestamp: 0,
            // The only validator is this machine's hardware consensus key.
            validators: vec![
                tenzro_node::config::GenesisValidator::from_local_hardware(tmp.path(), 1_000_000)
                    .expect("a hardware consensus key"),
            ],
            accounts: Vec::new(),
            // Standalone single-node test: it is the only validator, so it must
            // opt into solo self-quorum (an empty validator set is otherwise rejected).
            weak_subjectivity: None,
            time: tenzro_consensus::TimeRules::default(),
            network_params: Default::default(),
            economy: Default::default(),
            role_stakes: Vec::new(),
        }),
        ..Default::default()
    };
    (config, tmp)
}

struct Harness {
    _shutdown: broadcast::Sender<()>,
    _rpc: tokio::task::JoinHandle<tenzro_node::Result<()>>,
    _tmp: tempfile::TempDir,
    node: Arc<TenzroNode>,
}

async fn start_node() -> Harness {
    let (config, tmp) = test_config();
    start_with(config, tmp).await
}

/// A node whose HTTP-402 payee is `payee`.
async fn start_node_paying(payee: &Address) -> Harness {
    let (mut config, tmp) = test_config();
    config.payments.recipient = hex::encode(payee.as_bytes());
    start_with(config, tmp).await
}

async fn start_with(config: NodeConfig, tmp: tempfile::TempDir) -> Harness {
    let mut node = TenzroNode::new(config).await.expect("node creation");
    node.start().await.expect("node start");
    let node = Arc::new(node);
    let (shutdown, shutdown_rx) = broadcast::channel::<()>(1);
    let (addr_tx, addr_rx) = tokio::sync::oneshot::channel();
    let rpc = RpcServer::new(node.clone(), "127.0.0.1:0".to_string());
    let handle =
        tokio::spawn(async move { rpc.start_with_shutdown_and_addr(shutdown_rx, addr_tx).await });
    let _addr = addr_rx.await.expect("receive bound address");
    // The ledger rail pays gas from the node's own ledger account.
    fund(&node, &ledger_account(&node), ONE_TNZO);
    Harness {
        _shutdown: shutdown,
        _rpc: handle,
        _tmp: tmp,
        node,
    }
}

fn balance(node: &TenzroNode, a: &Address) -> u128 {
    use tenzro_vm::traits::VmState as _;
    let state = tenzro_vm::StateAdapter::with_storage(node.storage().expect("storage").clone());
    state.get_balance(a.as_bytes())
}

/// The node's own ledger account, the one its validator keys derive. The
/// settlement transactions it submits pay gas from here.
fn ledger_account(node: &TenzroNode) -> Address {
    Address::new(
        node.identity_signer()
            .expect("validator signer")
            .public_key()
            .account_slot(),
    )
}

/// Assert the treasury gained `share`, give or take the gas of the
/// transactions the node's own account submitted in between: the treasury
/// keeps part of what gas pays and reimburses a relayer's gas, so gas moves
/// either way between the two.
fn assert_treasury_gained(
    node: &TenzroNode,
    treasury: &Address,
    treasury_before: u128,
    node_before: u128,
    share: u128,
) {
    let gained = balance(node, treasury) as i128 - treasury_before as i128;
    let gas = node_before.abs_diff(balance(node, &ledger_account(node)));
    assert!(
        gained.abs_diff(share as i128) <= gas,
        "treasury gained {gained}; expected the share {share} give or take {gas} of gas"
    );
}

/// The settlement fee the chain charges on a payment of `amount` TNZO, at
/// the genesis rate.
/// The governed settlement fee on `amount` at the node's committed state.
fn governed_settlement_fee(node: &TenzroNode, amount: u128) -> u128 {
    let state = tenzro_vm::StateAdapter::with_storage(node.storage().expect("storage").clone());
    tenzro_vm::native::economy::settlement_fee(&state, amount)
}

fn settlement_fee(amount: u128) -> u128 {
    amount * tenzro_types::fees::DEFAULT_SETTLEMENT_FEE_BPS as u128 / 10_000
}

/// The part of the settlement fee on `amount` that goes to the treasury
/// rather than being burned.
fn treasury_share_of_fee(amount: u128) -> u128 {
    let fee = settlement_fee(amount);
    fee - fee * tenzro_vm::native::economy::DEFAULT_SETTLEMENT_FEE_BURN_BPS as u128 / 10_000
}

fn fund(node: &TenzroNode, a: &Address, amount: u128) {
    use tenzro_vm::traits::VmState as _;
    let mut state = tenzro_vm::StateAdapter::with_storage(node.storage().expect("storage").clone());
    let before = state.get_balance(a.as_bytes());
    state.set_balance(a.as_bytes(), before + amount);
    state.commit().expect("commit funded balance");
}

/// A payer holding its own hardware-style P-256 key.
struct Payer {
    signer: TestHybridSigner,
}

impl Payer {
    fn new() -> Self {
        Self {
            signer: TestHybridSigner::random(),
        }
    }

    fn public_key(&self) -> Vec<u8> {
        self.signer.public_key().p256.clone()
    }

    /// The account this payer's key controls.
    fn address(&self) -> Address {
        self.signer.address()
    }

    /// Sign and submit a transaction from this payer's own account.
    fn submit(
        &self,
        node: &TenzroNode,
        nonce: u64,
        to: Address,
        tx_type: TransactionType,
    ) -> String {
        let tx = Transaction::new(
            ChainId::from(CHAIN_ID),
            self.address(),
            to,
            Nonce::from(nonce),
            tx_type,
            2_000_000,
            GAS_PRICE,
        );
        let hash = tx.hash();
        let sig = self
            .signer
            .sign(SignatureContext::Transaction, hash.as_bytes())
            .expect("sign");
        let signed = SignedTransaction::new(tx, self.public_key(), sig);
        node.consensus()
            .expect("consensus")
            .submit_transaction(signed)
            .expect("admitted");
        hash.to_string()
    }
}

/// Wait for a finalized receipt and return whether the transaction succeeded.
async fn executed(node: &TenzroNode, tx_hash: &str) -> bool {
    use tenzro_storage::KvStore as _;
    let storage = node.storage().expect("storage").clone();
    let key = format!("receipt:{tx_hash}");
    for _ in 0..600 {
        if let Ok(Some(bytes)) = storage.get(tenzro_storage::CF_TRANSACTIONS, key.as_bytes()) {
            let v: serde_json::Value = serde_json::from_slice(&bytes).expect("receipt json");
            return v["success"].as_bool().unwrap_or(false);
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    panic!("transaction {tx_hash} did not execute within 60s");
}

fn payee() -> Address {
    let mut b = [0u8; 32];
    b[..20].copy_from_slice(&[0x02; 20]);
    Address::new(b)
}

async fn x402_challenge(node: &TenzroNode, amount: u128) -> tenzro_payments::PaymentChallenge {
    node.payment_gateway()
        .expect("gateway")
        .create_challenge(
            "x402",
            "/paid/resource",
            amount,
            "TNZO",
            &hex::encode(&payee().as_bytes()[..20]),
        )
        .await
        .expect("challenge")
}

#[tokio::test]
#[ignore = "needs this machine's hardware consensus key (TPM 2.0 or Secure Enclave)"]
async fn a_signed_payment_settles_on_chain_with_the_network_share() {
    let h = start_node().await;
    let payer = Payer::new();
    fund(&h.node, &payer.address(), AMOUNT * 2);
    let treasury = tenzro_types::network_treasury_address();
    let treasury_before = balance(&h.node, &treasury);
    let payee_before = balance(&h.node, &payee());
    let node_before = balance(&h.node, &ledger_account(&h.node));

    let ch = x402_challenge(&h.node, AMOUNT).await;
    let cred = sign_credential(&ch, "x402", "", &payer.signer, AMOUNT, AMOUNT).expect("cred");
    let receipt = h
        .node
        .payment_gateway()
        .unwrap()
        .verify_and_settle(&cred, PaymentExpectation::Challenge)
        .await
        .expect("settled");

    // The receipt exists only after the transaction executed: balances have
    // already moved, with no waiting here.
    // The treasury gains the settlement fee's non-burned share plus at most
    // the gas.
    let fee = settlement_fee(AMOUNT);
    let treasury_share = treasury_share_of_fee(AMOUNT);
    assert_eq!(balance(&h.node, &payer.address()), AMOUNT);
    assert_eq!(balance(&h.node, &payee()), payee_before + AMOUNT - fee);
    assert_treasury_gained(
        &h.node,
        &treasury,
        treasury_before,
        node_before,
        treasury_share,
    );
    let tx = receipt.settlement_tx.expect("settlement tx");
    assert!(executed(&h.node, &tx).await, "settlement tx succeeded");
    assert_eq!(receipt.extra["settlement_rail"], "tenzro-ledger");

    // The payment is in the payee's history, read from the event index, and
    // a payer filter that names someone else selects nothing.
    let call = |filter: serde_json::Value| {
        let node = h.node.clone();
        async move {
            tenzro_node::dispatch_embedded(
                &node,
                serde_json::json!({ "jsonrpc": "2.0", "id": 1, "method": "tenzro_listPayments", "params": [filter] }),
                tenzro_node::EmbeddedAuth::default(),
            )
            .await
        }
    };
    // A proof is anchored on the checkpoint covering the payment's block,
    // which the validator certifies after the block executes: until then the
    // node answers that no checkpoint covers it yet.
    let proven = serde_json::json!({ "payee": hex::encode(payee().as_bytes()), "from_height": 0, "proofs": true });
    let mut mine = serde_json::Value::Null;
    for _ in 0..300 {
        let reply = call(proven.clone()).await;
        let uncovered = reply["error"]["message"]
            .as_str()
            .is_some_and(|m| m.starts_with("no checkpoint covering height"));
        if !uncovered {
            assert!(reply["result"].is_object(), "{reply}");
            mine = reply["result"].clone();
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(
        mine.is_object(),
        "a checkpoint covered the payment within 30s"
    );
    let payments = mine["payments"].as_array().expect("payments");
    assert_eq!(payments.len(), 1, "{mine}");
    assert_eq!(payments[0]["record"]["class"], "native");
    let amount = &payments[0]["record"]["amount"];
    let amount = amount
        .as_str()
        .and_then(|a| a.parse::<u128>().ok())
        .or(amount.as_u64().map(u128::from));
    assert_eq!(amount, Some(AMOUNT));
    assert!(
        payments[0]["proof"].is_object(),
        "the entry carries its event proof"
    );
    let other = call(serde_json::json!({ "payer": "00", "from_height": 0 })).await;
    assert!(other["result"].is_object(), "{other}");
    let other = &other["result"];
    assert!(
        other["payments"].as_array().expect("payments").is_empty(),
        "{other}"
    );
}

#[tokio::test]
#[ignore = "needs this machine's hardware consensus key (TPM 2.0 or Secure Enclave)"]
async fn a_credential_signed_by_one_key_cannot_debit_another_account() {
    let h = start_node().await;
    let victim = Payer::new();
    let attacker = Payer::new();
    fund(&h.node, &victim.address(), AMOUNT * 2);
    let ch = x402_challenge(&h.node, AMOUNT).await;
    let mut cred =
        sign_credential(&ch, "x402", "", &attacker.signer, AMOUNT, AMOUNT).expect("cred");
    cred.payer_address = hex::encode(victim.address().as_bytes());
    let gw = h.node.payment_gateway().unwrap();
    assert!(
        gw.verify_and_settle(&cred, PaymentExpectation::Challenge)
            .await
            .is_err()
    );
    assert_eq!(balance(&h.node, &victim.address()), AMOUNT * 2);
}

#[tokio::test]
#[ignore = "needs this machine's hardware consensus key (TPM 2.0 or Secure Enclave)"]
async fn a_directly_submitted_settlement_with_a_forged_authorization_reverts() {
    let h = start_node().await;
    let victim = Payer::new();
    let attacker = Payer::new();
    fund(&h.node, &victim.address(), AMOUNT * 2);
    fund(&h.node, &attacker.address(), ONE_TNZO);

    // The attacker signs an authorization naming the victim as payer.
    let payment_id = "forged-1";
    let binding = tenzro_types::payment_authorization::PaymentBinding {
        request_digest: [1; 32],
        ..Default::default()
    };
    let preimage = payment_authorization_preimage(
        CHAIN_ID,
        payment_id,
        &victim.address(),
        &attacker.address(),
        AMOUNT,
        "TNZO",
        &binding,
    );
    let sig = attacker
        .signer
        .sign(SignatureContext::PaymentAuthorization, &preimage)
        .expect("sign");
    let tx_type = TransactionType::PayerSettle {
        payer: victim.address(),
        payee: attacker.address(),
        amount: AMOUNT,
        payment_id: payment_id.to_string(),
        authorization: PaymentAuthorization {
            resellers: Vec::new(),
            binding,
            public_key: attacker.public_key(),
            signature: sig,
            max_amount: AMOUNT,
            asset: "TNZO".to_string(),
        },
    };
    let tx = attacker.submit(&h.node, 0, attacker.address(), tx_type);
    assert!(
        !executed(&h.node, &tx).await,
        "forged settlement must revert"
    );
    assert_eq!(balance(&h.node, &victim.address()), AMOUNT * 2);
}

#[tokio::test]
#[ignore = "needs this machine's hardware consensus key (TPM 2.0 or Secure Enclave)"]
async fn a_payer_who_cannot_cover_the_amount_gets_no_receipt() {
    let h = start_node().await;
    let payer = Payer::new();
    fund(&h.node, &payer.address(), AMOUNT / 2);
    let ch = x402_challenge(&h.node, AMOUNT).await;
    let cred = sign_credential(&ch, "x402", "", &payer.signer, AMOUNT, AMOUNT).expect("cred");
    let gw = h.node.payment_gateway().unwrap();
    let err = gw
        .verify_and_settle(&cred, PaymentExpectation::Challenge)
        .await
        .expect_err("an unfunded payment must not produce a receipt");
    assert!(!err.to_string().is_empty());
    assert_eq!(balance(&h.node, &payer.address()), AMOUNT / 2);
}

#[tokio::test]
#[ignore = "needs this machine's hardware consensus key (TPM 2.0 or Secure Enclave)"]
async fn concurrent_submissions_of_one_credential_settle_once() {
    let h = start_node().await;
    let payer = Payer::new();
    fund(&h.node, &payer.address(), AMOUNT * 5);
    let ch = x402_challenge(&h.node, AMOUNT).await;
    let cred = sign_credential(&ch, "x402", "", &payer.signer, AMOUNT, AMOUNT).expect("cred");
    let mut tasks = Vec::new();
    for _ in 0..6 {
        let node = h.node.clone();
        let cred = cred.clone();
        tasks.push(tokio::spawn(async move {
            node.payment_gateway()
                .unwrap()
                .verify_and_settle(&cred, PaymentExpectation::Challenge)
                .await
                .map(|r| r.settlement_tx)
        }));
    }
    let mut refs = Vec::new();
    for t in tasks {
        if let Ok(Some(tx)) = t.await.unwrap() {
            refs.push(tx);
        }
    }
    refs.dedup();
    assert!(
        refs.len() <= 1,
        "at most one settlement transaction: {refs:?}"
    );
    // Exactly one debit.
    assert_eq!(balance(&h.node, &payer.address()), AMOUNT * 4);
}

#[tokio::test]
#[ignore = "needs this machine's hardware consensus key (TPM 2.0 or Secure Enclave)"]
async fn a_session_voucher_is_accepted_and_claimed_from_the_payers_escrow() {
    let h = start_node().await;
    let payer = Payer::new();
    fund(&h.node, &payer.address(), AMOUNT * 2);
    let payee_before = balance(&h.node, &payee());

    // The payer funds an escrow naming the payee: the session cap.
    let expires_at = (chrono::Utc::now().timestamp_millis() + 3_600_000) as u64;
    let create = TransactionType::CreateEscrow {
        usd_e6: 0,
        payee: payee(),
        amount: AMOUNT,
        asset_id: tenzro_types::asset::AssetId::tnzo(),
        expires_at,
        release_conditions: tenzro_types::settlement::ReleaseConditions::Timeout,
        reference: None,
    };
    let tx = payer.submit(&h.node, 0, payee(), create);
    assert!(executed(&h.node, &tx).await, "escrow funded");
    let escrow_id = escrow_id_for(&payer.address(), 0);

    // A session challenge paid by a cumulative voucher.
    let gw = h.node.payment_gateway().unwrap();
    let mut ch = gw
        .create_challenge(
            "mpp",
            "/paid/stream",
            AMOUNT / 5,
            "TNZO",
            &hex::encode(&payee().as_bytes()[..20]),
        )
        .await
        .expect("challenge");
    ch.extra
        .insert("intent".into(), serde_json::json!("session"));
    gw.challenge_store().store(&ch).expect("restamp");
    let cumulative = AMOUNT / 5;
    let voucher_sig = payer
        .signer
        .sign(
            SignatureContext::EscrowVoucher,
            &escrow_voucher_preimage(CHAIN_ID, &escrow_id, cumulative, &[0u8; 32]),
        )
        .expect("sign");
    let cred = tenzro_payments::PaymentCredential {
        credential_id: "voucher-1".into(),
        challenge_id: ch.challenge_id.clone(),
        protocol: "mpp".into(),
        payer_did: String::new(),
        payer_address: String::new(),
        amount: cumulative,
        asset: "TNZO".into(),
        signature: Some(voucher_sig.clone()),
        extra: std::collections::HashMap::from([
            (
                "escrow_id".to_string(),
                serde_json::json!(hex::encode(escrow_id)),
            ),
            (
                "cumulative_amount".to_string(),
                serde_json::json!(cumulative.to_string()),
            ),
            (
                "public_key".to_string(),
                serde_json::json!(hex::encode(payer.public_key())),
            ),
        ]),
    };
    let receipt = gw
        .verify_and_settle(&cred, PaymentExpectation::Challenge)
        .await
        .expect("voucher accepted");
    assert_eq!(receipt.extra["settlement_rail"], "escrow");

    // Close the session and claim the voucher on-chain.
    let sessions = h.node.payment_sessions().expect("sessions").clone();
    let due = sessions
        .close_session(&hex::encode(escrow_id))
        .expect("close")
        .expect("voucher due");
    assert_eq!(
        due.voucher,
        EscrowVoucher {
            binding: [0u8; 32],
            agent: None,
            escrow_id,
            cumulative_amount: cumulative,
            public_key: payer.public_key(),
            signature: voucher_sig.clone(),
            attribution: None,
        }
    );
    // The claim is what the session charged, never more than the voucher.
    assert!(due.amount > 0 && due.amount <= cumulative);
    let claimed = due.amount;
    let claimer = Payer::new();
    fund(&h.node, &claimer.address(), ONE_TNZO);
    let claim = claimer.submit(
        &h.node,
        0,
        payee(),
        TransactionType::ClaimEscrow { claims: vec![due] },
    );
    assert!(executed(&h.node, &claim).await, "claim succeeded");
    // The claim settles like any payment: the payee is paid it less the
    // settlement fee.
    let paid = claimed - settlement_fee(claimed);
    assert_eq!(balance(&h.node, &payee()), payee_before + paid);

    // A second claim of the same voucher does not advance and reverts.
    let replay = claimer.submit(
        &h.node,
        1,
        payee(),
        TransactionType::ClaimEscrow {
            claims: vec![EscrowClaim {
                voucher: EscrowVoucher {
                    binding: [0u8; 32],
                    escrow_id,
                    cumulative_amount: cumulative,
                    public_key: payer.public_key(),
                    signature: voucher_sig.clone(),
                    agent: None,
                    attribution: None,
                },
                amount: claimed,
            }],
        },
    );
    assert!(!executed(&h.node, &replay).await, "replayed claim reverts");
    assert_eq!(balance(&h.node, &payee()), payee_before + paid);
}

#[tokio::test]
#[ignore = "needs this machine's hardware consensus key (TPM 2.0 or Secure Enclave)"]
async fn a_hash_locked_delivery_pays_the_seller_exactly_when_the_key_is_published() {
    let h = start_node().await;
    let buyer = Payer::new();
    let seller = Payer::new();
    fund(&h.node, &buyer.address(), AMOUNT * 2);
    fund(&h.node, &seller.address(), ONE_TNZO);
    let seller_before = balance(&h.node, &seller.address());

    // The seller seals its response; the buyer funds an escrow locked by the
    // hash of the content key.
    let (delivery, key) = tenzro_payments::dvp::SealedDelivery::seal(
        "/paid/report",
        b"the paid response",
        AMOUNT,
        "TNZO",
        &hex::encode(&seller.address().as_bytes()[..20]),
        1_000,
        &tenzro_crypto::batch::ImmediateRecordSigner::new(std::sync::Arc::new(
            tenzro_crypto::composite::testing::TestHybridSigner::random(),
        )),
    )
    .expect("seal");
    delivery.verify().expect("statement verifies");
    let expires_at = (chrono::Utc::now().timestamp_millis() + 3_600_000) as u64;
    let lock = TransactionType::CreateEscrow {
        usd_e6: 0,
        payee: seller.address(),
        amount: AMOUNT,
        asset_id: tenzro_types::asset::AssetId::tnzo(),
        expires_at,
        release_conditions: tenzro_types::settlement::ReleaseConditions::HashLock {
            hash: delivery.lock().expect("lock"),
        },
        reference: None,
    };
    let tx = buyer.submit(&h.node, 0, seller.address(), lock);
    assert!(executed(&h.node, &tx).await, "escrow funded");
    let escrow_id = escrow_id_for(&buyer.address(), 0);

    // A wrong key does not open the lock.
    let probe = Payer::new();
    fund(&h.node, &probe.address(), ONE_TNZO);
    let wrong = probe.submit(
        &h.node,
        0,
        seller.address(),
        TransactionType::ClaimEscrowPreimage {
            escrow_id,
            preimage: vec![7u8; 32],
        },
    );
    assert!(!executed(&h.node, &wrong).await, "a wrong key reverts");
    assert_eq!(balance(&h.node, &seller.address()), seller_before);

    // The key opens it, pays the seller, and is on the ledger for the buyer.
    let claim = seller.submit(
        &h.node,
        0,
        seller.address(),
        TransactionType::ClaimEscrowPreimage {
            escrow_id,
            preimage: key.to_vec(),
        },
    );
    assert!(executed(&h.node, &claim).await, "the key opens the lock");
    assert!(balance(&h.node, &seller.address()) > seller_before + AMOUNT - ONE_TNZO);
    assert_eq!(
        delivery.open(&key).expect("decrypt"),
        b"the paid response".to_vec()
    );

    // The escrow is spent: the buyer cannot refund it.
    let refund = buyer.submit(
        &h.node,
        1,
        seller.address(),
        TransactionType::RefundEscrow { escrow_id },
    );
    assert!(
        !executed(&h.node, &refund).await,
        "a paid escrow cannot be refunded"
    );
}

/// The VM's escrow id: `SHA-256("tenzro/escrow/id" ‖ payer ‖ nonce_le)`.
fn escrow_id_for(payer: &Address, nonce: u64) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"tenzro/escrow/id");
    h.update(payer.as_bytes());
    h.update(nonce.to_le_bytes());
    h.finalize().into()
}

#[tokio::test]
#[ignore = "needs this machine's hardware consensus key (TPM 2.0 or Secure Enclave)"]
async fn a_sealed_delivery_is_redeemed_only_against_both_escrows_and_pays_the_network_its_share() {
    let seller = Address::new([0x51; 32]);
    let h = start_node_paying(&seller).await;
    let treasury = tenzro_types::network_treasury_address();
    let buyer = Payer::new();
    fund(&h.node, &buyer.address(), AMOUNT * 2);

    // The node seals a priced response.
    let signer = h.node.records().expect("node signer").clone();
    let delivery = h
        .node
        .sealed_offers()
        .offer(
            "/sites/s/report",
            b"the sealed page",
            AMOUNT,
            "TNZO",
            seller,
            1_000,
            signer.as_ref(),
        )
        .expect("offer");
    delivery.verify().expect("statement verifies");
    assert_eq!(delivery.seller_amount() + delivery.network_share, AMOUNT);

    let lock = delivery.lock().expect("lock");
    let expires_at = (chrono::Utc::now().timestamp_millis() + 3_600_000) as u64;
    let fund_leg = |nonce: u64, payee: Address, amount: u128| {
        buyer.submit(
            &h.node,
            nonce,
            payee,
            TransactionType::CreateEscrow {
                usd_e6: 0,
                payee,
                amount,
                asset_id: tenzro_types::asset::AssetId::tnzo(),
                expires_at,
                release_conditions: tenzro_types::settlement::ReleaseConditions::HashLock {
                    hash: lock,
                },
                reference: None,
            },
        )
    };
    let tx = fund_leg(0, seller, delivery.seller_amount());
    assert!(executed(&h.node, &tx).await, "seller escrow funded");
    let seller_escrow = escrow_id_for(&buyer.address(), 0);

    // Without the network's escrow the node does not reveal the key.
    let r = tenzro_node::sealed_delivery::redeem(&h.node, seller_escrow, None).await;
    assert!(r.is_err(), "redeemed without the network's share");
    assert_eq!(balance(&h.node, &seller), 0);

    let tx = fund_leg(1, treasury, delivery.network_share);
    assert!(executed(&h.node, &tx).await, "network escrow funded");
    let network_escrow = escrow_id_for(&buyer.address(), 1);
    let treasury_before = balance(&h.node, &treasury);
    let node_before = balance(&h.node, &ledger_account(&h.node));

    let redemption =
        tenzro_node::sealed_delivery::redeem(&h.node, seller_escrow, Some(network_escrow))
            .await
            .expect("redeemed");
    assert!(redemption.network_claim_tx.is_some());
    // One payment pays one network fee: the network's share was paid in its
    // own escrow, so the seller is paid the price less only that share, with
    // no settlement fee. The treasury gains at least its share.
    let seller_amount = delivery.seller_amount();
    let share = delivery.network_share;
    assert_eq!(balance(&h.node, &seller), seller_amount);
    assert_treasury_gained(&h.node, &treasury, treasury_before, node_before, share);
    let key = hex::decode(&redemption.key).expect("key hex");
    assert_eq!(
        delivery.open(&key).expect("decrypt"),
        b"the sealed page".to_vec()
    );

    // Redeemed once.
    let again =
        tenzro_node::sealed_delivery::redeem(&h.node, seller_escrow, Some(network_escrow)).await;
    assert!(again.is_err());
}

#[tokio::test]
#[ignore = "needs this machine's hardware consensus key (TPM 2.0 or Secure Enclave)"]
async fn a_payment_resold_on_a_node_pays_the_operator_its_price_and_the_reseller_its_commission() {
    use tenzro_types::leg_statement::{Statement, verify};
    use tenzro_types::payment_authorization::{
        PaymentBinding, ResellerLeg, payment_authorization_preimage_with_resellers,
    };
    let h = start_node().await;
    let payer = Payer::new();
    let operator = Address::new([0x5a; 32]);
    let reseller = Address::new([0x5b; 32]);
    fund(&h.node, &payer.address(), AMOUNT * 2);

    // The operator's price, a 10% commission on top, signed together.
    let amount = tenzro_vm::native::amount_with_leg(AMOUNT, 1_000).unwrap();
    let payment_id = "resold-1";
    let binding = PaymentBinding {
        request_digest: [7; 32],
        ..Default::default()
    };
    let resellers = vec![ResellerLeg {
        reseller,
        commission_bps: 1_000,
    }];
    let preimage = payment_authorization_preimage_with_resellers(
        CHAIN_ID,
        payment_id,
        &payer.address(),
        &operator,
        amount,
        "TNZO",
        &binding,
        &resellers,
    );
    let sig = payer
        .signer
        .sign(SignatureContext::PaymentAuthorization, &preimage)
        .expect("sign");
    let tx_type = TransactionType::PayerSettle {
        payer: payer.address(),
        payee: operator,
        amount,
        payment_id: payment_id.to_string(),
        authorization: PaymentAuthorization {
            resellers,
            binding,
            public_key: payer.public_key(),
            signature: sig,
            max_amount: amount,
            asset: "TNZO".to_string(),
        },
    };
    let tx = payer.submit(&h.node, 0, operator, tx_type);
    assert!(executed(&h.node, &tx).await, "the resold payment settles");

    let chain = tenzro_vm::StateAdapter::with_storage(h.node.storage().expect("storage").clone());
    let record = tenzro_vm::native::read_payment_by_id(&chain, payment_id).expect("a record");
    let legs = &record.settled.legs;
    assert_eq!(legs.len(), 2, "{legs:?}");
    assert_eq!(
        (legs[0].role.as_str(), legs[0].amount),
        ("operator", AMOUNT)
    );
    assert_eq!(legs[1].role.as_str(), "reseller");
    assert_eq!(legs[1].commission_bps, Some(1_000));
    assert_eq!(legs[0].amount + legs[1].amount, amount);
    // Each party holds exactly its own leg less the fee that leg paid.
    assert_eq!(balance(&h.node, &operator), legs[0].amount - legs[0].fee);
    assert_eq!(balance(&h.node, &reseller), legs[1].amount - legs[1].fee);

    // Each party's statement lists only its own leg and verifies against
    // the record the chain holds.
    let records = vec![record.exact_json()];
    let fetch = |r: &str| {
        let pay_ref: [u8; 32] = hex::decode(r).ok()?.try_into().ok()?;
        tenzro_vm::native::read_payment(&chain, &pay_ref).map(|r| r.exact_json())
    };
    let ops = Statement::for_account(&hex::encode(operator.as_bytes()), &records);
    assert_eq!(ops.lines.len(), 1);
    assert_eq!(ops.lines[0].role, "operator");
    assert!(verify(&ops, fetch).is_empty());
    let res = Statement::for_account(&hex::encode(reseller.as_bytes()), &records);
    assert_eq!(res.lines.len(), 1);
    assert_eq!(
        (res.lines[0].role.as_str(), res.lines[0].commission_bps),
        ("reseller", Some(1_000))
    );
    assert!(verify(&res, fetch).is_empty());
}

/// An SD-JWT the controller's passkey signs, with every claim but `vct`
/// disclosed selectively and no key binding.
fn passkey_sd_jwt(signer: &passkey_holder::PasskeyHolder, claims: serde_json::Value) -> String {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
    let mut digests = Vec::new();
    let mut discs = Vec::new();
    let mut body = serde_json::Map::new();
    for (name, v) in claims.as_object().expect("claims") {
        if name == "vct" {
            body.insert(name.clone(), v.clone());
            continue;
        }
        let d = B64.encode(serde_json::to_vec(&serde_json::json!(["salt", name, v])).unwrap());
        digests.push(serde_json::Value::String(tenzro_payments::ap2::b64_sha256(
            d.as_bytes(),
        )));
        discs.push(d);
    }
    body.insert("_sd".into(), serde_json::Value::Array(digests));
    body.insert("_sd_alg".into(), "sha-256".into());
    let mut h = serde_json::Map::new();
    h.insert("alg".into(), "ES256".into());
    h.insert(
        "jwk".into(),
        tenzro_payments::ap2::jwk_of(&signer.verifying_key()),
    );
    let mut out = tenzro_payments::ap2::sign_jws(&h, &serde_json::Value::Object(body), |m| {
        signer.sign_es256(m)
    });
    for d in discs {
        out.push('~');
        out.push_str(&d);
    }
    out.push('~');
    out
}

/// An agent pays a UCP checkout on a running node under real AP2 mandates.
/// The controller onboards with its passkey; the agent holds consensus
/// Terms naming that controller and pays from an account its DID lists. The
/// node authorizes every checkout with its hardware business key; the
/// controller's passkey signs the checkout mandate over the authorized
/// checkout and the payment mandate over the payment; the facilitator holds
/// the payment to the agent's DID, Terms and mandates, and it settles on
/// chain. A payment mandate signed by any other key is refused and nothing
/// moves.
#[tokio::test]
#[ignore = "needs this machine's hardware consensus key (TPM 2.0 or Secure Enclave)"]
async fn an_agent_pays_a_ucp_checkout_under_real_ap2_mandates() {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
    use tenzro_payments::ap2::{VCT_CHECKOUT, VCT_PAYMENT, b64_sha256};
    use tenzro_payments::ucp;
    use tenzro_payments::x402::X402PaymentRequirement;
    use tenzro_payments::x402::wire::{challenge_from_requirement, payload_for_credential};
    use tenzro_vm::traits::VmState as _;

    const MODEL: &str = "ucp-model";
    const AGENT: &str = "did:tenzro:machine:7b0c2f3e-5d2a-4d55-9a3e-1c2b3d4e5f60";
    const PER_TOKEN: u128 = 1_000_000_000_000_000;
    let h = start_node_paying(&payee()).await;
    h.node
        .served_models
        .insert(MODEL.to_string(), Some(tenzro_types::Visibility::Public));
    h.node.provider_pricing.write().models.insert(
        MODEL.to_string(),
        tenzro_types::price_card::RateCard {
            denom: tenzro_types::price_card::Denom::Wei,
            lines: [(
                "output_tokens".to_string(),
                tenzro_types::price_card::Rate::per(PER_TOKEN, 0),
            )]
            .into_iter()
            .collect(),
            ..Default::default()
        },
    );
    let rpc = |method: &'static str, params: serde_json::Value| {
        let node = h.node.clone();
        async move {
            let reply = tenzro_node::dispatch_embedded(
                &node,
                serde_json::json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params }),
                tenzro_node::EmbeddedAuth::default(),
            )
            .await;
            assert!(reply["error"].is_null(), "{method}: {reply}");
            reply["result"].clone()
        }
    };

    // The controller onboards with its own passkey.
    let controller = passkey_holder::PasskeyHolder::generate();
    let issued = rpc(
        "tenzro_createCustodyChallenge",
        controller.challenge_params(),
    )
    .await;
    let onboarded = rpc(
        "tenzro_onboardHuman",
        controller.onboard_params(
            serde_json::json!({ "display_name": "Controller" }),
            controller.authorize(&issued),
        ),
    )
    .await;
    let controller_did = onboarded["identity"]["did"]
        .as_str()
        .unwrap_or_else(|| panic!("no DID: {onboarded}"))
        .to_string();

    // The agent: an identity listing the key it pays with, and Terms on
    // chain naming the controller.
    let payer = Payer::new();
    fund(&h.node, &payer.address(), AMOUNT * 2);
    let registry = h.node.identity_registry().expect("identity registry");
    registry.upsert_identity_for_test(tenzro_identity::TenzroIdentity {
        did: tenzro_identity::TenzroDid::parse(AGENT).expect("agent DID"),
        public_keys: vec![tenzro_identity::PublicKeyInfo {
            key_id: "key-1".into(),
            key_type: "P-256".into(),
            public_key: payer.public_key(),
            purposes: vec![
                tenzro_identity::KeyPurpose::Authentication,
                tenzro_identity::KeyPurpose::AssertionMethod,
            ],
        }],
        identity_data: tenzro_identity::IdentityData::Machine {
            capabilities: Vec::new(),
            controller_did: Some(controller_did.clone()),
            reputation: 0,
            tenzro_agent_id: None,
            erc8004_agent_id: None,
        },
        status: tenzro_identity::IdentityStatus::Active,
        wallet_address: payer.address(),
        wallet_id: String::new(),
        pq_verifying_key: Vec::new(),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
        metadata: Default::default(),
    });
    {
        use tenzro_types::agent_terms::{AgentTerms, RootKind, TermsScope};
        // Terms spend limits are micro-units of account: AMOUNT at the TNZO
        // rate in force.
        let limit = {
            let chain =
                tenzro_vm::StateAdapter::with_storage(h.node.storage().expect("storage").clone());
            let rate = tenzro_vm::native::economy::read_fee_rate(&chain).rate_nano_usd;
            (AMOUNT * rate / 1_000_000_000_000_000_000_000).to_string()
        };
        let stored = tenzro_vm::native::StoredAgentTerms {
            terms: AgentTerms {
                controller_did: controller_did.clone(),
                agent_name: "ucp-buyer".into(),
                delegation_scope: TermsScope {
                    max_transaction_value: Some(limit.clone()),
                    max_daily_spend: Some(limit),
                    allowed_operations: vec!["payment".into()],
                    ..Default::default()
                },
                capabilities: Vec::new(),
                serving_nodes: Vec::new(),
                min_distinct_operators: 1,
                expires_at_ms: None,
                trifecta_exception: false,
                auto_approve: None,
                credentials: Vec::new(),
            },
            root: RootKind::Passkey,
            version: 1,
            approval_digest: String::new(),
            updated_at_ms: chrono::Utc::now().timestamp_millis(),
            renewed_at_ms: None,
        };
        let mut state =
            tenzro_vm::StateAdapter::with_storage(h.node.storage().expect("storage").clone());
        state.set_storage(
            &tenzro_vm::native::SYSTEM_ADDRESS,
            tenzro_vm::native::agent_terms::terms_key(AGENT).as_bytes(),
            serde_json::to_vec(&stored).expect("terms json"),
        );
        state.set_balance(
            tenzro_token::derive_bond_vault_address(AGENT).as_bytes(),
            AMOUNT,
        );
        state.commit().expect("commit terms");
    }

    // The node's web surface, as `main` serves it.
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .expect("a free port")
        .port();
    let state =
        std::sync::Arc::new(tenzro_node::web::handlers::WebState::new().with_node(h.node.clone()));
    let (web_stop, web_rx) = broadcast::channel::<()>(1);
    let web = tokio::spawn(
        tenzro_node::web::WebServer::new(format!("127.0.0.1:{port}"))
            .with_state_arc(state)
            .start_with_shutdown(web_rx),
    );
    let base = format!("http://127.0.0.1:{port}");
    let client = reqwest::Client::new();
    let send = |method: reqwest::Method,
                path: String,
                key: Option<String>,
                body: Option<serde_json::Value>| {
        let client = client.clone();
        let url = format!("{base}{path}");
        async move {
            for _ in 0..50 {
                let mut req = client
                    .request(method.clone(), &url)
                    .header(
                        "ucp-agent",
                        "profile=\"https://platform.example/.well-known/ucp\"",
                    )
                    .header("request-id", uuid::Uuid::new_v4().to_string());
                if let Some(k) = &key {
                    req = req.header("idempotency-key", k);
                }
                if let Some(b) = &body {
                    req = req.json(b);
                }
                if let Ok(r) = req.send().await {
                    let status = r.status().as_u16();
                    return (
                        status,
                        r.json::<serde_json::Value>().await.unwrap_or_default(),
                    );
                }
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
            panic!("the web surface did not answer at {url}");
        }
    };
    let key = || Some(uuid::Uuid::new_v4().to_string());

    let (status, profile) = send(reqwest::Method::GET, "/.well-known/ucp".into(), None, None).await;
    assert_eq!(status, 200, "{profile}");
    let business_key =
        tenzro_payments::ap2::key_from_jwk(&profile["keys"][0]).expect("the business key");

    let (status, checkout) = send(
        reqwest::Method::POST,
        "/checkout-sessions".into(),
        key(),
        Some(serde_json::json!({ "line_items": [{ "item": { "id": format!("{MODEL}/output_tokens") }, "quantity": 2000 }] })),
    )
    .await;
    assert_eq!(status, 201, "{checkout}");
    assert_eq!(checkout["status"], "ready_for_complete");
    assert!(
        ucp::verify_merchant_authorization(&business_key, &checkout),
        "the checkout is authorized by the key the profile publishes"
    );
    let id = checkout["id"].as_str().unwrap().to_string();
    let total = 2000 * PER_TOKEN;
    let requirement_json =
        checkout["ucp"]["payment_handlers"][ucp::TENZRO_HANDLER_NAME][0]["config"]["requirement"]
            .clone();
    let requirement: X402PaymentRequirement =
        serde_json::from_value(requirement_json.clone()).expect("the requirement");
    assert_eq!(requirement.amount_u128().unwrap(), total);

    // The controller's passkey approves the checkout and the payment.
    let exp = chrono::Utc::now().timestamp() + 600;
    let checkout_mandate = passkey_sd_jwt(
        &controller,
        serde_json::json!({ "vct": VCT_CHECKOUT, "checkout": checkout, "exp": exp }),
    );
    let payment_mandate_by = |signer: &passkey_holder::PasskeyHolder| {
        passkey_sd_jwt(
            signer,
            serde_json::json!({
                "vct": VCT_PAYMENT,
                "transaction_id": b64_sha256(ucp::checkout_jwt(&checkout).unwrap().as_bytes()),
                "payee": { "id": requirement.pay_to, "name": "node" },
                "payment_amount": { "amount": total.to_string(), "currency": "TNZO" },
                "payment_instrument": { "id": "tenzro-wallet", "type": "tenzro" },
                "exp": exp,
            }),
        )
    };
    // The agent signs the x402 payment of the total, naming its DID.
    let challenge =
        challenge_from_requirement(&requirement, "/checkout-sessions").expect("challenge");
    let credential = sign_credential(&challenge, "x402", AGENT, &payer.signer, total, total)
        .expect("credential");
    let payload = payload_for_credential(&challenge, &credential).expect("payload");
    let complete = |payment_mandate: String, checkout_mandate: String| {
        let token = serde_json::json!({ "payment": payload, "payment_mandate": payment_mandate });
        serde_json::json!({
            "payment": { "instruments": [{
                "id": "instr_1", "handler_id": "tenzro", "type": "tenzro_x402", "selected": true,
                "credential": { "type": "x402", "token": B64.encode(token.to_string()) }
            }] },
            "ap2": { "checkout_mandate": checkout_mandate },
        })
    };

    // A payment mandate signed by a key that is not the controller's is
    // refused by the facilitator; nothing moves.
    let stranger = passkey_holder::PasskeyHolder::generate();
    let forged_checkout = passkey_sd_jwt(
        &stranger,
        serde_json::json!({ "vct": VCT_CHECKOUT, "checkout": checkout, "exp": exp }),
    );
    let path = format!("/checkout-sessions/{id}/complete");
    let (status, refused) = send(
        reqwest::Method::POST,
        path.clone(),
        key(),
        Some(complete(payment_mandate_by(&stranger), forged_checkout)),
    )
    .await;
    assert_eq!(status, 200, "{refused}");
    assert_eq!(refused["status"], "ready_for_complete", "{refused}");
    assert_eq!(
        refused["messages"][0]["code"], "payment_declined",
        "{refused}"
    );
    assert_eq!(balance(&h.node, &payer.address()), AMOUNT * 2);

    let payee_before = balance(&h.node, &payee());
    let (status, done) = send(
        reqwest::Method::POST,
        path,
        key(),
        Some(complete(payment_mandate_by(&controller), checkout_mandate)),
    )
    .await;
    assert_eq!(status, 200, "{done}");
    assert_eq!(done["status"], "completed", "{done}");
    assert_eq!(balance(&h.node, &payer.address()), AMOUNT * 2 - total);
    let fee = governed_settlement_fee(&h.node, total);
    assert_eq!(balance(&h.node, &payee()), payee_before + total - fee);

    let _ = web_stop.send(());
    let _ = web.await;
}

/// Call `name` on the MCP endpoint at `url` and return the JSON-RPC response.
async fn mcp_call(url: &str, name: &str, arguments: serde_json::Value) -> serde_json::Value {
    let params = serde_json::json!({
        "name": name,
        "arguments": arguments,
        "_meta": {
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientInfo": { "name": "test", "version": "0" },
            "io.modelcontextprotocol/clientCapabilities": {},
        },
    });
    reqwest::Client::new()
        .post(url)
        .header("Content-Type", "application/json")
        .header("Accept", "application/json, text/event-stream")
        .header("MCP-Protocol-Version", "2026-07-28")
        .header("Mcp-Method", "tools/call")
        .header("Mcp-Name", name)
        .json(&serde_json::json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": params }))
        .send()
        .await
        .expect("mcp post")
        .json()
        .await
        .expect("mcp json")
}

/// A paid tool reached through the compact listing's `call` settles the
/// payer's signed payment on chain and debits it exactly once: the same call
/// again, with the same signed payment, moves nothing.
#[tokio::test]
#[ignore = "needs this machine's hardware consensus key (TPM 2.0 or Secure Enclave)"]
async fn a_paid_tool_called_through_the_compact_listing_is_charged_once() {
    let h = start_node().await;
    let payer = Payer::new();
    fund(&h.node, &payer.address(), AMOUNT * 2);
    let payee_before = balance(&h.node, &payee());

    let app = axum::Router::new()
        .nest_service("/mcp", tenzro_node::mcp::server::mcp_routes(h.node.clone()));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let compact = format!(
        "http://127.0.0.1:{}/mcp/compact",
        listener.local_addr().unwrap().port()
    );
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let payment_id = "mcp-compact-1";
    let binding = tenzro_types::payment_authorization::PaymentBinding {
        request_digest: [3; 32],
        ..Default::default()
    };
    let preimage = payment_authorization_preimage(
        CHAIN_ID,
        payment_id,
        &payer.address(),
        &payee(),
        AMOUNT,
        "TNZO",
        &binding,
    );
    let authorization = PaymentAuthorization {
        binding,
        public_key: payer.public_key(),
        signature: payer
            .signer
            .sign(SignatureContext::PaymentAuthorization, &preimage)
            .expect("sign"),
        max_amount: AMOUNT,
        asset: "TNZO".to_string(),
        resellers: Vec::new(),
    };
    let call = serde_json::json!({
        "name": "settle_payment",
        "arguments": {
            "payee": format!("0x{}", hex::encode(payee().as_bytes())),
            "amount_wei": AMOUNT.to_string(),
            "payment": {
                "payer": format!("0x{}", hex::encode(payer.address().as_bytes())),
                "payment_id": payment_id,
                "authorization": authorization,
            },
        },
    });

    let paid = mcp_call(&compact, "call", call.clone()).await;
    let settled = &paid["result"]["structuredContent"]["result"];
    let tx_hash = settled["tx_hash"]
        .as_str()
        .unwrap_or_else(|| panic!("{paid}"));
    assert!(executed(&h.node, tx_hash).await, "{paid}");
    assert_eq!(settled["amount"], AMOUNT.to_string(), "{paid}");
    assert_eq!(settled["payment_id"], payment_id, "{paid}");
    assert_eq!(balance(&h.node, &payer.address()), AMOUNT, "debited once");
    let credit: u128 = settled["payee_credit"].as_str().unwrap().parse().unwrap();
    assert_eq!(balance(&h.node, &payee()), payee_before + credit);

    let again = mcp_call(&compact, "call", call).await;
    if let Some(tx) = again["result"]["structuredContent"]["result"]["tx_hash"].as_str() {
        assert!(
            !executed(&h.node, tx).await,
            "a repeat must not settle: {again}"
        );
    } else {
        assert!(
            again["error"].is_object() || again["result"]["isError"] == true,
            "{again}"
        );
    }
    assert_eq!(
        balance(&h.node, &payer.address()),
        AMOUNT,
        "charged exactly once"
    );
    assert_eq!(balance(&h.node, &payee()), payee_before + credit);
}
