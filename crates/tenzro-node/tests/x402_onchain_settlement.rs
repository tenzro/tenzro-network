//! On-chain balance-change integration test for x402 → Tenzro-VM settlement.
//!
//! For an x402 payment whose asset is native TNZO, settlement does not stop at
//! the in-memory `SettlementEngine` ledger (which is receipt/audit-only). It
//! builds a system-key-signed `X402Settle` typed transaction, admits it to the
//! consensus mempool, and — once that tx lands in a finalized block —
//! `MultiVmRuntime` debits the payer and credits the payee in CF_ACCOUNTS. The
//! same CF_ACCOUNTS backing is what `token.balance_of` (hence `eth_getBalance`)
//! reads, so the balance move is observable on-chain.
//!
//! The VM unit tests exercise `execute_x402_settle` against an in-memory
//! `VmTransaction`, and the payments unit tests exercise `verify_and_settle`
//! against a recording callback. Neither catches the full loop: gateway →
//! real `TnzoSettlementCallback` → consensus mempool → finalized block → VM →
//! CF_ACCOUNTS → `balance_of`. This test drives that whole loop on a real
//! `TenzroNode` booted as a solo validator (single-node validator set,
//! threshold 1), funds the payer and the system (validator) gas account, runs
//! the settlement, waits for the validator's own consensus loop to propose and
//! finalize the admitted tx, and asserts the payer balance decreased, the
//! payee balance increased, and the recorded `settlement_tx` is a real
//! in-block 32-byte hash.

use async_trait::async_trait;
use chrono::Utc;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::broadcast;

use tenzro_consensus::ConsensusConfig;
use tenzro_node::{NodeConfig, RpcServer, TenzroNode};
use tenzro_payments::traits::{PaymentGateway, PaymentProtocol};
use tenzro_payments::types::{
    PaymentChallenge, PaymentCredential, PaymentReceipt, PaymentVerification,
};
use tenzro_types::RoleSet;
use tenzro_types::primitives::{Address, BlockHeight};

// ---------------------------------------------------------------------------
// Boilerplate — same node-booting harness the escrow integration test uses,
// except this node runs as a validator: the x402 settlement callback only
// takes the consensus-mediated path when a consensus engine exists, and
// `TenzroNode` initializes consensus for the validator role only. With an
// empty genesis validator list the engine falls back to a single-node
// validator set (threshold 1), so the node proposes and finalizes blocks
// solo. The genesis config itself is still required: `initialize_genesis`
// persists the height-0 block, and `handle_prepare_phase` refuses to vote
// on block 1 unless the parent at height 0 is fetchable (EIP-1559 base-fee
// validation).
// ---------------------------------------------------------------------------

fn test_config() -> (NodeConfig, tempfile::TempDir) {
    let tmp = tempfile::tempdir().expect("create temp dir");
    // `start()` strictly LOADS validator keys — provision the Ed25519 +
    // ML-DSA-65 + BLS12-381 keyset into the fresh data dir first.
    tenzro_node::keygen::generate_and_persist_keyset(tmp.path(), false)
        .expect("provision validator keyset");
    let config = NodeConfig {
        data_dir: tmp.path().to_path_buf(),
        roles: RoleSet::validator_only(),
        consensus: Some(ConsensusConfig::default()),
        genesis: Some(tenzro_node::config::GenesisConfig {
            version: tenzro_node::config::GENESIS_SCHEMA_VERSION,
            chain_id: 1337,
            timestamp: 0,
            validators: Vec::new(),
            accounts: Vec::new(),
            faucet: None,
            // Standalone single-node test: it is the only validator, so it must
            // opt into solo self-quorum (an empty validator set is otherwise rejected).
            weak_subjectivity: None,
            solo: true,
        }),
        ..Default::default()
    };
    (config, tmp)
}

async fn setup_test_server() -> (
    broadcast::Sender<()>,
    tokio::task::JoinHandle<tenzro_node::Result<()>>,
    tempfile::TempDir,
    Arc<TenzroNode>,
) {
    let (config, tmp) = test_config();
    let mut node = TenzroNode::new(config).await.expect("node creation");
    node.start().await.expect("node start");
    let node = Arc::new(node);

    let (shutdown_tx, shutdown_rx) = broadcast::channel::<()>(1);
    let (addr_tx, addr_rx) = tokio::sync::oneshot::channel();

    let rpc = RpcServer::new(node.clone(), "127.0.0.1:0".to_string());
    let handle =
        tokio::spawn(async move { rpc.start_with_shutdown_and_addr(shutdown_rx, addr_tx).await });

    // Wait for the RPC server to bind so the node is fully wired.
    let _addr = addr_rx.await.expect("receive bound address");

    (shutdown_tx, handle, tmp, node)
}

// ---------------------------------------------------------------------------
// A minimal x402-shaped protocol whose receipt asset is native TNZO so the
// gateway's real `TnzoSettlementCallback` takes the consensus-mediated path.
// ---------------------------------------------------------------------------

struct TnzoTestProtocol;

#[async_trait]
impl PaymentProtocol for TnzoTestProtocol {
    fn protocol_name(&self) -> &str {
        "test-tnzo"
    }

    async fn create_challenge(
        &self,
        resource: &str,
        amount: u128,
        asset: &str,
        recipient: &str,
    ) -> tenzro_payments::Result<PaymentChallenge> {
        Ok(PaymentChallenge {
            challenge_id: uuid::Uuid::new_v4().to_string(),
            protocol: "test-tnzo".to_string(),
            resource: resource.to_string(),
            amount,
            asset: asset.to_string(),
            recipient: recipient.to_string(),
            chain: "tenzro".to_string(),
            expires_at: Utc::now() + chrono::Duration::minutes(5),
            extra: HashMap::new(),
        })
    }

    async fn verify_credential(
        &self,
        challenge: &PaymentChallenge,
        credential: &PaymentCredential,
    ) -> tenzro_payments::Result<PaymentVerification> {
        Ok(PaymentVerification {
            verified: true,
            credential_id: credential.credential_id.clone(),
            challenge_id: challenge.challenge_id.clone(),
            payer_did: credential.payer_did.clone(),
            verified_at: Utc::now(),
            settlement_ref: None,
        })
    }

    async fn settle(
        &self,
        verification: &PaymentVerification,
    ) -> tenzro_payments::Result<PaymentReceipt> {
        // Receipt asset is TNZO → the gateway's callback routes through
        // consensus-mediated VM settlement (assets equal → no conversion).
        Ok(PaymentReceipt {
            receipt_id: uuid::Uuid::new_v4().to_string(),
            protocol: "test-tnzo".to_string(),
            challenge_id: verification.challenge_id.clone(),
            credential_id: verification.credential_id.clone(),
            amount: SETTLE_AMOUNT,
            asset: "TNZO".to_string(),
            settlement_tx: None,
            chain: "tenzro".to_string(),
            settled_at: Utc::now(),
            principal_chain: tenzro_types::principal_chain::anonymous_chain_for_did(
                verification.payer_did.clone(),
                BlockHeight::new(0),
            ),
            extra: HashMap::new(),
        })
    }

    async fn create_credential(
        &self,
        challenge: &PaymentChallenge,
        payer_did: &str,
        _wallet_id: &str,
    ) -> tenzro_payments::Result<PaymentCredential> {
        Ok(PaymentCredential {
            credential_id: uuid::Uuid::new_v4().to_string(),
            challenge_id: challenge.challenge_id.clone(),
            protocol: "test-tnzo".to_string(),
            payer_did: payer_did.to_string(),
            payer_address: String::new(),
            amount: challenge.amount,
            asset: challenge.asset.clone(),
            signature: Vec::new(),
            pq_signature: Vec::new(),
            pq_public_key: Vec::new(),
            extra: HashMap::new(),
        })
    }
}

// TNZO amount transferred payer → payee.
const SETTLE_AMOUNT: u128 = 5_000_000_000_000_000_000; // 5 TNZO (18-dec)

/// 32-byte address whose leading byte is `tag` and the rest zero — distinct,
/// deterministic, and a valid 32-byte Tenzro address that `bytes_to_address`
/// round-trips unchanged (hex-decoded full 32-byte slot).
fn addr(tag: u8) -> Address {
    let mut b = [0u8; 32];
    b[0] = tag;
    Address::new(b)
}

#[tokio::test]
async fn x402_tnzo_settlement_moves_onchain_balance() {
    let (_shutdown_tx, _handle, _tmp, node) = setup_test_server().await;

    let token = node.token().cloned().expect("token initialized");
    let gateway = node
        .payment_gateway()
        .cloned()
        .expect("payment gateway initialized");
    assert!(
        node.consensus().is_some(),
        "validator-role test node must have consensus initialized"
    );
    let system_addr = *node
        .local_validator_address()
        .expect("local validator address (system/gas account)");

    // --- Fund the accounts through the treasury mint path ---------------
    // `mint` requires the caller to be the treasury address and persists to
    // CF_ACCOUNTS, so the balance is visible to `balance_of` and the VM.
    let treasury = addr(0xAA);
    token.set_treasury_address(treasury);

    let payer = addr(0x01);
    let payee = addr(0x02);

    // Payer holds enough for the transfer; the system (validator) account
    // holds enough to cover the X402Settle gas (gas_price * GAS_X402_SETTLE =
    // 4_000_000_000 * 40_000 = 1.6e14). Fund it generously.
    let payer_start = SETTLE_AMOUNT * 3;
    let gas_budget: u128 = 1_000_000_000_000_000_000; // 1 TNZO
    token
        .mint(&payer, payer_start, &treasury)
        .expect("mint payer");
    // The system address may already carry a balance from node init; add on top.
    let system_start = token.balance_of(&system_addr);
    token
        .mint(&system_addr, gas_budget, &treasury)
        .expect("mint system gas");

    assert_eq!(token.balance_of(&payer), payer_start, "payer funded");
    let payee_start = token.balance_of(&payee);

    // --- Seed a challenge the gateway can look up, then settle ----------
    let recipient_hex = format!("0x{}", hex::encode(payee.as_bytes()));
    let payer_hex = format!("0x{}", hex::encode(payer.as_bytes()));

    // The protocol must be registered before the gateway can create a
    // challenge for it.
    gateway.register_protocol(Arc::new(TnzoTestProtocol));

    let challenge = gateway
        .create_challenge(
            "test-tnzo",
            "/paid/resource",
            SETTLE_AMOUNT,
            "TNZO",
            &recipient_hex,
        )
        .await
        .expect("create challenge");

    // Share the seeded challenge with the gateway's challenge store (the
    // store clone shares the same backing map).
    gateway.challenge_store().store(&challenge);

    let credential = PaymentCredential {
        credential_id: uuid::Uuid::new_v4().to_string(),
        challenge_id: challenge.challenge_id.clone(),
        protocol: "test-tnzo".to_string(),
        payer_did: "did:tenzro:machine:agent-payer".to_string(),
        payer_address: payer_hex,
        amount: SETTLE_AMOUNT,
        asset: "TNZO".to_string(),
        signature: Vec::new(),
        pq_signature: Vec::new(),
        pq_public_key: Vec::new(),
        extra: HashMap::new(),
    };

    let receipt = gateway
        .verify_and_settle(&credential)
        .await
        .expect("verify_and_settle");

    // The real callback returns the in-block tx hash. It must be a genuine
    // 32-byte hex hash — not a synthetic "transfer-only:*" ref and not the
    // bare receipt id.
    let settlement_tx = receipt
        .settlement_tx
        .clone()
        .expect("settlement_tx recorded");
    let hash_hex = settlement_tx.trim_start_matches("0x");
    assert_eq!(
        hash_hex.len(),
        64,
        "settlement_tx must be a 32-byte hex hash, got: {settlement_tx}"
    );
    assert!(
        hash_hex.chars().all(|c| c.is_ascii_hexdigit()),
        "settlement_tx must be hex, got: {settlement_tx}"
    );
    assert_ne!(
        settlement_tx, receipt.receipt_id,
        "settlement_tx must be the in-block tx hash, not the receipt id"
    );

    // --- Wait for the solo validator to finalize the admitted tx --------
    // The callback admitted the X402Settle tx to the consensus mempool. The
    // single-node validator set (threshold 1) means this node is always the
    // leader: its own consensus loop pulls the tx, proposes a block, and
    // finalizes it, after which the event loop executes the block through
    // `MultiVmRuntime` and commits the balance changes to CF_ACCOUNTS.
    let mut settled = false;
    for _ in 0..600 {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        if token.balance_of(&payer) != payer_start {
            settled = true;
            break;
        }
    }
    assert!(
        settled,
        "X402Settle tx must be finalized and executed within 60s"
    );

    // --- Assert the on-chain balance change -----------------------------
    let payer_end = token.balance_of(&payer);
    let payee_end = token.balance_of(&payee);

    assert_eq!(
        payer_end,
        payer_start - SETTLE_AMOUNT,
        "payer balance must decrease by the settled amount on-chain"
    );
    assert_eq!(
        payee_end,
        payee_start + SETTLE_AMOUNT,
        "payee balance must increase by the settled amount on-chain"
    );

    // The system (validator) account paid gas: its balance must have dropped
    // by exactly gas_price * GAS_X402_SETTLE relative to its post-mint total.
    let expected_gas = 4_000_000_000u128 * 40_000u128;
    let system_after = token.balance_of(&system_addr);
    assert_eq!(
        system_after,
        system_start + gas_budget - expected_gas,
        "system account must pay exactly the X402Settle gas cost"
    );
}
