//! Once `feature.fee_payer.activation_epoch` is live, a transaction whose
//! memo carried another account's consent has its fee paid by that account.
//! Driven through `ledger::execute_in_block`, the path the node's block loop
//! uses, with the consent as the node hands it to the VM.
//!
//! The payer's balance is debited the most the gas can cost before the
//! handler runs; what the gas did not use goes back, and a failed
//! transaction still costs the payer its fee. Before the gate is live the
//! consent is not read and the sender pays, as it always did.

use std::sync::Arc;

use tenzro_crypto::composite::testing::TestHybridSigner;
use tenzro_crypto::composite::{CompositeSignature, HybridSigner, SignatureContext};
use tenzro_storage::{CF_ACCOUNTS, KvStore, MemoryStore};
use tenzro_vm::account_keys::set_enrolled_pq_key;
use tenzro_vm::ledger::{self, BlockFees, TxOutcome, block_base_fee, execute_in_block};
use tenzro_vm::{
    MultiVmRuntime, StateAdapter, VmConfig, VmFeePayer, VmState, VmTransaction, VmType,
};

const ONE_TNZO: u128 = 1_000_000_000_000_000_000;
const GAS_PRICE: u128 = 20_000_000_000;
const GAS_LIMIT: u64 = 1_000_000;
const NOW_MS: i64 = 1_700_000_000_000;
const BOB: [u8; 32] = [0xB0; 32];

struct Party {
    signer: TestHybridSigner,
    account: Vec<u8>,
}

fn party(seed: u8) -> Party {
    let signer = TestHybridSigner::hybrid(seed);
    let account = signer.address().as_bytes().to_vec();
    Party { signer, account }
}

/// A store where `sender` and `payer` have enrolled their ML-DSA-65 keys and
/// hold the given balances, with the fee payer rule live.
fn store(sender: &Party, sender_holds: u128, payer: &Party, payer_holds: u128) -> Arc<dyn KvStore> {
    store_with(sender, sender_holds, payer, payer_holds, true)
}

fn store_with(
    sender: &Party,
    sender_holds: u128,
    payer: &Party,
    payer_holds: u128,
    live: bool,
) -> Arc<dyn KvStore> {
    let store: Arc<dyn KvStore> = Arc::new(MemoryStore::new());
    {
        let mut state = StateAdapter::with_storage(store.clone());
        if live {
            tenzro_vm::native::set_genesis_param(&mut state, ledger::FEE_PAYER_GATE, 0);
        }
        for (who, holds) in [(sender, sender_holds), (payer, payer_holds)] {
            let pk = who.signer.public_key().clone();
            let mut changes = Vec::new();
            set_enrolled_pq_key(&mut state, &pk.p256, pk.pq.clone().unwrap(), &mut changes);
            state.set_balance(&who.account, holds);
        }
        state.commit().unwrap();
    }
    store
        .put(
            CF_ACCOUNTS,
            b"total_supply",
            &(sender_holds + payer_holds).to_le_bytes(),
        )
        .unwrap();
    store
}

fn digest(nonce: u64) -> [u8; 32] {
    let mut d = [0u8; 32];
    d[..8].copy_from_slice(&nonce.to_le_bytes());
    d[8] = 0xfe;
    d
}

/// The digest a payer's consent to the transaction at `nonce` is over.
fn consent_digest(nonce: u64) -> [u8; 32] {
    let mut d = digest(nonce);
    d[9] = 0xc0;
    d
}

/// A transfer of `value` from `sender` to Bob at `nonce`, signed by the
/// sender, with the consent of `payer`: its signature over the consent
/// digest under the fee-payer context.
fn sponsored(sender: &Party, payer: &Party, value: u128, nonce: u64) -> VmTransaction {
    let d = digest(nonce);
    let mut tx = VmTransaction::new(
        sender.account.clone(),
        Some(BOB.to_vec()),
        value,
        Vec::new(),
        GAS_LIMIT,
        GAS_PRICE,
        nonce,
        VmType::Tenzro,
        VmConfig::default().chain_id,
    )
    .with_block_timestamp_ms(NOW_MS)
    .with_fee_payer(VmFeePayer::Consented {
        account: payer.account.clone(),
        public_key: payer.signer.public_key().p256.clone(),
        signature: payer
            .signer
            .sign(SignatureContext::FeePayer, &consent_digest(nonce))
            .unwrap(),
        digest: consent_digest(nonce).to_vec(),
    });
    tx.signature = Some(
        sender
            .signer
            .sign(SignatureContext::Transaction, &d)
            .unwrap(),
    );
    tx.public_key = Some(sender.signer.public_key().p256.clone());
    tx.signing_digest = Some(d.to_vec());
    tx.valid_until_ms = Some(NOW_MS + 60_000);
    tx
}

async fn run(state: &mut StateAdapter, tx: &VmTransaction) -> TxOutcome {
    let rt = MultiVmRuntime::new(VmConfig::default()).await.unwrap();
    let base = block_base_fee(state);
    let mut fees = BlockFees::default();
    let outcome = execute_in_block(&rt, state, tx, base, &mut fees).await;
    ledger::settle_block(state, &fees);
    ledger::verify_block(state).expect("block conserves value");
    ledger::verify_executed_block(state).expect("block adds no supply");
    outcome
}

/// The payer pays the whole fee and the sender only the value it sends: a
/// sender holding exactly the value sends all of it.
#[tokio::test]
async fn a_fee_payer_pays_the_fee_and_the_sender_only_the_value() {
    let (sender, payer) = (party(3), party(9));
    let store = store(&sender, ONE_TNZO, &payer, 5 * ONE_TNZO);
    let mut state = StateAdapter::with_storage(store);

    let outcome = run(&mut state, &sponsored(&sender, &payer, ONE_TNZO, 0)).await;
    let fee = match outcome {
        TxOutcome::Applied { fee, .. } => fee,
        other => panic!("expected the transfer to apply, got {other:?}"),
    };
    assert!(fee > 0);
    assert_eq!(state.get_balance(&sender.account), 0);
    assert_eq!(state.get_balance(&BOB), ONE_TNZO);
    assert_eq!(state.get_balance(&payer.account), 5 * ONE_TNZO - fee);
    assert_eq!(state.get_nonce(&sender.account), 1);
    assert_eq!(state.get_nonce(&payer.account), 0);
}

/// A transaction whose handler refuses it is undone, spends its nonce and
/// still costs the payer its fee; the sender pays nothing.
#[tokio::test]
async fn a_failed_transaction_still_costs_its_fee_payer() {
    let (sender, payer) = (party(3), party(9));
    let store = store(&sender, 0, &payer, 5 * ONE_TNZO);
    let mut state = StateAdapter::with_storage(store);

    // The sender holds nothing: beyond the gas its payer advances, it cannot
    // send a whole TNZO.
    let outcome = run(&mut state, &sponsored(&sender, &payer, ONE_TNZO, 0)).await;
    let fee = match outcome {
        TxOutcome::Reverted { fee, .. } => fee,
        other => panic!("expected the transfer to be reverted, got {other:?}"),
    };
    assert!(fee > 0);
    assert_eq!(state.get_balance(&sender.account), 0);
    assert_eq!(state.get_balance(&BOB), 0);
    assert_eq!(state.get_balance(&payer.account), 5 * ONE_TNZO - fee);
    assert_eq!(state.get_nonce(&sender.account), 1);
}

/// What the payer advances is for gas alone. A sender that sends any of it
/// on is reverted, and the payer is charged the fee and nothing more.
#[tokio::test]
async fn a_sender_cannot_spend_what_its_fee_payer_advanced() {
    let (sender, payer) = (party(3), party(9));
    let store = store(&sender, 0, &payer, 5 * ONE_TNZO);
    let mut state = StateAdapter::with_storage(store);

    let outcome = run(&mut state, &sponsored(&sender, &payer, 1, 0)).await;
    let (fee, reason) = match outcome {
        TxOutcome::Reverted { fee, reason, .. } => (fee, reason),
        other => panic!("expected the transfer to be reverted, got {other:?}"),
    };
    assert!(reason.contains("fee payer advanced"), "{reason}");
    assert_eq!(state.get_balance(&sender.account), 0);
    assert_eq!(state.get_balance(&BOB), 0);
    assert_eq!(state.get_balance(&payer.account), 5 * ONE_TNZO - fee);
    assert!(fee <= GAS_PRICE * u128::from(GAS_LIMIT));
}

/// A payer that cannot cover the gas limit at the gas price runs nothing:
/// the transaction spends its nonce and the payer pays what it holds.
#[tokio::test]
async fn a_fee_payer_below_the_gas_limit_runs_nothing_and_pays_what_it_holds() {
    let (sender, payer) = (party(3), party(9));
    let store = store(&sender, ONE_TNZO, &payer, 1_000);
    let mut state = StateAdapter::with_storage(store);

    let outcome = run(&mut state, &sponsored(&sender, &payer, ONE_TNZO, 0)).await;
    let fee = match outcome {
        TxOutcome::Reverted { fee, .. } => fee,
        other => panic!("expected the transfer to be reverted, got {other:?}"),
    };
    assert_eq!(fee, 1_000);
    assert_eq!(state.get_balance(&payer.account), 0);
    assert_eq!(state.get_balance(&sender.account), ONE_TNZO);
    assert_eq!(state.get_balance(&BOB), 0);
    assert_eq!(state.get_nonce(&sender.account), 1);
}

/// A change to a consent's account, signature and digest.
type Change = dyn Fn(&mut Vec<u8>, &mut CompositeSignature, &mut Vec<u8>);

/// A consent that does not stand refuses the transaction outright once the
/// rule is live: nothing runs, nothing is charged and no nonce is spent.
#[tokio::test]
async fn a_fee_payer_whose_consent_does_not_stand_refuses_the_transaction() {
    let (sender, payer) = (party(3), party(9));
    let honest = sponsored(&sender, &payer, ONE_TNZO, 0);
    let consented = |change: &Change| {
        let mut tx = honest.clone();
        if let Some(VmFeePayer::Consented {
            account,
            signature,
            digest,
            ..
        }) = tx.fee_payer.as_mut()
        {
            change(account, signature, digest);
        }
        tx
    };
    let sender_account = sender.account.clone();
    let mut refused_by_the_node = honest.clone();
    refused_by_the_node.fee_payer = Some(VmFeePayer::Refused("bad signature".into()));
    let mut evm = honest.clone();
    evm.vm_type = VmType::Evm;
    let refused = [
        // What the node could not verify from the memo.
        refused_by_the_node,
        // The P-256 leg alone, for a payer with an ML-DSA-65 key enrolled.
        consented(&|_, signature, _| signature.pq = None),
        // An ML-DSA-65 leg made for another transaction.
        consented(&|_, _, digest| *digest = consent_digest(1).to_vec()),
        // The sender naming itself.
        consented(&move |account, _, _| *account = sender_account.clone()),
        // A fee payer is named by native transactions only.
        evm,
    ];
    for (i, tx) in refused.iter().enumerate() {
        let store = store(&sender, ONE_TNZO, &payer, 5 * ONE_TNZO);
        let mut state = StateAdapter::with_storage(store);
        let outcome = run(&mut state, tx).await;
        assert!(
            matches!(outcome, TxOutcome::Rejected(_)),
            "case {i}: {outcome:?}"
        );
        assert_eq!(state.get_balance(&payer.account), 5 * ONE_TNZO, "case {i}");
        assert_eq!(state.get_balance(&sender.account), ONE_TNZO, "case {i}");
        assert_eq!(state.get_nonce(&sender.account), 0, "case {i}");
    }
}

/// Until the rule is live nothing about a fee payer is read: the sender
/// pays its own fee, whether the consent stands or not, and a sender that
/// cannot is refused as any sender would be.
#[tokio::test]
async fn before_the_rule_is_live_the_sender_pays() {
    let (sender, payer) = (party(3), party(9));
    let honest = sponsored(&sender, &payer, ONE_TNZO, 0);
    let mut refused = honest.clone();
    refused.fee_payer = Some(VmFeePayer::Refused("bad signature".into()));
    for tx in [&honest, &refused] {
        let store = store_with(&sender, 2 * ONE_TNZO, &payer, 5 * ONE_TNZO, false);
        let mut state = StateAdapter::with_storage(store);
        let fee = match run(&mut state, tx).await {
            TxOutcome::Applied { fee, .. } => fee,
            other => panic!("expected the transfer to apply, got {other:?}"),
        };
        assert!(fee > 0);
        assert_eq!(state.get_balance(&payer.account), 5 * ONE_TNZO);
        assert_eq!(state.get_balance(&sender.account), ONE_TNZO - fee);
        assert_eq!(state.get_balance(&BOB), ONE_TNZO);
    }
    // A sender holding only the value cannot also pay the gas.
    let store = store_with(&sender, ONE_TNZO, &payer, 5 * ONE_TNZO, false);
    let mut state = StateAdapter::with_storage(store);
    assert!(!matches!(
        run(&mut state, &honest).await,
        TxOutcome::Applied { .. }
    ));
    assert_eq!(state.get_balance(&payer.account), 5 * ONE_TNZO);
    assert_eq!(state.get_balance(&BOB), 0);
}
