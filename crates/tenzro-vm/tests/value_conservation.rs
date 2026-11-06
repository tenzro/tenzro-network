//! Value rules for block execution, driven through `ledger::execute_in_block`,
//! the path the node's block loop uses.
//!
//! Every test ends with a full ledger audit: after commit, the balances
//! stored under `balance:` in CF_ACCOUNTS sum to the stored `total_supply`.

use std::sync::Arc;

use tenzro_consensus::checkpoint::{
    CHECKPOINT_VOTE_DOMAIN, Checkpoint, CheckpointEquivocation, VoteSignature,
};
use tenzro_consensus::session::SessionKey;
use tenzro_consensus::{ValidatorPublicKey, ValidatorSigner};
use tenzro_crypto::signatures::{Ed25519SignerImpl, Signer};
use tenzro_storage::{CF_ACCOUNTS, KvStore, MemoryStore};
use tenzro_types::primitives::Address;
use tenzro_vm::ledger::{
    self, BlockFees, FEE_POOL_ADDRESS, TxOutcome, block_base_fee, execute_in_block,
    settle_transaction, verify_block,
};
use tenzro_vm::native::{
    SELECTOR_CHECKPOINT_EQUIVOCATION, SELECTOR_VALIDATOR_EXIT, SELECTOR_VALIDATOR_REGISTER,
    derive_treasury_address,
};
use tenzro_vm::{
    ExecutionResult, MultiVmRuntime, StateAdapter, VmConfig, VmState, VmTransaction, VmType,
};

const ONE_TNZO: u128 = 1_000_000_000_000_000_000;
/// Above the genesis base fee (USD-priced, converted at the genesis rate), so
/// every transaction pays a priority fee.
const GAS_PRICE: u128 = 20_000_000_000;
const DAY_MS: i64 = 24 * 60 * 60 * 1000;

/// A store holding `balances`, with `total_supply` equal to their sum.
fn funded_store(balances: &[(&[u8], u128)]) -> Arc<dyn KvStore> {
    let store: Arc<dyn KvStore> = Arc::new(MemoryStore::new());
    let mut supply = 0u128;
    {
        let mut state = StateAdapter::with_storage(store.clone());
        for (addr, amount) in balances {
            state.set_balance(addr, *amount);
            supply += amount;
        }
        state.commit().unwrap();
    }
    store
        .put(CF_ACCOUNTS, b"total_supply", &supply.to_le_bytes())
        .unwrap();
    store
}

fn stored_u128(store: &Arc<dyn KvStore>, key: &[u8]) -> u128 {
    store
        .get(CF_ACCOUNTS, key)
        .unwrap()
        .map(|b| {
            let mut a = [0u8; 16];
            a.copy_from_slice(&b);
            u128::from_le_bytes(a)
        })
        .unwrap_or(0)
}

/// Sum of every stored balance equals stored total supply.
fn assert_ledger_balances(store: &Arc<dyn KvStore>) {
    let mut sum = 0u128;
    for (_, v) in store.scan_prefix(CF_ACCOUNTS, b"balance:").unwrap() {
        let mut a = [0u8; 16];
        a.copy_from_slice(&v);
        sum += u128::from_le_bytes(a);
    }
    assert_eq!(
        sum,
        stored_u128(store, b"total_supply"),
        "balances != total supply"
    );
}

async fn runtime() -> MultiVmRuntime {
    MultiVmRuntime::new(VmConfig::default()).await.unwrap()
}

fn tx(from: &[u8], to: Option<&[u8]>, value: u128, data: Vec<u8>, nonce: u64) -> VmTransaction {
    VmTransaction::new(
        from.to_vec(),
        to.map(|t| t.to_vec()),
        value,
        data,
        1_000_000,
        GAS_PRICE,
        nonce,
        VmType::Tenzro,
        CHAIN_ID,
    )
    .with_block_timestamp_ms(1_700_000_000_000)
}

/// Settles the block's fees, checks the block rule, commits, audits. Total
/// supply never rises: fees and settlements may burn, nothing adds TNZO.
fn finish_block(state: &mut StateAdapter, store: &Arc<dyn KvStore>, fees: &BlockFees, _base: u128) {
    let supply_before = stored_u128(store, b"total_supply");
    ledger::settle_block(state, fees);
    verify_block(state).expect("block conserves value");
    ledger::verify_executed_block(state).expect("block adds no supply");
    state.commit().unwrap();
    assert_ledger_balances(store);
    assert!(
        stored_u128(store, b"total_supply") <= supply_before,
        "the block raised total supply"
    );
}

#[tokio::test]
async fn a_self_transfer_pays_the_fee_and_nothing_else() {
    let alice = [0xA1u8; 32];
    let store = funded_store(&[(&alice, 10 * ONE_TNZO)]);
    let mut state = StateAdapter::with_storage(store.clone());
    let rt = runtime().await;
    let base = block_base_fee(&state);
    let mut fees = BlockFees::default();

    let outcome = execute_in_block(
        &rt,
        &mut state,
        &tx(&alice, Some(&alice), 9 * ONE_TNZO, Vec::new(), 0),
        base,
        &mut fees,
    )
    .await;
    let fee = match outcome {
        TxOutcome::Applied { fee, .. } => fee,
        other => panic!("expected the self-transfer to apply, got {other:?}"),
    };

    assert!(fee > 0);
    assert_eq!(state.get_balance(&alice), 10 * ONE_TNZO - fee);
    assert_eq!(state.get_balance(&FEE_POOL_ADDRESS), fee);
    finish_block(&mut state, &store, &fees, base);
}

#[tokio::test]
async fn a_transaction_that_creates_value_is_undone_and_charged() {
    let payer = [0xB1u8; 32];
    let other = [0xB2u8; 32];
    let store = funded_store(&[(&payer, 5 * ONE_TNZO)]);
    let mut state = StateAdapter::with_storage(store.clone());
    let base = block_base_fee(&state);
    let mut fees = BlockFees::default();
    let t = tx(&payer, None, 0, vec![1, 2, 3, 4], 0);

    // An executor that credits value from nowhere and pays no fee.
    state.begin_transaction();
    state.set_balance(&other, 1_000 * ONE_TNZO);
    let forged = ExecutionResult::success(21_000, Vec::new(), Vec::new(), Vec::new());
    let outcome = settle_transaction(&mut state, &t, Ok(forged), base, &mut fees);

    match outcome {
        TxOutcome::Reverted { reason, fee, .. } => {
            assert!(reason.contains("value not conserved"), "{reason}");
            assert_eq!(fee, GAS_PRICE * 21_000);
        }
        other => panic!("minting transaction was kept: {other:?}"),
    }
    assert_eq!(state.get_balance(&other), 0);
    assert_eq!(state.get_balance(&payer), 5 * ONE_TNZO - GAS_PRICE * 21_000);
    finish_block(&mut state, &store, &fees, base);
}

#[tokio::test]
async fn a_transaction_that_declares_a_supply_increase_is_undone_and_charged() {
    let payer = [0xB3u8; 32];
    let other = [0xB4u8; 32];
    let store = funded_store(&[(&payer, 5 * ONE_TNZO)]);
    let mut state = StateAdapter::with_storage(store.clone());
    let base = block_base_fee(&state);
    let mut fees = BlockFees::default();
    let t = tx(&payer, None, 0, vec![1, 2, 3, 4], 0);
    let fee = GAS_PRICE * 21_000;

    // An executor that pays its fee, credits new TNZO and declares it, so
    // the balances match the declaration exactly.
    state.begin_transaction();
    state.set_balance(&payer, 5 * ONE_TNZO - fee);
    state.set_balance(&other, ONE_TNZO);
    let mut declared = ExecutionResult::success(21_000, Vec::new(), Vec::new(), Vec::new());
    declared.supply_change = ONE_TNZO as i128;
    let outcome = settle_transaction(&mut state, &t, Ok(declared), base, &mut fees);

    match outcome {
        TxOutcome::Reverted {
            reason, fee: paid, ..
        } => {
            assert!(reason.contains("supply"), "{reason}");
            assert_eq!(paid, fee);
        }
        other => panic!("a transaction that added supply was kept: {other:?}"),
    }
    assert_eq!(state.get_balance(&other), 0);
    let supply_before = stored_u128(&store, b"total_supply");
    finish_block(&mut state, &store, &fees, base);
    assert!(stored_u128(&store, b"total_supply") <= supply_before);
}

#[test]
fn a_block_that_records_a_supply_increase_is_refused() {
    let alice = [0xF3u8; 32];
    let store = funded_store(&[(&alice, ONE_TNZO)]);
    let mut state = StateAdapter::with_storage(store);

    // Value credited and recorded as added supply: the balances match the
    // record, but a block after genesis never adds TNZO.
    state.set_balance(&[0xF4u8; 32], 7);
    state.record_supply_change(7, 0);
    assert!(verify_block(&state).is_ok());
    assert!(ledger::verify_executed_block(&state).is_err());
}

#[tokio::test]
async fn a_declared_burn_is_kept_and_lowers_supply() {
    let payer = [0xC1u8; 32];
    let store = funded_store(&[(&payer, 5 * ONE_TNZO)]);
    let mut state = StateAdapter::with_storage(store.clone());
    let base = block_base_fee(&state);
    let mut fees = BlockFees::default();
    let t = tx(&payer, None, 0, vec![1, 2, 3, 4], 0);
    let fee = GAS_PRICE * 21_000;

    state.begin_transaction();
    state.set_balance(&payer, 5 * ONE_TNZO - ONE_TNZO - fee);
    let burned =
        ExecutionResult::success(21_000, Vec::new(), Vec::new(), Vec::new()).with_burn(ONE_TNZO);
    assert!(matches!(
        settle_transaction(&mut state, &t, Ok(burned), base, &mut fees),
        TxOutcome::Applied { .. }
    ));

    let supply_before = stored_u128(&store, b"total_supply");
    finish_block(&mut state, &store, &fees, base);
    assert!(stored_u128(&store, b"total_supply") <= supply_before - ONE_TNZO);
}

#[tokio::test]
async fn fees_are_split_between_burn_and_treasury_from_what_was_paid() {
    let alice = [0xD1u8; 32];
    let bob = [0xD2u8; 32];
    let store = funded_store(&[(&alice, 10 * ONE_TNZO)]);
    let mut state = StateAdapter::with_storage(store.clone());
    let rt = runtime().await;
    let base = block_base_fee(&state);
    assert!(
        GAS_PRICE > base,
        "test pays a priority fee above the base fee"
    );
    let mut fees = BlockFees::default();

    for nonce in 0..3 {
        let outcome = execute_in_block(
            &rt,
            &mut state,
            &tx(&alice, Some(&bob), ONE_TNZO, Vec::new(), nonce),
            base,
            &mut fees,
        )
        .await;
        assert!(matches!(outcome, TxOutcome::Applied { .. }), "{outcome:?}");
    }
    let treasury = derive_treasury_address();
    let settled = ledger::settle_block(&mut state, &fees);

    assert_eq!(settled.collected, fees.collected);
    assert_eq!(settled.burned, fees.base_fee_revenue);
    assert_eq!(
        settled.to_treasury + settled.to_insurance,
        fees.collected - fees.base_fee_revenue
    );
    assert_eq!(
        settled.to_insurance,
        tenzro_vm::native::insurance::fee_share(&state, fees.collected - fees.base_fee_revenue)
    );
    assert_eq!(state.get_balance(&FEE_POOL_ADDRESS), 0);
    assert_eq!(state.get_balance(treasury.as_bytes()), settled.to_treasury);
    assert_eq!(
        state.get_balance(tenzro_vm::native::insurance::pool_address().as_bytes()),
        settled.to_insurance
    );
    assert!(
        settled.next_base_fee < base,
        "a near-empty block lowers the base fee"
    );

    let supply_before = stored_u128(&store, b"total_supply");
    verify_block(&state).unwrap();
    state.commit().unwrap();
    assert_ledger_balances(&store);
    assert_eq!(
        stored_u128(&store, b"total_supply"),
        supply_before - settled.burned
    );
    assert_eq!(stored_u128(&store, b"total_burned"), settled.burned);

    // The next block is priced at the stored base fee.
    let next = StateAdapter::with_storage(store.clone());
    assert_eq!(block_base_fee(&next), settled.next_base_fee);
}

/// A failed transaction whose sender holds less than its gas pays what it
/// holds and no more; the block burns the base part of what was paid, so the
/// fee a receipt reports (what was taken) and the supply's fall agree exactly.
#[tokio::test]
async fn a_failed_transaction_pays_what_its_sender_holds_and_the_burn_follows_what_was_paid() {
    let payer = [0xE1u8; 32];
    let gas = 21_000u64;
    let holds = GAS_PRICE * u128::from(gas) / 3;
    let store = funded_store(&[(&payer, holds)]);
    let mut state = StateAdapter::with_storage(store.clone());
    let base = block_base_fee(&state);
    let mut fees = BlockFees::default();

    state.begin_transaction();
    let failed = ExecutionResult::failed(gas, "refused".to_string());
    let outcome = settle_transaction(
        &mut state,
        &tx(&payer, None, 0, Vec::new(), 0),
        Ok(failed),
        base,
        &mut fees,
    );
    let fee = match outcome {
        TxOutcome::Reverted { fee, .. } => fee,
        other => panic!("expected a revert, got {other:?}"),
    };
    assert_eq!(
        fee, holds,
        "the sender pays what it holds, not the whole fee"
    );
    assert_eq!(state.get_balance(&payer), 0);
    assert_eq!(fees.collected, fee);
    let base_part = base.min(GAS_PRICE).saturating_mul(u128::from(gas)).min(fee);
    assert_eq!(fees.base_fee_revenue, base_part);

    let supply_before = stored_u128(&store, b"total_supply");
    let settled = ledger::settle_block(&mut state, &fees);
    verify_block(&state).unwrap();
    state.commit().unwrap();
    assert_ledger_balances(&store);
    assert_eq!(settled.burned, base_part);
    assert_eq!(
        stored_u128(&store, b"total_supply"),
        supply_before - base_part
    );
}

#[tokio::test]
async fn a_refused_transaction_spends_its_nonce_and_the_next_one_runs() {
    let alice = [0xE3u8; 32];
    let bob = [0xE4u8; 32];
    let store = funded_store(&[(&alice, ONE_TNZO)]);
    let mut state = StateAdapter::with_storage(store.clone());
    let rt = runtime().await;
    let base = block_base_fee(&state);
    let mut fees = BlockFees::default();

    // More than the account holds: the transfer handler refuses it.
    let overdraw = tx(&alice, Some(&bob), 5 * ONE_TNZO, Vec::new(), 0);
    let charged = match execute_in_block(&rt, &mut state, &overdraw, base, &mut fees).await {
        TxOutcome::Reverted { fee, .. } => fee,
        other => panic!("a refused transfer must revert and spend its nonce, got {other:?}"),
    };
    assert!(charged > 0);
    assert_eq!(state.get_nonce(&alice), 1);
    assert_eq!(state.get_balance(&bob), 0);

    // The same transaction ordered again is stale and never executes.
    let again = execute_in_block(&rt, &mut state, &overdraw, base, &mut fees).await;
    assert!(
        matches!(
            again,
            TxOutcome::Rejected(tenzro_vm::VmError::InvalidNonce {
                expected: 1,
                got: 0
            })
        ),
        "{again:?}"
    );

    // The account's next transaction is not held behind the refused one.
    let next = tx(&alice, Some(&bob), ONE_TNZO / 2, Vec::new(), 1);
    assert!(matches!(
        execute_in_block(&rt, &mut state, &next, base, &mut fees).await,
        TxOutcome::Applied { .. }
    ));
    assert_eq!(state.get_balance(&bob), ONE_TNZO / 2);
    assert_eq!(state.get_nonce(&alice), 2);
    finish_block(&mut state, &store, &fees, base);
}

/// A checkpoint-signers record from an account with no bond is refused: only
/// a bonded validator records a certificate, so no other account can name
/// itself a signer and claim vote work.
#[tokio::test]
async fn a_checkpoint_record_from_an_unbonded_account_is_refused() {
    let mallory = [0xE7u8; 32];
    let store = funded_store(&[(&mallory, ONE_TNZO)]);
    let mut state = StateAdapter::with_storage(store.clone());
    let rt = runtime().await;
    let base = block_base_fee(&state);
    let mut fees = BlockFees::default();

    let record = tenzro_vm::native::CheckpointSigners {
        epoch: 0,
        index: 0,
        anchor_round: u64::MAX - 1,
        signers: vec![tenzro_types::primitives::Address::new(mallory)],
    };
    let mut data = tenzro_vm::native::SELECTOR_CHECKPOINT_SIGNERS.to_vec();
    data.extend_from_slice(&serde_json::to_vec(&record).unwrap());
    assert!(
        matches!(
            execute_in_block(
                &rt,
                &mut state,
                &tx(&mallory, None, 0, data, 0),
                base,
                &mut fees
            )
            .await,
            TxOutcome::Reverted { .. }
        ),
        "an unbonded account must not record checkpoint signers"
    );
    let votes = tenzro_vm::native::read_epoch_votes(&state, 0).unwrap();
    assert_eq!(votes.certified_rounds, 0);
    finish_block(&mut state, &store, &fees, base);
}

/// A checkpoint-signers record the node found unverifiable executes with no
/// signers: the VM refuses it, charges it and spends its nonce, so the
/// recording validator's next transaction runs instead of failing behind it.
#[tokio::test]
async fn an_unverifiable_checkpoint_record_spends_its_nonce() {
    let validator = [0xE5u8; 32];
    let bob = [0xE6u8; 32];
    let store = funded_store(&[(&validator, ONE_TNZO)]);
    let mut state = StateAdapter::with_storage(store.clone());
    let rt = runtime().await;
    let base = block_base_fee(&state);
    let mut fees = BlockFees::default();

    let record = tx(
        &validator,
        None,
        0,
        tenzro_vm::native::SELECTOR_CHECKPOINT_SIGNERS.to_vec(),
        0,
    );
    assert!(
        matches!(
            execute_in_block(&rt, &mut state, &record, base, &mut fees).await,
            TxOutcome::Reverted { .. }
        ),
        "an empty checkpoint record must be refused and charged"
    );
    assert_eq!(state.get_nonce(&validator), 1);

    let next = tx(&validator, Some(&bob), ONE_TNZO / 4, Vec::new(), 1);
    assert!(matches!(
        execute_in_block(&rt, &mut state, &next, base, &mut fees).await,
        TxOutcome::Applied { .. }
    ));
    assert_eq!(state.get_nonce(&validator), 2);
    finish_block(&mut state, &store, &fees, base);
}

#[tokio::test]
async fn a_gas_price_below_the_base_fee_never_executes() {
    let alice = [0xE1u8; 32];
    let store = funded_store(&[(&alice, ONE_TNZO)]);
    let mut state = StateAdapter::with_storage(store.clone());
    let rt = runtime().await;
    let base = block_base_fee(&state);
    let mut fees = BlockFees::default();
    let mut cheap = tx(&alice, Some(&[0xE2u8; 32]), 1, Vec::new(), 0);
    cheap.gas_price = base - 1;

    let outcome = execute_in_block(&rt, &mut state, &cheap, base, &mut fees).await;
    assert!(matches!(outcome, TxOutcome::Rejected(_)), "{outcome:?}");
    assert_eq!(state.get_balance(&alice), ONE_TNZO);
    assert_eq!(state.get_nonce(&alice), 0);
    finish_block(&mut state, &store, &fees, base);
}

#[test]
fn a_block_with_an_unaccounted_write_is_refused() {
    let alice = [0xF1u8; 32];
    let store = funded_store(&[(&alice, ONE_TNZO)]);
    let mut state = StateAdapter::with_storage(store);

    // A write outside any transaction rule: value appears with no supply
    // change recorded for it.
    state.set_balance(&[0xF2u8; 32], 7);
    assert!(verify_block(&state).is_err());

    // Recording it as minted makes the block balance again.
    state.record_supply_change(7, 0);
    assert!(verify_block(&state).is_ok());
}

// ---- Validator bonds ----------------------------------------------------

/// Chain id every test transaction carries.
const CHAIN_ID: u64 = 1337;

/// A validator: its account, a software composite consensus key standing in
/// for its hardware key, and its node key.
struct Validator {
    address: [u8; 32],
    ml_dsa: ml_dsa::ExpandedSigningKey<ml_dsa::MlDsa65>,
    p256: p256::ecdsa::SigningKey,
    public: ValidatorPublicKey,
    node: Ed25519SignerImpl,
}

impl Validator {
    /// Validator at account `[byte; 32]` whose consensus key comes from
    /// `seed`.
    fn new(byte: u8, seed: u8) -> Self {
        let ml_dsa = ml_dsa::ExpandedSigningKey::<ml_dsa::MlDsa65>::from_seed(&[seed; 32].into());
        let mut s = [seed; 32];
        s[0] = 1;
        let p256 = p256::ecdsa::SigningKey::from_slice(&s).unwrap();
        let public = ValidatorPublicKey::new(
            ml_dsa.verifying_key().encode().to_vec(),
            p256.verifying_key()
                .to_sec1_point(false)
                .as_bytes()
                .to_vec(),
        )
        .unwrap();
        Self {
            address: [byte; 32],
            ml_dsa,
            p256,
            public,
            node: Ed25519SignerImpl::generate().unwrap(),
        }
    }

    fn register_data(&self, stake: u128) -> Vec<u8> {
        self.register_data_to(stake, Address::new(self.address))
    }

    /// A registration whose bond, once exited, is paid to `withdrawal`.
    fn register_data_to(&self, stake: u128, withdrawal: Address) -> Vec<u8> {
        // A struct rather than `json!`: the stake does not fit a JSON value's
        // 64-bit number, but serializes directly as a u128.
        #[derive(serde::Serialize)]
        struct Register {
            ml_dsa_pubkey: Vec<u8>,
            p256_pubkey: Vec<u8>,
            node_key: [u8; 32],
            proof_of_possession: Vec<u8>,
            node_key_proof: Vec<u8>,
            vrf_key: [u8; 32],
            vrf_key_proof: Vec<u8>,
            withdrawal_address: Address,
            self_stake: u128,
            metadata_uri: String,
        }
        let node_key: [u8; 32] = self.node.public_key().as_bytes().try_into().unwrap();
        let proof =
            tenzro_consensus::validator_key::prove_registration(self, &self.address, &node_key)
                .unwrap();
        let node_key_proof = self
            .node
            .sign(
                &tenzro_consensus::validator_key::node_key_registration_message(
                    &self.address,
                    &self.public,
                    &node_key,
                ),
            )
            .unwrap()
            .to_bytes();
        let vrf = tenzro_crypto::vrf::VrfSecretKey([self.address[0] ^ 0x5a; 32]);
        let vrf_key = tenzro_crypto::vrf::VrfProver::public_key(&vrf).0;
        let vrf_key_proof = tenzro_crypto::vrf::VrfProver::prove(
            &vrf,
            &tenzro_consensus::validator_key::vrf_key_registration_alpha(
                &self.address,
                &self.public,
                &node_key,
                &vrf_key,
            ),
        )
        .unwrap()
        .as_bytes()
        .to_vec();
        let payload = Register {
            ml_dsa_pubkey: self.public.ml_dsa.clone(),
            p256_pubkey: self.public.p256.clone(),
            node_key,
            proof_of_possession: proof,
            node_key_proof,
            vrf_key,
            vrf_key_proof,
            withdrawal_address: withdrawal,
            self_stake: stake,
            metadata_uri: String::new(),
        };
        let mut data = SELECTOR_VALIDATOR_REGISTER.to_vec();
        data.extend_from_slice(&serde_json::to_vec(&payload).unwrap());
        data
    }

    /// A checkpoint of index `index` whose blocks root is `[block; 32]`.
    fn checkpoint(index: u64, block: u8) -> Checkpoint {
        Checkpoint {
            chain_id: CHAIN_ID,
            genesis_hash: [0u8; 32],
            epoch: 0,
            index,
            prev: [0u8; 32],
            first_height: index,
            last_height: index,
            blocks_root: [block; 32],
            state_height: tenzro_consensus::checkpoint::checkpoint_state_height(index, index),
            state_root: [0u8; 32],
            statement_root: [0u8; 32],
            next_committee_root: None,
            anchor_round: index,
            timestamp_ms: 0,
            ordering_root: [0; 32],
        }
    }

    /// `checkpoint` as `signer` votes for it: signed by a fresh session key
    /// that `signer`'s hardware key certified for the checkpoint's epoch.
    fn signed(signer: &Validator, cp: &Checkpoint) -> VoteSignature {
        let session = SessionKey::generate().unwrap();
        let cert = tenzro_consensus::session::sign_certificate(
            signer,
            cp.chain_id,
            cp.genesis_hash,
            cp.epoch,
            session.public_key().clone(),
        )
        .unwrap();
        let signature = session.sign(CHECKPOINT_VOTE_DOMAIN, &cp.digest()).unwrap();
        VoteSignature {
            session: cert,
            signature,
        }
    }

    /// Evidence against this validator's key: `first` as it signed it, and
    /// `second` as `second_signer` signed it.
    fn evidence(
        &self,
        first: &Checkpoint,
        second: &Checkpoint,
        second_signer: &Validator,
    ) -> Vec<u8> {
        let ev = CheckpointEquivocation {
            public_key: self.public.clone(),
            first: first.clone(),
            first_signature: Self::signed(self, first),
            second: second.clone(),
            second_signature: Self::signed(second_signer, second),
        };
        let mut data = SELECTOR_CHECKPOINT_EQUIVOCATION.to_vec();
        data.extend_from_slice(&bincode::serialize(&ev).unwrap());
        data
    }
}

impl ValidatorSigner for Validator {
    fn public_key(&self) -> &ValidatorPublicKey {
        &self.public
    }

    fn sign(
        &self,
        domain: &[u8],
        message: &[u8],
    ) -> tenzro_consensus::Result<tenzro_consensus::CompositeSignature> {
        use p256::ecdsa::signature::hazmat::PrehashSigner;
        use sha2::Digest;
        let rep = tenzro_consensus::validator_key::message_representative(domain, message).unwrap();
        let ml = self
            .ml_dsa
            .sign_deterministic(&rep, tenzro_consensus::validator_key::ml_dsa_context())
            .unwrap();
        let digest: [u8; 32] = sha2::Sha256::digest(&rep).into();
        let ec: p256::ecdsa::Signature = self.p256.sign_prehash(&digest).unwrap();
        Ok(tenzro_consensus::CompositeSignature {
            ml_dsa: ml.encode().to_vec(),
            p256: ec.to_bytes().to_vec(),
        })
    }
}

async fn run(
    rt: &MultiVmRuntime,
    state: &mut StateAdapter,
    fees: &mut BlockFees,
    mut t: VmTransaction,
    now_ms: i64,
) -> TxOutcome {
    t = t.with_block_timestamp_ms(now_ms);
    let base = block_base_fee(state);
    execute_in_block(rt, state, &t, base, fees).await
}

#[tokio::test]
async fn exit_unbonds_for_seven_days_before_paying_out() {
    let v = Validator::new(0x51, 0x51);
    let store = funded_store(&[(&v.address, 20_000 * ONE_TNZO)]);
    let mut state = StateAdapter::with_storage(store.clone());
    let rt = runtime().await;
    let mut fees = BlockFees::default();
    let t0 = 1_700_000_000_000;

    let reg = run(
        &rt,
        &mut state,
        &mut fees,
        tx(&v.address, None, 0, v.register_data(10_000 * ONE_TNZO), 0),
        t0,
    )
    .await;
    assert!(matches!(reg, TxOutcome::Applied { .. }), "{reg:?}");
    let after_register = state.get_balance(&v.address);

    // Step one: unbonding starts; nothing is paid out.
    let exit = run(
        &rt,
        &mut state,
        &mut fees,
        tx(&v.address, None, 0, SELECTOR_VALIDATOR_EXIT.to_vec(), 1),
        t0 + 1,
    )
    .await;
    let TxOutcome::Applied { fee, .. } = exit else {
        panic!("exit failed: {exit:?}");
    };
    assert_eq!(state.get_balance(&v.address), after_register - fee);

    // Withdrawing inside the period is refused.
    let early = run(
        &rt,
        &mut state,
        &mut fees,
        tx(&v.address, None, 0, SELECTOR_VALIDATOR_EXIT.to_vec(), 2),
        t0 + 6 * DAY_MS,
    )
    .await;
    assert!(!matches!(early, TxOutcome::Applied { .. }), "{early:?}");

    // After seven days the bond comes back.
    let before = state.get_balance(&v.address);
    let nonce = state.get_nonce(&v.address);
    let paid = run(
        &rt,
        &mut state,
        &mut fees,
        tx(&v.address, None, 0, SELECTOR_VALIDATOR_EXIT.to_vec(), nonce),
        t0 + 8 * DAY_MS,
    )
    .await;
    let TxOutcome::Applied { fee, .. } = paid else {
        panic!("withdrawal failed: {paid:?}");
    };
    assert_eq!(
        state.get_balance(&v.address),
        before + 10_000 * ONE_TNZO - fee
    );

    let base = block_base_fee(&state);
    finish_block(&mut state, &store, &fees, base);
}

#[tokio::test]
async fn equivocation_evidence_from_session_signed_votes_slashes_the_hardware_identity() {
    let v = Validator::new(0x61, 0x61);
    let reporter = [0x62u8; 32];
    let store = funded_store(&[(&v.address, 20_000 * ONE_TNZO), (&reporter, 10 * ONE_TNZO)]);
    let mut state = StateAdapter::with_storage(store.clone());
    let rt = runtime().await;
    let mut fees = BlockFees::default();
    let t0 = 1_700_000_000_000;
    let stake = 10_000 * ONE_TNZO;

    let reg = run(
        &rt,
        &mut state,
        &mut fees,
        tx(&v.address, None, 0, v.register_data(stake), 0),
        t0,
    )
    .await;
    assert!(matches!(reg, TxOutcome::Applied { .. }), "{reg:?}");

    // Signing the same checkpoint twice is not equivocation.
    let same = v.evidence(
        &Validator::checkpoint(7, 1),
        &Validator::checkpoint(7, 1),
        &v,
    );
    let r = run(
        &rt,
        &mut state,
        &mut fees,
        tx(&reporter, None, 0, same, 0),
        t0,
    )
    .await;
    assert!(!matches!(r, TxOutcome::Applied { .. }), "{r:?}");

    // A second checkpoint signed by someone else's key does not verify.
    let impostor = Validator::new(0x61, 0x77);
    let forged = v.evidence(
        &Validator::checkpoint(8, 1),
        &Validator::checkpoint(8, 2),
        &impostor,
    );
    let nonce = state.get_nonce(&reporter);
    let r = run(
        &rt,
        &mut state,
        &mut fees,
        tx(&reporter, None, 0, forged, nonce),
        t0,
    )
    .await;
    assert!(!matches!(r, TxOutcome::Applied { .. }), "{r:?}");

    // Real equivocation: two checkpoints with one index, each signed by a
    // session key the registered hardware key certified (two different
    // session keys, as after a restart). The penalty is proportional to the
    // stake that equivocated: this validator holds all bonded stake, so the
    // whole bond goes to the insurance pool; nothing is burned.
    let pool = tenzro_vm::native::insurance::pool_address();
    let first = stake;
    let supply_before = state.total_supply();
    let pool_before = state.get_balance(pool.as_bytes());
    let good = v.evidence(
        &Validator::checkpoint(9, 1),
        &Validator::checkpoint(9, 2),
        &v,
    );
    let nonce = state.get_nonce(&reporter);
    let r = run(
        &rt,
        &mut state,
        &mut fees,
        tx(&reporter, None, 0, good.clone(), nonce),
        t0,
    )
    .await;
    let TxOutcome::Applied { result, .. } = r else {
        panic!("valid evidence was refused: {r:?}");
    };
    assert_eq!(result.supply_change, 0);
    assert_eq!(state.total_supply(), supply_before);
    assert_eq!(state.get_balance(pool.as_bytes()), pool_before + first);

    // The same evidence cannot slash twice.
    let nonce = state.get_nonce(&reporter);
    let r = run(
        &rt,
        &mut state,
        &mut fees,
        tx(&reporter, None, 0, good, nonce),
        t0,
    )
    .await;
    assert!(!matches!(r, TxOutcome::Applied { .. }), "{r:?}");

    // A second offence finds nothing left at stake.
    let pool_before = state.get_balance(pool.as_bytes());
    let again = v.evidence(
        &Validator::checkpoint(40, 1),
        &Validator::checkpoint(40, 2),
        &v,
    );
    let nonce = state.get_nonce(&reporter);
    let r = run(
        &rt,
        &mut state,
        &mut fees,
        tx(&reporter, None, 0, again, nonce),
        t0,
    )
    .await;
    assert!(matches!(r, TxOutcome::Applied { .. }), "{r:?}");
    assert_eq!(state.get_balance(pool.as_bytes()), pool_before);

    // Nothing is left to exit with.
    let n = state.get_nonce(&v.address);
    let exit = run(
        &rt,
        &mut state,
        &mut fees,
        tx(&v.address, None, 0, SELECTOR_VALIDATOR_EXIT.to_vec(), n),
        t0,
    )
    .await;
    assert!(!matches!(exit, TxOutcome::Applied { .. }), "{exit:?}");

    let base = block_base_fee(&state);
    finish_block(&mut state, &store, &fees, base);
}

#[tokio::test]
async fn each_resource_has_its_own_market_and_a_congested_one_is_paid_on_top() {
    use tenzro_vm::ledger::{Resource, resource_base_fee_usd};
    let payer = [0xE1u8; 32];
    let store = funded_store(&[(&payer, 5 * ONE_TNZO)]);
    let mut state = StateAdapter::with_storage(store.clone());
    let compute_before = tenzro_vm::ledger::block_base_fee_usd(&state);

    // A block that created far more state than its target, with no compute
    // congestion: the state-growth fee rises, compute's and the others fall.
    let fees = BlockFees {
        resource_units: [
            tenzro_vm::ledger::DEFAULT_RESOURCE_TARGET_PER_BLOCK * 2,
            0,
            0,
        ],
        ..Default::default()
    };
    ledger::settle_block(&mut state, &fees);
    let growth = resource_base_fee_usd(&state, Resource::StateGrowth);
    assert!(
        growth > compute_before,
        "state growth priced up by its own use"
    );
    assert!(resource_base_fee_usd(&state, Resource::Bandwidth) < compute_before);
    assert!(tenzro_vm::ledger::block_base_fee_usd(&state) < compute_before);

    // A transaction that creates one entry pays the state-growth premium on
    // top of its gas, into the fee pool, and the value rule holds.
    let base = block_base_fee(&state);
    let mut fees = BlockFees::default();
    let t = tx(&payer, None, 0, Vec::new(), 0);
    let gas = 21_000 + 20_000;
    state.begin_transaction();
    state.set_balance(&payer, 5 * ONE_TNZO - GAS_PRICE * gas as u128);
    let created = tenzro_vm::StateChange::new(vec![9], b"slot".to_vec(), None, Some(vec![1]));
    let result = ExecutionResult::success(gas, Vec::new(), Vec::new(), vec![created]);
    let fee = match settle_transaction(&mut state, &t, Ok(result), base, &mut fees) {
        TxOutcome::Applied { fee, .. } => fee,
        other => panic!("expected the transaction to apply, got {other:?}"),
    };
    assert!(
        fee > GAS_PRICE * gas as u128,
        "the premium is paid on top of gas"
    );
    assert_eq!(fees.resource_units[0], 20_000);
    assert_eq!(state.get_balance(&FEE_POOL_ADDRESS), fee);
    assert_eq!(state.get_balance(&payer), 5 * ONE_TNZO - fee);
    finish_block(&mut state, &store, &fees, base);
}

#[tokio::test]
async fn a_registered_consensus_key_cannot_be_registered_again_by_another_account() {
    let v = Validator::new(0x64, 0x64);
    // The same key, held by the same operator, from a second account.
    let twin = Validator::new(0x65, 0x64);
    let reporter = [0x66u8; 32];
    let store = funded_store(&[
        (&v.address, 20_000 * ONE_TNZO),
        (&twin.address, 10 * ONE_TNZO),
        (&reporter, 10 * ONE_TNZO),
    ]);
    let mut state = StateAdapter::with_storage(store.clone());
    let rt = runtime().await;
    let mut fees = BlockFees::default();
    let t0 = 1_700_000_000_000;
    let stake = 10_000 * ONE_TNZO;

    let reg = run(
        &rt,
        &mut state,
        &mut fees,
        tx(&v.address, None, 0, v.register_data(stake), 0),
        t0,
    )
    .await;
    assert!(matches!(reg, TxOutcome::Applied { .. }), "{reg:?}");

    let again = run(
        &rt,
        &mut state,
        &mut fees,
        tx(&twin.address, None, 0, twin.register_data(1), 0),
        t0,
    )
    .await;
    assert!(
        !matches!(again, TxOutcome::Applied { .. }),
        "a key registered by one account was registered again by another: {again:?}"
    );

    // Evidence against the key still reaches the bond that registered it.
    let pool = tenzro_vm::native::insurance::pool_address();
    let pool_before = state.get_balance(pool.as_bytes());
    let ev = v.evidence(
        &Validator::checkpoint(9, 1),
        &Validator::checkpoint(9, 2),
        &v,
    );
    let r = run(
        &rt,
        &mut state,
        &mut fees,
        tx(&reporter, None, 0, ev, 0),
        t0,
    )
    .await;
    assert!(matches!(r, TxOutcome::Applied { .. }), "{r:?}");
    assert_eq!(state.get_balance(pool.as_bytes()), pool_before + stake);

    let base = block_base_fee(&state);
    finish_block(&mut state, &store, &fees, base);
}

/// A validator's hardware is lost for good, so nothing can sign as its
/// account again. The operator's withdrawal address, named at registration,
/// exits the bond for it; after the unbonding period the bond is paid to that
/// address, and the operator registers new hardware, whose account and
/// consensus key come from the new machine. No one else can exit the old
/// validator, and every step conserves value.
#[tokio::test]
async fn a_validator_whose_hardware_is_lost_exits_through_its_withdrawal_address() {
    let old = Validator::new(0x91, 0x91);
    let operator = [0x92u8; 32];
    let stranger = [0x94u8; 32];
    let new = Validator::new(0x93, 0x93);
    let stake = 10_000 * ONE_TNZO;
    let store = funded_store(&[
        (&old.address, 20_000 * ONE_TNZO),
        (&operator, 10 * ONE_TNZO),
        (&stranger, 10 * ONE_TNZO),
    ]);
    let mut state = StateAdapter::with_storage(store.clone());
    let rt = runtime().await;
    let mut fees = BlockFees::default();
    let t0 = 1_700_000_000_000;
    let exit_for = |v: &Validator| {
        let mut d = SELECTOR_VALIDATOR_EXIT.to_vec();
        d.extend_from_slice(&v.address);
        d
    };

    let reg = run(
        &rt,
        &mut state,
        &mut fees,
        tx(
            &old.address,
            None,
            0,
            old.register_data_to(stake, Address::new(operator)),
            0,
        ),
        t0,
    )
    .await;
    assert!(matches!(reg, TxOutcome::Applied { .. }), "{reg:?}");

    // From here the old machine signs nothing.
    let by_stranger = run(
        &rt,
        &mut state,
        &mut fees,
        tx(&stranger, None, 0, exit_for(&old), 0),
        t0 + 1,
    )
    .await;
    assert!(
        !matches!(by_stranger, TxOutcome::Applied { .. }),
        "{by_stranger:?}"
    );

    let n = state.get_nonce(&operator);
    let start = run(
        &rt,
        &mut state,
        &mut fees,
        tx(&operator, None, 0, exit_for(&old), n),
        t0 + 1,
    )
    .await;
    assert!(matches!(start, TxOutcome::Applied { .. }), "{start:?}");

    let n = state.get_nonce(&operator);
    let early = run(
        &rt,
        &mut state,
        &mut fees,
        tx(&operator, None, 0, exit_for(&old), n),
        t0 + 6 * DAY_MS,
    )
    .await;
    assert!(!matches!(early, TxOutcome::Applied { .. }), "{early:?}");

    let before = state.get_balance(&operator);
    let n = state.get_nonce(&operator);
    let paid = run(
        &rt,
        &mut state,
        &mut fees,
        tx(&operator, None, 0, exit_for(&old), n),
        t0 + 8 * DAY_MS,
    )
    .await;
    let TxOutcome::Applied { fee, .. } = paid else {
        panic!("withdrawal failed: {paid:?}");
    };
    assert_eq!(state.get_balance(&operator), before + stake - fee);

    // The operator funds the new machine's account, which registers.
    let n = state.get_nonce(&operator);
    let fund = run(
        &rt,
        &mut state,
        &mut fees,
        tx(
            &operator,
            Some(&new.address),
            stake + ONE_TNZO,
            Vec::new(),
            n,
        ),
        t0 + 8 * DAY_MS,
    )
    .await;
    assert!(matches!(fund, TxOutcome::Applied { .. }), "{fund:?}");
    let reg = run(
        &rt,
        &mut state,
        &mut fees,
        tx(
            &new.address,
            None,
            0,
            new.register_data_to(stake, Address::new(operator)),
            0,
        ),
        t0 + 8 * DAY_MS,
    )
    .await;
    assert!(matches!(reg, TxOutcome::Applied { .. }), "{reg:?}");

    let base = block_base_fee(&state);
    finish_block(&mut state, &store, &fees, base);
}
