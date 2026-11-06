//! EIP-7702 execution semantics, after the Prague `eip7702` cases of the
//! Ethereum execution-spec tests (`test_set_code_txs.py`, `test_gas.py`):
//! intrinsic gas per authorization, the refund for an authority that already
//! exists, invalid authorizations skipped while the transaction runs,
//! nonces, chain id 0, clearing a delegation and delegations that outlast
//! a reverting call.

use k256::ecdsa::SigningKey;
use revm::primitives::U256;
use sha3::{Digest, Keccak256};
use tenzro_vm::external_tx::intrinsic_gas;
use tenzro_vm::ledger::{BlockFees, TxOutcome, execute_in_block};
use tenzro_vm::{
    Eip7702Authorization, ExecutionResult, MultiVmRuntime, StateAdapter, VmConfig, VmState,
    VmTransaction, VmType,
};

const CHAIN: u64 = 1337;
const GAS_PRICE: u128 = 1_000_000_000;
const PER_EMPTY_ACCOUNT_COST: u64 = 25_000;
const PER_AUTH_BASE_COST: u64 = 12_500;
/// An account with no code: calling it costs exactly the intrinsic gas.
const PLAIN: [u8; 20] = [0x77; 20];
/// `PUSH1 0x2a PUSH1 0x00 SSTORE STOP`.
const SSTORE_42: [u8; 6] = [0x60, 0x2a, 0x60, 0x00, 0x55, 0x00];
/// `PUSH1 0x00 PUSH1 0x00 REVERT`.
const REVERTS: [u8; 5] = [0x60, 0x00, 0x60, 0x00, 0xfd];
const SECP256K1_N: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];

fn key(seed: u8) -> SigningKey {
    SigningKey::from_slice(&[seed; 32]).unwrap()
}

fn address(k: &SigningKey) -> [u8; 20] {
    let point = k.verifying_key().to_sec1_point(false);
    let h = Keccak256::digest(&point.as_bytes()[1..]);
    h[12..].try_into().unwrap()
}

fn sign(k: &SigningKey, chain_id: U256, delegate: [u8; 20], nonce: u64) -> Eip7702Authorization {
    let mut auth = Eip7702Authorization {
        chain_id,
        delegate_address: delegate.to_vec(),
        nonce,
        signature: vec![],
    };
    let (sig, rid) = k.sign_prehash_recoverable(&auth.signing_hash()).unwrap();
    auth.signature = sig.to_bytes().to_vec();
    auth.signature.push(rid.to_byte());
    auth
}

fn auth(k: &SigningKey, delegate: [u8; 20], nonce: u64) -> Eip7702Authorization {
    sign(k, U256::from(CHAIN), delegate, nonce)
}

fn designator(delegate: [u8; 20]) -> Vec<u8> {
    let mut c = vec![0xef, 0x01, 0x00];
    c.extend_from_slice(&delegate);
    c
}

struct World {
    rt: MultiVmRuntime,
    state: StateAdapter,
    sender: SigningKey,
}

impl World {
    async fn new() -> Self {
        let rt = MultiVmRuntime::new(VmConfig::default()).await.unwrap();
        let mut state = StateAdapter::new();
        let sender = key(1);
        state.set_balance(&address(&sender), 1_000_000_000_000_000_000);
        // These cases pin the EVM's own authorization rules, so the
        // admission limits (tests/eip7702_sweep_guard.rs) are lifted here.
        for (name, v) in [
            ("evm.max_authorizations_per_tx", 256u64),
            ("evm.universal_authorization_allowed", 1),
            ("evm.multiple_authorizations_per_signer_allowed", 1),
            ("evm.foreign_chain_authorization_allowed", 1),
        ] {
            tenzro_vm::VmState::set_storage(
                &mut state,
                &tenzro_vm::native::SYSTEM_ADDRESS,
                tenzro_vm::native::governed_param_key(name).as_bytes(),
                v.to_le_bytes().to_vec(),
            );
        }
        state.set_code(&[0xd0; 20], SSTORE_42.to_vec());
        state.set_code(&[0xde; 20], REVERTS.to_vec());
        Self { rt, state, sender }
    }

    fn tx(&self, to: [u8; 20], auths: Vec<Eip7702Authorization>) -> VmTransaction {
        let from = address(&self.sender).to_vec();
        let nonce = self.state.get_nonce(&from);
        VmTransaction::new(
            from,
            Some(to.to_vec()),
            0,
            vec![],
            300_000,
            GAS_PRICE,
            nonce,
            VmType::Evm,
            CHAIN,
        )
        .with_authorization_list(auths)
    }

    async fn run(&mut self, to: [u8; 20], auths: Vec<Eip7702Authorization>) -> ExecutionResult {
        let tx = self.tx(to, auths);
        self.rt
            .execute_transaction(&tx, &mut self.state)
            .await
            .expect("the transaction executes")
    }

    fn code(&self, a: [u8; 20]) -> Vec<u8> {
        self.state.get_code(&a).unwrap_or_default()
    }
}

// test_set_code_to_sstore: the authority runs the delegate's code in its
// own storage.
#[tokio::test]
async fn a_delegated_authority_runs_the_delegate_code_in_its_own_storage() {
    let mut w = World::new().await;
    let signer = key(2);
    let a = address(&signer);
    let r = w.run(a, vec![auth(&signer, [0xd0; 20], 0)]).await;
    assert!(r.success, "{:?}", r.revert_reason);
    assert_eq!(w.code(a), designator([0xd0; 20]));
    assert_eq!(w.state.get_nonce(&a), 1);
    let slot = w.state.get_storage(&a, &[0u8; 32]).expect("slot 0 written");
    assert_eq!(slot.last(), Some(&0x2a));
    assert!(
        w.state.get_storage(&[0xd0; 20], &[0u8; 32]).is_none(),
        "the delegate's own storage is untouched"
    );
}

// test_gas_cost: every authorization costs PER_EMPTY_ACCOUNT_COST in
// intrinsic gas, whether it is valid or not.
#[tokio::test]
async fn intrinsic_gas_charges_every_authorization() {
    let mut w = World::new().await;
    let fresh = key(3);
    let r = w.run(PLAIN, vec![auth(&fresh, [0xd0; 20], 0)]).await;
    assert!(r.success);
    assert_eq!(r.gas_used, 21_000 + PER_EMPTY_ACCOUNT_COST);

    let wrong_nonce = key(4);
    let r = w
        .run(
            PLAIN,
            vec![
                auth(&key(5), [0xd0; 20], 0),
                auth(&wrong_nonce, [0xd0; 20], 9),
            ],
        )
        .await;
    assert!(r.success);
    assert_eq!(
        r.gas_used,
        21_000 + 2 * PER_EMPTY_ACCOUNT_COST,
        "the skipped authorization is still paid for"
    );

    assert_eq!(
        intrinsic_gas(&[], false, &[], 3),
        21_000 + 3 * PER_EMPTY_ACCOUNT_COST
    );
    assert_eq!(
        intrinsic_gas(&[], false, &[([1; 20], vec![[2; 32]])], 1),
        21_000 + PER_EMPTY_ACCOUNT_COST + 2_400 + 1_900
    );
    // EIP-7623: 100 non-zero calldata bytes (400 tokens) cost more as the
    // floor (21000 + 10 * 400) than as standard calldata (21000 + 4 * 400).
    assert_eq!(intrinsic_gas(&[1u8; 100], false, &[], 0), 25_000);
}

// test_gas_cost (existing authority): an authority already in the state
// refunds PER_EMPTY_ACCOUNT_COST - PER_AUTH_BASE_COST, under the 1/5 cap.
#[tokio::test]
async fn an_existing_authority_refunds_part_of_its_cost_under_the_cap() {
    let mut w = World::new().await;
    let existing = key(6);
    w.state.set_balance(&address(&existing), 1);
    let r = w.run(PLAIN, vec![auth(&existing, [0xd0; 20], 0)]).await;
    assert!(r.success);
    let spent = 21_000 + PER_EMPTY_ACCOUNT_COST;
    let refund = (PER_EMPTY_ACCOUNT_COST - PER_AUTH_BASE_COST).min(spent / 5);
    assert_eq!(r.gas_used, spent - refund);

    let (empty, existing2) = (key(7), key(8));
    w.state.set_balance(&address(&existing2), 1);
    let r = w
        .run(
            PLAIN,
            vec![auth(&empty, [0xd0; 20], 0), auth(&existing2, [0xd0; 20], 0)],
        )
        .await;
    let spent = 21_000 + 2 * PER_EMPTY_ACCOUNT_COST;
    assert_eq!(
        r.gas_used,
        spent - (PER_EMPTY_ACCOUNT_COST - PER_AUTH_BASE_COST).min(spent / 5)
    );
}

// test_valid_tx_invalid_chain_id, test_valid_tx_invalid_auth_signature,
// test_set_code_to_non_empty_storage / account with code, nonce mismatch,
// nonce 2**64-1: each invalid authorization is skipped; the transaction and
// the valid authorizations beside it still apply.
#[tokio::test]
async fn invalid_authorizations_are_skipped_and_the_transaction_runs() {
    let mut w = World::new().await;
    let good = key(10);
    let (other_chain, wide_chain, bad_nonce, max_nonce, has_code, high_s, bad_parity) = (
        key(11),
        key(12),
        key(13),
        key(14),
        key(15),
        key(16),
        key(17),
    );
    w.state.set_code(&address(&has_code), vec![0x00]);
    w.state.set_nonce(&address(&max_nonce), u64::MAX);

    let mut high = auth(&high_s, [0xd0; 20], 0);
    let s = U256::from_be_slice(&high.signature[32..64]);
    let flipped = U256::from_be_bytes(SECP256K1_N) - s;
    high.signature[32..64].copy_from_slice(&flipped.to_be_bytes::<32>());
    high.signature[64] ^= 1;
    let mut parity = auth(&bad_parity, [0xd0; 20], 0);
    parity.signature[64] = 2;

    let auths = vec![
        sign(&other_chain, U256::from(CHAIN + 1), [0xd0; 20], 0),
        sign(&wide_chain, U256::from(1u8) << 64usize, [0xd0; 20], 0),
        auth(&bad_nonce, [0xd0; 20], 1),
        auth(&max_nonce, [0xd0; 20], u64::MAX),
        auth(&has_code, [0xd0; 20], 0),
        high,
        parity,
        auth(&good, [0xd0; 20], 0),
    ];
    let n = auths.len() as u64;
    let r = w.run(PLAIN, auths).await;
    assert!(r.success, "{:?}", r.revert_reason);
    // Only the valid authority could refund, and it did not exist.
    assert_eq!(r.gas_used, 21_000 + n * PER_EMPTY_ACCOUNT_COST);

    assert_eq!(w.code(address(&good)), designator([0xd0; 20]));
    assert_eq!(w.state.get_nonce(&address(&good)), 1);
    for k in [&other_chain, &wide_chain, &bad_nonce, &high_s, &bad_parity] {
        assert!(
            w.code(address(k)).is_empty(),
            "a skipped authorization delegated"
        );
        assert_eq!(
            w.state.get_nonce(&address(k)),
            0,
            "a skipped authorization spent a nonce"
        );
    }
    assert_eq!(
        w.code(address(&has_code)),
        vec![0x00],
        "code that is not a delegation is kept"
    );
    assert_eq!(w.state.get_nonce(&address(&max_nonce)), u64::MAX);
    assert_eq!(
        w.state.get_nonce(&address(&w.sender)),
        1,
        "the sender's nonce is spent once"
    );
}

// test_set_code_multiple_valid_authorization_tuples_same_signer_increasing_nonce
// and ..._same_nonce: each valid tuple applies in order, the last wins; a
// repeated nonce is stale by the time it is reached.
#[tokio::test]
async fn one_signer_several_tuples_apply_in_order() {
    let mut w = World::new().await;
    let k = key(20);
    let a = address(&k);
    let r = w
        .run(
            PLAIN,
            vec![
                auth(&k, [0xd0; 20], 0),
                auth(&k, [0xd1; 20], 1),
                auth(&k, [0xd2; 20], 2),
            ],
        )
        .await;
    assert!(r.success);
    assert_eq!(w.code(a), designator([0xd2; 20]));
    assert_eq!(w.state.get_nonce(&a), 3);

    let k = key(21);
    let a = address(&k);
    w.run(
        PLAIN,
        vec![auth(&k, [0xd0; 20], 0), auth(&k, [0xd1; 20], 0)],
    )
    .await;
    assert_eq!(w.code(a), designator([0xd0; 20]));
    assert_eq!(w.state.get_nonce(&a), 1);
}

// test_self_sponsored_set_code: the sender's own authorization carries the
// nonce after the transaction's, and both are spent.
#[tokio::test]
async fn a_self_sponsored_authorization_spends_the_next_nonce() {
    let mut w = World::new().await;
    let me = address(&w.sender);
    let mine = auth(&w.sender, [0xd0; 20], 1);
    let r = w.run(me, vec![mine]).await;
    assert!(r.success, "{:?}", r.revert_reason);
    assert_eq!(w.code(me), designator([0xd0; 20]));
    assert_eq!(w.state.get_nonce(&me), 2);
    assert_eq!(
        w.state
            .get_storage(&me, &[0u8; 32])
            .and_then(|v| v.last().copied()),
        Some(0x2a)
    );

    // Signed for the transaction's own nonce, it is stale once the
    // transaction has spent it: skipped, one nonce spent.
    let mut w = World::new().await;
    let me = address(&w.sender);
    let stale = auth(&w.sender, [0xd0; 20], 0);
    assert!(w.run(PLAIN, vec![stale]).await.success);
    assert!(w.code(me).is_empty());
    assert_eq!(w.state.get_nonce(&me), 1);
}

// test_set_code_all_invalid_authorization_tuples with chain id 0, and
// test_reset_code: chain id 0 is valid everywhere; delegating to the zero
// address clears the code.
#[tokio::test]
async fn chain_id_zero_applies_and_the_zero_address_clears_a_delegation() {
    let mut w = World::new().await;
    let k = key(30);
    let a = address(&k);
    assert!(
        w.run(PLAIN, vec![sign(&k, U256::ZERO, [0xd0; 20], 0)])
            .await
            .success
    );
    assert_eq!(w.code(a), designator([0xd0; 20]));
    assert!(w.run(PLAIN, vec![auth(&k, [0u8; 20], 1)]).await.success);
    assert!(w.code(a).is_empty(), "delegation not cleared");
    assert_eq!(w.state.get_nonce(&a), 2);
}

// test_set_code_to_self_destruct / revert cases: a delegation is applied
// before execution and stands when the call reverts.
#[tokio::test]
async fn a_delegation_outlasts_a_reverting_call() {
    let mut w = World::new().await;
    let k = key(40);
    let a = address(&k);
    let tx = w.tx(a, vec![auth(&k, [0xde; 20], 0)]);
    let mut fees = BlockFees::default();
    let outcome = execute_in_block(&w.rt, &mut w.state, &tx, 0, &mut fees).await;
    assert!(
        matches!(outcome, TxOutcome::Reverted { .. }),
        "the delegate reverts"
    );
    assert_eq!(w.code(a), designator([0xde; 20]));
    assert_eq!(w.state.get_nonce(&a), 1);
    assert_eq!(w.state.get_nonce(&address(&w.sender)), 1);
}

/// The block and receipt bloom is the Ethereum one: the same bits as the
/// EVM's own implementation for the same logs.
#[test]
fn the_logs_bloom_matches_the_evm_reference() {
    use revm::primitives::alloy_primitives::{Bloom, Log, LogData};
    let logs: Vec<([u8; 20], Vec<[u8; 32]>)> = vec![
        ([0x11; 20], vec![[0xaa; 32], [0xbb; 32]]),
        ([0x22; 20], vec![]),
        ([0x33; 20], vec![[0x01; 32]]),
    ];
    let mut reference = Bloom::ZERO;
    let mut ours = tenzro_types::LogsBloom::default();
    for (a, topics) in &logs {
        let log = Log {
            address: (*a).into(),
            data: LogData::new_unchecked(
                topics.iter().map(|t| (*t).into()).collect(),
                Default::default(),
            ),
        };
        reference.accrue_log(&log);
        ours.accrue_log(a, topics);
    }
    assert_eq!(ours.0, reference.0.0);
    assert!(ours.may_contain(&[0x11; 20]) && ours.may_contain(&[0xaa; 32]));
    assert!(!tenzro_types::LogsBloom::default().may_contain(&[0x11; 20]));
}
