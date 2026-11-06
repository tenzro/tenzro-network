//! Tenzro precompiles reached through real entry points: transactions via
//! `MultiVmRuntime::execute_transaction`, and read-only calls via
//! `MultiVmRuntime::call` (the `eth_call` path).

use std::sync::Arc;

use tenzro_vm::precompiles::{
    PRECOMPILE_NFT_FACTORY, PRECOMPILE_RANDOMNESS_BEACON, PRECOMPILE_TEE_VERIFY,
    PRECOMPILE_TNZO_BRIDGE, PRECOMPILE_TOKEN_FACTORY, PRECOMPILE_ZK_VERIFY, SELECTOR_RANDOM,
    SELECTOR_STATEMENT_SYSTEMS, compute_zk_commitment, zk_statement_count_slot,
};
use tenzro_vm::traits::VmState;
use tenzro_vm::{
    ContractCall, ExecutionResult, MultiVmRuntime, StateAdapter, VmConfig, VmTransaction, VmType,
};

const CHAIN: u64 = 1337;
const GAS_PRICE: u128 = 1_000_000_000;
const GAS_LIMIT: u64 = 3_000_000;
const TEN_TNZO: u128 = 10_000_000_000_000_000_000;
const ONE_TNZO: u128 = 1_000_000_000_000_000_000;
const BLOCK: u64 = 100;
const BLOCK_MS: i64 = 1_700_000_000_000;

fn word(v: u128) -> Vec<u8> {
    let mut w = vec![0u8; 32];
    w[16..].copy_from_slice(&v.to_be_bytes());
    w
}
fn addr_word(a: &[u8; 20]) -> Vec<u8> {
    let mut w = vec![0u8; 32];
    w[12..].copy_from_slice(a);
    w
}
fn dyn_bytes(b: &[u8]) -> Vec<u8> {
    let mut out = word(b.len() as u128);
    out.extend_from_slice(b);
    out.resize(32 + b.len().div_ceil(32) * 32, 0);
    out
}
fn call_data(sel: [u8; 4], args: &[Vec<u8>]) -> Vec<u8> {
    let mut d = sel.to_vec();
    for a in args {
        d.extend_from_slice(a);
    }
    d
}
fn sel(sig: &str) -> [u8; 4] {
    use sha3::{Digest, Keccak256};
    let h = Keccak256::digest(sig.as_bytes());
    [h[0], h[1], h[2], h[3]]
}

async fn runtime() -> MultiVmRuntime {
    MultiVmRuntime::new(VmConfig::default()).await.unwrap()
}

fn evm_tx(from: [u8; 20], to: [u8; 20], data: Vec<u8>, nonce: u64, height: u64) -> VmTransaction {
    VmTransaction::new(
        from.to_vec(),
        Some(to.to_vec()),
        0,
        data,
        GAS_LIMIT,
        GAS_PRICE,
        nonce,
        VmType::Evm,
        CHAIN,
    )
    .with_block_height(height)
    .with_block_timestamp_ms(BLOCK_MS + (height as i64 - BLOCK as i64) * 1000)
}

async fn send(
    rt: &MultiVmRuntime,
    state: &mut StateAdapter,
    from: [u8; 20],
    to: [u8; 20],
    data: Vec<u8>,
) -> ExecutionResult {
    let nonce = state.get_nonce(&from);
    rt.execute_transaction(&evm_tx(from, to, data, nonce, BLOCK), state)
        .await
        .unwrap()
}

fn sum(state: &StateAdapter, accounts: &[&[u8]]) -> u128 {
    accounts.iter().map(|a| state.get_balance(a)).sum()
}

/// Deploy code that copies its calldata to `target` with STATICCALL and
/// stores the first returned word at slot 0 and the call's success at slot 1.
fn deploy_static_caller(state: &mut StateAdapter, at: [u8; 20], target: [u8; 20]) {
    let mut code = vec![0x36, 0x60, 0x00, 0x60, 0x00, 0x37]; // CALLDATACOPY(0,0,size)
    code.extend_from_slice(&[0x60, 0x20, 0x60, 0x00, 0x36, 0x60, 0x00, 0x73]);
    code.extend_from_slice(&target);
    code.extend_from_slice(&[0x5a, 0xfa]); // GAS STATICCALL
    code.extend_from_slice(&[0x60, 0x01, 0x55]); // SSTORE(1, success)
    code.extend_from_slice(&[0x60, 0x00, 0x51, 0x60, 0x00, 0x55, 0x00]); // SSTORE(0, mload 0)
    state.set_code(&at, code);
}

fn storage_word(state: &StateAdapter, addr: &[u8; 20], slot: u8) -> [u8; 32] {
    let mut key = [0u8; 32];
    key[31] = slot;
    let mut out = [0u8; 32];
    if let Some(v) = state.get_storage(addr, &key) {
        out.copy_from_slice(&v);
    }
    out
}

const ALICE: [u8; 20] = [0xA1; 20];
const BOB: [u8; 20] = [0xB0; 20];
const MALLORY: [u8; 20] = [0x66; 20];

fn funded() -> StateAdapter {
    let mut s = StateAdapter::new();
    for a in [ALICE, BOB, MALLORY] {
        s.set_balance(&a, TEN_TNZO);
    }
    s
}

#[tokio::test]
async fn evm_fee_is_exactly_gas_times_price_and_no_beneficiary_is_credited() {
    let rt = runtime().await;
    let mut state = funded();
    let coinbase = [0u8; 20];
    let before = sum(&state, &[&ALICE, &BOB, &coinbase]);
    let tx = VmTransaction::new(
        ALICE.to_vec(),
        Some(BOB.to_vec()),
        ONE_TNZO,
        vec![],
        21_000,
        GAS_PRICE,
        0,
        VmType::Evm,
        CHAIN,
    )
    .with_block_height(BLOCK);
    let r = rt.execute_transaction(&tx, &mut state).await.unwrap();
    assert!(r.success);
    let after = sum(&state, &[&ALICE, &BOB, &coinbase]);
    assert_eq!(before - after, r.gas_used as u128 * GAS_PRICE);
    assert_eq!(state.get_balance(&coinbase), 0);
}

#[tokio::test]
async fn block_number_and_timestamp_come_from_the_block() {
    let rt = runtime().await;
    let mut state = funded();
    let contract = [0xC1; 20];
    // NUMBER SSTORE(0); TIMESTAMP SSTORE(1); STOP
    state.set_code(
        &contract,
        vec![0x43, 0x60, 0x00, 0x55, 0x42, 0x60, 0x01, 0x55, 0x00],
    );
    let r = send(&rt, &mut state, ALICE, contract, vec![]).await;
    assert!(r.success);
    assert_eq!(
        storage_word(&state, &contract, 0)[24..],
        BLOCK.to_be_bytes()
    );
    assert_eq!(
        storage_word(&state, &contract, 1)[24..],
        ((BLOCK_MS / 1000) as u64).to_be_bytes()
    );
}

#[tokio::test]
async fn wtnzo_pointer_moves_native_balance_inside_a_transaction() {
    let rt = runtime().await;
    let mut state = funded();
    let before = sum(&state, &[&ALICE, &BOB, &PRECOMPILE_TNZO_BRIDGE]);
    let data = call_data(
        sel("transfer(address,uint256)"),
        &[addr_word(&BOB), word(ONE_TNZO)],
    );
    let r = send(&rt, &mut state, ALICE, PRECOMPILE_TNZO_BRIDGE, data).await;
    assert!(r.success, "{:?}", r.revert_reason);
    assert_eq!(state.get_balance(&BOB), TEN_TNZO + ONE_TNZO);
    let after = sum(&state, &[&ALICE, &BOB, &PRECOMPILE_TNZO_BRIDGE]);
    assert_eq!(before - after, r.gas_used as u128 * GAS_PRICE);
    // Emits an ERC-20 Transfer log.
    assert!(!r.logs.is_empty());
}

#[tokio::test]
async fn wtnzo_transfer_from_without_allowance_is_refused() {
    let rt = runtime().await;
    let mut state = funded();
    let data = call_data(
        sel("transferFrom(address,address,uint256)"),
        &[addr_word(&ALICE), addr_word(&MALLORY), word(ONE_TNZO)],
    );
    let r = send(&rt, &mut state, MALLORY, PRECOMPILE_TNZO_BRIDGE, data).await;
    assert!(!r.success);
    assert_eq!(state.get_balance(&ALICE), TEN_TNZO);
}

#[tokio::test]
async fn wtnzo_transfer_from_spends_the_allowance() {
    let rt = runtime().await;
    let mut state = funded();
    let approve = call_data(
        sel("approve(address,uint256)"),
        &[addr_word(&BOB), word(ONE_TNZO)],
    );
    assert!(
        send(&rt, &mut state, ALICE, PRECOMPILE_TNZO_BRIDGE, approve)
            .await
            .success
    );
    let pull = call_data(
        sel("transferFrom(address,address,uint256)"),
        &[addr_word(&ALICE), addr_word(&BOB), word(ONE_TNZO)],
    );
    assert!(
        send(&rt, &mut state, BOB, PRECOMPILE_TNZO_BRIDGE, pull.clone())
            .await
            .success
    );
    // The allowance is spent: a second pull is refused.
    assert!(
        !send(&rt, &mut state, BOB, PRECOMPILE_TNZO_BRIDGE, pull)
            .await
            .success
    );
}

#[tokio::test]
async fn eth_call_refuses_state_changes_and_persists_nothing() {
    let rt = runtime().await;
    let state = funded();
    let transfer = call_data(
        sel("transfer(address,uint256)"),
        &[addr_word(&BOB), word(ONE_TNZO)],
    );
    let call = ContractCall::new(
        ALICE.to_vec(),
        PRECOMPILE_TNZO_BRIDGE.to_vec(),
        transfer,
        0,
        GAS_LIMIT,
        VmType::Evm,
    )
    .at_block(BLOCK, BLOCK_MS);
    let r = rt.call(&call, &state).await.unwrap();
    assert!(
        !r.success,
        "a state-changing selector must be refused on the read-only path"
    );
    assert_eq!(state.get_balance(&ALICE), TEN_TNZO);
    assert_eq!(state.get_balance(&BOB), TEN_TNZO);

    // A read on the same path works and sees committed state.
    let bal = call_data(sel("balanceOf(address)"), &[addr_word(&BOB)]);
    let call = ContractCall::new(
        ALICE.to_vec(),
        PRECOMPILE_TNZO_BRIDGE.to_vec(),
        bal,
        0,
        GAS_LIMIT,
        VmType::Evm,
    );
    let r = rt.call(&call, &state).await.unwrap();
    assert!(r.success);
    assert_eq!(r.output, word(TEN_TNZO));
}

#[tokio::test]
async fn eth_call_cannot_move_an_nft() {
    let rt = runtime().await;
    let mut state = funded();
    let (collection, token) = create_and_mint(&rt, &mut state, ALICE, ALICE).await;
    let steal = call_data(
        sel("transferNft(bytes32,address,uint256)"),
        &[collection.to_vec(), addr_word(&MALLORY), word(token)],
    );
    let call = ContractCall::new(
        ALICE.to_vec(),
        PRECOMPILE_NFT_FACTORY.to_vec(),
        steal,
        0,
        GAS_LIMIT,
        VmType::Evm,
    );
    let r = rt.call(&call, &state).await.unwrap();
    assert!(!r.success);
    assert_eq!(owner_of(&rt, &state, &collection, token).await, ALICE);
}

async fn create_and_mint(
    rt: &MultiVmRuntime,
    state: &mut StateAdapter,
    creator: [u8; 20],
    to: [u8; 20],
) -> ([u8; 32], u128) {
    let name = dyn_bytes(b"Tenzro Cats");
    let symbol = dyn_bytes(b"TCAT");
    let mut args = word(96);
    args.extend(word(96 + name.len() as u128));
    args.extend(word(0));
    args.extend(name);
    args.extend(symbol);
    let r = send(
        rt,
        state,
        creator,
        PRECOMPILE_NFT_FACTORY,
        call_data(sel("createCollection(string,string,uint8)"), &[args]),
    )
    .await;
    assert!(r.success, "{:?}", r.revert_reason);
    let mut collection = [0u8; 32];
    collection.copy_from_slice(&r.output);
    let token = 7u128;
    let mint = call_data(
        [0x40, 0xc1, 0x0f, 0x19],
        &[
            collection.to_vec(),
            addr_word(&to),
            word(token),
            word(128),
            dyn_bytes(b"ipfs://x"),
        ],
    );
    let r = send(rt, state, creator, PRECOMPILE_NFT_FACTORY, mint).await;
    assert!(r.success, "{:?}", r.revert_reason);
    (collection, token)
}

async fn owner_of(
    rt: &MultiVmRuntime,
    state: &StateAdapter,
    collection: &[u8; 32],
    token: u128,
) -> [u8; 20] {
    let data = call_data(
        [0x63, 0x52, 0x21, 0x1e],
        &[collection.to_vec(), word(token)],
    );
    let call = ContractCall::new(
        BOB.to_vec(),
        PRECOMPILE_NFT_FACTORY.to_vec(),
        data,
        0,
        GAS_LIMIT,
        VmType::Evm,
    );
    let r = rt.call(&call, state).await.unwrap();
    assert!(r.success);
    let mut a = [0u8; 20];
    a.copy_from_slice(&r.output[12..32]);
    a
}

#[tokio::test]
async fn nft_transfer_is_bound_to_the_real_sender() {
    let rt = runtime().await;
    let mut state = funded();
    let (collection, token) = create_and_mint(&rt, &mut state, ALICE, ALICE).await;

    // Mallory cannot move Alice's token.
    let steal = call_data(
        sel("transferNft(bytes32,address,uint256)"),
        &[collection.to_vec(), addr_word(&MALLORY), word(token)],
    );
    assert!(
        !send(&rt, &mut state, MALLORY, PRECOMPILE_NFT_FACTORY, steal)
            .await
            .success
    );
    assert_eq!(owner_of(&rt, &state, &collection, token).await, ALICE);

    // Mallory cannot mint into Alice's collection.
    let mint = call_data(
        [0x40, 0xc1, 0x0f, 0x19],
        &[
            collection.to_vec(),
            addr_word(&MALLORY),
            word(8),
            word(128),
            dyn_bytes(b""),
        ],
    );
    assert!(
        !send(&rt, &mut state, MALLORY, PRECOMPILE_NFT_FACTORY, mint)
            .await
            .success
    );

    // Alice can transfer her own token.
    let give = call_data(
        sel("transferNft(bytes32,address,uint256)"),
        &[collection.to_vec(), addr_word(&BOB), word(token)],
    );
    assert!(
        send(&rt, &mut state, ALICE, PRECOMPILE_NFT_FACTORY, give)
            .await
            .success
    );
    assert_eq!(owner_of(&rt, &state, &collection, token).await, BOB);
}

#[tokio::test]
async fn random_mint_uses_a_later_block_hash_the_minter_cannot_choose() {
    let rt = runtime().await;
    let store = Arc::new(tenzro_storage::MemoryStore::new());
    let mut state = StateAdapter::with_storage(store.clone() as Arc<dyn tenzro_storage::KvStore>);
    state.set_balance(&ALICE, TEN_TNZO);
    state.set_balance(&BOB, TEN_TNZO);
    let name = dyn_bytes(b"Rare");
    let mut args = word(96);
    args.extend(word(96 + name.len() as u128));
    args.extend(word(0));
    args.extend(name);
    args.extend(dyn_bytes(b"R"));
    let r = send(
        &rt,
        &mut state,
        ALICE,
        PRECOMPILE_NFT_FACTORY,
        call_data(sel("createCollection(string,string,uint8)"), &[args]),
    )
    .await;
    let collection = r.output.clone();

    let req = send(
        &rt,
        &mut state,
        ALICE,
        PRECOMPILE_NFT_FACTORY,
        call_data(
            sel("mintRandom(bytes32,address,uint256)"),
            &[collection.clone(), addr_word(&BOB), word(1000)],
        ),
    )
    .await;
    assert!(req.success, "{:?}", req.revert_reason);
    let request_id = req.output.clone();
    let fulfill = call_data(sel("fulfillRandom(bytes32)"), &[request_id]);

    // Block N+1: its hash is not known yet.
    let nonce = state.get_nonce(&ALICE);
    let r = rt
        .execute_transaction(
            &evm_tx(
                ALICE,
                PRECOMPILE_NFT_FACTORY,
                fulfill.clone(),
                nonce,
                BLOCK + 1,
            ),
            &mut state,
        )
        .await
        .unwrap();
    assert!(!r.success);

    // Block N+2 with block N+1's hash committed.
    use tenzro_storage::KvStore;
    let mut key = b"height_hash:".to_vec();
    key.extend_from_slice(&(BLOCK + 1).to_be_bytes());
    store
        .put(tenzro_storage::CF_BLOCKS, &key, &[0x42; 32])
        .unwrap();
    let nonce = state.get_nonce(&BOB);
    let r = rt
        .execute_transaction(
            &evm_tx(
                BOB,
                PRECOMPILE_NFT_FACTORY,
                fulfill.clone(),
                nonce,
                BLOCK + 2,
            ),
            &mut state,
        )
        .await
        .unwrap();
    assert!(r.success, "{:?}", r.revert_reason);
    let mut coll = [0u8; 32];
    coll.copy_from_slice(&collection);
    let token = u128::from_be_bytes(r.output[16..32].try_into().unwrap());
    assert!(token < 1000);
    assert_eq!(owner_of(&rt, &state, &coll, token).await, BOB);

    // A request is fulfilled once.
    let nonce = state.get_nonce(&BOB);
    let r = rt
        .execute_transaction(
            &evm_tx(BOB, PRECOMPILE_NFT_FACTORY, fulfill, nonce, BLOCK + 2),
            &mut state,
        )
        .await
        .unwrap();
    assert!(!r.success);
}

#[tokio::test]
async fn contracts_reach_zk_verify_inside_transactions_and_it_reads_state() {
    let rt = runtime().await;
    let mut state = funded();
    let contract = [0xC2; 20];
    deploy_static_caller(&mut state, contract, PRECOMPILE_ZK_VERIFY);
    let statement = tenzro_zk::statement_commitment("settlement", &[vec![9; 32], vec![8; 32]]);
    let mut query = SELECTOR_STATEMENT_SYSTEMS.to_vec();
    query.extend_from_slice(&statement);

    let r = send(&rt, &mut state, ALICE, contract, query.clone()).await;
    assert!(r.success);
    assert_eq!(
        storage_word(&state, &contract, 1)[31],
        1,
        "the precompile must exist"
    );
    assert_eq!(
        storage_word(&state, &contract, 0),
        [0u8; 32],
        "nothing attested yet"
    );

    state.set_storage(
        &PRECOMPILE_ZK_VERIFY,
        &zk_statement_count_slot(&statement),
        word(2),
    );
    let r = send(&rt, &mut state, ALICE, contract, query.clone()).await;
    assert!(r.success);
    assert_eq!(
        storage_word(&state, &contract, 0)[31],
        2,
        "two proof systems attested in state"
    );

    let call = ContractCall::new(
        ALICE.to_vec(),
        PRECOMPILE_ZK_VERIFY.to_vec(),
        query,
        0,
        GAS_LIMIT,
        VmType::Evm,
    );
    assert_eq!(rt.call(&call, &state).await.unwrap().output, word(2));
}

#[tokio::test]
async fn attest_zk_proof_refuses_a_proof_that_does_not_verify() {
    let rt = runtime().await;
    let mut state = funded();
    let proof = tenzro_zk::Proof::new(
        vec![1, 2, 3],
        vec![vec![9; 32], vec![8; 32]],
        "settlement".to_string(),
    );
    let mut data = tenzro_vm::native::SELECTOR_ZK_ATTEST.to_vec();
    data.extend_from_slice(&bincode::serialize(&proof).unwrap());
    let tx = VmTransaction::new(
        ALICE.to_vec(),
        Some(vec![0u8; 20]),
        0,
        data.clone(),
        tenzro_vm::native::zk_attest_gas(data.len()),
        GAS_PRICE,
        0,
        VmType::Tenzro,
        CHAIN,
    );
    let r = rt.execute_transaction(&tx, &mut state).await;
    assert!(r.is_err() || !r.unwrap().success);
    assert!(!tenzro_vm::precompiles::zk_commitment_attested(
        &state,
        &compute_zk_commitment(&proof)
    ));
}

fn simulated_report(timestamp_ms: i64) -> Vec<u8> {
    let mut report = tenzro_types::AttestationReport {
        vendor: tenzro_types::TeeVendor::IntelTdx,
        attestation_data: vec![1; 64],
        certificates: vec![vec![2; 64]],
        timestamp: tenzro_types::Timestamp::new(timestamp_ms),
        ..Default::default()
    };
    report
        .metadata
        .insert("simulated".to_string(), "true".to_string());
    serde_json::to_vec(&serde_json::json!({
        "report": report,
        "expected_binding": vec![0u8; 64],
    }))
    .unwrap()
}

#[tokio::test]
async fn tee_verify_rejects_simulated_and_future_reports() {
    let rt = runtime().await;
    let mut state = funded();
    let contract = [0xC3; 20];
    deploy_static_caller(&mut state, contract, PRECOMPILE_TEE_VERIFY);
    // A fresh report in a block produced now, so that only the simulated
    // flag (or the future timestamp) can be the reason for refusal.
    let now_ms = tenzro_types::Timestamp::now().as_millis();
    for ts in [now_ms - 1000, now_ms + 60_000] {
        let nonce = state.get_nonce(&ALICE);
        let tx = evm_tx(ALICE, contract, simulated_report(ts), nonce, BLOCK)
            .with_block_timestamp_ms(now_ms);
        let r = rt.execute_transaction(&tx, &mut state).await.unwrap();
        assert!(r.success);
        assert_eq!(
            storage_word(&state, &contract, 1)[31],
            1,
            "TEE_VERIFY must exist"
        );
        assert_eq!(storage_word(&state, &contract, 0), [0u8; 32]);
    }
}

#[tokio::test]
async fn randomness_beacon_is_deterministic_and_advances_per_request() {
    let rt = runtime().await;
    let mut data = SELECTOR_RANDOM.to_vec();
    data.extend_from_slice(&[7u8; 32]);
    let mut a = funded();
    let mut b = funded();
    let r1 = send(
        &rt,
        &mut a,
        ALICE,
        PRECOMPILE_RANDOMNESS_BEACON,
        data.clone(),
    )
    .await;
    let r2 = send(
        &rt,
        &mut b,
        ALICE,
        PRECOMPILE_RANDOMNESS_BEACON,
        data.clone(),
    )
    .await;
    assert!(r1.success && r2.success);
    assert_eq!(
        r1.output, r2.output,
        "same state, same block: same output on every validator"
    );
    let r3 = send(&rt, &mut a, ALICE, PRECOMPILE_RANDOMNESS_BEACON, data).await;
    assert_ne!(r1.output, r3.output, "a second request draws a new output");
}

#[tokio::test]
async fn spl_transfer_to_an_evm_account_is_visible_through_wtnzo() {
    use tenzro_vm::svm::spl_adapter::SPL_TOKEN_PROGRAM_ID;
    let rt = runtime().await;
    let mut state = funded();
    let svm_signer = [0x77u8; 32];
    state.set_balance(&svm_signer, TEN_TNZO);
    let mut dest = [0u8; 32];
    dest[..20].copy_from_slice(&BOB);
    let before = sum(&state, &[&svm_signer, &BOB]);
    let tx = VmTransaction::new(
        svm_signer.to_vec(),
        Some(SPL_TOKEN_PROGRAM_ID.to_vec()),
        0,
        spl_transfer([svm_signer, dest, svm_signer], 1_000_000_000), // 1 TNZO in SPL units
        200_000,
        GAS_PRICE,
        0,
        VmType::Svm,
        CHAIN,
    );
    let r = rt.execute_transaction(&tx, &mut state).await.unwrap();
    assert!(r.success, "{:?}", r.revert_reason);
    let after = sum(&state, &[&svm_signer, &BOB]);
    assert_eq!(before - after, r.gas_used as u128 * GAS_PRICE);

    let bal = call_data(sel("balanceOf(address)"), &[addr_word(&BOB)]);
    let call = ContractCall::new(
        ALICE.to_vec(),
        PRECOMPILE_TNZO_BRIDGE.to_vec(),
        bal,
        0,
        GAS_LIMIT,
        VmType::Evm,
    );
    assert_eq!(
        rt.call(&call, &state).await.unwrap().output,
        word(TEN_TNZO + ONE_TNZO)
    );
}

fn spl_transfer(accounts: [[u8; 32]; 3], amount_spl: u64) -> Vec<u8> {
    let mut data = vec![3u8];
    for a in accounts {
        data.extend_from_slice(&a);
    }
    data.push(3u8);
    data.extend_from_slice(&amount_spl.to_le_bytes());
    data
}

#[tokio::test]
async fn spl_transfer_from_someone_elses_account_is_refused() {
    use tenzro_vm::svm::spl_adapter::SPL_TOKEN_PROGRAM_ID;
    let rt = runtime().await;
    let mut state = StateAdapter::new();
    let victim = [0x11u8; 32];
    let attacker = [0x22u8; 32];
    state.set_balance(&victim, TEN_TNZO);
    state.set_balance(&attacker, TEN_TNZO);
    let tx = VmTransaction::new(
        attacker.to_vec(),
        Some(SPL_TOKEN_PROGRAM_ID.to_vec()),
        0,
        spl_transfer([victim, attacker, attacker], 5_000_000_000),
        200_000,
        GAS_PRICE,
        0,
        VmType::Svm,
        CHAIN,
    );
    let r = rt.execute_transaction(&tx, &mut state).await.unwrap();
    assert!(!r.success);
    assert_eq!(state.get_balance(&victim), TEN_TNZO);
}

#[tokio::test]
async fn spl_transfer_to_self_costs_only_the_fee() {
    use tenzro_vm::svm::spl_adapter::SPL_TOKEN_PROGRAM_ID;
    let rt = runtime().await;
    let mut state = StateAdapter::new();
    let me = [0x33u8; 32];
    state.set_balance(&me, TEN_TNZO);
    let tx = VmTransaction::new(
        me.to_vec(),
        Some(SPL_TOKEN_PROGRAM_ID.to_vec()),
        0,
        spl_transfer([me, me, me], 5_000_000_000),
        200_000,
        GAS_PRICE,
        0,
        VmType::Svm,
        CHAIN,
    );
    let r = rt.execute_transaction(&tx, &mut state).await.unwrap();
    assert!(r.success, "{:?}", r.revert_reason);
    assert_eq!(
        state.get_balance(&me),
        TEN_TNZO - r.gas_used as u128 * GAS_PRICE
    );
}

#[tokio::test]
async fn token_factory_ledger_lives_in_state_and_binds_the_sender() {
    let rt = runtime().await;
    let mut state = funded();
    let name = dyn_bytes(b"Gold");
    let mut args = word(128);
    args.extend(word(128 + name.len() as u128));
    args.extend(word(18));
    args.extend(word(1_000));
    args.extend(name);
    args.extend(dyn_bytes(b"GLD"));
    let r = send(
        &rt,
        &mut state,
        ALICE,
        PRECOMPILE_TOKEN_FACTORY,
        call_data(sel("createToken(string,string,uint8,uint256)"), &[args]),
    )
    .await;
    assert!(r.success, "{:?}", r.revert_reason);
    let id = r.output.clone();
    let xfer = |amt: u128| {
        call_data(
            sel("transfer(bytes32,address,uint256)"),
            &[id.clone(), addr_word(&BOB), word(amt)],
        )
    };
    assert!(
        send(&rt, &mut state, ALICE, PRECOMPILE_TOKEN_FACTORY, xfer(400))
            .await
            .success
    );
    assert!(
        !send(&rt, &mut state, MALLORY, PRECOMPILE_TOKEN_FACTORY, xfer(1))
            .await
            .success
    );
    let bal = |who: [u8; 20]| {
        ContractCall::new(
            ALICE.to_vec(),
            PRECOMPILE_TOKEN_FACTORY.to_vec(),
            call_data(
                sel("balanceOf(bytes32,address)"),
                &[id.clone(), addr_word(&who)],
            ),
            0,
            GAS_LIMIT,
            VmType::Evm,
        )
    };
    assert_eq!(
        rt.call(&bal(ALICE), &state).await.unwrap().output,
        word(600)
    );
    assert_eq!(rt.call(&bal(BOB), &state).await.unwrap().output, word(400));
}

#[tokio::test]
async fn erc7943_views_and_the_erc20_facade_share_the_factory_ledger() {
    use tenzro_vm::evm::token_factory::{ERC7943_FUNCTIONS, interface_id};
    let rt = runtime().await;
    let mut state = funded();
    let name = dyn_bytes(b"Gold");
    let mut args = word(128);
    args.extend(word(128 + name.len() as u128));
    args.extend(word(18));
    args.extend(word(1_000));
    args.extend(name);
    args.extend(dyn_bytes(b"GLD"));
    let r = send(
        &rt,
        &mut state,
        ALICE,
        PRECOMPILE_TOKEN_FACTORY,
        call_data(sel("createToken(string,string,uint8,uint256)"), &[args]),
    )
    .await;
    assert!(r.success, "{:?}", r.revert_reason);
    let id = r.output.clone();
    let token: [u8; 32] = id.clone().try_into().unwrap();
    let view = |to: [u8; 20], data: Vec<u8>| {
        ContractCall::new(ALICE.to_vec(), to.to_vec(), data, 0, GAS_LIMIT, VmType::Evm)
    };

    let facade_word = rt
        .call(
            &view(
                PRECOMPILE_TOKEN_FACTORY,
                call_data(sel("facadeOf(bytes32)"), std::slice::from_ref(&id)),
            ),
            &state,
        )
        .await
        .unwrap()
        .output;
    let facade: [u8; 20] = facade_word[12..].try_into().unwrap();
    assert_eq!(
        facade,
        tenzro_vm::evm::token_factory::facade_address(&token)
    );

    // The facade is the token: ERC-20 metadata, balances and transfers.
    assert_eq!(
        rt.call(&view(facade, sel("decimals()").to_vec()), &state)
            .await
            .unwrap()
            .output,
        word(18)
    );
    assert_eq!(
        rt.call(&view(facade, sel("totalSupply()").to_vec()), &state)
            .await
            .unwrap()
            .output,
        word(1_000)
    );
    let r = send(
        &rt,
        &mut state,
        ALICE,
        facade,
        call_data(
            sel("transfer(address,uint256)"),
            &[addr_word(&BOB), word(150)],
        ),
    )
    .await;
    assert!(r.success, "{:?}", r.revert_reason);
    let r = send(
        &rt,
        &mut state,
        ALICE,
        PRECOMPILE_TOKEN_FACTORY,
        call_data(
            sel("transfer(bytes32,address,uint256)"),
            &[id.clone(), addr_word(&BOB), word(50)],
        ),
    )
    .await;
    assert!(r.success);
    let bal = |who: [u8; 20]| {
        view(
            facade,
            call_data(sel("balanceOf(address)"), &[addr_word(&who)]),
        )
    };
    assert_eq!(
        rt.call(&bal(BOB), &state).await.unwrap().output,
        word(200),
        "facade and factory move one balance"
    );
    assert_eq!(
        rt.call(&bal(ALICE), &state).await.unwrap().output,
        word(800)
    );

    // ERC-165 discovery of the ERC-7943 interface, on the facade and the factory.
    let mut iface = interface_id(&ERC7943_FUNCTIONS).to_vec();
    iface.resize(32, 0);
    for at in [facade, PRECOMPILE_TOKEN_FACTORY] {
        let out = rt
            .call(
                &view(
                    at,
                    call_data(sel("supportsInterface(bytes4)"), &[iface.clone()]),
                ),
                &state,
            )
            .await
            .unwrap()
            .output;
        assert_eq!(out, word(1));
    }

    // canTransfer through eth_call is the ledger's own verdict, before and after a halt.
    let can = |amount: u128| {
        view(
            facade,
            call_data(
                sel("canTransfer(address,address,uint256)"),
                &[addr_word(&BOB), addr_word(&ALICE), word(amount)],
            ),
        )
    };
    let ledger = |state: &StateAdapter, amount: u128| {
        tenzro_vm::token_ledger::can_transfer(
            &mut tenzro_vm::token_ledger::StateView(state),
            &token,
            &BOB,
            &ALICE,
            amount,
            BLOCK_MS,
        )
        .unwrap()
        .is_ok()
    };
    assert_eq!(
        rt.call(&can(10), &state).await.unwrap().output,
        word(u128::from(ledger(&state, 10)))
    );
    assert!(ledger(&state, 10));
    state.set_storage(
        &PRECOMPILE_TOKEN_FACTORY,
        &tenzro_vm::evm::precompile_host::slot_key(b"token/halted", &[&token]),
        tenzro_vm::evm::precompile_host::u128_to_word(1).to_vec(),
    );
    assert!(!ledger(&state, 10));
    assert_eq!(rt.call(&can(10), &state).await.unwrap().output, word(0));
    let r = send(
        &rt,
        &mut state,
        BOB,
        facade,
        call_data(
            sel("transfer(address,uint256)"),
            &[addr_word(&ALICE), word(1)],
        ),
    )
    .await;
    assert!(!r.success, "a halted token refuses through the facade");

    // A factory token has no issuer powers: the ERC-7943 writes refuse.
    let r = send(
        &rt,
        &mut state,
        ALICE,
        facade,
        call_data(
            sel("setFrozenTokens(address,uint256)"),
            &[addr_word(&BOB), word(5)],
        ),
    )
    .await;
    assert!(!r.success);
    let frozen = rt
        .call(
            &view(
                facade,
                call_data(sel("getFrozenTokens(address)"), &[addr_word(&BOB)]),
            ),
            &state,
        )
        .await
        .unwrap()
        .output;
    assert_eq!(frozen, word(0));
}
