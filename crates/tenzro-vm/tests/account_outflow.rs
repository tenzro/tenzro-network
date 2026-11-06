//! Opt-in outflow limits on a plain account: the cap per window holds
//! whatever path moves the funds, a queued release can be cancelled by the
//! owner's guardian before it unlocks, a loosening waits out the hold, and an
//! account with a policy takes no delegation.

use k256::ecdsa::SigningKey;
use revm::primitives::U256;
use sha3::{Digest, Keccak256};
use tenzro_vm::account_outflow::{Op, SELECTOR_ACCOUNT_OUTFLOW};
use tenzro_vm::ledger::{BlockFees, TxOutcome, execute_in_block};
use tenzro_vm::native::{SYSTEM_ADDRESS, governed_param_key};
use tenzro_vm::{
    Eip7702Authorization, ExecutionResult, MultiVmRuntime, StateAdapter, VmConfig, VmState,
    VmTransaction, VmType,
};

const CHAIN: u64 = 1337;
const E18: u128 = 1_000_000_000_000_000_000;
const T0: i64 = 1_700_000_000_000;
const HOUR: i64 = 3_600_000;
const DAY: u64 = 24 * 3_600_000;
const OWNER: [u8; 20] = [0xa1; 20];
const SHOP: [u8; 20] = [0xb1; 20];

struct World {
    rt: MultiVmRuntime,
    state: StateAdapter,
}

impl World {
    async fn new() -> Self {
        let rt = MultiVmRuntime::new(VmConfig::default()).await.unwrap();
        let mut state = StateAdapter::new();
        state.set_balance(&OWNER, 10 * E18);
        Self { rt, state }
    }

    async fn op(&mut self, from: [u8; 20], op: &Op, at: i64) -> ExecutionResult {
        let mut data = SELECTOR_ACCOUNT_OUTFLOW.to_vec();
        data.extend_from_slice(&serde_json::to_vec(op).unwrap());
        let nonce = self.state.get_nonce(&from);
        let mut tx = VmTransaction::new(
            from.to_vec(),
            Some(SYSTEM_ADDRESS.to_vec()),
            0,
            data,
            500_000,
            1_000_000_000,
            nonce,
            VmType::Tenzro,
            CHAIN,
        );
        tx.block_timestamp_ms = Some(at);
        let r = self
            .rt
            .execute_transaction(&tx, &mut self.state)
            .await
            .expect("the operation executes");
        if !r.success {
            eprintln!("operation refused: {:?}", r.revert_reason);
        }
        r
    }

    /// An EVM value transfer in a block, which undoes a failed one.
    async fn send(&mut self, from: [u8; 20], to: [u8; 20], value: u128, at: i64) -> TxOutcome {
        let nonce = self.state.get_nonce(&from);
        let mut tx = VmTransaction::new(
            from.to_vec(),
            Some(to.to_vec()),
            value,
            vec![],
            21_000,
            1_000_000_000,
            nonce,
            VmType::Evm,
            CHAIN,
        );
        tx.block_timestamp_ms = Some(at);
        let mut fees = BlockFees::default();
        execute_in_block(&self.rt, &mut self.state, &tx, 0, &mut fees).await
    }

    fn govern(&mut self, name: &str, value: u64) {
        self.state.set_storage(
            &SYSTEM_ADDRESS,
            governed_param_key(name).as_bytes(),
            value.to_le_bytes().to_vec(),
        );
    }
}

fn set(cap: u128, hold_ms: u64, guardian: Option<String>) -> Op {
    Op::Set {
        account: OWNER.to_vec(),
        window_ms: DAY,
        cap,
        hold_ms,
        guardian,
    }
}

fn kept(o: &TxOutcome) -> bool {
    matches!(o, TxOutcome::Applied { .. })
}

#[tokio::test]
async fn a_stolen_key_drains_at_most_the_cap_per_window() {
    let mut w = World::new().await;
    assert!(w.op(OWNER, &set(E18, HOUR as u64, None), T0).await.success);
    let o = w.send(OWNER, SHOP, E18 / 2, T0 + 1000).await;
    assert!(kept(&o), "{o:?}");
    assert_eq!(w.state.get_balance(&SHOP), E18 / 2);
    let o = w.send(OWNER, SHOP, E18, T0 + 2000).await;
    assert!(!kept(&o), "past the cap: {o:?}");
    assert_eq!(
        w.state.get_balance(&SHOP),
        E18 / 2,
        "the refused send was undone"
    );
    // A repeat of small sends cannot add up past the cap either.
    let mut sent = E18 / 2;
    for i in 0..50 {
        if kept(&w.send(OWNER, SHOP, E18 / 10, T0 + 3000 + i).await) {
            sent += E18 / 10;
        }
    }
    assert!(sent <= E18, "{sent} left against a cap of {E18}");
    // The next window opens a new allowance.
    let o = w.send(OWNER, SHOP, E18 / 2, T0 + DAY as i64 + 5000).await;
    assert!(kept(&o), "{o:?}");
}

#[tokio::test]
async fn an_account_without_a_policy_is_not_limited() {
    let mut w = World::new().await;
    let o = w.send(OWNER, SHOP, 9 * E18, T0).await;
    assert!(kept(&o), "{o:?}");
}

#[tokio::test]
async fn a_policy_account_takes_no_delegation_so_no_sweeper_runs_as_it() {
    let mut w = World::new().await;
    // The owner's key signs an authorization for a sweeper; a policy refuses it.
    let key = SigningKey::from_slice(&[0x31; 32]).unwrap();
    let point = key.verifying_key().to_sec1_point(false);
    let addr: [u8; 20] = Keccak256::digest(&point.as_bytes()[1..])[12..]
        .try_into()
        .unwrap();
    w.state.set_balance(&addr, 5 * E18);
    w.state.set_balance(&SHOP, E18);
    let mut a = Eip7702Authorization {
        chain_id: U256::from(CHAIN),
        delegate_address: vec![0xd0; 20],
        nonce: 0,
        signature: vec![],
    };
    let (sig, rid) = key.sign_prehash_recoverable(&a.signing_hash()).unwrap();
    a.signature = sig.to_bytes().to_vec();
    a.signature.push(rid.to_byte());
    let mut policy = set(E18, HOUR as u64, None);
    if let Op::Set { account, .. } = &mut policy {
        *account = addr.to_vec();
    }
    assert!(w.op(addr, &policy, T0).await.success);
    let mut tx = VmTransaction::new(
        SHOP.to_vec(),
        Some(vec![0x77; 20]),
        0,
        vec![],
        2_000_000,
        1_000_000_000,
        0,
        VmType::Evm,
        CHAIN,
    )
    .with_authorization_list(vec![a]);
    tx.block_timestamp_ms = Some(T0 + 10);
    let e =
        w.rt.execute_transaction(&tx, &mut w.state)
            .await
            .unwrap_err();
    assert!(e.to_string().contains("outflow policy"), "{e}");
}

#[tokio::test]
async fn a_release_waits_for_the_hold_and_only_the_account_claims_it() {
    let mut w = World::new().await;
    w.op(OWNER, &set(E18, HOUR as u64, None), T0).await;
    let req = |amount| Op::RequestRelease {
        account: OWNER.to_vec(),
        to: SHOP.to_vec(),
        amount,
    };
    assert!(w.op(OWNER, &req(5 * E18), T0 + 10).await.success);
    let claim = |id| Op::ClaimRelease {
        account: OWNER.to_vec(),
        id,
        approval: None,
    };
    assert!(
        !w.op(OWNER, &claim(0), T0 + HOUR / 2).await.success,
        "too early"
    );
    assert!(
        !w.op(SHOP, &claim(0), T0 + 2 * HOUR).await.success,
        "a stranger"
    );
    assert_eq!(w.state.get_balance(&SHOP), 0);
    assert!(w.op(OWNER, &claim(0), T0 + 2 * HOUR).await.success);
    assert_eq!(w.state.get_balance(&SHOP), 5 * E18);
}

#[tokio::test]
async fn a_loosening_is_queued_for_the_hold_and_then_takes_effect() {
    let mut w = World::new().await;
    w.op(OWNER, &set(E18, HOUR as u64, None), T0).await;
    assert!(
        w.op(OWNER, &set(100 * E18, HOUR as u64, None), T0 + 10)
            .await
            .success
    );
    let o = w.send(OWNER, SHOP, 2 * E18, T0 + 20).await;
    assert!(!kept(&o), "the old cap still holds during the hold: {o:?}");
    let o = w.send(OWNER, SHOP, 2 * E18, T0 + HOUR + 100).await;
    assert!(kept(&o), "after the hold the new cap is in force: {o:?}");
}

#[tokio::test]
async fn the_floors_on_hold_and_window_are_governed() {
    let mut w = World::new().await;
    assert!(!w.op(OWNER, &set(E18, 1000, None), T0).await.success);
    w.govern("accounts.outflow_min_hold_ms", 1000);
    assert!(w.op(OWNER, &set(E18, 1000, None), T0).await.success);
}
