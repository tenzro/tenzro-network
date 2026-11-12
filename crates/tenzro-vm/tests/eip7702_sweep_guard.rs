//! The sweep shape of a stolen key: one key signs a run of EIP-7702
//! authorizations (consecutive nonces, every chain) and lands them in one
//! set-code transaction. Admission refuses it before any entry is applied;
//! the limits are governed parameters, so governance can tighten or relax
//! them and these tests move with the stored value.

use k256::ecdsa::SigningKey;
use revm::primitives::U256;
use sha3::{Digest, Keccak256};
use tenzro_vm::native::{SYSTEM_ADDRESS, governed_param_key};
use tenzro_vm::{
    Eip7702Authorization, MultiVmRuntime, StateAdapter, VmConfig, VmState, VmTransaction, VmType,
};

const CHAIN: u64 = 1337;

fn key(seed: u8) -> SigningKey {
    SigningKey::from_slice(&[seed; 32]).unwrap()
}

fn address(k: &SigningKey) -> [u8; 20] {
    let point = k.verifying_key().to_sec1_point(false);
    let h = Keccak256::digest(&point.as_bytes()[1..]);
    h[12..].try_into().unwrap()
}

fn sign(k: &SigningKey, chain_id: U256, nonce: u64) -> Eip7702Authorization {
    let mut a = Eip7702Authorization {
        chain_id,
        delegate_address: vec![0xd0; 20],
        nonce,
        signature: vec![],
    };
    let (sig, rid) = k.sign_prehash_recoverable(&a.signing_hash()).unwrap();
    a.signature = sig.to_bytes().to_vec();
    a.signature.push(rid.to_byte());
    a
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
        Self { rt, state, sender }
    }

    fn govern(&mut self, name: &str, value: u64) {
        self.state.set_storage(
            &SYSTEM_ADDRESS,
            governed_param_key(name).as_bytes(),
            value.to_le_bytes().to_vec(),
        );
    }

    async fn submit(&mut self, auths: Vec<Eip7702Authorization>) -> Result<bool, String> {
        let from = address(&self.sender).to_vec();
        let nonce = self.state.get_nonce(&from);
        let tx = VmTransaction::new(
            from,
            Some(vec![0x77; 20]),
            0,
            vec![],
            2_000_000,
            1_000_000_000,
            nonce,
            VmType::Evm,
            CHAIN,
        )
        .with_authorization_list(auths);
        match self.rt.execute_transaction(&tx, &mut self.state).await {
            Ok(r) => refusal(r).map(|r| r.success),
            Err(e) => Err(e.to_string()),
        }
    }
}

/// A transaction a rule refuses is final: it spends its nonce, pays the base
/// gas and comes back as a failed result carrying the rule's message.
fn refusal(r: tenzro_vm::ExecutionResult) -> Result<tenzro_vm::ExecutionResult, String> {
    match r.revert_reason.as_deref() {
        Some(reason) if !r.success && reason.starts_with("Invalid transaction") => {
            Err(reason.to_string())
        }
        _ => Ok(r),
    }
}

#[tokio::test]
async fn fifty_authorizations_over_consecutive_nonces_are_refused() {
    let mut w = World::new().await;
    let thief = key(9);
    let batch: Vec<_> = (0..50)
        .map(|n| sign(&thief, U256::from(CHAIN), n))
        .collect();
    let e = w.submit(batch).await.unwrap_err();
    assert!(e.contains("limit"), "{e}");
    assert!(
        w.state
            .get_code(&address(&thief))
            .unwrap_or_default()
            .is_empty()
    );
    assert_eq!(w.state.get_nonce(&address(&thief)), 0, "no nonce was spent");
}

#[tokio::test]
async fn two_authorizations_from_one_signer_are_refused_even_inside_the_limit() {
    let mut w = World::new().await;
    let thief = key(9);
    let e = w
        .submit(vec![
            sign(&thief, U256::from(CHAIN), 0),
            sign(&thief, U256::from(CHAIN), 1),
        ])
        .await
        .unwrap_err();
    assert!(e.contains("one signer"), "{e}");
}

#[tokio::test]
async fn an_authorization_for_every_chain_is_refused_until_governance_admits_it() {
    let mut w = World::new().await;
    let k = key(9);
    let e = w.submit(vec![sign(&k, U256::ZERO, 0)]).await.unwrap_err();
    assert!(e.contains("every chain"), "{e}");
    w.govern("evm.universal_authorization_allowed", 1);
    assert_eq!(w.submit(vec![sign(&k, U256::ZERO, 0)]).await, Ok(true));
}

#[tokio::test]
async fn an_authorization_signed_for_another_chain_is_refused_until_governance_admits_it() {
    let mut w = World::new().await;
    let e = w
        .submit(vec![sign(&key(9), U256::from(1u64), 0)])
        .await
        .unwrap_err();
    assert!(e.contains("another chain"), "{e}");
    w.govern("evm.foreign_chain_authorization_allowed", 1);
    assert_eq!(
        w.submit(vec![sign(&key(9), U256::from(1u64), 0)]).await,
        Ok(true)
    );
}

#[tokio::test]
async fn one_signer_twice_is_admitted_only_when_governance_says_so() {
    let mut w = World::new().await;
    w.govern("evm.multiple_authorizations_per_signer_allowed", 1);
    let k = key(9);
    let r = w
        .submit(vec![
            sign(&k, U256::from(CHAIN), 0),
            sign(&k, U256::from(CHAIN), 1),
        ])
        .await;
    assert_eq!(r, Ok(true));
}

#[tokio::test]
async fn one_authorization_for_this_chain_still_applies_and_the_limit_is_governed() {
    let mut w = World::new().await;
    assert_eq!(
        w.submit(vec![sign(&key(8), U256::from(CHAIN), 0)]).await,
        Ok(true)
    );
    w.govern("evm.max_authorizations_per_tx", 1);
    let e = w
        .submit(vec![
            sign(&key(10), U256::from(CHAIN), 0),
            sign(&key(11), U256::from(CHAIN), 0),
        ])
        .await
        .unwrap_err();
    assert!(e.contains("limit is 1"), "{e}");
    w.govern("evm.max_authorizations_per_tx", 64);
    let many: Vec<_> = (20..30)
        .map(|s| sign(&key(s), U256::from(CHAIN), 0))
        .collect();
    assert_eq!(w.submit(many).await, Ok(true));
}

fn designator(delegate: [u8; 20]) -> Vec<u8> {
    let mut c = vec![0xef, 0x01, 0x00];
    c.extend_from_slice(&delegate);
    c
}

impl World {
    async fn submit_at(
        &mut self,
        auths: Vec<Eip7702Authorization>,
        now_ms: i64,
    ) -> Result<tenzro_vm::ExecutionResult, String> {
        let from = address(&self.sender).to_vec();
        let nonce = self.state.get_nonce(&from);
        let mut tx = VmTransaction::new(
            from,
            Some(vec![0x77; 20]),
            0,
            vec![],
            2_000_000,
            1_000_000_000,
            nonce,
            VmType::Evm,
            CHAIN,
        )
        .with_authorization_list(auths);
        tx.block_timestamp_ms = Some(now_ms);
        match self.rt.execute_transaction(&tx, &mut self.state).await {
            Ok(r) => refusal(r),
            Err(e) => Err(e.to_string()),
        }
    }
}

const T0: i64 = 1_700_000_000_000;
const HOUR: i64 = 3_600_000;

// A thief who lands one entry per transaction, so no single list is large,
// is stopped by the per-account ceiling across the window; the window rolls.
#[tokio::test]
async fn one_entry_per_transaction_is_stopped_by_the_ceiling_across_the_window() {
    let mut w = World::new().await;
    let thief = key(9);
    let a = address(&thief);
    let mut landed = 0;
    let mut refused = None;
    for n in 0..8u64 {
        match w
            .submit_at(
                vec![sign(&thief, U256::from(CHAIN), n)],
                T0 + n as i64 * 1000,
            )
            .await
        {
            Ok(r) => {
                assert!(r.success);
                landed += 1;
            }
            Err(e) => {
                refused = Some(e);
                break;
            }
        }
    }
    assert_eq!(landed, 4, "the genesis ceiling is 4 changes per window");
    assert!(refused.unwrap().contains("ceiling"));
    // Once the window has passed the account may change again.
    let r = w
        .submit_at(vec![sign(&thief, U256::from(CHAIN), 4)], T0 + 25 * HOUR)
        .await
        .unwrap();
    assert!(r.success);
    assert_eq!(w.state.get_code(&a).unwrap(), designator([0xd0; 20]));
}

#[tokio::test]
async fn a_landed_delegation_change_is_logged_for_monitors() {
    let mut w = World::new().await;
    let k = key(8);
    let r = w
        .submit_at(vec![sign(&k, U256::from(CHAIN), 0)], T0)
        .await
        .unwrap();
    let log = r
        .logs
        .iter()
        .find(|l| l.topics.first().map(|t| t.as_slice()) == Some(b"DelegationChanged".as_slice()))
        .expect("a DelegationChanged log");
    assert_eq!(log.topics[1], address(&k).to_vec());
    assert!(log.data.ends_with(&designator([0xd0; 20])));
}

#[tokio::test]
async fn the_governed_ceiling_moves_with_the_stored_value() {
    let mut w = World::new().await;
    w.govern("evm.delegation_changes_per_window", 1);
    let k = key(8);
    w.submit_at(vec![sign(&k, U256::from(CHAIN), 0)], T0)
        .await
        .unwrap();
    let e = w
        .submit_at(vec![sign(&k, U256::from(CHAIN), 1)], T0 + 1000)
        .await
        .unwrap_err();
    assert!(e.contains("ceiling is 1"), "{e}");
}

#[tokio::test]
async fn an_unlisted_delegate_is_refused_while_the_list_is_enforced() {
    let mut w = World::new().await;
    w.govern("evm.delegate_allowlist_enforced", 1);
    let code = vec![0x60, 0x2a, 0x60, 0x00, 0x55, 0x00];
    w.state.set_code(&[0xd0; 20], code.clone());
    let k = key(8);
    let e = w
        .submit_at(vec![sign(&k, U256::from(CHAIN), 0)], T0)
        .await
        .unwrap_err();
    assert!(e.contains("governed list"), "{e}");
    // Governance lists the code hash (SetDelegateCode enacts exactly this).
    let hash = tenzro_vm::delegation_guard::code_hash_hex(&code);
    w.state.set_storage(
        &SYSTEM_ADDRESS,
        tenzro_vm::delegation_guard::delegate_code_key(&hash).as_bytes(),
        vec![1],
    );
    assert!(
        w.submit_at(vec![sign(&k, U256::from(CHAIN), 0)], T0)
            .await
            .unwrap()
            .success
    );
    // Clearing a delegation (the zero address) is always admitted.
    let mut clear = sign(&k, U256::from(CHAIN), 1);
    clear.delegate_address = vec![0; 20];
    let (sig, rid) = k.sign_prehash_recoverable(&clear.signing_hash()).unwrap();
    clear.signature = sig.to_bytes().to_vec();
    clear.signature.push(rid.to_byte());
    assert!(w.submit_at(vec![clear], T0 + 1000).await.unwrap().success);
    assert!(
        w.state
            .get_code(&address(&k))
            .unwrap_or_default()
            .is_empty()
    );
}
