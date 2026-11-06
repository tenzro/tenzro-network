//! A failing or hostile storage object must not stall block application.
//! The blob store's entries are poisoned per object (a write that failed
//! with no space left), and every later access to one panics. Block
//! application never touches the blob store (tenzro-types
//! tests/block_path_guard.rs); this runs real block execution while a
//! background task panics on every "announcement", the shape of the live
//! log, and checks that every block applies and the runtime survives.

use tenzro_vm::ledger::{BlockFees, TxOutcome, execute_in_block};
use tenzro_vm::{MultiVmRuntime, StateAdapter, VmConfig, VmState, VmTransaction, VmType};

const E18: u128 = 1_000_000_000_000_000_000;
const CHAIN: u64 = 1337;
const OWNER: [u8; 20] = [0xa1; 20];
const SHOP: [u8; 20] = [0xb1; 20];

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn blocks_apply_while_a_poisoned_storage_object_panics_on_every_announcement() {
    let rt = MultiVmRuntime::new(VmConfig::default()).await.unwrap();
    let mut state = StateAdapter::new();
    state.set_balance(&OWNER, 1_000 * E18);

    // The storage side: an announcement every few microseconds, each one
    // reaching an entry that panics.
    let storage = tokio::spawn(async move {
        let mut panics = 0u32;
        for _ in 0..300 {
            let attempt = tokio::spawn(async {
                panic!("poisoned storage should not be used");
            });
            if attempt.await.is_err() {
                panics += 1;
            }
            tokio::task::yield_now().await;
        }
        panics
    });

    // The chain side: 150 blocks of one transfer each.
    for block in 0..150u64 {
        let nonce = state.get_nonce(&OWNER);
        let mut tx = VmTransaction::new(
            OWNER.to_vec(),
            Some(SHOP.to_vec()),
            E18,
            vec![],
            21_000,
            1_000_000_000,
            nonce,
            VmType::Evm,
            CHAIN,
        );
        tx.block_timestamp_ms = Some(1_800_000_000_000 + block as i64 * 2_000);
        let mut fees = BlockFees::default();
        let outcome = execute_in_block(&rt, &mut state, &tx, 0, &mut fees).await;
        assert!(
            matches!(outcome, TxOutcome::Applied { .. }),
            "block {block} did not apply: {outcome:?}"
        );
        tokio::task::yield_now().await;
    }

    assert_eq!(storage.await.expect("the storage task finishes"), 300);
    assert_eq!(state.get_balance(&SHOP), 150 * E18, "every block applied");
}
