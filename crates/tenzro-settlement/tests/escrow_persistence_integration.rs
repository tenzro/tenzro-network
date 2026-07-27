//! Integration tests for `EscrowManager` persistence.
//!
//! These tests confirm that the on-chain escrow primitive's "denormalized
//! query index" — the off-VM `EscrowManager` — survives node restarts. The VM
//! itself is the source of truth for escrow state (balances live in
//! `CF_ACCOUNTS`, the canonical record lives under `escrow:<id>` in VM
//! storage). The settlement-layer manager mirrors that record into
//! `CF_SETTLEMENTS` so RPC read endpoints
//! (`tenzro_getEscrow`, `tenzro_listEscrowsByPayer`,
//! `tenzro_listEscrowsByPayee`) return data immediately on startup without
//! waiting for a fresh write.
//!
//! What we exercise here:
//!
//! 1. Create-then-restart: an escrow created against a persistent manager is
//!    visible verbatim through a freshly-constructed manager pointing at the
//!    same RocksDB path, including both `escrow:<id>` lookup and the payer /
//!    payee secondary indices.
//! 2. Mutation-then-restart: mutations (`release`, `refund`) write through
//!    atomically and survive restart.
//! 3. Multi-record fan-out: many escrows with different payer/payee
//!    combinations are all rehydrated and indexed correctly.
//!
//! This is *not* the full HTTP-level integration test (which exists at the VM
//! layer in `crates/tenzro-vm/src/native/mod.rs::tests`); it is the
//! settlement-layer-specific guarantee that the off-chain query index
//! survives a process death — the bug class that motivated the on-chain
//! migration in the first place (escrows used to die with the node because
//! every `handle_create_escrow` call instantiated a fresh detached
//! `EscrowManager`).

use std::sync::Arc;

use dashmap::DashMap;
use tenzro_settlement::{EscrowManager, EscrowStatus};
use tenzro_storage::RocksDbStore;
use tenzro_types::asset::AssetId;
use tenzro_types::primitives::{Address, Timestamp};
use tenzro_types::settlement::{ProofType, ReleaseConditions, ServiceProof};

/// 32-byte address built from a single byte tag, matching the canonical
/// Tenzro address shape used elsewhere in the workspace.
fn addr(tag: u8) -> Address {
    Address::new([tag; 32])
}

fn tnzo() -> AssetId {
    AssetId("TNZO".to_string())
}

/// A timestamp far in the future so escrows are never auto-expired during the
/// test run.
fn far_future() -> Timestamp {
    let now_ms = chrono::Utc::now().timestamp_millis();
    Timestamp::new(now_ms + 24 * 60 * 60 * 1000)
}

/// 1. Create an escrow on a persistent manager, drop it (simulating node
///    shutdown), then reopen the same RocksDB path with a fresh manager.
///    The escrow record + both indices must be restored verbatim.
#[test]
fn test_escrow_record_and_indices_survive_restart() {
    let temp = tempfile::tempdir().expect("create temp dir");
    let path = temp.path();

    let payer = addr(0x11);
    let payee = addr(0x22);
    let amount: u128 = 5_000;
    let escrow_id;

    // Phase 1: create + persist.
    {
        let storage = Arc::new(RocksDbStore::open_default(path).expect("open rocksdb"));
        let balances: Arc<DashMap<(Address, AssetId), u128>> = Arc::new(DashMap::new());
        balances.insert((payer, tnzo()), 1_000_000);

        let mgr = EscrowManager::with_storage(balances, storage);
        let escrow = mgr
            .create_escrow(
                payer,
                payee,
                amount,
                tnzo(),
                far_future(),
                ReleaseConditions::Timeout,
            )
            .expect("create escrow");

        assert_eq!(escrow.status, EscrowStatus::Funded);
        escrow_id = escrow.escrow_id.clone();
    }

    // Phase 2: reopen — simulates node restart.
    {
        let storage = Arc::new(RocksDbStore::open_default(path).expect("reopen rocksdb"));
        // Balances are *not* the source of truth post-migration (the VM owns
        // CF_ACCOUNTS); the manager just needs an empty map for the API.
        let balances: Arc<DashMap<(Address, AssetId), u128>> = Arc::new(DashMap::new());
        let mgr = EscrowManager::with_storage(balances, storage);

        // Direct lookup must succeed.
        let restored = mgr
            .get_escrow(&escrow_id)
            .expect("escrow visible after restart");
        assert_eq!(restored.escrow_id, escrow_id);
        assert_eq!(restored.payer, payer);
        assert_eq!(restored.payee, payee);
        assert_eq!(restored.amount, amount);
        assert_eq!(restored.status, EscrowStatus::Funded);

        // Both secondary indices must be rebuilt.
        let by_payer = mgr.get_escrows_by_payer(&payer);
        assert_eq!(by_payer.len(), 1);
        assert_eq!(by_payer[0].escrow_id, escrow_id);

        let by_payee = mgr.get_escrows_by_payee(&payee);
        assert_eq!(by_payee.len(), 1);
        assert_eq!(by_payee[0].escrow_id, escrow_id);
    }
}

/// 2. Mutations (`release`, `refund`) must survive a restart with the post-
///    mutation status preserved exactly.
#[test]
fn test_release_status_survives_restart() {
    let temp = tempfile::tempdir().expect("create temp dir");
    let path = temp.path();

    let payer = addr(0x33);
    let payee = addr(0x44);
    let escrow_id;

    // Phase 1: create + release.
    {
        let storage = Arc::new(RocksDbStore::open_default(path).expect("open rocksdb"));
        let balances: Arc<DashMap<(Address, AssetId), u128>> = Arc::new(DashMap::new());
        balances.insert((payer, tnzo()), 1_000_000);
        let mgr = EscrowManager::with_storage(balances, storage);

        let escrow = mgr
            .create_escrow(
                payer,
                payee,
                1_000,
                tnzo(),
                far_future(),
                ReleaseConditions::Timeout,
            )
            .expect("create escrow");
        escrow_id = escrow.escrow_id.clone();

        let proof = ServiceProof::new(ProofType::Cryptographic, b"timeout-noop".to_vec());
        mgr.release_escrow(&escrow_id, &proof)
            .expect("release escrow");
    }

    // Phase 2: reopen — status must be `Released`.
    {
        let storage = Arc::new(RocksDbStore::open_default(path).expect("reopen rocksdb"));
        let balances: Arc<DashMap<(Address, AssetId), u128>> = Arc::new(DashMap::new());
        let mgr = EscrowManager::with_storage(balances, storage);

        let restored = mgr.get_escrow(&escrow_id).expect("escrow still visible");
        assert_eq!(restored.status, EscrowStatus::Released);
    }
}

#[test]
fn test_refund_status_survives_restart() {
    let temp = tempfile::tempdir().expect("create temp dir");
    let path = temp.path();

    let payer = addr(0x55);
    let payee = addr(0x66);
    let escrow_id;

    // Phase 1: create with a `Custom` condition (refund permitted before
    // expiry on Custom + Timeout per `EscrowAccount::can_refund`).
    {
        let storage = Arc::new(RocksDbStore::open_default(path).expect("open rocksdb"));
        let balances: Arc<DashMap<(Address, AssetId), u128>> = Arc::new(DashMap::new());
        balances.insert((payer, tnzo()), 1_000_000);
        let mgr = EscrowManager::with_storage(balances, storage);

        let escrow = mgr
            .create_escrow(
                payer,
                payee,
                2_500,
                tnzo(),
                far_future(),
                ReleaseConditions::Custom {
                    condition: "refundable-by-payer".to_string(),
                },
            )
            .expect("create escrow");
        escrow_id = escrow.escrow_id.clone();

        mgr.refund_escrow(&escrow_id).expect("refund escrow");
    }

    // Phase 2: status persists.
    {
        let storage = Arc::new(RocksDbStore::open_default(path).expect("reopen rocksdb"));
        let balances: Arc<DashMap<(Address, AssetId), u128>> = Arc::new(DashMap::new());
        let mgr = EscrowManager::with_storage(balances, storage);

        let restored = mgr.get_escrow(&escrow_id).expect("escrow still visible");
        assert_eq!(restored.status, EscrowStatus::Refunded);
    }
}

/// 3. Many escrows with overlapping payers / payees — every record + every
///    index entry must be restored on restart.
#[test]
fn test_multi_escrow_fan_out_survives_restart() {
    let temp = tempfile::tempdir().expect("create temp dir");
    let path = temp.path();

    // Two payers, three payees; create six escrows with varied combinations.
    let payer_a = addr(0xa0);
    let payer_b = addr(0xb0);
    let payee_x = addr(0x10);
    let payee_y = addr(0x20);
    let payee_z = addr(0x30);

    let mut created_ids: Vec<(Address, Address, String)> = Vec::new();

    {
        let storage = Arc::new(RocksDbStore::open_default(path).expect("open rocksdb"));
        let balances: Arc<DashMap<(Address, AssetId), u128>> = Arc::new(DashMap::new());
        balances.insert((payer_a, tnzo()), 10_000_000);
        balances.insert((payer_b, tnzo()), 10_000_000);

        let mgr = EscrowManager::with_storage(balances, storage);

        for (payer, payee, amount) in [
            (payer_a, payee_x, 100u128),
            (payer_a, payee_y, 200u128),
            (payer_a, payee_z, 300u128),
            (payer_b, payee_x, 400u128),
            (payer_b, payee_y, 500u128),
            (payer_b, payee_z, 600u128),
        ] {
            let e = mgr
                .create_escrow(
                    payer,
                    payee,
                    amount,
                    tnzo(),
                    far_future(),
                    ReleaseConditions::Timeout,
                )
                .expect("create");
            created_ids.push((payer, payee, e.escrow_id));
        }
    }

    // Reopen.
    {
        let storage = Arc::new(RocksDbStore::open_default(path).expect("reopen rocksdb"));
        let balances: Arc<DashMap<(Address, AssetId), u128>> = Arc::new(DashMap::new());
        let mgr = EscrowManager::with_storage(balances, storage);

        // Each individual record is reachable.
        for (_, _, id) in &created_ids {
            let r = mgr.get_escrow(id).expect("record visible after restart");
            assert_eq!(&r.escrow_id, id);
            assert_eq!(r.status, EscrowStatus::Funded);
        }

        // Indices contain the right counts.
        assert_eq!(mgr.get_escrows_by_payer(&payer_a).len(), 3);
        assert_eq!(mgr.get_escrows_by_payer(&payer_b).len(), 3);
        assert_eq!(mgr.get_escrows_by_payee(&payee_x).len(), 2);
        assert_eq!(mgr.get_escrows_by_payee(&payee_y).len(), 2);
        assert_eq!(mgr.get_escrows_by_payee(&payee_z).len(), 2);

        // Every (payer, payee, id) triple from phase 1 appears under the
        // appropriate payer index.
        for (payer, _payee, id) in &created_ids {
            let by_payer = mgr.get_escrows_by_payer(payer);
            assert!(
                by_payer.iter().any(|e| &e.escrow_id == id),
                "escrow {} missing from payer {} index",
                id,
                payer
            );
        }
    }
}

/// 4. An in-memory manager (no storage) must NOT see records persisted by a
///    persistent manager — confirms the new `with_storage` constructor is the
///    only thing wiring up the durable path. (Belt-and-braces; without this
///    we could regress and silently fall back to in-memory mode.)
#[test]
fn test_in_memory_manager_does_not_see_persisted_records() {
    let temp = tempfile::tempdir().expect("create temp dir");
    let path = temp.path();

    let payer = addr(0x77);
    let payee = addr(0x88);

    // Persist one record.
    {
        let storage = Arc::new(RocksDbStore::open_default(path).expect("open rocksdb"));
        let balances: Arc<DashMap<(Address, AssetId), u128>> = Arc::new(DashMap::new());
        balances.insert((payer, tnzo()), 100_000);
        let mgr = EscrowManager::with_storage(balances, storage);
        mgr.create_escrow(
            payer,
            payee,
            42,
            tnzo(),
            far_future(),
            ReleaseConditions::Timeout,
        )
        .expect("create");
    }

    // A fresh in-memory manager cannot see that record.
    let in_mem = EscrowManager::new(Arc::new(DashMap::new()));
    assert_eq!(in_mem.get_escrows_by_payer(&payer).len(), 0);
    assert_eq!(in_mem.get_escrows_by_payee(&payee).len(), 0);
}
