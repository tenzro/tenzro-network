//! Integration tests for the four-manager settlement persistence sweep.
//!
//! These tests are the durability counterpart to
//! `escrow_persistence_integration.rs`: they confirm that the three other
//! settlement-layer managers (`SettlementEngine`, `BatchProcessor`,
//! `FeeCollector`) plus `ChannelManager`'s dispute index actually survive a
//! node restart when wired through their `with_storage(...)` constructors.
//!
//! The shape of every test mirrors the escrow tests:
//!
//! 1. Phase 1 — open a fresh `RocksDbStore` at a `tempdir` path, build the
//!    manager via `with_storage(...)`, mutate state, then drop the manager.
//! 2. Phase 2 — reopen the same RocksDB path and rebuild the manager. The
//!    manager's hydrate step must rehydrate the records verbatim through its
//!    public read API (no test-only escape hatches into private state).
//!
//! The single in-memory `EscrowManager`-style invariant test exists at
//! `escrow_persistence_integration.rs::test_in_memory_manager_does_not_see_persisted_records`;
//! we re-create the equivalent assertion here for `SettlementEngine` and
//! `FeeCollector` because the same regression class (silently falling back to
//! the in-memory variant in `init_settlement`) would re-introduce the original
//! escrow bug for these other managers too.

use std::sync::Arc;

use dashmap::DashMap;

use tenzro_settlement::{
    BatchProcessor, ChannelManager, FeeCollector, RocksDbChannelStorage, SettlementConfig,
    SettlementEngine,
};
use tenzro_storage::RocksDbStore;
use tenzro_token::NetworkTreasury;
use tenzro_types::asset::AssetId;
use tenzro_types::primitives::{Address, Hash, Timestamp};
use tenzro_types::settlement::{
    ProofType, ServiceProof, ServiceType, SettlementReceipt, SettlementRequest, SettlementStatus,
};

// ---- helpers -------------------------------------------------------------

fn addr(tag: u8) -> Address {
    Address::new([tag; 32])
}

fn tnzo() -> AssetId {
    AssetId::tnzo()
}

/// A timestamp 24h in the future so channels never expire mid-test.
fn far_future() -> Timestamp {
    let now_ms = chrono::Utc::now().timestamp_millis();
    Timestamp::new(now_ms + 24 * 60 * 60 * 1000)
}

fn settlement_request(
    provider: Address,
    customer: Address,
    amount: u64,
    request_seed: u8,
) -> SettlementRequest {
    // Use a `Merkle` proof — its verifier only requires `proof_data.len() >= 32`
    // and accepts any byte content, which keeps the test fixtures small while
    // still going through the real verify path. (`Cryptographic` would require
    // an Ed25519 signature whose signer address must match the provider, which
    // doesn't compose with our deterministic test addresses.)
    let proof = ServiceProof::new(ProofType::Merkle, vec![request_seed; 32]);
    SettlementRequest::new(
        provider,
        customer,
        ServiceType::ModelInference {
            model_id: format!("model-{:02x}", request_seed),
            tokens: 1_000,
        },
        amount,
        proof,
    )
}

/// Build a `SettlementEngine` wired to `path`, fund the customer with TNZO,
/// run a single settlement, return the receipt.
async fn create_and_settle(
    path: &std::path::Path,
    provider: Address,
    customer: Address,
    amount: u64,
) -> SettlementReceipt {
    let storage = Arc::new(RocksDbStore::open_default(path).expect("open rocksdb"));
    let treasury = Arc::new(NetworkTreasury::new(addr(0xff)));
    let config = SettlementConfig::new(addr(0xff));
    let engine = SettlementEngine::with_storage(config, treasury, storage)
        .expect("build engine with storage");
    engine.set_balance(&customer, &tnzo(), 10_000_000);

    let req = settlement_request(provider, customer, amount, 0xa5);
    engine.settle(req).await.expect("settle")
}

// ---- SettlementEngine ----------------------------------------------------

/// A single settlement persists the receipt + both per-address indices, all
/// observable verbatim through `get_settlement` / `get_settlements_for_address`
/// after a fresh manager reopens the same RocksDB path.
#[tokio::test]
async fn test_settlement_engine_receipt_and_indices_survive_restart() {
    let temp = tempfile::tempdir().expect("create temp dir");
    let path = temp.path();

    let provider = addr(0x11);
    let customer = addr(0x22);

    let original = create_and_settle(path, provider, customer, 5_000).await;

    // Phase 2 — reopen.
    let storage = Arc::new(RocksDbStore::open_default(path).expect("reopen rocksdb"));
    let treasury = Arc::new(NetworkTreasury::new(addr(0xff)));
    let config = SettlementConfig::new(addr(0xff));
    let engine = SettlementEngine::with_storage(config, treasury, storage)
        .expect("rebuild engine");

    // Receipt visible via direct lookup.
    let restored = engine
        .get_settlement(&original.receipt_id)
        .expect("receipt visible after restart");
    assert_eq!(restored.receipt_id, original.receipt_id);
    assert_eq!(restored.provider, provider);
    assert_eq!(restored.customer, customer);
    assert_eq!(restored.amount, 5_000);
    assert_eq!(restored.status, SettlementStatus::Completed);

    // Both per-address indices restored.
    let by_provider = engine.get_settlements_for_address(&provider);
    assert_eq!(by_provider.len(), 1);
    assert_eq!(by_provider[0].receipt_id, original.receipt_id);

    let by_customer = engine.get_settlements_for_address(&customer);
    assert_eq!(by_customer.len(), 1);
    assert_eq!(by_customer[0].receipt_id, original.receipt_id);
}

/// Multiple settlements with overlapping providers/customers — both the
/// receipt cache and per-address indices must be fully rehydrated.
#[tokio::test]
async fn test_settlement_engine_multi_receipt_fan_out_survives_restart() {
    let temp = tempfile::tempdir().expect("create temp dir");
    let path = temp.path();

    let provider_a = addr(0xa0);
    let provider_b = addr(0xb0);
    let customer_x = addr(0x10);
    let customer_y = addr(0x20);

    // Phase 1 — settle 4 transactions across two providers and two customers.
    let mut ids: Vec<String> = Vec::new();
    {
        let storage = Arc::new(RocksDbStore::open_default(path).expect("open rocksdb"));
        let treasury = Arc::new(NetworkTreasury::new(addr(0xff)));
        let engine = SettlementEngine::with_storage(
            SettlementConfig::new(addr(0xff)),
            treasury,
            storage,
        )
        .expect("build engine");

        engine.set_balance(&customer_x, &tnzo(), 10_000_000);
        engine.set_balance(&customer_y, &tnzo(), 10_000_000);

        // Amounts must be ≥ `SettlementConfig` min (1000); using distinct
        // amounts makes failure messages easier to triage.
        for (provider, customer, amount, seed) in [
            (provider_a, customer_x, 1_100u64, 0x01u8),
            (provider_a, customer_y, 1_200u64, 0x02u8),
            (provider_b, customer_x, 1_300u64, 0x03u8),
            (provider_b, customer_y, 1_400u64, 0x04u8),
        ] {
            let req = settlement_request(provider, customer, amount, seed);
            let r = engine.settle(req).await.expect("settle");
            ids.push(r.receipt_id);
        }
    }

    // Phase 2 — reopen.
    let storage = Arc::new(RocksDbStore::open_default(path).expect("reopen rocksdb"));
    let treasury = Arc::new(NetworkTreasury::new(addr(0xff)));
    let engine = SettlementEngine::with_storage(
        SettlementConfig::new(addr(0xff)),
        treasury,
        storage,
    )
    .expect("rebuild engine");

    // Every individual record reachable.
    for id in &ids {
        let r = engine.get_settlement(id).expect("receipt visible");
        assert_eq!(&r.receipt_id, id);
        assert_eq!(r.status, SettlementStatus::Completed);
    }

    // Provider indices: 2 each.
    assert_eq!(engine.get_settlements_for_address(&provider_a).len(), 2);
    assert_eq!(engine.get_settlements_for_address(&provider_b).len(), 2);

    // Customer indices: 2 each.
    assert_eq!(engine.get_settlements_for_address(&customer_x).len(), 2);
    assert_eq!(engine.get_settlements_for_address(&customer_y).len(), 2);
}

/// A non-storage `SettlementEngine` must NOT see records persisted by a
/// storage-backed engine — this is the regression guard against
/// `init_settlement` silently falling back to `SettlementEngine::new()`.
#[tokio::test]
async fn test_in_memory_settlement_engine_does_not_see_persisted_records() {
    let temp = tempfile::tempdir().expect("create temp dir");
    let path = temp.path();

    let provider = addr(0x77);
    let customer = addr(0x88);
    let original = create_and_settle(path, provider, customer, 1_000).await;

    let treasury = Arc::new(NetworkTreasury::new(addr(0xff)));
    let in_mem = SettlementEngine::new(SettlementConfig::new(addr(0xff)), treasury)
        .expect("build in-memory engine");
    assert!(in_mem.get_settlement(&original.receipt_id).is_err());
    assert_eq!(in_mem.get_settlements_for_address(&provider).len(), 0);
    assert_eq!(in_mem.get_settlements_for_address(&customer).len(), 0);
}

// ---- BatchProcessor ------------------------------------------------------

/// A successfully processed batch persists its metadata + result so that a
/// fresh processor reading the same RocksDB path can recover the result via
/// `load_batch_result`.
#[tokio::test]
async fn test_batch_processor_result_survives_restart() {
    let temp = tempfile::tempdir().expect("create temp dir");
    let path = temp.path();

    let provider = addr(0xc0);
    let customer = addr(0xc1);

    // Phase 1: create + process a batch.
    let batch_id;
    {
        let storage = Arc::new(RocksDbStore::open_default(path).expect("open rocksdb"));
        let processor = BatchProcessor::new(100).with_storage(storage);

        let reqs = vec![
            settlement_request(provider, customer, 1_100, 0x10),
            settlement_request(provider, customer, 1_200, 0x11),
            settlement_request(provider, customer, 1_300, 0x12),
        ];
        let batch = processor.create_batch(reqs).expect("create batch");
        batch_id = batch.batch_id.clone();

        // Stub settle_fn — we only care about persistence here, not real
        // settlement bookkeeping.
        let result = processor
            .process_batch(&batch_id, |req| async move {
                Ok(SettlementReceipt::new(
                    req.request_id.clone(),
                    Hash::default(),
                    req.provider,
                    req.customer,
                    req.service_type.clone(),
                    req.amount,
                    SettlementStatus::Completed,
                ))
            })
            .await
            .expect("process batch");

        assert_eq!(result.successful, 3);
        assert_eq!(result.failed, 0);
    }

    // Phase 2: reopen. `load_batch_result` is the documented post-restart
    // read path on `BatchProcessor`.
    let storage = Arc::new(RocksDbStore::open_default(path).expect("reopen rocksdb"));
    let processor = BatchProcessor::new(100).with_storage(storage);

    let restored = processor
        .load_batch_result(&batch_id)
        .expect("load batch result")
        .expect("batch result must be persisted");

    assert_eq!(restored.batch_id, batch_id);
    assert_eq!(restored.successful, 3);
    assert_eq!(restored.failed, 0);
    assert_eq!(restored.receipts.len(), 3);
}

/// A failed batch must NOT persist any state — atomic rollback applies to
/// the storage layer too.
#[tokio::test]
async fn test_batch_processor_failure_persists_nothing() {
    let temp = tempfile::tempdir().expect("create temp dir");
    let path = temp.path();

    let provider = addr(0xd0);
    let customer = addr(0xd1);

    let batch_id;
    {
        let storage = Arc::new(RocksDbStore::open_default(path).expect("open rocksdb"));
        let processor = BatchProcessor::new(100).with_storage(storage);

        let batch = processor
            .create_batch(vec![
                settlement_request(provider, customer, 1_100, 0x20),
                settlement_request(provider, customer, 1_200, 0x21),
            ])
            .expect("create batch");
        batch_id = batch.batch_id.clone();

        let _ = processor
            .process_batch(&batch_id, |_req| async move {
                Err(tenzro_settlement::SettlementError::PaymentFailed(
                    "stub failure for atomicity test".into(),
                ))
            })
            .await;
    }

    // Phase 2: reopen. Failed batches MUST NOT have a persisted result.
    let storage = Arc::new(RocksDbStore::open_default(path).expect("reopen rocksdb"));
    let processor = BatchProcessor::new(100).with_storage(storage);
    let result = processor
        .load_batch_result(&batch_id)
        .expect("load result call");
    assert!(
        result.is_none(),
        "failed batch must not leave persisted result"
    );
}

// ---- FeeCollector --------------------------------------------------------

/// Per-asset totals, counts, and the fee history must all rehydrate verbatim
/// after a restart.
#[test]
fn test_fee_collector_totals_counts_and_history_survive_restart() {
    let temp = tempfile::tempdir().expect("create temp dir");
    let path = temp.path();

    // Phase 1: collect three fees in TNZO.
    {
        let storage = Arc::new(RocksDbStore::open_default(path).expect("open rocksdb"));
        let treasury = Arc::new(NetworkTreasury::new(addr(0xff)));
        let collector = FeeCollector::with_storage(treasury, storage);

        collector
            .collect_fee("settlement-1", &tnzo(), 1_000)
            .expect("collect 1");
        collector
            .collect_fee("settlement-2", &tnzo(), 2_500)
            .expect("collect 2");
        collector
            .collect_fee("settlement-3", &tnzo(), 500)
            .expect("collect 3");
    }

    // Phase 2: reopen — totals/counts/history must match exactly.
    let storage = Arc::new(RocksDbStore::open_default(path).expect("reopen rocksdb"));
    let treasury = Arc::new(NetworkTreasury::new(addr(0xff)));
    let collector = FeeCollector::with_storage(treasury, storage);

    assert_eq!(collector.get_fees_by_asset(&tnzo()), 4_000);
    let stats = collector.get_collection_stats();
    assert_eq!(stats.total_collections, 3);

    let history = collector.get_history();
    assert_eq!(history.len(), 3);
    // Hydrate is timestamp-sorted, but `Timestamp::now()` has ms resolution
    // and three rapid `collect_fee` calls can collide on the same timestamp,
    // so we don't assert an order — only set membership and the per-record
    // (amount, source) pairing, which is what callers actually depend on.
    let mut pairs: Vec<(u128, &str)> = history
        .iter()
        .map(|r| (r.amount, r.source_settlement.as_str()))
        .collect();
    pairs.sort();
    let mut expected: Vec<(u128, &str)> = vec![
        (1_000, "settlement-1"),
        (2_500, "settlement-2"),
        (500, "settlement-3"),
    ];
    expected.sort();
    assert_eq!(pairs, expected);
}

/// Fees across multiple assets must rehydrate as independent per-asset
/// totals + counts.
#[test]
fn test_fee_collector_multi_asset_totals_survive_restart() {
    let temp = tempfile::tempdir().expect("create temp dir");
    let path = temp.path();

    let usdc = AssetId("USDC".to_string());
    let usdt = AssetId("USDT".to_string());

    {
        let storage = Arc::new(RocksDbStore::open_default(path).expect("open rocksdb"));
        let treasury = Arc::new(NetworkTreasury::new(addr(0xff)));
        let collector = FeeCollector::with_storage(treasury, storage);

        collector.collect_fee("s-tnzo-1", &tnzo(), 100).unwrap();
        collector.collect_fee("s-tnzo-2", &tnzo(), 200).unwrap();
        collector.collect_fee("s-usdc-1", &usdc, 1_000_000).unwrap();
        collector.collect_fee("s-usdt-1", &usdt, 2_000_000).unwrap();
        collector.collect_fee("s-usdt-2", &usdt, 3_000_000).unwrap();
    }

    let storage = Arc::new(RocksDbStore::open_default(path).expect("reopen rocksdb"));
    let treasury = Arc::new(NetworkTreasury::new(addr(0xff)));
    let collector = FeeCollector::with_storage(treasury, storage);

    let totals = collector.get_total_collected();
    assert_eq!(totals.get(&tnzo()).copied().unwrap_or(0), 300);
    assert_eq!(totals.get(&usdc).copied().unwrap_or(0), 1_000_000);
    assert_eq!(totals.get(&usdt).copied().unwrap_or(0), 5_000_000);

    let stats = collector.get_collection_stats();
    assert_eq!(stats.total_collections, 5);
    assert_eq!(stats.total_collected.len(), 3);
}

/// A non-storage `FeeCollector` must NOT see records persisted by a
/// storage-backed collector — same regression class as the
/// `SettlementEngine` and `EscrowManager` invariants.
#[test]
fn test_in_memory_fee_collector_does_not_see_persisted_records() {
    let temp = tempfile::tempdir().expect("create temp dir");
    let path = temp.path();

    {
        let storage = Arc::new(RocksDbStore::open_default(path).expect("open rocksdb"));
        let treasury = Arc::new(NetworkTreasury::new(addr(0xff)));
        let collector = FeeCollector::with_storage(treasury, storage);
        collector.collect_fee("s-1", &tnzo(), 1_234).unwrap();
    }

    let in_mem = FeeCollector::new(Arc::new(NetworkTreasury::new(addr(0xff))));
    assert_eq!(in_mem.get_fees_by_asset(&tnzo()), 0);
    assert_eq!(in_mem.get_collection_stats().total_collections, 0);
    assert!(in_mem.get_history().is_empty());
}

// ---- ChannelManager (dispute index) -------------------------------------

/// Disputes opened pre-restart must rehydrate alongside their channels via
/// `RocksDbChannelStorage` so the 24h dispute timeout doesn't strand parties
/// after a node restart.
///
/// (`ChannelManager`'s channel persistence already had pre-existing test
/// coverage in the unit-test layer; this test focuses on the new dispute
/// persistence added in subtask #59.)
#[test]
fn test_channel_dispute_survives_restart() {
    let temp = tempfile::tempdir().expect("create temp dir");
    let path = temp.path();

    let payer = addr(0xe1);
    let payee = addr(0xe2);

    let dispute_id;
    let channel_id;

    // Phase 1: open channel + open dispute.
    {
        let storage = Arc::new(RocksDbStore::open_default(path).expect("open rocksdb"));
        let backend: Arc<dyn tenzro_settlement::ChannelStorage> =
            Arc::new(RocksDbChannelStorage::new(storage));
        let manager = ChannelManager::with_storage(backend);

        manager.set_balance(&payer, &tnzo(), 1_000_000);

        let channel = manager
            .open_channel(payer, payee, 10_000, tnzo(), far_future())
            .expect("open channel");
        channel_id = channel.channel_id.clone();

        let dispute = manager
            .open_dispute(&channel_id, payer, b"i was overcharged".to_vec())
            .expect("open dispute");
        dispute_id = dispute.dispute_id.clone();
    }

    // Phase 2: reopen — both the channel and the dispute must be visible
    // through the manager's public read API.
    {
        let storage = Arc::new(RocksDbStore::open_default(path).expect("reopen rocksdb"));
        let backend: Arc<dyn tenzro_settlement::ChannelStorage> =
            Arc::new(RocksDbChannelStorage::new(storage));
        let manager = ChannelManager::with_storage(backend);

        let channel = manager.get_channel(&channel_id).expect("channel restored");
        assert_eq!(channel.payer, payer);
        assert_eq!(channel.payee, payee);

        let dispute = manager.get_dispute(&dispute_id).expect("dispute restored");
        assert_eq!(dispute.dispute_id, dispute_id);
        assert_eq!(dispute.channel_id, channel_id);
        assert_eq!(dispute.challenger, payer);
        assert_eq!(dispute.challenger_evidence, b"i was overcharged");

        // The per-channel index must also be rebuilt — opening a second
        // dispute from `respond_to_dispute` would otherwise miss the
        // existing one and let parties double-dispute the same channel.
        let by_channel = manager.get_disputes_for_channel(&channel_id);
        assert_eq!(by_channel.len(), 1);
        assert_eq!(by_channel[0].dispute_id, dispute_id);
    }
}

/// Suppress unused-import warnings if the file is compiled with subset
/// feature flags (kept at module level rather than per-test for clarity).
#[allow(dead_code)]
fn _unused_imports_anchor() {
    let _: Option<DashMap<(Address, AssetId), u128>> = None;
}
