//! Criterion benchmarks for tenzro-bridge hot paths.
//!
//! The synchronous hot path on every bridge message is:
//! - `TenzroMessage::new` → `compute_hash` (SHA-256 over chain ids + nonce + payload)
//! - `TenzroMessage::sign` (Ed25519 / Secp256k1 over the 32-byte hash)
//! - `TenzroMessage::verify_signature` (counterpart on the inbound side)
//! - `encode` / `decode` (JSON wire framing)
//!
//! These run on every outbound LayerZero / CCIP / deBridge / Canton message,
//! so any regression here multiplies across all bridge fan-out.

use criterion::{Criterion, black_box, criterion_group, criterion_main};

use tenzro_bridge::message_format::{MessageType, TenzroMessage};
use tenzro_crypto::KeyPair;
use tenzro_crypto::keys::KeyType;

const PAYLOAD_SIZE: usize = 256;
const SRC_CHAIN: u64 = 1337;
const DST_CHAIN: u64 = 137;

fn sample_message() -> TenzroMessage {
    TenzroMessage::new(
        MessageType::TokenTransfer,
        SRC_CHAIN,
        DST_CHAIN,
        "0x1111111111111111111111111111111111111111",
        "0x2222222222222222222222222222222222222222",
        vec![0xab; PAYLOAD_SIZE],
        42,
    )
}

fn signed_message() -> TenzroMessage {
    let mut msg = sample_message();
    let keypair = KeyPair::generate(KeyType::Ed25519).expect("ed25519 keypair");
    msg.sign(keypair).expect("sign");
    msg
}

fn bench_new_message(c: &mut Criterion) {
    let mut group = c.benchmark_group("message_format");
    group.bench_function("new_token_transfer_256b_payload", |b| {
        b.iter(|| {
            let m = TenzroMessage::new(
                black_box(MessageType::TokenTransfer),
                black_box(SRC_CHAIN),
                black_box(DST_CHAIN),
                black_box("0x1111111111111111111111111111111111111111"),
                black_box("0x2222222222222222222222222222222222222222"),
                black_box(vec![0xab; PAYLOAD_SIZE]),
                black_box(42),
            );
            black_box(m);
        });
    });
    group.finish();
}

fn bench_sign(c: &mut Criterion) {
    let mut group = c.benchmark_group("message_format_sign");
    group.bench_function("ed25519", |b| {
        b.iter_with_setup(
            || {
                (
                    sample_message(),
                    KeyPair::generate(KeyType::Ed25519).expect("ed25519 keypair"),
                )
            },
            |(mut msg, kp)| {
                msg.sign(kp).expect("sign");
                black_box(msg);
            },
        );
    });
    group.bench_function("secp256k1", |b| {
        b.iter_with_setup(
            || {
                (
                    sample_message(),
                    KeyPair::generate(KeyType::Secp256k1).expect("secp keypair"),
                )
            },
            |(mut msg, kp)| {
                msg.sign(kp).expect("sign");
                black_box(msg);
            },
        );
    });
    group.finish();
}

fn bench_verify(c: &mut Criterion) {
    let msg = signed_message();
    let mut group = c.benchmark_group("message_format_verify");
    group.bench_function("ed25519", |b| {
        b.iter(|| {
            let ok = msg.verify_signature().expect("verify");
            black_box(ok);
        });
    });
    group.finish();
}

fn bench_encode_decode(c: &mut Criterion) {
    let msg = signed_message();
    let bytes = msg.encode().expect("encode");
    let mut group = c.benchmark_group("message_format_codec");
    group.bench_function("encode_json", |b| {
        b.iter(|| {
            let b = msg.encode().expect("encode");
            black_box(b);
        });
    });
    group.bench_function("decode_json", |b| {
        b.iter(|| {
            let m = TenzroMessage::decode(black_box(&bytes)).expect("decode");
            black_box(m);
        });
    });
    group.finish();
}

// ---------- fee-in-TNZO + ERC-7683 benches ----------

use std::sync::Arc;
use tenzro_bridge::fee_oracle::{BridgeAdapterId, GovernanceFeeRow, GovernanceSetFeeOracle};
use tenzro_bridge::fee_sponsor::{BridgeFeeSponsor, WiredBridgeFeeSurface};
use tenzro_bridge::router::BridgeRouter;
use tenzro_types::intent_7683::{
    BridgeFeeHint, CrossChainOrder, ProofRoute, TENZRO_MAINNET_CHAIN_ID, TenzroOrderData,
    compute_order_id,
};
use tenzro_types::primitives::{Address, Hash};

fn build_wired_surface() -> Arc<WiredBridgeFeeSurface> {
    let oracle = Arc::new(GovernanceSetFeeOracle::new());
    for adapter in [
        BridgeAdapterId::LayerZero,
        BridgeAdapterId::ChainlinkCcip,
        BridgeAdapterId::Wormhole,
        BridgeAdapterId::DeBridge,
        BridgeAdapterId::Hyperlane,
        BridgeAdapterId::Axelar,
        BridgeAdapterId::LiFi,
        BridgeAdapterId::Canton,
    ] {
        oracle.set_rate(GovernanceFeeRow {
            adapter,
            dest_chain: "eip155:1".into(),
            rate_q18: 2 * 1_000_000_000_000_000_000u128, // 2.0
            markup_bps: 100,
            valid_window_ms: 60_000,
            updated_at_ms: 0,
        });
    }
    let sponsor = Arc::new(BridgeFeeSponsor::new());
    Arc::new(WiredBridgeFeeSurface::new(oracle, sponsor))
}

fn bench_fee_oracle_quote(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let surface = build_wired_surface();
    let mut group = c.benchmark_group("fee_oracle");
    group.bench_function("governance_set_quote_single_pair", |b| {
        b.iter(|| {
            let q = rt
                .block_on(surface.oracle.quote(
                    BridgeAdapterId::LayerZero,
                    "eip155:1",
                    black_box(1_000_000),
                ))
                .unwrap();
            black_box(q);
        });
    });
    group.bench_function("governance_set_quote_all_8_adapters", |b| {
        b.iter(|| {
            for adapter in [
                BridgeAdapterId::LayerZero,
                BridgeAdapterId::ChainlinkCcip,
                BridgeAdapterId::Wormhole,
                BridgeAdapterId::DeBridge,
                BridgeAdapterId::Hyperlane,
                BridgeAdapterId::Axelar,
                BridgeAdapterId::LiFi,
                BridgeAdapterId::Canton,
            ] {
                let q = rt
                    .block_on(
                        surface
                            .oracle
                            .quote(adapter, "eip155:1", black_box(1_000_000)),
                    )
                    .unwrap();
                black_box(q);
            }
        });
    });
    group.finish();
}

fn bench_sponsor_record(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let surface = build_wired_surface();
    // Pre-quote one envelope so the sponsor path runs in isolation.
    let quote = rt.block_on(async {
        surface
            .oracle
            .quote(BridgeAdapterId::Wormhole, "eip155:1", 1_000_000)
            .await
            .unwrap()
    });
    let mut group = c.benchmark_group("fee_sponsor");
    group.bench_function("record_sponsorship_single", |b| {
        b.iter(|| {
            let r = surface
                .sponsor
                .record_sponsorship(&quote, black_box("did:tn:human:bench"))
                .unwrap();
            black_box(r);
        });
    });
    group.finish();
}

fn bench_router_list_pools(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let surface = build_wired_surface();
    let router = BridgeRouter::new().with_fee_surface(surface);
    let mut group = c.benchmark_group("router");
    group.bench_function("list_sponsorship_pools_8_adapters", |b| {
        b.iter(|| {
            let pools = rt.block_on(router.list_sponsorship_pools());
            black_box(pools);
        });
    });
    group.finish();
}

fn bench_7683_compute_order_id(c: &mut Criterion) {
    let order_data = TenzroOrderData {
        inputs: vec![],
        outputs: vec![],
        dest_chain_id: 8453,
        dest_recipient: [0xaa; 32],
        fill_deadline: 1_700_002_000,
        proof_route: ProofRoute::LayerZero,
        bridge_fee_hint: Some(BridgeFeeHint {
            quote_id_hex: "0xdeadbeef".to_string(),
            tnzo_amount_wei: "5100000".to_string(),
            valid_until_ms: 1_700_001_000,
            preferred_adapter: "layerzero".to_string(),
        }),
    };
    let order_data_bytes = bincode::serialize(&order_data).unwrap();
    let order = CrossChainOrder {
        settlement_contract: Address::new([1u8; 32]),
        swapper: Address::new([2u8; 32]),
        nonce: 7,
        origin_chain_id: TENZRO_MAINNET_CHAIN_ID,
        fill_deadline: 1_700_002_000,
        order_data_type: Hash::new([0xcc; 32]),
        order_data: order_data_bytes,
    };
    let mut group = c.benchmark_group("erc7683");
    group.bench_function("compute_order_id", |b| {
        b.iter(|| {
            let id = compute_order_id(black_box(&order));
            black_box(id);
        });
    });
    group.bench_function("serde_round_trip_order_data", |b| {
        b.iter(|| {
            let v = serde_json::to_vec(black_box(&order_data)).unwrap();
            let d: TenzroOrderData = serde_json::from_slice(&v).unwrap();
            black_box(d);
        });
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_new_message,
    bench_sign,
    bench_verify,
    bench_encode_decode,
    bench_fee_oracle_quote,
    bench_sponsor_record,
    bench_router_list_pools,
    bench_7683_compute_order_id,
);
criterion_main!(benches);
