//! Criterion benchmarks for the Plonky3 STARK hot path.
//!
//! Covers the three production AIRs (Inference / Settlement / Identity) at the
//! pinned testnet trace height `1 << 3`, plus the wire-format
//! `verify_proof_envelope` dispatch consumed by the EVM `ZK_VERIFY`
//! precompile, MCP `verify_zk_proof` tool, and web verification API.

use std::time::Duration;

use criterion::{BatchSize, Criterion, black_box, criterion_group, criterion_main};
use p3_field::PrimeCharacteristicRing;
use p3_koala_bear::KoalaBear;
use p3_matrix::dense::RowMajorMatrix;

use tenzro_zk::plonky3::{encode_proof, encode_public_inputs};
use tenzro_zk::{
    IdentityAir, InferenceAir, Plonky3Prover, Plonky3Verifier, PqQcAggregationAir, Proof,
    SettlementAir, generate_identity_trace, generate_inference_trace, generate_pq_qc_trace,
    generate_settlement_trace, identity_public_inputs, inference_public_inputs,
    pq_qc_public_inputs, settlement_public_inputs, verify_proof_envelope,
};

const TRACE_HEIGHT: usize = 1 << 3;

// ------------------------------- Inference ----------------------------------

fn build_inference_witness() -> (RowMajorMatrix<KoalaBear>, Vec<KoalaBear>) {
    let model = KoalaBear::from_u64(3);
    let input = KoalaBear::from_u64(5);
    let output = KoalaBear::from_u64(15);
    let trace = generate_inference_trace(model, input, output, TRACE_HEIGHT);
    let pis = inference_public_inputs(model, input, output);
    (trace, pis)
}

fn bench_inference_prove(c: &mut Criterion) {
    let prover = Plonky3Prover::<InferenceAir>::new();
    let mut group = c.benchmark_group("plonky3_prove");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(15));
    group.bench_function("inference_air", |b| {
        b.iter_batched(
            build_inference_witness,
            |(trace, pis)| {
                black_box(prover.prove_air(&InferenceAir, trace, &pis));
            },
            BatchSize::SmallInput,
        );
    });
    group.finish();
}

fn bench_inference_verify(c: &mut Criterion) {
    let prover = Plonky3Prover::<InferenceAir>::new();
    let verifier = Plonky3Verifier::<InferenceAir>::new();
    let (trace, pis) = build_inference_witness();
    let proof = prover.prove_air(&InferenceAir, trace, &pis);

    let mut group = c.benchmark_group("plonky3_verify");
    group.bench_function("inference_air", |b| {
        b.iter(|| {
            verifier
                .verify_air(&InferenceAir, black_box(&proof), black_box(&pis))
                .expect("valid proof must verify");
        });
    });
    group.finish();
}

// ------------------------------- Settlement ---------------------------------

fn build_settlement_witness() -> (RowMajorMatrix<KoalaBear>, Vec<KoalaBear>) {
    let payer_balance = KoalaBear::from_u64(500);
    let service_proof = KoalaBear::from_u64(7);
    let prev_nonce = KoalaBear::from_u64(5);
    let nonce = KoalaBear::from_u64(6);
    let amount = KoalaBear::from_u64(100);
    let trace = generate_settlement_trace(
        payer_balance,
        service_proof,
        nonce,
        prev_nonce,
        amount,
        TRACE_HEIGHT,
    );
    let pis = settlement_public_inputs(service_proof, amount);
    (trace, pis)
}

fn bench_settlement_prove(c: &mut Criterion) {
    let prover = Plonky3Prover::<SettlementAir>::new();
    let mut group = c.benchmark_group("plonky3_prove");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(15));
    group.bench_function("settlement_air", |b| {
        b.iter_batched(
            build_settlement_witness,
            |(trace, pis)| {
                black_box(prover.prove_air(&SettlementAir, trace, &pis));
            },
            BatchSize::SmallInput,
        );
    });
    group.finish();
}

fn bench_settlement_verify(c: &mut Criterion) {
    let prover = Plonky3Prover::<SettlementAir>::new();
    let verifier = Plonky3Verifier::<SettlementAir>::new();
    let (trace, pis) = build_settlement_witness();
    let proof = prover.prove_air(&SettlementAir, trace, &pis);

    let mut group = c.benchmark_group("plonky3_verify");
    group.bench_function("settlement_air", |b| {
        b.iter(|| {
            verifier
                .verify_air(&SettlementAir, black_box(&proof), black_box(&pis))
                .expect("valid proof must verify");
        });
    });
    group.finish();
}

// -------------------------------- Identity ----------------------------------

fn build_identity_witness() -> (RowMajorMatrix<KoalaBear>, Vec<KoalaBear>) {
    let private_key = KoalaBear::from_u64(5);
    let capabilities = KoalaBear::from_u64(7);
    let capability_blinding = KoalaBear::from_u64(3);
    let actual_reputation = KoalaBear::from_u64(150);
    let minimum_reputation = KoalaBear::from_u64(100);
    let trace = generate_identity_trace(
        private_key,
        capabilities,
        capability_blinding,
        actual_reputation,
        minimum_reputation,
        TRACE_HEIGHT,
    );
    let pis = identity_public_inputs(private_key, capabilities, capability_blinding);
    (trace, pis)
}

fn bench_identity_prove(c: &mut Criterion) {
    let prover = Plonky3Prover::<IdentityAir>::new();
    let mut group = c.benchmark_group("plonky3_prove");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(15));
    group.bench_function("identity_air", |b| {
        b.iter_batched(
            build_identity_witness,
            |(trace, pis)| {
                black_box(prover.prove_air(&IdentityAir, trace, &pis));
            },
            BatchSize::SmallInput,
        );
    });
    group.finish();
}

fn bench_identity_verify(c: &mut Criterion) {
    let prover = Plonky3Prover::<IdentityAir>::new();
    let verifier = Plonky3Verifier::<IdentityAir>::new();
    let (trace, pis) = build_identity_witness();
    let proof = prover.prove_air(&IdentityAir, trace, &pis);

    let mut group = c.benchmark_group("plonky3_verify");
    group.bench_function("identity_air", |b| {
        b.iter(|| {
            verifier
                .verify_air(&IdentityAir, black_box(&proof), black_box(&pis))
                .expect("valid proof must verify");
        });
    });
    group.finish();
}

// ---------------------------- Envelope dispatch -----------------------------
//
// `verify_proof_envelope` is the bytes-in / Result-out function consumed by
// the EVM `ZK_VERIFY` precompile path, MCP/web/A2A verifier tools, and the
// settlement engine's `DefaultZkVerifier`. It dispatches on the `circuit_id`
// embedded in the wire `Proof`.

fn build_inference_envelope() -> Proof {
    let (trace, pis) = build_inference_witness();
    let prover = Plonky3Prover::<InferenceAir>::new();
    let p3_proof = prover.prove_air(&InferenceAir, trace, &pis);
    Proof::new(
        encode_proof(&p3_proof).expect("encode proof"),
        encode_public_inputs(&pis),
        "inference".to_string(),
    )
}

fn bench_verify_envelope(c: &mut Criterion) {
    let proof = build_inference_envelope();
    let mut group = c.benchmark_group("plonky3_verify_envelope");
    group.bench_function("inference", |b| {
        b.iter(|| {
            verify_proof_envelope(black_box(&proof)).expect("valid envelope must verify");
        });
    });
    group.finish();
}

// --------------------------- PQ QC aggregation ------------------------------
//
// G11 go/no-go inputs: proving time and proof size for a certificate over
// N ∈ {4, 16, 64} signer seats. This AIR binds aggregation *structure* — the
// bitmap↔verification coupling, popcount, and message digest — with each
// `verified[i]` witnessed from an off-circuit native ML-DSA-65 verification.
// It does NOT fold the lattice verification equation into constraints; these
// numbers are the baseline against which an in-circuit variant would be judged.

const PQ_QC_SIZES: [usize; 3] = [4, 16, 64];

fn build_pq_qc_witness(n: usize) -> (RowMajorMatrix<KoalaBear>, Vec<KoalaBear>) {
    // Every seat present and verified — the widest trace for a given N.
    let bitmap: Vec<bool> = (0..n).map(|_| true).collect();
    let verified = bitmap.clone();
    let message = b"tenzro/qc/bench";
    let trace = generate_pq_qc_trace(&bitmap, &verified, message, TRACE_HEIGHT);
    let pis = pq_qc_public_inputs(&bitmap, message);
    (trace, pis)
}

fn bench_pq_qc_prove(c: &mut Criterion) {
    let mut group = c.benchmark_group("plonky3_prove");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(20));
    for &n in &PQ_QC_SIZES {
        let air = PqQcAggregationAir::new(n);
        let prover = Plonky3Prover::<PqQcAggregationAir>::new();
        group.bench_function(format!("pq_qc_air_n{n}"), |b| {
            b.iter_batched(
                || build_pq_qc_witness(n),
                |(trace, pis)| {
                    black_box(prover.prove_air(&air, trace, &pis));
                },
                BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

fn bench_pq_qc_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("plonky3_verify");
    for &n in &PQ_QC_SIZES {
        let air = PqQcAggregationAir::new(n);
        let prover = Plonky3Prover::<PqQcAggregationAir>::new();
        let verifier = Plonky3Verifier::<PqQcAggregationAir>::new();
        let (trace, pis) = build_pq_qc_witness(n);
        let proof = prover.prove_air(&air, trace, &pis);
        group.bench_function(format!("pq_qc_air_n{n}"), |b| {
            b.iter(|| {
                verifier
                    .verify_air(&air, black_box(&proof), black_box(&pis))
                    .expect("valid proof must verify");
            });
        });
    }
    group.finish();
}

/// Not a timing bench — reports the encoded proof size (bytes) for each N so
/// the go/no-go report has a size column alongside the proving-time column.
/// Criterion runs the body once per iteration; the size is emitted via the
/// group id which shows in the summary line.
fn bench_pq_qc_proof_size(c: &mut Criterion) {
    let mut group = c.benchmark_group("plonky3_pq_qc_proof_size_bytes");
    group.sample_size(10);
    for &n in &PQ_QC_SIZES {
        let air = PqQcAggregationAir::new(n);
        let prover = Plonky3Prover::<PqQcAggregationAir>::new();
        let (trace, pis) = build_pq_qc_witness(n);
        let proof = prover.prove_air(&air, trace, &pis);
        let encoded = encode_proof(&proof).expect("encode proof");
        let bytes = encoded.len();
        // Encode the measured size in the bench name so it lands in the report.
        group.bench_function(format!("n{n}_bytes{bytes}"), |b| {
            b.iter(|| black_box(encoded.len()));
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_inference_prove,
    bench_inference_verify,
    bench_settlement_prove,
    bench_settlement_verify,
    bench_identity_prove,
    bench_identity_verify,
    bench_verify_envelope,
    bench_pq_qc_prove,
    bench_pq_qc_verify,
    bench_pq_qc_proof_size,
);
criterion_main!(benches);
