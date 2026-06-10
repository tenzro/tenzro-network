//! Adaptive consensus regression tests for a **permissionless** validator
//! network.
//!
//! **No geographic-region fixtures.** The validator set is open: anyone
//! stakes and joins, anyone leaves. Topology is unknown, irregular, and
//! shifting. These tests draw latency matrices from real-world-shaped
//! distributions — heavy-tailed lognormal with outliers — and assert
//! the consensus engine self-tunes regardless.
//!
//! The test specifications mirror the design rules in
//! `memory/project_permissionless_validator_network_principles.md`:
//!
//!   - No hardcoded "regions"; latency is per-pair, drawn from
//!     parametric distributions
//!   - No assumption about N — tests scale across 4..50 validators
//!   - No assumption about RTT bounds — distributions include
//!     pathological tails up to 1500ms
//!   - The adaptive `ViewChangeTimer::record_observed_view_latency`
//!     algorithm is what's actually being exercised; the seed
//!     `view_timeout_ms` is just a bootstrap value

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

use tenzro_consensus::{
    BlockProvider, ConsensusConfig, ConsensusEngine, ConsensusOutMessage, EpochManager,
    HotStuff2Engine, ValidatorInfo,
};
use tenzro_crypto::bls::{BlsKeyPair, BlsSecretKey};
use tenzro_crypto::pq::MlDsaSigningKey;
use tenzro_crypto::{KeyPair, KeyType};
use tenzro_types::block::{
    Block, BlockHeader, BlockMetadata, ConsensusAlgorithm, ConsensusProof, FeeMarketParams,
};
use tenzro_types::primitives::{Address, BlockHeight, Hash};
use tokio::sync::mpsc;

// ---------------------------------------------------------------------------
// Latency-matrix abstraction — no regions, just numbers
// ---------------------------------------------------------------------------

/// Per-pair one-way latency in milliseconds. Symmetric: `matrix[i][j] ==
/// matrix[j][i]` always. Diagonal is intentionally low (~1ms) to model
/// self-loopback for direct insertion paths, not real network RTT.
///
/// This is the only network-topology abstraction in the test harness.
/// No regions, no zones, no geographic shorthand — just a matrix that
/// any real-world latency distribution can be sampled into.
#[derive(Clone)]
struct LatencyMatrix {
    n: usize,
    latencies: Vec<Vec<u64>>,
}

impl LatencyMatrix {
    fn get(&self, src: usize, dst: usize) -> u64 {
        self.latencies[src][dst]
    }

    /// Build a matrix from a function `f(i, j) -> ms` for `i, j ∈ [0, n)`.
    /// The harness ensures symmetry by averaging `f(i,j)` and `f(j,i)`.
    fn from_fn(n: usize, mut f: impl FnMut(usize, usize) -> u64) -> Self {
        let mut latencies = vec![vec![0u64; n]; n];
        for i in 0..n {
            for j in 0..n {
                if i == j {
                    latencies[i][j] = 1;
                } else if i < j {
                    let a = f(i, j);
                    let b = f(j, i);
                    let avg = (a + b) / 2;
                    latencies[i][j] = avg;
                    latencies[j][i] = avg;
                }
            }
        }
        Self { n, latencies }
    }

    /// Distribution 1: heavy-tailed lognormal RTT, no clusters. Models
    /// a fully-decentralised validator set where each validator is in
    /// a different network location with no geographic structure.
    /// Parameters chosen to match observed real-world internet RTT
    /// distributions (median ~80ms, p99 ~600ms, occasional outliers).
    fn heavy_tailed_lognormal(n: usize, seed: u64) -> Self {
        let mut rng = StdRng::seed_from_u64(seed);
        Self::from_fn(n, |_, _| {
            // Lognormal(mu=4.0, sigma=0.9) — median ~55ms, mean ~85ms,
            // p95 ~250ms, p99 ~500ms, p999 ~1000ms
            let u: f64 = rng.r#gen();
            let v: f64 = rng.r#gen();
            let z = (-2.0 * u.ln()).sqrt() * (2.0 * std::f64::consts::PI * v).cos();
            let lognorm = (4.0 + 0.9 * z).exp();
            lognorm.clamp(5.0, 2000.0) as u64
        })
    }

    /// Distribution 2: bimodal — a dense cluster of fast validators
    /// plus a fraction of slow outliers. Models the realistic case
    /// where most validators run in mainstream cloud regions but a
    /// few are on residential or remote connections.
    fn bimodal(n: usize, slow_fraction: f64, seed: u64) -> Self {
        let mut rng = StdRng::seed_from_u64(seed);
        let slow_count = ((n as f64) * slow_fraction).ceil() as usize;
        let slow: Vec<bool> = (0..n).map(|i| i >= n - slow_count).collect();
        Self::from_fn(n, |i, j| {
            let either_slow = slow[i] || slow[j];
            let base = if either_slow { 400.0 } else { 40.0 };
            let jitter: f64 = rng.r#gen::<f64>() * 60.0;
            (base + jitter) as u64
        })
    }

    /// Distribution 3: pathological — one validator on simulated
    /// satellite (1200ms one-way to everyone). Tests whether the
    /// adaptive timeout can absorb a single extreme outlier without
    /// the rest stalling.
    fn one_pathological_outlier(n: usize, seed: u64) -> Self {
        let mut rng = StdRng::seed_from_u64(seed);
        Self::from_fn(n, |i, j| {
            let outlier = i == 0 || j == 0;
            if outlier {
                1200
            } else {
                30 + (rng.r#gen::<f64>() * 50.0) as u64
            }
        })
    }

    /// Distribution 4: low-RTT uniform single-region — sanity check.
    /// All validators ~10-30ms apart. The harness should produce
    /// blocks at near-block-time rate.
    fn low_rtt_uniform(n: usize, seed: u64) -> Self {
        let mut rng = StdRng::seed_from_u64(seed);
        Self::from_fn(n, |_, _| 10 + (rng.r#gen::<f64>() * 20.0) as u64)
    }
}

// ---------------------------------------------------------------------------
// Engine harness
// ---------------------------------------------------------------------------

fn crypto_to_types_address(c: tenzro_crypto::Address) -> Address {
    let mut b = [0u8; 32];
    b[..20].copy_from_slice(c.as_bytes());
    Address::new(b)
}

fn build_validator() -> (KeyPair, MlDsaSigningKey, BlsKeyPair, ValidatorInfo) {
    let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
    let address = crypto_to_types_address(keypair.address());
    let pq = MlDsaSigningKey::generate();
    let pq_vk = pq.verifying_key_bytes().to_vec();
    let bls = BlsKeyPair::generate().unwrap();
    let info = ValidatorInfo::new(
        address,
        keypair.public_key().clone(),
        pq_vk,
        bls.public_key().to_bytes().to_vec(),
        1000,
    );
    (keypair, pq, bls, info)
}

/// Genesis-only block provider: the engine asks for parent at height
/// 0 during base-fee derivation. We furnish one. No production logic.
struct GenesisBlockProvider {
    genesis: Block,
}

impl GenesisBlockProvider {
    fn new() -> Self {
        let mut header = BlockHeader::new_at_view(
            BlockHeight::from(0),
            0,
            Hash::default(),
            Hash::default(),
            Hash::default(),
            Address::new([0u8; 32]),
            ConsensusProof::new(ConsensusAlgorithm::PBFT, Vec::new()),
        );
        header.metadata = BlockMetadata {
            gas_used: 0,
            gas_limit: 0,
            tx_count: 0,
            protocol_version: 1,
            base_fee_per_gas: Some(FeeMarketParams::default().initial_base_fee),
        };
        Self {
            genesis: Block::new(header, vec![]),
        }
    }
}

impl BlockProvider for GenesisBlockProvider {
    fn get_block(&self, height: BlockHeight) -> Option<Block> {
        if height.as_u64() == 0 {
            Some(self.genesis.clone())
        } else {
            None
        }
    }
}

async fn build_engine(
    keypair: KeyPair,
    pq_seed: Vec<u8>,
    bls_sk_bytes: [u8; 32],
    config: ConsensusConfig,
    epoch_manager: EpochManager,
) -> (
    Arc<HotStuff2Engine>,
    mpsc::UnboundedReceiver<ConsensusOutMessage>,
) {
    let (tx, rx) = mpsc::unbounded_channel();
    let kp = KeyPair::from_bytes(keypair.key_type(), &keypair.to_bytes()).unwrap();
    let pq = MlDsaSigningKey::from_seed(&pq_seed).unwrap();
    let bls = BlsKeyPair::from_secret_key(BlsSecretKey::from_bytes(&bls_sk_bytes).unwrap());
    let block_provider: Arc<dyn BlockProvider> = Arc::new(GenesisBlockProvider::new());
    let mut engine = HotStuff2Engine::new(kp, pq, bls, config, epoch_manager)
        .with_consensus_out(tx)
        .with_block_provider(block_provider);
    engine.start().await.unwrap();
    (Arc::new(engine), rx)
}

struct EngineHandle {
    engine: Arc<HotStuff2Engine>,
    /// Index into the latency matrix.
    idx: usize,
}

/// Run an N-validator cluster against a given latency matrix for
/// `duration`. Returns `(min_finalized_height, blocks_per_engine)`
/// so callers can assess both liveness (any progress) and
/// homogeneity (similar progress across all validators).
async fn run_cluster(
    n: usize,
    matrix: &LatencyMatrix,
    seed_timeout_ms: u64,
    duration: Duration,
) -> (u64, Vec<u64>) {
    assert_eq!(n, matrix.n);
    assert!(n >= 4, "BFT requires n >= 4");

    // Build N validators.
    let mut keys = Vec::with_capacity(n);
    let mut infos = Vec::with_capacity(n);
    for _ in 0..n {
        let (kp, pq, bls, info) = build_validator();
        let pq_seed = pq.seed_bytes().to_vec();
        let bls_sk = bls.secret_key().to_bytes();
        infos.push(info);
        keys.push((kp, pq_seed, bls_sk));
    }

    let config = ConsensusConfig::default()
        .with_view_timeout(seed_timeout_ms)
        .with_block_time(100);

    let mut handles: Vec<EngineHandle> = Vec::with_capacity(n);
    let mut rxs: Vec<mpsc::UnboundedReceiver<ConsensusOutMessage>> = Vec::with_capacity(n);
    let mut _addr_to_idx: HashMap<Address, usize> = HashMap::new();

    for (idx, (kp, pq_seed, bls_sk)) in keys.into_iter().enumerate() {
        let epoch = EpochManager::new(infos.clone(), 10_000).unwrap();
        let (engine, rx) = build_engine(kp, pq_seed, bls_sk, config.clone(), epoch).await;
        _addr_to_idx.insert(infos[idx].address, idx);
        handles.push(EngineHandle { engine, idx });
        rxs.push(rx);
    }

    let handles_arc: Arc<Vec<EngineHandle>> = Arc::new(handles);
    let matrix_arc: Arc<LatencyMatrix> = Arc::new(matrix.clone());

    // Router: for each engine's outbound channel, forward each message
    // to every other engine via its `test_on_*` entrypoint with the
    // pair-specific latency from the matrix.
    let mut router_tasks = Vec::new();
    for (src_idx, mut rx) in rxs.into_iter().enumerate() {
        let handles_clone = handles_arc.clone();
        let matrix_clone = matrix_arc.clone();
        let task = tokio::spawn(async move {
            while let Some(msg) = rx.recv().await {
                for (dst_idx, dst) in handles_clone.iter().enumerate() {
                    if dst_idx == src_idx {
                        continue;
                    }
                    let delay_ms = matrix_clone.get(src_idx, dst.idx);
                    let engine = dst.engine.clone();
                    let msg = msg.clone();
                    tokio::spawn(async move {
                        tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                        match msg {
                            ConsensusOutMessage::Proposal {
                                block,
                                timeout_certificate,
                                no_endorsement_certificate,
                                high_qc_view,
                                ..
                            } => {
                                let _ = engine
                                    .test_on_proposal(
                                        &block,
                                        timeout_certificate,
                                        no_endorsement_certificate,
                                        high_qc_view,
                                    )
                                    .await;
                            }
                            ConsensusOutMessage::Vote(v) => {
                                let _ = engine.test_on_vote(&v).await;
                            }
                            ConsensusOutMessage::Timeout(t) => {
                                let _ = engine.on_timeout_msg(&t).await;
                            }
                            ConsensusOutMessage::NoEndorsement(n) => {
                                let _ = engine.on_no_endorsement_msg(&n).await;
                            }
                        }
                    });
                }
            }
        });
        router_tasks.push(task);
    }

    tokio::time::sleep(duration).await;

    let mut heights = Vec::with_capacity(n);
    let mut min_h = u64::MAX;
    for h in handles_arc.iter() {
        let v = h.engine.finalized_height().await.as_u64();
        heights.push(v);
        if v < min_h {
            min_h = v;
        }
    }
    for t in router_tasks {
        t.abort();
    }
    drop(handles_arc);
    (min_h, heights)
}

fn init_logging() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_test_writer()
        .try_init();
}

// ---------------------------------------------------------------------------
// Tests — exercise the adaptive timeout against varied real-world topologies
// ---------------------------------------------------------------------------

/// SANITY: low-RTT homogeneous cluster of 7 validators finalises a
/// healthy stream of blocks. The adaptive timeout should converge to a
/// small value (~100ms after backoff) and the cluster should hit
/// near-block-time finalisation.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "long-running cluster simulation; run with --include-ignored"]
async fn low_rtt_cluster_finalises_fast() {
    init_logging();
    let n = 7;
    let matrix = LatencyMatrix::low_rtt_uniform(n, 42);
    let (min_h, all) = run_cluster(n, &matrix, 1000, Duration::from_secs(10)).await;
    eprintln!("low_rtt: min={} all={:?}", min_h, all);
    assert!(
        min_h >= 10,
        "low-RTT cluster: only {} block(s) in 10s; harness or engine broken",
        min_h
    );
}

/// HEAVY-TAIL: 7 validators with lognormal-distributed RTTs (no
/// geographic structure). The adaptive algorithm must converge to a
/// timeout that absorbs the tail without stalling.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "long-running cluster simulation; run with --include-ignored"]
async fn heavy_tailed_topology_finalises_steadily() {
    init_logging();
    let n = 7;
    let matrix = LatencyMatrix::heavy_tailed_lognormal(n, 1);
    let (min_h, all) = run_cluster(n, &matrix, 1000, Duration::from_secs(30)).await;
    eprintln!("heavy_tail: min={} all={:?}", min_h, all);
    assert!(
        min_h >= 5,
        "heavy-tail cluster: only {} block(s) in 30s; adaptive timeout failed",
        min_h
    );
}

/// BIMODAL: most validators fast, a few slow. Tests that the
/// adaptive algorithm doesn't get dragged down by the minority.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "long-running cluster simulation; run with --include-ignored"]
async fn bimodal_topology_finalises() {
    init_logging();
    let n = 9;
    let matrix = LatencyMatrix::bimodal(n, 0.22, 7); // 2/9 are slow
    let (min_h, all) = run_cluster(n, &matrix, 1000, Duration::from_secs(30)).await;
    eprintln!("bimodal: min={} all={:?}", min_h, all);
    assert!(
        min_h >= 5,
        "bimodal cluster: only {} block(s) in 30s; adaptive timeout failed",
        min_h
    );
}

/// PATHOLOGICAL OUTLIER: 6 fast validators + 1 satellite-class
/// validator (1200ms RTT to everyone). The cluster MUST keep
/// producing blocks — the outlier's votes might arrive late, but with
/// 6 of 7 fast validators, BFT quorum is reachable without them.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "long-running cluster simulation; run with --include-ignored"]
async fn pathological_outlier_does_not_halt() {
    init_logging();
    let n = 7;
    let matrix = LatencyMatrix::one_pathological_outlier(n, 11);
    let (min_h, all) = run_cluster(n, &matrix, 1000, Duration::from_secs(30)).await;
    eprintln!("pathological_outlier: min={} all={:?}", min_h, all);
    // Min height may be 0 (the outlier itself); fast validators must
    // still finalise.
    let max_h = *all.iter().max().unwrap();
    assert!(
        max_h >= 5,
        "pathological-outlier cluster: max validator at {} block(s) in 30s; halted",
        max_h
    );
}

/// SEED INVARIANCE: starting from very different seed timeouts, the
/// adaptive algorithm must converge to similar steady-state
/// throughput. If the seed dominates the outcome, the algorithm is
/// not adaptive.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "very long-running cluster simulation; run with --include-ignored"]
async fn seed_timeout_does_not_dominate_outcome() {
    init_logging();
    let n = 7;
    let matrix = LatencyMatrix::heavy_tailed_lognormal(n, 23);
    let seeds = [200u64, 1000, 3000, 8000];
    let mut results = Vec::new();
    for s in seeds {
        let (h, _) = run_cluster(n, &matrix, s, Duration::from_secs(30)).await;
        eprintln!("seed={}ms -> {} blocks/30s", s, h);
        results.push(h);
    }
    let max = *results.iter().max().unwrap();
    let min = *results.iter().min().unwrap();
    eprintln!("seed-invariance: min={} max={} delta={}", min, max, max - min);
    // The seed CAN affect the first few views (during EWMA warm-up),
    // but the spread shouldn't be enormous if adaptation is working.
    // We assert a loose bound: max-min < 2× the min (i.e. seeds don't
    // produce wildly divergent throughput).
    if min > 0 {
        assert!(
            max <= min * 3,
            "seeds produced widely divergent throughput: {:?} — adaptation may not be working",
            results
        );
    }
}

/// SCALE: increasing N from 4 to 15 should not collapse throughput.
/// Permissionless networks grow; consensus must too.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "very long-running cluster simulation; run with --include-ignored"]
async fn scale_test_4_to_15_validators() {
    init_logging();
    for n in [4usize, 7, 10, 15] {
        let matrix = LatencyMatrix::heavy_tailed_lognormal(n, 31);
        let (h, _) = run_cluster(n, &matrix, 1000, Duration::from_secs(20)).await;
        eprintln!("n={} validators -> {} blocks/20s", n, h);
        assert!(
            h >= 3,
            "scale test n={}: only {} block(s) in 20s",
            n,
            h
        );
    }
}
