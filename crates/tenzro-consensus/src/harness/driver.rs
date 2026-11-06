//! Discrete-event driver: runs `n` protocol nodes over an emulated WAN with
//! open-loop load, and measures what the proof gates ask for.

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};
use std::sync::Arc;

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

use super::wan::Wan;
use crate::core::Target;
use crate::vertex::Digest;

/// A batch as the load generator hands it to a node.
#[derive(Debug, Clone)]
pub struct SimBatch {
    /// Unique digest.
    pub digest: Digest,
    /// Transactions in the batch.
    pub transactions: u32,
}

/// What a node produced since the last drain.
pub struct Output<M> {
    /// Messages to send.
    pub sends: Vec<(Target, M)>,
    /// Blocks this node ordered: height, anchor digest, batch digests.
    pub ordered: Vec<(u64, Digest, Vec<Digest>)>,
    /// Checkpoints this node saw certified: (index, last height, digest).
    pub certified: Vec<(u64, u64, Digest)>,
    /// Evidence events: the validators it convicts.
    pub convicted: Vec<u16>,
    /// Bytes the node must persist before these sends, to recover.
    pub journal_bytes: u64,
}

impl<M> Default for Output<M> {
    fn default() -> Self {
        Self {
            sends: Vec::new(),
            ordered: Vec::new(),
            certified: Vec::new(),
            convicted: Vec::new(),
            journal_bytes: 0,
        }
    }
}

/// One protocol node under emulation.
pub trait SimNode {
    /// Wire message.
    type Msg: Clone;
    /// Starts the node.
    fn start(&mut self, now_ms: u64);
    /// Delivers one frame of messages from `from`.
    fn deliver(&mut self, from: u16, msgs: Vec<Self::Msg>, now_ms: u64);
    /// Advances timers.
    fn tick(&mut self, now_ms: u64);
    /// Hands the node a batch its clients submitted.
    fn submit(&mut self, batch: SimBatch, tx_bytes: usize);
    /// Takes the node's outputs.
    fn drain(&mut self, now_ms: u64) -> Output<Self::Msg>;
    /// Encoded size of a message, with batch payloads at `tx_bytes` per
    /// transaction.
    fn size(m: &Self::Msg, tx_bytes: usize) -> usize;
    /// Processing cost of a received message, microseconds.
    fn cost_us(m: &Self::Msg, tx_bytes: usize) -> u64;
    /// Accounting class of a message: `"payload"` counts as data, anything
    /// else as consensus metadata.
    fn class(m: &Self::Msg) -> &'static str;
    /// Sizes of the node's state, for memory tracing.
    fn mem_probe(&self) -> String {
        String::new()
    }
}

/// A network partition: during `[from_ms, until_ms)` messages between the
/// two sides are held and arrive after it heals.
#[derive(Debug, Clone)]
pub struct Partition {
    /// Start, milliseconds.
    pub from_ms: u64,
    /// Heal, milliseconds.
    pub until_ms: u64,
    /// Nodes on side A; the rest are side B.
    pub side_a: Vec<u16>,
}

/// One emulated run.
#[derive(Debug, Clone)]
pub struct Scenario {
    /// Number of nodes.
    pub n: usize,
    /// Network.
    pub wan: Wan,
    /// Offered load, transactions per second across all nodes.
    pub offered_tps: f64,
    /// Transaction size in bytes.
    pub tx_bytes: usize,
    /// How often a node cuts a batch, milliseconds.
    pub batch_interval_ms: u64,
    /// Run length, milliseconds.
    pub duration_ms: u64,
    /// Measurement starts here, milliseconds.
    pub warmup_ms: u64,
    /// Nodes that never start.
    pub crashed: Vec<u16>,
    /// Optional partition.
    pub partition: Option<Partition>,
    /// Node timer resolution, milliseconds.
    pub tick_ms: u64,
    /// RNG seed.
    pub seed: u64,
}

impl Scenario {
    /// A run of `n` nodes over ten regions at `offered_tps`.
    pub fn wan(n: usize, offered_tps: f64, duration_ms: u64) -> Self {
        Self {
            n,
            wan: Wan::spread(n, super::wan::REGIONS),
            offered_tps,
            tx_bytes: 512,
            batch_interval_ms: 50,
            duration_ms,
            warmup_ms: (duration_ms / 5).min(10_000),
            crashed: Vec::new(),
            partition: None,
            tick_ms: 5,
            seed: 7,
        }
    }
}

/// Latency distribution summary, milliseconds.
#[derive(Debug, Clone, Copy, Default)]
pub struct Percentiles {
    /// Samples (transactions).
    pub count: f64,
    /// Median.
    pub p50: f64,
    /// 99th percentile.
    pub p99: f64,
    /// Mean.
    pub mean: f64,
}

fn percentiles(mut samples: Vec<(f64, f64)>) -> Percentiles {
    if samples.is_empty() {
        return Percentiles::default();
    }
    samples.sort_by(|a, b| a.0.total_cmp(&b.0));
    let total: f64 = samples.iter().map(|s| s.1).sum();
    let at = |q: f64| {
        let target = q * total;
        let mut acc = 0.0;
        for (v, w) in &samples {
            acc += w;
            if acc >= target {
                return *v;
            }
        }
        samples.last().expect("non-empty").0
    };
    let mean = samples.iter().map(|(v, w)| v * w).sum::<f64>() / total;
    Percentiles {
        count: total,
        p50: at(0.5),
        p99: at(0.99),
        mean,
    }
}

/// What a run measured.
#[derive(Debug, Clone, Default)]
pub struct Report {
    /// Submit-to-ordered latency at the submitting node.
    pub ordered: Percentiles,
    /// Submit-to-certified latency at the submitting node.
    pub certified: Percentiles,
    /// Transactions ordered per second in the measurement window.
    pub ordered_tps: f64,
    /// Longest gap between consecutive blocks at any live node after
    /// warm-up, milliseconds.
    pub max_stall_ms: f64,
    /// Heights on which two live nodes ordered different blocks.
    pub safety_violations: usize,
    /// Checkpoint indices certified with two different digests.
    pub certificate_conflicts: usize,
    /// Highest height ordered by every live node.
    pub common_height: u64,
    /// Distinct checkpoints certified over the run.
    pub checkpoints_certified: usize,
    /// Mean consensus metadata sent per node, megabits per second.
    pub metadata_mbps: f64,
    /// Mean payload sent per node, megabits per second.
    pub payload_mbps: f64,
    /// Mean recovery journal written per node, megabytes per second.
    pub journal_mb_per_s: f64,
    /// Validators convicted of equivocation, by any node.
    pub convicted: Vec<u16>,
    /// Ordered p50 per 1-second bucket of submission time, for recovery
    /// measurements: (second, p50 ms).
    pub ordered_p50_by_second: Vec<(u64, f64)>,
    /// Emulated events processed.
    pub events: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Kind {
    Process,
    Tick,
    Cut,
}

struct Batch {
    first_us: u64,
    last_us: u64,
    count: u32,
    author: u16,
}

/// Runs `nodes` through `sc` and reports.
#[allow(clippy::needless_range_loop)] // the loop index is also the node's id in the event queue
pub fn run<N: SimNode>(sc: &Scenario, mut nodes: Vec<N>) -> Report {
    let n = sc.n;
    let mut rng = StdRng::seed_from_u64(sc.seed);
    let mut seq: u64 = 0;
    let mut heap: BinaryHeap<Reverse<(u64, u64, Kind, u16)>> = BinaryHeap::new();
    // A message sent to every peer is held once, shared by every queued
    // frame that carries it, and copied only when a receiver processes it.
    let mut inbox: HashMap<u64, (u16, u16, Vec<Arc<N::Msg>>)> = HashMap::new();
    let push = |heap: &mut BinaryHeap<_>, t: u64, k: Kind, node: u16, seq: &mut u64| -> u64 {
        *seq += 1;
        heap.push(Reverse((t, *seq, k, node)));
        *seq
    };
    let alive = |i: usize| !sc.crashed.contains(&(i as u16));
    let mut egress_free = vec![0u64; n];
    let mut cpu_free = vec![0u64; n];
    let mut bytes_meta = vec![0u64; n];
    let mut bytes_payload = vec![0u64; n];
    let mut bytes_journal = vec![0u64; n];
    let mut batches: HashMap<Digest, Batch> = HashMap::new();
    let mut height_batches: Vec<HashMap<u64, Vec<Digest>>> = vec![HashMap::new(); n];
    let mut certified_upto = vec![0u64; n];
    let mut ordered_samples: Vec<(f64, f64)> = Vec::new();
    let mut by_second: HashMap<u64, Vec<(f64, f64)>> = HashMap::new();
    let mut certified_samples: Vec<(f64, f64)> = Vec::new();
    let mut anchors: Vec<HashMap<u64, Digest>> = vec![HashMap::new(); n];
    let mut last_block_ms = vec![sc.warmup_ms as f64; n];
    let mut max_stall = 0.0f64;
    let mut ordered_tx_window: f64 = 0.0;
    let mut cert_digests: HashMap<u64, Digest> = HashMap::new();
    let mut cert_conflicts = 0usize;
    let mut convicted: Vec<u16> = Vec::new();
    let mut next_seq = vec![0u64; n];
    let per_node_rate = sc.offered_tps / n as f64;
    let end_us = sc.duration_ms * 1_000;
    let warm_us = sc.warmup_ms * 1_000;

    for i in 0..n {
        if alive(i) {
            nodes[i].start(0);
            push(&mut heap, 0, Kind::Tick, i as u16, &mut seq);
            let offset = rng.gen_range(0..sc.batch_interval_ms * 1_000);
            push(&mut heap, offset, Kind::Cut, i as u16, &mut seq);
        }
    }

    let mem_trace = std::env::var("TDC_MEM_TRACE").is_ok();
    let mut next_trace_us: u64 = 1_000_000;
    let mut events: u64 = 0;
    let mut pending_drain: Vec<u16> = (0..n as u16).filter(|i| alive(*i as usize)).collect();
    let mut now_us: u64 = 0;
    loop {
        // Flush every node touched by the last event.
        for i in pending_drain.drain(..) {
            let i = i as usize;
            let out = nodes[i].drain(now_us / 1_000);
            bytes_journal[i] += out.journal_bytes;
            // Group messages per destination into one frame.
            let mut frames: HashMap<u16, Vec<Arc<N::Msg>>> = HashMap::new();
            for (t, m) in out.sends {
                match t {
                    Target::All => {
                        let m = Arc::new(m);
                        for p in 0..n as u16 {
                            if p as usize != i {
                                frames.entry(p).or_default().push(Arc::clone(&m));
                            }
                        }
                    }
                    Target::One(p) => frames.entry(p).or_default().push(Arc::new(m)),
                }
            }
            let mut dests: Vec<u16> = frames.keys().copied().collect();
            dests.sort_unstable();
            for p in dests {
                let msgs = frames.remove(&p).expect("present");
                let mut size = 48usize;
                let mut cost = 5u64;
                for m in &msgs {
                    let s = N::size(m, sc.tx_bytes);
                    size += s;
                    cost += N::cost_us(m, sc.tx_bytes);
                    if N::class(m) == "payload" {
                        bytes_payload[i] += s as u64;
                    } else {
                        bytes_meta[i] += s as u64;
                    }
                }
                let depart = egress_free[i].max(now_us) + sc.wan.serialization_us(size);
                egress_free[i] = depart;
                let mut arrive = depart + sc.wan.delay_us(i, p as usize, &mut rng);
                if let Some(part) = &sc.partition {
                    let a = part.side_a.contains(&(i as u16));
                    let b = part.side_a.contains(&p);
                    let (from_us, until_us) = (part.from_ms * 1_000, part.until_ms * 1_000);
                    if a != b && depart < until_us && arrive >= from_us {
                        arrive = arrive.max(until_us + sc.wan.delay_us(i, p as usize, &mut rng));
                    }
                }
                if !alive(p as usize) {
                    continue;
                }
                // The receiver processes frames one at a time.
                let start = arrive.max(cpu_free[p as usize]);
                let done = start + cost;
                cpu_free[p as usize] = done;
                let id = push(&mut heap, done, Kind::Process, p, &mut seq);
                inbox.insert(id, (p, i as u16, msgs));
            }
            let now_ms_f = now_us as f64 / 1_000.0;
            for (h, anchor, digests) in out.ordered {
                if let Some(prev) = anchors[i].insert(h, anchor) {
                    debug_assert_eq!(prev, anchor);
                }
                if now_us >= warm_us {
                    max_stall = max_stall.max(now_ms_f - last_block_ms[i]);
                }
                last_block_ms[i] = now_ms_f;
                for d in &digests {
                    if let Some(b) = batches.get(d)
                        && b.author as usize == i
                    {
                        let samples = spread(b, now_us);
                        // Throughput is what is ordered during the window,
                        // whenever it was submitted: counting only batches
                        // submitted in the window would drop the last
                        // ordering latency's worth of them.
                        if now_us >= warm_us && now_us <= end_us {
                            ordered_tx_window += b.count as f64;
                        }
                        if b.first_us >= warm_us && now_us <= end_us {
                            by_second
                                .entry(b.first_us / 1_000_000)
                                .or_default()
                                .extend(samples.iter().copied());
                            ordered_samples.extend(samples);
                        }
                    }
                }
                height_batches[i].insert(h, digests);
            }
            for (index, last_height, digest) in out.certified {
                match cert_digests.get(&index) {
                    Some(d) if *d != digest => cert_conflicts += 1,
                    Some(_) => {}
                    None => {
                        cert_digests.insert(index, digest);
                    }
                }
                for h in certified_upto[i] + 1..=last_height {
                    if let Some(ds) = height_batches[i].remove(&h) {
                        for d in ds {
                            if let Some(b) = batches.get(&d)
                                && b.author as usize == i
                                && b.first_us >= warm_us
                                && now_us <= end_us
                            {
                                certified_samples.extend(spread(b, now_us));
                            }
                        }
                    }
                }
                certified_upto[i] = certified_upto[i].max(last_height);
            }
            for c in out.convicted {
                if !convicted.contains(&c) {
                    convicted.push(c);
                }
            }
        }

        let Some(Reverse((t, id, kind, node))) = heap.pop() else {
            break;
        };
        if t > end_us {
            break;
        }
        if mem_trace && t >= next_trace_us {
            next_trace_us += 1_000_000;
            let rss_mb = std::fs::read_to_string("/proc/self/statm")
                .ok()
                .and_then(|s| {
                    s.split_whitespace()
                        .nth(1)
                        .and_then(|p| p.parse::<u64>().ok())
                })
                .map_or(0, |pages| pages * 4096 / 1_000_000);
            println!(
                "MEM t={}s rss={rss_mb}MB heap={} inbox={} inbox_msgs={} batches={} samples={} node0: {}",
                t / 1_000_000,
                heap.len(),
                inbox.len(),
                inbox.values().map(|(_, _, m)| m.len()).sum::<usize>(),
                batches.len(),
                ordered_samples.len(),
                nodes[0].mem_probe()
            );
        }
        now_us = t;
        events += 1;
        let i = node as usize;
        match kind {
            Kind::Process => {
                let (_, from, msgs) = inbox.remove(&id).expect("queued frame");
                nodes[i].deliver(
                    from,
                    msgs.into_iter().map(Arc::unwrap_or_clone).collect(),
                    t / 1_000,
                );
            }
            Kind::Tick => {
                nodes[i].tick(t / 1_000);
                push(
                    &mut heap,
                    t + sc.tick_ms * 1_000,
                    Kind::Tick,
                    node,
                    &mut seq,
                );
            }
            Kind::Cut => {
                let window = sc.batch_interval_ms as f64 / 1_000.0;
                let mean = per_node_rate * window;
                let count = poisson(mean, &mut rng);
                if count > 0 {
                    let s = next_seq[i];
                    next_seq[i] += 1;
                    let mut h = blake3::Hasher::new();
                    h.update(b"sim-batch");
                    h.update(&node.to_be_bytes());
                    h.update(&s.to_be_bytes());
                    let digest: Digest = h.finalize().into();
                    let span = sc.batch_interval_ms * 1_000;
                    batches.insert(
                        digest,
                        Batch {
                            first_us: t.saturating_sub(span),
                            last_us: t,
                            count,
                            author: node,
                        },
                    );
                    nodes[i].submit(
                        SimBatch {
                            digest,
                            transactions: count,
                        },
                        sc.tx_bytes,
                    );
                }
                push(
                    &mut heap,
                    t + sc.batch_interval_ms * 1_000,
                    Kind::Cut,
                    node,
                    &mut seq,
                );
            }
        }
        pending_drain.push(node);
    }

    // Safety: every live pair agrees on every height both ordered.
    let live: Vec<usize> = (0..n).filter(|i| alive(*i)).collect();
    for &i in &live {
        max_stall = max_stall.max(sc.duration_ms as f64 - last_block_ms[i]);
    }
    let mut violations = 0usize;
    let mut reference: HashMap<u64, Digest> = HashMap::new();
    for &i in &live {
        for (h, d) in &anchors[i] {
            match reference.get(h) {
                Some(x) if x != d => violations += 1,
                Some(_) => {}
                None => {
                    reference.insert(*h, *d);
                }
            }
        }
    }
    let heights: Vec<u64> = live
        .iter()
        .map(|i| anchors[*i].keys().max().copied().unwrap_or(0))
        .collect();
    let window_s = (sc.duration_ms - sc.warmup_ms) as f64 / 1_000.0;
    let run_s = sc.duration_ms as f64 / 1_000.0;
    let mut ordered_p50_by_second: Vec<(u64, f64)> = by_second
        .into_iter()
        .map(|(s, v)| (s, percentiles(v).p50))
        .collect();
    ordered_p50_by_second.sort_by_key(|x| x.0);
    Report {
        ordered: percentiles(ordered_samples),
        certified: percentiles(certified_samples),
        ordered_tps: ordered_tx_window / window_s,
        max_stall_ms: max_stall,
        safety_violations: violations,
        certificate_conflicts: cert_conflicts,
        common_height: heights.iter().copied().min().unwrap_or(0),
        checkpoints_certified: cert_digests.len(),
        metadata_mbps: live
            .iter()
            .map(|i| bytes_meta[*i] as f64 * 8.0 / 1e6 / run_s)
            .sum::<f64>()
            / live.len().max(1) as f64,
        payload_mbps: live
            .iter()
            .map(|i| bytes_payload[*i] as f64 * 8.0 / 1e6 / run_s)
            .sum::<f64>()
            / live.len().max(1) as f64,
        journal_mb_per_s: live
            .iter()
            .map(|i| bytes_journal[*i] as f64 / 1e6 / run_s)
            .sum::<f64>()
            / live.len().max(1) as f64,
        convicted,
        ordered_p50_by_second,
        events,
    }
}

/// Latency samples for one batch: its transactions arrived uniformly over
/// its window; each of up to 8 points carries an equal share.
fn spread(b: &Batch, now_us: u64) -> Vec<(f64, f64)> {
    let k = (b.count as usize).clamp(1, 8);
    let w = b.count as f64 / k as f64;
    (0..k)
        .map(|j| {
            let at =
                b.first_us as f64 + (b.last_us - b.first_us) as f64 * (j as f64 + 0.5) / k as f64;
            ((now_us as f64 - at) / 1_000.0, w)
        })
        .collect()
}

fn poisson(mean: f64, rng: &mut StdRng) -> u32 {
    if mean <= 0.0 {
        return 0;
    }
    if mean > 50.0 {
        // Normal approximation for large means.
        let u1: f64 = rng.gen_range(f64::EPSILON..1.0);
        let u2: f64 = rng.gen_range(0.0..1.0);
        let z = (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos();
        return (mean + z * mean.sqrt()).round().max(0.0) as u32;
    }
    let l = (-mean).exp();
    let mut k = 0u32;
    let mut p = 1.0;
    loop {
        p *= rng.gen_range(0.0..1.0f64);
        if p <= l {
            return k;
        }
        k += 1;
    }
}
