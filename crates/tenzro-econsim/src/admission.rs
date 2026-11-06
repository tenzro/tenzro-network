//! Admission under adversarial load: what a Sybil flood gets into the
//! mempool past the node's admission layers, and what honest senders keep.
//!
//! The layers, in the order a submission meets them, with the network's
//! genesis values of their governed parameters:
//! - the per-address request floor (`rpc.address_rate_per_second`,
//!   `rpc.address_burst`): any request within it goes on;
//! - past the floor, a per-address budget of identity checks
//!   (`rpc.identity_checks_per_second`): a submission within it goes on only
//!   when its sender is in the verified or delegated lane;
//! - the sender's own lane quota, the real
//!   [`tenzro_consensus::admission::AdmissionController`] with the governed
//!   `admission.*` rates and bursts;
//! - the mempool's balance check: an account that cannot pay is refused.
//!
//! Time is simulated: each scenario runs for a number of seconds of offered
//! load at a fixed tick, so its result follows from its inputs alone.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::Serialize;
use tenzro_consensus::admission::{
    AdmissionConfig, AdmissionController, AdmissionDecision, Lane, LaneResolver,
};
use tenzro_types::account_signature::{ClassicalProof, CompositeSignature};
use tenzro_types::primitives::{Address, ChainId, Nonce};
use tenzro_types::transaction::{SignedTransaction, Transaction, TransactionType};
use tenzro_vm::governance as g;

/// Who a sender is to admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sender {
    /// Attested identity with bonded stake.
    Verified,
    /// Machine under a verified controller, or holding an agent bond.
    Delegated,
    /// Anyone else, able to pay.
    Open,
    /// Anyone else, unable to pay (a fresh key).
    Unfunded,
}

/// A group of senders behind some addresses, offering a steady rate.
#[derive(Debug, Clone)]
pub struct Group {
    pub name: &'static str,
    pub kind: Sender,
    pub senders: u32,
    pub addresses: u32,
    /// Submissions offered per second by the whole group.
    pub offered_per_second: f64,
    pub honest: bool,
}

/// One scenario's outcome.
#[derive(Debug, Clone, Serialize)]
pub struct AdmissionOutcome {
    pub scenario: String,
    pub seconds: u32,
    /// Per group: name, offered per second, admitted to the mempool per
    /// second, admitted share.
    pub groups: Vec<(String, f64, f64, f64)>,
}

fn genesis(key: &str) -> u64 {
    g::governed_param(key).map_or(0, |p| p.genesis)
}

/// The values of the admission layers' governed parameters.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct Limits {
    pub address_rate: f64,
    pub address_burst: f64,
    pub identity_checks: f64,
    /// Per lane (verified, delegated, open): a sender's rate per second and
    /// burst.
    pub lanes: [(f64, u32); 3],
    /// Per lane: the least gas price admitted, as a multiple of the base fee.
    pub fee_mult: [f64; 3],
}

impl Limits {
    pub fn genesis() -> Self {
        let lane = |rate: &str, burst: &str| (genesis(rate) as f64 / 1000.0, genesis(burst) as u32);
        let mult = |key: &str| genesis(key) as f64 / 10_000.0;
        Self {
            address_rate: genesis(g::RPC_ADDRESS_RATE_PARAM) as f64,
            address_burst: genesis(g::RPC_ADDRESS_BURST_PARAM) as f64,
            identity_checks: genesis(g::RPC_IDENTITY_CHECKS_PARAM) as f64,
            lanes: [
                lane(
                    g::ADMISSION_VERIFIED_RATE_PARAM,
                    g::ADMISSION_VERIFIED_BURST_PARAM,
                ),
                lane(
                    g::ADMISSION_DELEGATED_RATE_PARAM,
                    g::ADMISSION_DELEGATED_BURST_PARAM,
                ),
                lane(g::ADMISSION_OPEN_RATE_PARAM, g::ADMISSION_OPEN_BURST_PARAM),
            ],
            fee_mult: [
                mult(g::ADMISSION_VERIFIED_FEE_MULT_PARAM),
                mult(g::ADMISSION_DELEGATED_FEE_MULT_PARAM),
                mult(g::ADMISSION_OPEN_FEE_MULT_PARAM),
            ],
        }
    }
}

fn lane_index(lane: Lane) -> usize {
    match lane {
        Lane::Verified => 0,
        Lane::Delegated => 1,
        Lane::Open => 2,
    }
}

struct Resolver(HashMap<Address, Lane>, Limits);

impl LaneResolver for Resolver {
    fn assign_lane(&self, tx: &SignedTransaction) -> Lane {
        self.0
            .get(&tx.transaction.from)
            .copied()
            .unwrap_or(Lane::Open)
    }
    fn bucket_key(&self, tx: &SignedTransaction) -> Address {
        tx.transaction.from
    }
    fn limits(&self, lane: Lane) -> Option<(f64, u32)> {
        Some(self.1.lanes[lane_index(lane)])
    }
    fn fee_mult(&self, lane: Lane) -> Option<f64> {
        Some(self.1.fee_mult[lane_index(lane)])
    }
}

/// A token bucket on simulated time.
struct Bucket {
    tokens: f64,
    rate: f64,
    cap: f64,
    at: f64,
}

impl Bucket {
    fn new(rate: f64, cap: f64) -> Self {
        Self {
            tokens: cap,
            rate,
            cap,
            at: 0.0,
        }
    }
    fn take(&mut self, t: f64) -> bool {
        self.tokens = (self.tokens + (t - self.at) * self.rate).min(self.cap);
        self.at = t;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

fn tx(from: Address, nonce: u64) -> SignedTransaction {
    let t = Transaction::new(
        ChainId::from(1),
        from,
        Address::new([0xee; 32]),
        Nonce::from(nonce),
        TransactionType::Transfer { amount: 1 },
        21_000,
        1,
    );
    SignedTransaction::new(
        t,
        Vec::new(),
        CompositeSignature::classical(ClassicalProof::Raw {
            signature: Vec::new(),
        }),
    )
}

fn sender_address(group: usize, i: u32) -> Address {
    let mut a = [0u8; 32];
    a[0] = group as u8 + 1;
    a[1..5].copy_from_slice(&i.to_be_bytes());
    Address::new(a)
}

/// Runs `groups` for `seconds` of offered load under `limits`.
pub fn run(scenario: &str, groups: &[Group], seconds: u32, limits: Limits) -> AdmissionOutcome {
    let lanes: HashMap<Address, Lane> = groups
        .iter()
        .enumerate()
        .flat_map(|(gi, gr)| {
            let lane = match gr.kind {
                Sender::Verified => Lane::Verified,
                Sender::Delegated => Lane::Delegated,
                Sender::Open | Sender::Unfunded => Lane::Open,
            };
            (0..gr.senders).map(move |i| (sender_address(gi, i), lane))
        })
        .collect();
    let ctrl = AdmissionController::new(
        AdmissionConfig::default(),
        Arc::new(Resolver(lanes, limits)),
    );
    let start = Instant::now();
    let mut floors: HashMap<(usize, u32), (Bucket, Bucket)> = HashMap::new();
    let mut offered = vec![0u64; groups.len()];
    let mut admitted = vec![0u64; groups.len()];
    let mut credit = vec![0f64; groups.len()];
    let mut next = vec![0u32; groups.len()];
    let mut nonces: HashMap<Address, u64> = HashMap::new();
    let tick = 0.01;
    let ticks = (seconds as f64 / tick) as u64;
    for k in 0..ticks {
        let t = k as f64 * tick;
        let now = start + Duration::from_secs_f64(t);
        for (gi, gr) in groups.iter().enumerate() {
            credit[gi] += gr.offered_per_second * tick;
            while credit[gi] >= 1.0 {
                credit[gi] -= 1.0;
                offered[gi] += 1;
                let i = next[gi] % gr.senders;
                next[gi] = next[gi].wrapping_add(1);
                let addr_of = i % gr.addresses.max(1);
                let (floor, checks) = floors.entry((gi, addr_of)).or_insert_with(|| {
                    (
                        Bucket::new(limits.address_rate, limits.address_burst),
                        Bucket::new(limits.identity_checks, limits.identity_checks),
                    )
                });
                let within_floor = floor.take(t);
                let verified_or_delegated = matches!(gr.kind, Sender::Verified | Sender::Delegated);
                if !within_floor && !(checks.take(t) && verified_or_delegated) {
                    continue;
                }
                let from = sender_address(gi, i);
                let n = nonces.entry(from).or_insert(0);
                if !matches!(
                    ctrl.try_admit_at(&tx(from, *n), now),
                    AdmissionDecision::Admit { .. }
                ) {
                    continue;
                }
                if gr.kind == Sender::Unfunded {
                    continue;
                }
                *n += 1;
                admitted[gi] += 1;
            }
        }
    }
    let s = seconds as f64;
    AdmissionOutcome {
        scenario: scenario.to_string(),
        seconds,
        groups: groups
            .iter()
            .enumerate()
            .map(|(i, gr)| {
                let o = offered[i] as f64 / s;
                let a = admitted[i] as f64 / s;
                (gr.name.to_string(), o, a, if o > 0.0 { a / o } else { 1.0 })
            })
            .collect(),
    }
}

fn honest(
    name: &'static str,
    kind: Sender,
    senders: u32,
    addresses: u32,
    per_second: f64,
) -> Group {
    Group {
        name,
        kind,
        senders,
        addresses,
        offered_per_second: per_second,
        honest: true,
    }
}

fn attacker(
    name: &'static str,
    kind: Sender,
    senders: u32,
    addresses: u32,
    per_second: f64,
) -> Group {
    Group {
        name,
        kind,
        senders,
        addresses,
        offered_per_second: per_second,
        honest: false,
    }
}

/// The scenarios: a Sybil flood of fresh keys from one address and from a
/// thousand, a funded Sybil flood, verified users sharing one address, and
/// anonymous users sharing one address; each beside honest verified and
/// delegated senders on their own addresses.
pub fn study(seconds: u32) -> Vec<AdmissionOutcome> {
    let l = Limits::genesis();
    let base = || {
        vec![
            honest("verified users", Sender::Verified, 100, 100, 200.0),
            honest("delegated agents", Sender::Delegated, 200, 200, 200.0),
        ]
    };
    let with = |extra: Vec<Group>| {
        let mut v = base();
        v.extend(extra);
        v
    };
    vec![
        run(
            "sybil-fresh-keys-one-address",
            &with(vec![attacker(
                "fresh keys",
                Sender::Unfunded,
                10_000,
                1,
                5_000.0,
            )]),
            seconds,
            l,
        ),
        run(
            "sybil-fresh-keys-botnet",
            &with(vec![attacker(
                "fresh keys",
                Sender::Unfunded,
                10_000,
                1_000,
                20_000.0,
            )]),
            seconds,
            l,
        ),
        run(
            "sybil-funded-keys-botnet",
            &with(vec![attacker(
                "funded keys",
                Sender::Open,
                10_000,
                1_000,
                20_000.0,
            )]),
            seconds,
            l,
        ),
        run(
            "verified-users-behind-one-address",
            &with(vec![honest(
                "verified behind NAT",
                Sender::Verified,
                200,
                1,
                400.0,
            )]),
            seconds,
            l,
        ),
        run(
            "anonymous-users-behind-one-address",
            &with(vec![honest(
                "anonymous behind NAT",
                Sender::Open,
                200,
                1,
                100.0,
            )]),
            seconds,
            l,
        ),
    ]
}

/// A sender group at the chain: its lane, what admission lets through, and
/// the most it pays for one transfer.
#[derive(Debug, Clone)]
pub struct Flow {
    pub name: &'static str,
    pub lane: Lane,
    /// Transfers per second admission lets into the mempool.
    pub per_second: f64,
    /// The most the group pays for one transfer, USD; above it, it waits.
    pub max_usd: f64,
    pub honest: bool,
}

/// One flood run at the chain.
#[derive(Debug, Clone, Serialize)]
pub struct FloodOutcome {
    pub scenario: String,
    pub open_fee_mult: f64,
    pub seconds: f64,
    /// Per group: name, offered per second, included per second, included
    /// share, mean USD a transfer paid.
    pub groups: Vec<(String, f64, f64, f64, f64)>,
    /// What the dishonest groups paid, USD per day at this rate.
    pub attacker_usd_per_day: f64,
    /// What a transfer at the base fee costs at the end, USD.
    pub base_transfer_usd_end: f64,
}

/// Runs `flows` on the real ledger for `blocks` blocks at real block time.
/// Each block takes transactions lane by lane in the block builder's draw
/// weights until it is full; each pays its lane's multiple of the base fee
/// when that is within what its group pays, and waits otherwise.
pub fn flood(
    scenario: &str,
    flows: &[Flow],
    fee_mult: [f64; 3],
    blocks: u32,
    price_usd: f64,
) -> FloodOutcome {
    use crate::chain::{Chain, Clock, GenesisPlan, tnzo};
    use std::collections::BTreeMap;
    use tenzro_sim::ledger::USER_BASE;

    let mut params = BTreeMap::new();
    params.insert("fees.tnzo_usd_nano".to_string(), (price_usd * 1e9) as u64);
    const PER_FLOW: u32 = 400;
    let plan = GenesisPlan {
        validators: 4,
        standby: 0,
        bond_tnzo: g::genesis_param("stake.validator_tnzo").max(1),
        balance_tnzo: 100_000,
        users: PER_FLOW * flows.len() as u32,
        treasury_tnzo: 0,
        insurance_tnzo: 0,
        reserve_tnzo: 0,
        opening_accounts: Vec::new(),
        network_params: params,
    };
    let mut chain = Chain::new(&plan, Clock::REAL);
    let block_s = Clock::REAL.block_ms as f64 / 1000.0;
    let w = AdmissionConfig::default().lane_weights;
    let weights = [w.0.max(1), w.1.max(1), w.2.max(1)];
    let mut credit = vec![0f64; flows.len()];
    let mut offered = vec![0u64; flows.len()];
    let mut included = vec![0u64; flows.len()];
    let mut paid_usd = vec![0f64; flows.len()];
    let mut next = vec![0u32; flows.len()];
    for _ in 0..blocks {
        let base = chain.base_fee();
        let mut queue: Vec<u64> = flows
            .iter()
            .enumerate()
            .map(|(i, f)| {
                credit[i] += f.per_second * block_s;
                let n = credit[i].floor();
                credit[i] -= n;
                offered[i] += n as u64;
                n as u64
            })
            .collect();
        // Each lane's flows in turn, its draw weight at a time, until the
        // block is full or every queue is empty; within a lane, flows go in
        // proportion to what they offered.
        let first: Vec<u64> = queue.iter().map(|q| (*q).max(1)).collect();
        let mut full = false;
        while !full && queue.iter().any(|q| *q > 0) {
            for (li, lane) in [Lane::Verified, Lane::Delegated, Lane::Open]
                .iter()
                .enumerate()
            {
                for _ in 0..weights[li] {
                    let Some(i) = (0..flows.len())
                        .filter(|i| flows[*i].lane == *lane && queue[*i] > 0)
                        .max_by(|a, b| {
                            let fa = queue[*a] as f64 / first[*a] as f64;
                            let fb = queue[*b] as f64 / first[*b] as f64;
                            fa.total_cmp(&fb)
                        })
                    else {
                        break;
                    };
                    queue[i] -= 1;
                    let price = (base as f64 * fee_mult[li]).ceil() as u128;
                    let usd = tnzo(price.saturating_mul(21_000)) * price_usd;
                    if usd > flows[i].max_usd {
                        continue;
                    }
                    let from = USER_BASE + i as u32 * PER_FLOW + next[i] % PER_FLOW;
                    next[i] = next[i].wrapping_add(1);
                    if !chain.transfer(from, from, 0, Some(price)) {
                        full = true;
                        break;
                    }
                    included[i] += 1;
                    paid_usd[i] += usd;
                }
                if full {
                    break;
                }
            }
        }
        chain.produce();
    }
    let secs = blocks as f64 * block_s;
    let attacker: f64 = flows
        .iter()
        .zip(&paid_usd)
        .filter(|(f, _)| !f.honest)
        .map(|(_, p)| *p)
        .sum();
    FloodOutcome {
        scenario: scenario.to_string(),
        open_fee_mult: fee_mult[2],
        seconds: secs,
        groups: flows
            .iter()
            .enumerate()
            .map(|(i, f)| {
                let o = offered[i] as f64 / secs;
                let a = included[i] as f64 / secs;
                let mean = if included[i] > 0 {
                    paid_usd[i] / included[i] as f64
                } else {
                    0.0
                };
                (
                    f.name.to_string(),
                    o,
                    a,
                    if o > 0.0 { a / o } else { 1.0 },
                    mean,
                )
            })
            .collect(),
        attacker_usd_per_day: attacker / secs * 86_400.0,
        base_transfer_usd_end: tnzo(chain.base_fee().saturating_mul(21_000)) * price_usd,
    }
}

/// What the open lane's per-sender quota lets a funded botnet and honest
/// anonymous users through.
#[derive(Debug, Clone, Serialize)]
pub struct QuotaRow {
    pub open_rate: f64,
    pub open_burst: u32,
    /// A funded 10,000-key botnet behind 1,000 addresses offering 20,000/s:
    /// admitted per second.
    pub botnet_admitted_per_second: f64,
    /// Honest anonymous senders, each on its own address at 0.2/s with
    /// bursts: admitted share.
    pub anonymous_share: f64,
    /// Anonymous users sharing one address: admitted share.
    pub anonymous_nat_share: f64,
}

/// The sweep behind the proposed open-lane defaults.
#[derive(Debug, Clone, Serialize)]
pub struct DefaultsStudy {
    pub price_usd: f64,
    pub quotas: Vec<QuotaRow>,
    pub floods: Vec<FloodOutcome>,
}

/// Sweeps the open lane's per-sender quota on the admission layers, then its
/// fee multiple on the ledger under floods from funded fresh keys and from
/// bonded identities, beside honest senders who pay at most one cent.
pub fn defaults_study(seconds: u32, blocks: u32, price_usd: f64, threads: usize) -> DefaultsStudy {
    let quotas: Vec<QuotaRow> = [(0.25, 5u32), (0.25, 10), (0.5, 10), (1.0, 20), (2.0, 40)]
        .iter()
        .map(|&(rate, burst)| {
            let mut l = Limits::genesis();
            l.lanes[2] = (rate, burst);
            let o = run(
                "quota",
                &[
                    honest("anonymous", Sender::Open, 500, 500, 100.0),
                    honest("anonymous behind NAT", Sender::Open, 200, 1, 40.0),
                    attacker("funded keys", Sender::Open, 10_000, 1_000, 20_000.0),
                ],
                seconds,
                l,
            );
            let by = |n: &str| o.groups.iter().find(|g| g.0 == n).unwrap().clone();
            QuotaRow {
                open_rate: rate,
                open_burst: burst,
                botnet_admitted_per_second: by("funded keys").2,
                anonymous_share: by("anonymous").3,
                anonymous_nat_share: by("anonymous behind NAT").3,
            }
        })
        .collect();
    let botnet = quotas
        .iter()
        .find(|q| {
            let l = Limits::genesis().lanes[2];
            q.open_rate == l.0 && q.open_burst == l.1
        })
        .map_or(10_000.0, |q| q.botnet_admitted_per_second);
    let honest_flows = || {
        vec![
            Flow {
                name: "verified users",
                lane: Lane::Verified,
                per_second: 200.0,
                max_usd: 0.01,
                honest: true,
            },
            Flow {
                name: "delegated agents",
                lane: Lane::Delegated,
                per_second: 200.0,
                max_usd: 0.01,
                honest: true,
            },
            Flow {
                name: "anonymous users",
                lane: Lane::Open,
                per_second: 50.0,
                max_usd: 0.01,
                honest: true,
            },
        ]
    };
    let mut jobs = Vec::new();
    for &mult in &[1.0f64, 2.0, 4.0, 8.0, 16.0, 32.0] {
        let base = Limits::genesis().fee_mult;
        let m = [base[0], base[1], mult.max(base[1])];
        jobs.push(("no flood".to_string(), honest_flows(), m));
        for &(who, lane, rate) in &[
            ("funded fresh keys", Lane::Open, botnet),
            ("500 bonded identities", Lane::Delegated, 5_000.0),
        ] {
            for &max in &[0.01, 1.0] {
                let mut f = honest_flows();
                f.push(Flow {
                    name: "flood",
                    lane,
                    per_second: rate,
                    max_usd: max,
                    honest: false,
                });
                jobs.push((format!("{who}, paying up to ${max}"), f, m));
            }
        }
    }
    let next = std::sync::atomic::AtomicUsize::new(0);
    let out = std::sync::Mutex::new(vec![None; jobs.len()]);
    std::thread::scope(|sc| {
        for _ in 0..threads.max(1) {
            sc.spawn(|| {
                loop {
                    let i = next.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    let Some((name, flows, m)) = jobs.get(i) else {
                        break;
                    };
                    let o = flood(name, flows, *m, blocks, price_usd);
                    out.lock().unwrap()[i] = Some(o);
                }
            });
        }
    });
    DefaultsStudy {
        price_usd,
        quotas,
        floods: out.into_inner().unwrap().into_iter().flatten().collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn share(o: &AdmissionOutcome, group: &str) -> (f64, f64) {
        let g = o.groups.iter().find(|g| g.0 == group).unwrap();
        (g.2, g.3)
    }

    /// Honest verified and delegated senders keep their throughput through
    /// every flood; fresh keys get nothing in; a funded botnet gets in at the
    /// cost of the fee it pays on each transaction; verified
    /// users sharing one address are not held to its floor.
    #[test]
    fn floods_do_not_crowd_out_attested_senders() {
        let out = study(20);
        for o in &out {
            for honest in ["verified users", "delegated agents"] {
                let (_, s) = share(o, honest);
                assert!(s > 0.99, "{}: {honest} admitted share {s}", o.scenario);
            }
        }
        let by = |n: &str| out.iter().find(|o| o.scenario == n).unwrap();
        assert_eq!(
            share(by("sybil-fresh-keys-one-address"), "fresh keys").0,
            0.0
        );
        assert_eq!(share(by("sybil-fresh-keys-botnet"), "fresh keys").0, 0.0);
        // A funded botnet is held only by what it pays: every key it admits
        // is an account that pays the open lane's fee floor per transaction.
        let (funded, _) = share(by("sybil-funded-keys-botnet"), "funded keys");
        assert!(funded > 0.0);
        let (_, nat) = share(
            by("verified-users-behind-one-address"),
            "verified behind NAT",
        );
        assert!(
            nat > 0.99,
            "verified users behind one address admitted share {nat}"
        );
    }

    /// On the ledger, a flood far above the block's capacity drives the base
    /// fee up until it prices itself out, while verified senders, drawn
    /// first, keep their transfers in.
    #[test]
    fn a_flood_pays_the_open_multiple_and_verified_senders_stay_in() {
        let flows = [
            Flow {
                name: "verified",
                lane: Lane::Verified,
                per_second: 100.0,
                max_usd: 0.01,
                honest: true,
            },
            Flow {
                name: "flood",
                lane: Lane::Open,
                per_second: 20_000.0,
                max_usd: 0.01,
                honest: false,
            },
        ];
        let at = |mult: f64| flood("test", &flows, [1.0, 1.5, mult], 40, 0.10);
        let (low, high) = (at(2.0), at(8.0));
        for o in [&low, &high] {
            let v = &o.groups[0];
            assert!(v.3 > 0.99, "verified included share {}", v.3);
        }
        for o in [&low, &high] {
            let f = &o.groups[1];
            assert!(f.3 < 0.2, "flood included share {}", f.3);
            assert!(o.attacker_usd_per_day > 0.0);
        }
    }
}
