//! Rewards paid on settlements, checked against collusion.
//!
//! - S1, settlement-activity wash: one actor pays a second account it holds
//!   through settlement plans, beside honest
//!   providers paid by honest buyers. Runs on the simulated ledger, so the
//!   fee, the plan commit and the epoch's ecosystem coupons
//!   are the VM's own code. Measures the actor's net (rewards issued less
//!   everything it paid) and the honest providers' share of the bucket.
//! - S7, provider-bucket wash: the same day, with every provider (the
//!   actor's second account among them) reporting its plans as served work,
//!   so the work report and the epoch's provider coupons are the VM's own
//!   code too. Measures the same net and share in the provider bucket.
//! - S5, cheat deterrence under price: what an upheld fault costs a provider
//!   that substitutes a cheaper answer, at the sampling share and penalty in
//!   force, across payment sizes and a TNZO price path that falls 90%.
//! - S6, one subsidy bound: on one settlement a colluding buyer, provider
//!   and app take every reward the settlement can earn. Across every setting
//!   governance can reach, the rewards stay below what the settlement paid
//!   to parties outside the trade.

use std::collections::BTreeMap;

use tenzro_sim::ledger::{TNZO, USER_BASE};
use tenzro_types::primitives::Address;
use tenzro_types::settlement::{Leg, LegClass, LegKind, PlanOp, leg_id};
use tenzro_types::split::{
    SPLIT_RULE_VERSION, SplitBasis, SplitLine, SplitRecipient, SplitRole, SplitRule,
};
use tenzro_vm::native as n;
use tenzro_vm::traits::VmState;

use crate::bme::TestResult;
use crate::chain::{Chain, Clock, GenesisPlan, tnzo};
use crate::economy::NATIVE_GAS;

const HONEST_PAYER: u32 = USER_BASE;
const HONEST_PROVIDERS: [u32; 3] = [USER_BASE + 1, USER_BASE + 2, USER_BASE + 3];
const WASH_PAYER: u32 = USER_BASE + 4;
const WASH_PROVIDER: u32 = USER_BASE + 5;
/// The app the honest payer buys through.
const HONEST_APP: u32 = USER_BASE + 6;
/// The app the wash payer attributes its wash to: a second root acting with it.
const WASH_APP: u32 = USER_BASE + 7;
/// Liquid balance of each simulated account, whole TNZO.
const BALANCE_TNZO: u64 = 40_000_000;
/// Most one party settles in the one simulated day, whole TNZO.
const MAX_DAY_TNZO: f64 = 30_000_000.0;
/// Blocks of the day that carry settlements; each provider reports the
/// plans of one block in the next.
const PAYING_BLOCKS: u64 = 8;

/// The reward bucket a wash run measures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WashBucket {
    /// The ecosystem coupons the app a settlement is attributed to earns
    /// (S1).
    Activity,
    /// The provider coupons reported settled work earns (S7).
    Provider,
}

impl WashBucket {
    fn role(self) -> tenzro_token::rewards::RoleBucket {
        match self {
            WashBucket::Activity => tenzro_token::rewards::RoleBucket::Ecosystem,
            WashBucket::Provider => tenzro_token::rewards::RoleBucket::Provider,
        }
    }
}

/// One S1 or S7 run: a day of honest revenue and wash beside it.
#[derive(Debug, Clone, serde::Serialize)]
pub struct WashPoint {
    /// The reward bucket measured.
    pub bucket: WashBucket,
    /// Honest providers' revenue, USD a day.
    pub revenue_usd_day: f64,
    /// Wash volume over honest revenue.
    pub wash_ratio: f64,
    /// Whether the wash pays the paying account itself (else a second account).
    pub one_account: bool,
    /// TNZO price, USD.
    pub price_usd: f64,
    /// What the wash cost its actor: fees and gas, USD.
    pub wash_cost_usd: f64,
    /// Rewards in the measured bucket the epoch issued the actor, USD.
    pub wash_reward_usd: f64,
    /// Reward less cost, USD.
    pub wash_net_usd: f64,
    /// Rewards in the measured bucket issued to the honest providers, USD.
    pub honest_reward_usd: f64,
    /// Honest providers' share of the rewards issued in the measured bucket.
    pub honest_share: f64,
    /// Wash plans the ledger committed.
    pub wash_plans_applied: u64,
    /// Honest plans the ledger committed.
    pub honest_plans_applied: u64,
    /// Reports of wash plans the ledger applied.
    pub wash_reports_applied: u64,
    /// The first reason the ledger refused a plan or a report, if it did.
    pub first_refusal: Option<String>,
}

fn pay_to(to: Address) -> SplitRule {
    SplitRule {
        version: SPLIT_RULE_VERSION,
        lines: vec![SplitLine {
            role: SplitRole::Payee,
            recipient: SplitRecipient::Address(to),
            basis: SplitBasis::Remainder,
            cap: None,
        }],
    }
}

fn did_of(id: u32) -> String {
    format!(
        "{}{}",
        tenzro_vm::governance::HUMAN_DID_PREFIX,
        hex::encode(tenzro_sim::ledger::account(id))
    )
}

pub(crate) fn open_plan(
    nonce: u64,
    to: u32,
    app: Option<u32>,
    amount: u128,
    deadline_ms: u64,
) -> Vec<u8> {
    let split = pay_to(Address::new(tenzro_sim::ledger::account(to)));
    let op = PlanOp::Open {
        nonce,
        quote_digest: [9; 32],
        split_hash: split.hash(),
        split,
        legs: vec![Leg {
            kind: LegKind::NativeTransfer {
                amount,
                escrow_id: None,
            },
            class_required: LegClass::Native,
            usd_e6: 0,
            max_network_fee: 0,
        }],
        decide_deadline_ms: deadline_ms,
        agent: None,
        attribution: app.map(|app| tenzro_types::settlement::CallAttribution {
            app_did: Some(did_of(app)),
            ..Default::default()
        }),
    };
    serde_json::to_vec(&op).expect("plan op")
}

pub(crate) fn report(legs: &[[u8; 32]]) -> Vec<u8> {
    let hex: Vec<String> = legs.iter().map(hex::encode).collect();
    serde_json::json!({ "op": "report_settled_work", "legs": hex })
        .to_string()
        .into_bytes()
}

fn bucket_reward(state: &dyn VmState, id: u32, epoch: u64, bucket: WashBucket) -> u128 {
    n::rewards::read_coupons(state, &Address::new(tenzro_sim::ledger::account(id)))
        .unwrap_or_default()
        .iter()
        .filter(|c| c.epoch == epoch && c.bucket == bucket.role())
        .map(|c| c.amount)
        .sum()
}

/// One simulated day of S1 or S7. Under [`WashBucket::Provider`] each
/// provider reports the plans of one block in the next. `None` when a party
/// would settle more than the simulated accounts hold.
pub fn wash_point(
    bucket: WashBucket,
    revenue_usd_day: f64,
    wash_ratio: f64,
    one_account: bool,
    price_usd: f64,
    params: &BTreeMap<String, u64>,
) -> Option<WashPoint> {
    let honest_tnzo = revenue_usd_day / price_usd;
    let wash_tnzo = revenue_usd_day * wash_ratio / price_usd;
    if honest_tnzo > MAX_DAY_TNZO || wash_tnzo > MAX_DAY_TNZO {
        return None;
    }
    let mut network_params = params.clone();
    network_params.insert(
        "fees.tnzo_usd_nano".into(),
        (price_usd * 1e9).round().max(1.0) as u64,
    );
    let plan = GenesisPlan {
        validators: 4,
        standby: 0,
        bond_tnzo: tenzro_vm::governance::genesis_param("stake.validator_tnzo").max(1),
        balance_tnzo: BALANCE_TNZO,
        users: 8,
        treasury_tnzo: 0,
        insurance_tnzo: 0,
        reserve_tnzo: 0,
        opening_accounts: Vec::new(),
        network_params,
    };
    let mut chain = Chain::new(&plan, Clock::HOURLY);
    let wash_to = if one_account {
        WASH_PAYER
    } else {
        WASH_PROVIDER
    };
    // Who earns in the measured bucket: the attributed apps for activity,
    // the paid providers for provider work.
    let (wash_earner, honest_earners): (u32, Vec<u32>) = match bucket {
        WashBucket::Activity => (WASH_APP, vec![HONEST_APP]),
        WashBucket::Provider => (wash_to, HONEST_PROVIDERS.to_vec()),
    };
    let held = |c: &Chain| {
        let mut ids = vec![WASH_PAYER, WASH_APP];
        if !one_account {
            ids.push(WASH_PROVIDER);
        }
        ids.iter()
            .map(|id| c.balance_of(&tenzro_sim::ledger::account(*id)))
            .sum::<u128>()
    };
    let to_wei = |t: f64| (t * TNZO as f64) as u128;
    let honest_each = to_wei(honest_tnzo / HONEST_PROVIDERS.len() as f64 / PAYING_BLOCKS as f64);
    let wash_each = to_wei(wash_tnzo / PAYING_BLOCKS as f64);

    chain.produce();
    let epoch = chain.epoch();
    let before = held(&chain);
    let mut pending: Vec<(u32, [u8; 32])> = Vec::new();
    let mut wash_reports_applied = 0u64;
    let mut wash_plans_applied = 0u64;
    let mut honest_plans_applied = 0u64;
    let mut first_refusal: Option<String> = None;
    let mut nonce = 0u64;
    for block in 0..=PAYING_BLOCKS {
        // Plans are decided against calendar time: one block's worth past
        // the next block, so each commits in the block that carries it.
        let deadline = (chain.now_ms().max(0) as u64) + 2 * chain.clock.block_calendar_ms() as u64;
        let mut by_provider: BTreeMap<u32, Vec<[u8; 32]>> = BTreeMap::new();
        for (who, plan) in pending.drain(..) {
            by_provider.entry(who).or_default().push(leg_id(&plan, 0));
        }
        for (who, legs) in &by_provider {
            chain.call(
                *who,
                None,
                0,
                n::SELECTOR_FUNDING,
                &report(legs),
                NATIVE_GAS,
                None,
            );
        }
        if block < PAYING_BLOCKS {
            for to in HONEST_PROVIDERS {
                nonce += 1;
                if honest_each > 0 {
                    let body = open_plan(nonce, to, Some(HONEST_APP), honest_each, deadline);
                    chain.call(
                        HONEST_PAYER,
                        None,
                        0,
                        n::SELECTOR_SETTLEMENT_PLAN,
                        &body,
                        NATIVE_GAS,
                        None,
                    );
                }
            }
            nonce += 1;
            if wash_each > 0 {
                let body = open_plan(nonce, wash_to, Some(WASH_APP), wash_each, deadline);
                chain.call(
                    WASH_PAYER,
                    None,
                    0,
                    n::SELECTOR_SETTLEMENT_PLAN,
                    &body,
                    NATIVE_GAS,
                    None,
                );
            }
        }
        for r in chain.produce() {
            let (from, data) = match &r.tx {
                tenzro_sim::ledger::SimTx::Call { from, data, .. } => (*from, data.clone()),
                _ => continue,
            };
            let ours = data.starts_with(&n::SELECTOR_SETTLEMENT_PLAN)
                || data.starts_with(&n::SELECTOR_FUNDING);
            if ours && !r.applied && first_refusal.is_none() {
                first_refusal = Some(r.error.clone());
            }
            if data.starts_with(&n::SELECTOR_SETTLEMENT_PLAN) && r.applied {
                if from == HONEST_PAYER {
                    honest_plans_applied += 1;
                } else {
                    wash_plans_applied += 1;
                }
                if bucket != WashBucket::Provider {
                    continue;
                }
                let out: serde_json::Value = serde_json::from_slice(&r.output).unwrap_or_default();
                let id = out["plan_id"]
                    .as_str()
                    .and_then(|s| hex::decode(s).ok())
                    .and_then(|b| <[u8; 32]>::try_from(b).ok());
                let to = if from == HONEST_PAYER {
                    None
                } else {
                    Some(wash_to)
                };
                if let Some(id) = id {
                    let who = to.unwrap_or_else(|| {
                        n::read_plan(chain.state(), &id)
                            .and_then(|p| {
                                match p.split.lines.first().map(|l| l.recipient.clone()) {
                                    Some(SplitRecipient::Address(a)) => Some(a),
                                    _ => None,
                                }
                            })
                            .and_then(|a| {
                                HONEST_PROVIDERS
                                    .iter()
                                    .copied()
                                    .find(|p| tenzro_sim::ledger::account(*p) == a.0)
                            })
                            .unwrap_or(HONEST_PROVIDERS[0])
                    });
                    pending.push((who, id));
                }
            } else if data.starts_with(&n::SELECTOR_FUNDING) && from == wash_to && r.applied {
                wash_reports_applied += 1;
            }
        }
    }
    let after = held(&chain);
    while chain.epoch() <= epoch {
        chain.produce();
    }
    chain.produce();
    let state = chain.state();
    let wash_reward = bucket_reward(state, wash_earner, epoch, bucket);
    let honest_reward: u128 = honest_earners
        .iter()
        .map(|p| bucket_reward(state, *p, epoch, bucket))
        .sum();
    let cost = tnzo(before.saturating_sub(after)) * price_usd;
    let reward = tnzo(wash_reward) * price_usd;
    let total = (wash_reward + honest_reward).max(1);
    Some(WashPoint {
        bucket,
        revenue_usd_day,
        wash_ratio,
        one_account,
        price_usd,
        wash_cost_usd: cost,
        wash_reward_usd: reward,
        wash_net_usd: reward - cost,
        honest_reward_usd: tnzo(honest_reward) * price_usd,
        honest_share: honest_reward as f64 / total as f64,
        wash_plans_applied,
        honest_plans_applied,
        wash_reports_applied,
        first_refusal,
    })
}

/// Honest revenue levels S1 sweeps, USD a day.
pub const S1_REVENUE: [f64; 4] = [100.0, 1_000.0, 10_000.0, 100_000.0];
/// Wash volume over honest revenue.
pub const S1_RATIO: [f64; 5] = [0.0, 1.0, 10.0, 100.0, 1_000.0];
/// TNZO prices, USD.
pub const S1_PRICE: [f64; 3] = [0.01, 0.10, 1.0];

/// Every S1 and S7 point, over `threads` threads.
pub fn s1_sweep(threads: usize) -> Vec<WashPoint> {
    let mut grid = Vec::new();
    for bucket in [WashBucket::Activity, WashBucket::Provider] {
        for &r in &S1_REVENUE {
            for &k in &S1_RATIO {
                for &p in &S1_PRICE {
                    grid.push((bucket, r, k, false, p));
                }
            }
        }
        for &p in &S1_PRICE {
            grid.push((bucket, 1_000.0, 10.0, true, p));
        }
    }
    let params = BTreeMap::new();
    let chunk = grid.len().div_ceil(threads.max(1));
    let mut out: Vec<WashPoint> = std::thread::scope(|s| {
        let handles: Vec<_> = grid
            .chunks(chunk)
            .map(|part| {
                let params = &params;
                s.spawn(move || {
                    part.iter()
                        .filter_map(|&(b, r, k, one, p)| wash_point(b, r, k, one, p, params))
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        handles
            .into_iter()
            .flat_map(|h| h.join().expect("S1 worker"))
            .collect()
    });
    out.sort_by(|a, b| {
        (
            a.bucket as u8,
            a.revenue_usd_day,
            a.wash_ratio,
            a.price_usd,
            a.one_account as u8,
        )
            .partial_cmp(&(
                b.bucket as u8,
                b.revenue_usd_day,
                b.wash_ratio,
                b.price_usd,
                b.one_account as u8,
            ))
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    out
}

/// The verdict of S1 (`WashBucket::Activity`) or S7
/// (`WashBucket::Provider`): no wash point in that bucket pays its actor.
pub fn s1_result(points: &[WashPoint], bucket: WashBucket) -> TestResult {
    let points: Vec<&WashPoint> = points.iter().filter(|p| p.bucket == bucket).collect();
    let washing: Vec<&WashPoint> = points
        .iter()
        .copied()
        .filter(|p| p.wash_ratio > 0.0)
        .collect();
    let worst = washing.iter().max_by(|a, b| {
        a.wash_net_usd
            .partial_cmp(&b.wash_net_usd)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    // A point counts only when its plans committed, the honest providers
    // were paid for theirs and, in the provider bucket with a second
    // account, the wash was reported.
    let reported = |p: &WashPoint| {
        bucket != WashBucket::Provider || p.one_account || p.wash_reports_applied > 0
    };
    let ran = points
        .iter()
        .find(|p| {
            p.honest_plans_applied == 0
                || p.honest_reward_usd <= 0.0
                || (p.wash_ratio > 0.0 && (p.wash_plans_applied == 0 || !reported(p)))
        })
        .map(|p| {
            format!(
                "point ${:.0}/day, {}x wash, TNZO ${} did not run: {} honest and {} wash plans committed, {} wash reports applied, honest reward ${:.4}; first refusal: {}",
                p.revenue_usd_day,
                p.wash_ratio,
                p.price_usd,
                p.honest_plans_applied,
                p.wash_plans_applied,
                p.wash_reports_applied,
                p.honest_reward_usd,
                p.first_refusal.as_deref().unwrap_or("none")
            )
        });
    let least_honest = washing
        .iter()
        .map(|p| p.honest_share)
        .fold(1.0f64, f64::min);
    let (number, name) = match bucket {
        WashBucket::Activity => (201, "S1 settlement-activity wash never pays"),
        WashBucket::Provider => (207, "S7 provider-bucket wash never pays"),
    };
    TestResult {
        number,
        name: name.into(),
        pass: !washing.is_empty() && washing.iter().all(|p| p.wash_net_usd < 0.0) && ran.is_none(),
        detail: match (ran, worst) {
            (Some(why), _) => why,
            (None, Some(w)) => format!(
                "{} wash points; best for the actor: ${:.4} net a day (reward ${:.4}, cost ${:.4}) at ${:.0}/day honest revenue, {}x wash, TNZO ${}{}; least honest share of the bucket {:.4}",
                washing.len(),
                w.wash_net_usd,
                w.wash_reward_usd,
                w.wash_cost_usd,
                w.revenue_usd_day,
                w.wash_ratio,
                w.price_usd,
                if w.one_account { ", one account" } else { "" },
                least_honest
            ),
            (None, None) => "no wash point ran".into(),
        },
    }
}

/// One S5 point.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CheatPoint {
    /// Payment for the answer, USD.
    pub payment_usd: f64,
    /// TNZO price, USD.
    pub price_usd: f64,
    /// What a substituted answer saves, share of the payment.
    pub gain_share: f64,
    /// Share of answers re-executed at this payment.
    pub sample: f64,
    /// Penalty an upheld fault pays, USD.
    pub penalty_usd: f64,
    /// Expected loss per cheat less its gain, USD: at least zero deters.
    pub margin_usd: f64,
}

/// Payment sizes S5 sweeps, USD.
pub const S5_PAYMENT: [f64; 6] = [0.0001, 0.001, 0.01, 0.1, 1.0, 10.0];
/// TNZO price path: launch, then down 50%, 90%, and up 10x.
pub const S5_PRICE: [f64; 4] = [0.10, 0.05, 0.01, 1.0];
/// Gain of a substituted answer, share of the payment.
pub const S5_GAIN: [f64; 3] = [0.1, 0.5, 0.9];

/// The penalty, wei, an upheld fault on an answer paid `payment` wei pays
/// at the chain state's parameters and rate.
fn penalty_wei(state: &dyn VmState, payment: u128) -> u128 {
    n::inference_fault::penalty_due(state, payment)
}

/// Every S5 point, each on a chain at its price with `params`.
pub fn s5_sweep(params: &BTreeMap<String, u64>) -> Vec<CheatPoint> {
    let mut out = Vec::new();
    for &p in &S5_PRICE {
        let mut network_params = params.clone();
        network_params.insert("fees.tnzo_usd_nano".into(), (p * 1e9).round() as u64);
        let chain = Chain::new(
            &GenesisPlan {
                validators: 4,
                standby: 0,
                bond_tnzo: tenzro_vm::governance::genesis_param("stake.validator_tnzo").max(1),
                balance_tnzo: 1,
                users: 1,
                treasury_tnzo: 0,
                insurance_tnzo: 0,
                reserve_tnzo: 0,
                opening_accounts: Vec::new(),
                network_params,
            },
            Clock::HOURLY,
        );
        let state = chain.state();
        for &pay in &S5_PAYMENT {
            let wei = (pay / p * TNZO as f64) as u128;
            let sample = n::inference_fault::sample_bps_for(state, wei) as f64 / 10_000.0;
            let penalty = tnzo(penalty_wei(state, wei)) * p;
            for &g in &S5_GAIN {
                let gain = g * pay;
                out.push(CheatPoint {
                    payment_usd: pay,
                    price_usd: p,
                    gain_share: g,
                    sample,
                    penalty_usd: penalty,
                    margin_usd: sample * (pay + penalty) - gain,
                });
            }
        }
    }
    out
}

/// S5's verdict: cheating never pays in expectation.
pub fn s5_result(points: &[CheatPoint]) -> TestResult {
    let worst = points.iter().min_by(|a, b| {
        a.margin_usd
            .partial_cmp(&b.margin_usd)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    TestResult {
        number: 205,
        name: "S5 a substituted answer never pays in expectation, at any price".into(),
        pass: points.iter().all(|p| p.margin_usd >= 0.0),
        detail: match worst {
            Some(w) => format!(
                "worst: payment ${}, TNZO ${}, gain {:.0}% of the payment, sampled {:.2}%, penalty ${:.6}: expected loss less gain ${:.6}",
                w.payment_usd,
                w.price_usd,
                w.gain_share * 100.0,
                w.sample * 100.0,
                w.penalty_usd,
                w.margin_usd
            ),
            None => "no point".into(),
        },
    }
}

/// The most every reward one settlement can earn adds up to, as a share of
/// the protocol fee it paid outside the trade, over every pair of settings
/// governance can reach for the provider reward and the activity reward.
pub fn s6_worst_subsidy_share() -> (f64, u64, u64) {
    use n::economy::ACTIVITY_REWARD_FEE_PARAM;
    use n::rewards::PROVIDER_REWARD_COST_PARAM;
    let p = tenzro_vm::governance::governed_param(PROVIDER_REWARD_COST_PARAM).expect("registered");
    let a = tenzro_vm::governance::governed_param(ACTIVITY_REWARD_FEE_PARAM).expect("registered");
    let steps = |lo: u64, hi: u64| -> Vec<u64> {
        let mut v: Vec<u64> = (0..=100).map(|i| lo + (hi - lo) * i / 100).collect();
        v.push(hi);
        v.dedup();
        v
    };
    let value: u128 = 1_000 * TNZO;
    let fee: u128 = value / 1_000;
    let mut worst = (0.0f64, 0u64, 0u64);
    for pv in steps(p.min, p.max) {
        for av in steps(a.min, a.max) {
            let mut scheduled = BTreeMap::new();
            scheduled.insert(PROVIDER_REWARD_COST_PARAM, pv);
            scheduled.insert(ACTIVITY_REWARD_FEE_PARAM, av);
            let get = |k: &str| {
                scheduled
                    .get(k)
                    .copied()
                    .unwrap_or_else(|| tenzro_vm::governance::genesis_param(k))
            };
            let reachable =
                tenzro_vm::governance::joint_change_allowed(PROVIDER_REWARD_COST_PARAM, pv, &get)
                    .is_ok()
                    && tenzro_vm::governance::joint_change_allowed(
                        ACTIVITY_REWARD_FEE_PARAM,
                        av,
                        &get,
                    )
                    .is_ok();
            if !reachable {
                continue;
            }
            let provider = tenzro_token::rewards::provider_work_weight(value - fee, fee, pv);
            let activity = fee * u128::from(av) / 10_000;
            let share = (provider + activity) as f64 / fee as f64;
            if share > worst.0 {
                worst = (share, pv, av);
            }
        }
    }
    worst
}

/// S6's verdict.
pub fn s6_result() -> TestResult {
    let (share, pv, av) = s6_worst_subsidy_share();
    TestResult {
        number: 206,
        name: "S6 every reward on one settlement stays below what it paid outside the trade".into(),
        pass: share < 1.0,
        detail: format!(
            "most a colluding buyer, provider and app take back over every reachable setting: {:.4} of the protocol fee (provider reward {pv} bps, activity reward {av} bps of the fee)",
            share
        ),
    }
}

/// S1, S5, S6 and S7 together; the wash points carry both S1's and S7's.
pub fn tests(threads: usize) -> (Vec<TestResult>, Vec<WashPoint>, Vec<CheatPoint>) {
    let s1 = s1_sweep(threads);
    let s5 = s5_sweep(&BTreeMap::new());
    (
        vec![
            s1_result(&s1, WashBucket::Activity),
            s5_result(&s5),
            s6_result(),
            s1_result(&s1, WashBucket::Provider),
        ],
        s1,
        s5,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// S1 runs on the settlement and reward rules the VM has now: every plan
    /// commits and nothing is refused, the honest providers are credited,
    /// and the test has something to measure.
    #[test]
    fn a_wash_point_runs_on_the_current_settlement_rules() {
        let point = wash_point(
            WashBucket::Activity,
            100.0,
            1.0,
            false,
            0.1,
            &BTreeMap::new(),
        )
        .expect("the point fits");
        assert_eq!(point.first_refusal, None, "{point:?}");
        assert!(point.honest_plans_applied > 0, "{point:?}");
        assert!(point.wash_plans_applied > 0, "{point:?}");
        assert!(point.honest_reward_usd > 0.0, "{point:?}");
    }

    /// S7 runs on the reporting rules the VM has now: every plan commits,
    /// the providers' reports of plans another party paid are applied, and
    /// the honest providers earn provider reward for them.
    #[test]
    fn a_provider_wash_point_runs_on_the_current_reporting_rules() {
        let point = wash_point(
            WashBucket::Provider,
            100.0,
            1.0,
            false,
            0.1,
            &BTreeMap::new(),
        )
        .expect("the point fits");
        assert_eq!(point.first_refusal, None, "{point:?}");
        assert!(point.honest_plans_applied > 0, "{point:?}");
        assert!(point.wash_plans_applied > 0, "{point:?}");
        assert!(point.honest_reward_usd > 0.0, "{point:?}");
    }
}
