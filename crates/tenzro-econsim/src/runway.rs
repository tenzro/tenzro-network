//! Sponsorship and grants runway on market-stress traces.
//!
//! The treasury pays out TNZO it already holds (nothing is issued) and, for
//! the running cost, stablecoin it already holds, to APPROVED operators,
//! validators, developers and contributors, one governance proposal per
//! disbursement, only against verified availability or work or an approved
//! milestone. This module replays the market-stress traces through the usage
//! accounting ([`crate::usage::replay`]) for the paid usage, the fees the
//! treasury keeps and the income a validator earns, and runs the treasury's
//! cash flow on those daily series. Nothing here generates a population, a
//! market or a shock.
//!
//! Treasury accounts:
//! - the TNZO balance: the genesis treasury allocation, which only falls
//!   (the settlement fee and the treasury leg arrive in stable assets and
//!   stay stable; no stable-to-TNZO conversion is assumed);
//! - the stable account: an opening reserve plus the stable fees the
//!   treasury keeps after the validator cover reserve took its fill.
//!
//! A sponsored validator is paid, per day, the part of the governed running
//! cost its own protocol income did not cover, times the share of the day it
//! was verified available. An unapproved operator, or one with no verified
//! work, is paid nothing ([`sponsor_payout`]).
//!
//! Beyond the end of a trace the last year repeats (an assumption).

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde_json::{Value, json};

use crate::usage::{Outcome, PricePath, Rules, Trace, replay};

pub const SHARES: [f64; 3] = [0.001, 0.01, 0.1];
/// TNZO prices held constant, USD.
pub const PRICES: [f64; 3] = [0.03, 0.30, 3.00];
/// Sizes of the approved validator set.
pub const SETS: [u32; 3] = [7, 11, 21];
pub const LEGS: [u64; 2] = [0, 100];
pub const REGIONS: [&str; 4] = ["region-a", "region-b", "region-c", "region-v"];
/// The governed validator running cost, USD a month, and a day.
pub const COST_MONTH: f64 = 1500.0;
pub const COST_DAY: f64 = COST_MONTH * 12.0 / 365.0;
/// Days simulated: ten years.
pub const HORIZON: usize = 3650;
pub const YEARS: usize = 10;
/// Genesis treasury allocation, TNZO. ASSUMPTION: the repository fixes the
/// rewards pool (400M) and the total (1B), not the treasury's share.
pub const TREASURY_TNZO: f64 = 100_000_000.0;
/// Bootstrap angel allocation, TNZO (default of the open decision), taken out of the treasury.
pub const ANGEL_TNZO: f64 = 5_000_000.0;
/// Opening stable reserves, USD.
pub const RESERVES: [f64; 4] = [250_000.0, 500_000.0, 1_000_000.0, 2_000_000.0];
/// Governance approval delays, days.
pub const DELAYS: [usize; 4] = [0, 3, 7, 14];
/// Days of expected need left when a new proposal is filed.
pub const BUFFERS: [usize; 4] = [3, 7, 14, 30];
/// Grant budgets, share of the balance a year.
pub const GRANT_PCT: [f64; 4] = [0.0, 0.02, 0.05, 0.10];
pub const TAPER_MONTHS: [usize; 4] = [0, 12, 24, 36];
pub const BONDS_USD: [f64; 3] = [10_000.0, 50_000.0, 250_000.0];

// Existing governed limits (config/genesis-launch.toml).
pub const PROPOSAL_CAP: f64 = 0.02;
pub const PERIOD_CAP: f64 = 0.03;
pub const PERIOD_DAYS: usize = 30;
pub const LARGE_SPEND_TNZO: f64 = 100_000.0;
pub const LARGE_TIMELOCK_DAYS: usize = 14;
pub const BASE_TIMELOCK_DAYS: usize = 2;
pub const RESERVE_DRAW: f64 = 0.03;
pub const RESERVE_REVENUE: f64 = 0.30;
/// Days an operator carries its cost unpaid before it leaves. ASSUMPTION.
pub const GRACE_DAYS: usize = 14;
/// Yearly capital cost of holding a bond. ASSUMPTION.
pub const BOND_CARRY: f64 = 0.10;

/// What a sponsored operator is paid for a day: the shortfall times the
/// share of the day it was verified available; nothing when it is not
/// approved, was not verified, or has no shortfall.
pub fn sponsor_payout(approved: bool, verified_share: f64, shortfall_usd: f64) -> f64 {
    if !approved || verified_share <= 0.0 || shortfall_usd <= 0.0 {
        return 0.0;
    }
    shortfall_usd * verified_share.min(1.0)
}

/// What a grantee is paid: only an approved grantee, against a verified
/// milestone, at most the milestone's amount.
pub fn grant_payout(approved: bool, milestone_verified: bool, amount: f64) -> f64 {
    if !approved || !milestone_verified || amount <= 0.0 {
        return 0.0;
    }
    amount
}

/// Payments with no operator over `cap` of the total paid: an operator's
/// excess is withheld, not given to the others.
pub fn cap_shares(pay: &[f64], cap: f64) -> Vec<f64> {
    let total: f64 = pay.iter().sum();
    pay.iter().map(|p| p.min(cap * total)).collect()
}

/// Days of coverage lost when `revoked` of `n` approved validators are
/// revoked and a replacement takes `delay` days to approve: none while at
/// least 7 remain.
pub fn revocation_lapse_days(n: u32, revoked: u32, delay: usize) -> usize {
    if n.saturating_sub(revoked) >= 7 {
        0
    } else {
        delay
    }
}

/// Daily series of one replay.
#[derive(Clone)]
pub struct Series {
    pub n: u32,
    pub price: f64,
    /// Governed running cost of one validator, USD a day.
    pub cost_day: f64,
    /// Income of each active validator, USD.
    pub earned: Vec<f64>,
    /// Stable fees the treasury kept after the cover reserve's fill.
    pub surplus: Vec<f64>,
    /// Stable fees kept, whole.
    pub kept: Vec<f64>,
    pub active: Vec<f64>,
    pub fee: Vec<f64>,
    pub paid: Vec<f64>,
}

fn at(v: &[f64], t: usize) -> f64 {
    let n = v.len();
    if n == 0 {
        return 0.0;
    }
    if t < n {
        return v[t];
    }
    let w = 365.min(n);
    v[n - w + (t - n) % w]
}

impl Series {
    pub fn from_outcome(n: u32, price: f64, cost_day: f64, o: &Outcome) -> Series {
        let tb = &o.tick_book;
        Series {
            n,
            price,
            cost_day,
            earned: tb.iter().map(|t| t.validator_income_each_usd).collect(),
            surplus: tb.iter().map(|t| t.treasury_surplus_usd).collect(),
            kept: tb.iter().map(|t| t.fees_kept_usd).collect(),
            active: tb.iter().map(|t| f64::from(t.validators_active)).collect(),
            fee: tb.iter().map(|t| t.fee_usd).collect(),
            paid: tb.iter().map(|t| t.paid_usd).collect(),
        }
    }

    /// Sponsorship due on day `t` for the whole set, USD.
    pub fn need(&self, t: usize) -> f64 {
        let a = at(&self.active, t);
        if a <= 0.0 {
            return 0.0;
        }
        let sf = (self.cost_day - at(&self.earned, t)).max(0.0);
        a * sponsor_payout(true, a / f64::from(self.n.max(1)), sf)
            / (a / f64::from(self.n.max(1))).max(1e-12)
    }

    fn mean(&self, v: &[f64], from: usize, to: usize) -> f64 {
        let n = (to - from).max(1) as f64;
        (from..to).map(|t| at(v, t)).sum::<f64>() / n
    }
}

fn rules(
    n: u32,
    share: f64,
    leg: u64,
    price: f64,
    cost_month: f64,
    blackout: Option<(u64, u64)>,
    regions: usize,
    outage: Option<u64>,
) -> Rules {
    let mut regs: Vec<String> = REGIONS.iter().map(|s| s.to_string()).collect();
    if regions >= 5 {
        regs.push("region-w".into());
    }
    let mut r = Rules {
        validators: n,
        standby: 0,
        exit_ratio: 0.0,
        join_ratio: 1e9,
        market_share: share,
        pool_depth_usd: Some(1_000_000.0),
        rails: Some(BTreeMap::from([
            ("USDA".to_string(), 0.6),
            ("USDB".to_string(), 0.4),
        ])),
        validator_regions: Some(regs),
        price_path: Some(PricePath::Held(price)),
        blackout,
        ..Rules::default()
    };
    r.overrides.insert(
        tenzro_vm::native::economy::TREASURY_LEG_INFERENCE_PARAM.into(),
        leg,
    );
    r.overrides.insert(
        tenzro_vm::native::rewards::VALIDATOR_BASE_COST_PARAM.into(),
        cost_month as u64,
    );
    if let Some(tick) = outage {
        r.extra_shocks.push(crate::usage::ShockEntry {
            tick,
            until: Some(tick + 1),
            kind: "region_offline".into(),
            region: Some("region-a".into()),
            regions: None,
            asset: None,
            value: None,
        });
    }
    r
}

/// Rolling sum over the last `PERIOD_DAYS` entries.
struct Ring {
    v: Vec<f64>,
    sum: f64,
}

impl Ring {
    fn new() -> Ring {
        Ring {
            v: Vec::new(),
            sum: 0.0,
        }
    }
    fn push(&mut self, x: f64) {
        self.v.push(x);
        self.sum += x;
        if self.v.len() > PERIOD_DAYS {
            self.sum -= self.v[self.v.len() - PERIOD_DAYS - 1];
        }
    }
    fn sum(&self) -> f64 {
        self.sum.max(0.0)
    }
}

fn year_of(t: usize) -> usize {
    (t / 365).min(YEARS - 1)
}

/// Result of the continuous cash flow.
#[derive(Debug, Clone, Default)]
pub struct FundOut {
    pub first_short_day: Option<usize>,
    pub unpaid_usd: f64,
    pub need_usd: f64,
    pub depleted_day: Option<usize>,
    pub b_end_year: Vec<f64>,
    pub s_end_year: Vec<f64>,
    pub sponsor_tnzo_year: Vec<f64>,
    pub grants_tnzo_year: Vec<f64>,
    pub stable_paid_year: Vec<f64>,
    pub need_usd_year: Vec<f64>,
    pub b_final: f64,
    pub conserved: bool,
}

#[derive(Debug, Clone)]
pub struct FundCfg {
    pub r0: f64,
    pub b0: f64,
    pub price: f64,
    pub stable_limit: bool,
    pub tnzo_limit: bool,
    pub grant_pct: f64,
    /// Share of the set the treasury sponsors (the rest runs in kind).
    pub need_scale: f64,
    /// Extra stable income a day, USD, from the package's mechanisms.
    pub extra: Vec<f64>,
}

impl Default for FundCfg {
    fn default() -> Self {
        FundCfg {
            r0: 0.0,
            b0: 0.0,
            price: 0.30,
            stable_limit: false,
            tnzo_limit: true,
            grant_pct: 0.0,
            need_scale: 1.0,
            extra: Vec::new(),
        }
    }
}

/// Pays the daily need from the stable account, then from the TNZO balance
/// under the 3%-in-30-days limit; grants take what the limit leaves.
pub fn fund(s: &Series, c: &FundCfg) -> FundOut {
    let mut o = FundOut {
        b_end_year: vec![0.0; YEARS],
        s_end_year: vec![0.0; YEARS],
        sponsor_tnzo_year: vec![0.0; YEARS],
        grants_tnzo_year: vec![0.0; YEARS],
        stable_paid_year: vec![0.0; YEARS],
        need_usd_year: vec![0.0; YEARS],
        ..FundOut::default()
    };
    let (mut b, mut st) = (c.b0, c.r0);
    let (mut rev, mut spaid, mut out) = (Ring::new(), Ring::new(), Ring::new());
    let mut year_b = c.b0;
    let mut total_out = 0.0;
    let mut due_grant = 0.0;
    for t in 0..HORIZON {
        if t % 365 == 0 {
            year_b = b;
        }
        let need = s.need(t) * c.need_scale;
        o.need_usd += need;
        o.need_usd_year[year_of(t)] += need;
        st += at(&s.surplus, t) + at(&c.extra, t);
        rev.push(at(&s.kept, t));
        let allow = if c.stable_limit {
            (RESERVE_REVENUE * rev.sum() + RESERVE_DRAW * st - spaid.sum()).max(0.0)
        } else {
            f64::INFINITY
        };
        let pay_s = need.min(st).min(allow);
        st -= pay_s;
        spaid.push(pay_s);
        o.stable_paid_year[year_of(t)] += pay_s;
        let rem = need - pay_s;
        let tn_need = rem / c.price;
        let room = if c.tnzo_limit {
            (PERIOD_CAP * b - out.sum()).max(0.0)
        } else {
            f64::INFINITY
        };
        let pay_t = tn_need.min(room).min(b);
        b -= pay_t;
        total_out += pay_t;
        o.sponsor_tnzo_year[year_of(t)] += pay_t;
        let mut day_out = pay_t;
        let short = need - pay_s - pay_t * c.price;
        if short > 1e-6 {
            o.unpaid_usd += short;
            o.first_short_day.get_or_insert(t);
        }
        if c.grant_pct > 0.0 {
            due_grant += c.grant_pct * year_b / 365.0;
            if t % PERIOD_DAYS == PERIOD_DAYS - 1 {
                let room = if c.tnzo_limit {
                    (PERIOD_CAP * b - out.sum() - day_out).max(0.0)
                } else {
                    f64::INFINITY
                };
                let pay_g = due_grant.min(room).min(b);
                b -= pay_g;
                total_out += pay_g;
                day_out += pay_g;
                o.grants_tnzo_year[year_of(t)] += pay_g;
                // a grant the limit held back is not carried: the budget is a yearly ceiling
                due_grant = 0.0;
            }
        }
        out.push(day_out);
        if b < 1.0 && o.depleted_day.is_none() {
            o.depleted_day = Some(t);
        }
        if (t + 1) % 365 == 0 && t / 365 < YEARS {
            o.b_end_year[t / 365] = b;
            o.s_end_year[t / 365] = st;
        }
    }
    o.b_final = b;
    o.conserved = (c.b0 - b - total_out).abs() < 1e-3 * c.b0.max(1.0) * 1e-6 + 1e-6;
    o
}

/// Result of the proposal-by-proposal cash flow.
#[derive(Debug, Clone, Default)]
pub struct GovOut {
    pub unfunded_days: usize,
    pub lapse_days: usize,
    pub lapse_events: usize,
    pub proposals: usize,
    pub tnzo_paid: f64,
    pub stable_paid: f64,
    pub first_lapse_day: Option<usize>,
    pub max_cap_ratio: f64,
}

#[derive(Debug, Clone)]
pub struct GovCfg {
    pub r0: f64,
    pub b0: f64,
    pub price: f64,
    pub delay: usize,
    pub buffer_days: usize,
    pub tranche_days: usize,
    pub grace: usize,
    /// Apply the existing timelocks: 2 days for any proposal, 14 for one of
    /// 100,000 TNZO or more.
    pub statutory: bool,
}

/// Each disbursement is a proposal filed when the approved budget falls under
/// `buffer_days` of expected need, enacted `delay` days later, within the
/// per-proposal (2%) and per-period (3%) limits and the reserve's draw limit.
pub fn gov(s: &Series, c: &GovCfg) -> GovOut {
    let mut o = GovOut::default();
    let (mut b, mut st) = (c.b0, c.r0);
    let (mut rev, mut spaid, mut out) = (Ring::new(), Ring::new(), Ring::new());
    // Approved before launch: the first tranche is in place on day 0.
    let mut budget = c.tranche_days as f64 * f64::from(s.n) * s.cost_day;
    let mut pending: Option<(usize, f64, f64, f64)> = None; // day, stable part, tnzo part, delay
    let mut streak = 0usize;
    let mut need_hist: Vec<f64> = Vec::new();
    for t in 0..HORIZON {
        let need = s.need(t);
        need_hist.push(need);
        st += at(&s.surplus, t);
        rev.push(at(&s.kept, t));
        let mut day_out = 0.0;
        let mut day_spaid = 0.0;
        if let Some((d, sp, tn, _)) = pending
            && t >= d
        {
            let room_p = PERIOD_CAP * b - out.sum();
            let tn_ok = tn.min(PROPOSAL_CAP * b).min(room_p.max(0.0)).min(b);
            let sp_ok = sp.min(st);
            b -= tn_ok;
            st -= sp_ok;
            budget += sp_ok + tn_ok * c.price;
            day_out = tn_ok;
            day_spaid = sp_ok;
            o.tnzo_paid += tn_ok;
            o.stable_paid += sp_ok;
            if b > 0.0 {
                o.max_cap_ratio = o.max_cap_ratio.max((out.sum() + tn_ok) / (b + tn_ok));
            }
            pending = None;
        }
        out.push(day_out);
        spaid.push(day_spaid);
        let pay = need.min(budget);
        budget -= pay;
        if need > 1e-9 && pay < need - 1e-9 {
            o.unfunded_days += 1;
            streak += 1;
            if streak > c.grace {
                o.lapse_days += 1;
                if streak == c.grace + 1 {
                    o.lapse_events += 1;
                    o.first_lapse_day.get_or_insert(t);
                }
            }
        } else if need > 1e-9 {
            streak = 0;
        }
        if pending.is_none() {
            let lo = need_hist.len().saturating_sub(30);
            let mean = need_hist[lo..].iter().sum::<f64>() / (need_hist.len() - lo) as f64;
            let est = if t < 30 { mean.max(0.0) } else { mean };
            if est > 0.0 && budget < c.buffer_days as f64 * est {
                let want = c.tranche_days as f64 * est;
                let allow_s =
                    (RESERVE_REVENUE * rev.sum() + RESERVE_DRAW * st - spaid.sum()).max(0.0);
                let sp = want.min(st).min(allow_s);
                let rem = want - sp;
                let tn = (rem / c.price)
                    .min(PROPOSAL_CAP * b)
                    .min((PERIOD_CAP * b - out.sum()).max(0.0))
                    .min(b);
                let mut d = c.delay;
                if c.statutory {
                    d = d.max(BASE_TIMELOCK_DAYS);
                    if tn >= LARGE_SPEND_TNZO {
                        d = d.max(LARGE_TIMELOCK_DAYS);
                    }
                }
                if sp + tn * c.price > 0.0 {
                    o.proposals += 1;
                    pending = Some((t + d, sp, tn, d as f64));
                }
            }
        }
    }
    o
}

#[derive(Debug, Clone)]
pub struct TaperCfg {
    /// Months over which the per-validator top-up ceiling falls to zero; 0: no ceiling.
    pub months: usize,
    pub bond_usd: f64,
    pub price: f64,
}

#[derive(Debug, Clone, Default)]
pub struct TaperOut {
    pub cost_year: Vec<f64>,
    pub bond_buy_usd_year: Vec<f64>,
    pub sold_tnzo_year: Vec<f64>,
    pub burn_tnzo_year: Vec<f64>,
    pub set_year: Vec<usize>,
    pub sponsored_year: Vec<usize>,
    pub entrants: usize,
    pub sponsored_exits: usize,
    pub entrant_exits: usize,
    pub lapse_days: usize,
    pub independent_month: Option<usize>,
}

fn set_index(total: usize) -> usize {
    if total <= 7 {
        0
    } else if total <= 11 {
        1
    } else {
        2
    }
}

fn tolerance(i: usize, n: usize) -> f64 {
    0.05 + 0.30 * i as f64 / (n.max(2) - 1) as f64
}

/// Sponsored validators start at 7; self-staked entrants join when the
/// income of the set covers cost, the bond's carry and a margin. A top-up
/// ceiling falls linearly over `months`. Operators leave when their net
/// income stays under minus their tolerance for a month. ASSUMPTION:
/// tolerances spread over 5% to 35% of cost; at most one entrant a month;
/// entrants and exits keep the set in at least four regions.
pub fn taper(sets: &[Series; 3], c: &TaperCfg) -> TaperOut {
    let mut o = TaperOut {
        cost_year: vec![0.0; YEARS],
        bond_buy_usd_year: vec![0.0; YEARS],
        sold_tnzo_year: vec![0.0; YEARS],
        burn_tnzo_year: vec![0.0; YEARS],
        set_year: vec![0; YEARS],
        sponsored_year: vec![0; YEARS],
        ..TaperOut::default()
    };
    let mut spons: Vec<f64> = (0..7).map(|i| tolerance(i, 7)).collect();
    let mut ent: Vec<f64> = Vec::new();
    let cd = sets[0].cost_day;
    let carry_day = c.bond_usd * BOND_CARRY / 365.0;
    let (mut m_net_s, mut m_earn, mut m_next, mut m_top) = (0.0, 0.0, 0.0, 0.0);
    let mut top_months: Vec<f64> = Vec::new();
    let mut joined = 0usize;
    for t in 0..HORIZON {
        let total = spons.len() + ent.len();
        let idx = set_index(total.max(1));
        let s = &sets[idx];
        let earned = at(&s.earned, t);
        let k = t / 30;
        let ceiling = if c.months == 0 {
            cd
        } else {
            cd * (1.0 - k as f64 / c.months as f64).max(0.0)
        };
        let topup = (cd - earned).max(0.0).min(ceiling);
        let a = at(&s.active, t) / f64::from(s.n);
        let pay = spons.len() as f64 * sponsor_payout(true, a, topup);
        o.cost_year[year_of(t)] += pay;
        o.sold_tnzo_year[year_of(t)] += pay / c.price;
        o.burn_tnzo_year[year_of(t)] += at(&s.fee, t) * 0.5 / c.price;
        if total < 7 {
            o.lapse_days += 1;
        }
        m_net_s += earned + topup - cd;
        m_earn += earned;
        m_top += topup;
        let nxt = &sets[set_index((total + 1).max(1))];
        m_next += at(&nxt.earned, t);
        if t % 30 == 29 {
            let net_s = m_net_s / 30.0;
            let net_e = m_earn / 30.0 - cd - carry_day;
            let before = spons.len();
            let n0 = spons.len();
            spons = spons
                .iter()
                .copied()
                .enumerate()
                .filter(|(_, tol)| net_s >= -tol * cd)
                .map(|(_, tol)| tol)
                .collect();
            o.sponsored_exits += before - spons.len();
            let _ = n0;
            let eb = ent.len();
            ent.retain(|tol| net_e >= -tol * cd);
            o.entrant_exits += eb - ent.len();
            let nxt_earn = m_next / 30.0;
            if spons.len() + ent.len() < 21 && nxt_earn >= 1.2 * cd + carry_day {
                ent.push(tolerance(joined % 7, 7));
                joined += 1;
                o.entrants += 1;
                o.bond_buy_usd_year[year_of(t)] += c.bond_usd;
            }
            top_months.push(m_top / 30.0);
            m_net_s = 0.0;
            m_earn = 0.0;
            m_next = 0.0;
            m_top = 0.0;
        }
        if (t + 1) % 365 == 0 && t / 365 < YEARS {
            o.set_year[t / 365] = spons.len() + ent.len();
            o.sponsored_year[t / 365] = spons.len();
        }
    }
    // The month after which no top-up is paid again within the horizon.
    let last = top_months.iter().rposition(|x| *x >= 1e-9);
    o.independent_month = match last {
        None => Some(0),
        Some(l) if l + 1 < top_months.len() => Some(l + 1),
        _ => None,
    };
    o
}

/// Daily need of a set of `m` devices of one class, USD.
fn class_rows(o: &Outcome) -> Value {
    let tb = &o.tick_book;
    let mut out = serde_json::Map::new();
    for (name, units_day, cost, _tier, _share) in crate::recycle::classes() {
        let cost_mid = (cost.0 + cost.1) / 2.0;
        let mut short = Vec::with_capacity(tb.len());
        let mut net = Vec::with_capacity(tb.len());
        for t in tb {
            let (svc_u, rel_u) = if t.units > 0.0 {
                (
                    t.paid_usd * t.provider_share / t.units,
                    t.provider_release_usd / t.units,
                )
            } else {
                (0.0, 0.0)
            };
            let earn = o.utilisation_mean * units_day * (svc_u + rel_u);
            net.push(earn - cost_mid);
            short.push((cost_mid - earn).max(0.0));
        }
        let mean = |v: &[f64], a: usize, b: usize| {
            let b = b.min(v.len());
            if a >= b {
                0.0
            } else {
                v[a..b].iter().sum::<f64>() / (b - a) as f64
            }
        };
        let n = short.len();
        out.insert(
            name.into(),
            json!({
                "cost": cost_mid,
                "net_day": mean(&net, 30, n),
                "short_y1": mean(&short, 0, 365),
                "short_y2": mean(&short, 365, 730),
                "short_y3": mean(&short, 730, n),
                "short_last": mean(&short, n.saturating_sub(365), n),
                "frac_pos": short.iter().filter(|x| **x > 1e-9).count() as f64 / n.max(1) as f64,
            }),
        );
    }
    Value::Object(out)
}

fn yr_mean(s: &Series, a: usize, b: usize) -> f64 {
    (a..b).map(|t| s.need(t)).sum::<f64>() / (b - a).max(1) as f64
}

/// The first day from which every trailing 30-day mean of what each
/// validator earns covers its cost, and the paid usage a day over that
/// window. What a validator earns is what the cover and the base reward
/// paid it.
pub fn breakeven_paid(s: &Series) -> (Option<usize>, f64) {
    breakeven_by(s, |t| s.earned[t])
}

/// [`breakeven_paid`] with each validator credited the stable fees the treasury
/// kept that day shared over the active set, as if every kept fee reached
/// the validators. The gap to [`breakeven_paid`] is what the cover's fill share,
/// its reserve target and the base reward's own bound hold back.
pub fn breakeven_kept(s: &Series) -> (Option<usize>, f64) {
    breakeven_by(s, |t| s.kept[t] / s.active[t].max(1.0))
}

fn breakeven_by(s: &Series, each: impl Fn(usize) -> f64) -> (Option<usize>, f64) {
    let n = s.earned.len();
    if n < 31 {
        return (None, 0.0);
    }
    let mut ok_from: Option<usize> = None;
    for t in (30..n).rev() {
        let m = (t - 29..=t).map(&each).sum::<f64>() / 30.0;
        if m >= s.cost_day {
            ok_from = Some(t);
        } else {
            break;
        }
    }
    match ok_from {
        Some(t) => {
            let p = s.paid[t - 29..=t].iter().sum::<f64>() / 30.0;
            (Some(t), p)
        }
        None => (None, 0.0),
    }
}

fn arr(v: &[f64]) -> Value {
    json!(v)
}

fn fund_json(o: &FundOut) -> Value {
    json!({
        "first_short_day": o.first_short_day,
        "unpaid_usd": o.unpaid_usd,
        "need_usd": o.need_usd,
        "depleted_day": o.depleted_day,
        "b_end_year": arr(&o.b_end_year),
        "s_end_year": arr(&o.s_end_year),
        "sponsor_tnzo_year": arr(&o.sponsor_tnzo_year),
        "grants_tnzo_year": arr(&o.grants_tnzo_year),
        "stable_paid_year": arr(&o.stable_paid_year),
        "need_usd_year": arr(&o.need_usd_year),
        "conserved": o.conserved,
    })
}

/// Replays every trace under `dirs` and runs the studies; one JSON record per study.
pub fn sweep(
    dirs: &[PathBuf],
    threads: usize,
    mut sink: impl FnMut(Value),
    mut bad: impl FnMut(String),
) {
    let files = crate::usage_lw::find(dirs);
    crate::chaos::run_parallel(
        &files,
        threads,
        |(m, t): &(PathBuf, PathBuf)| -> Result<Vec<Value>, String> {
            let trace = Trace::read_lw(m, t)?;
            let p = &trace.manifest.parameters;
            let get = |k: &str| {
                p.get("lw.scenario")
                    .and_then(|s| s.get(k))
                    .and_then(|s| s.as_str())
                    .unwrap_or("?")
                    .to_string()
            };
            let base = json!({
                "seed": trace.manifest.seed,
                "scenario": get("name"),
                "variant": get("variant"),
                "inside_band": p.get("lw.inside_band").and_then(|v| v.as_bool()).unwrap_or(false),
            });
            let mut out = Vec::new();
            let mk = |kind: &str, share: f64, leg: u64, price: f64, n: u32, body: Value| {
                let mut r = base.clone();
                let m = r.as_object_mut().expect("object");
                m.insert("kind".into(), json!(kind));
                m.insert("share".into(), json!(share));
                m.insert("leg".into(), json!(leg));
                m.insert("price".into(), json!(price));
                m.insert("n".into(), json!(n));
                m.insert("body".into(), body);
                r
            };
            for &share in &SHARES {
                for &leg in &LEGS {
                    for &price in &PRICES {
                        let mut ser: Vec<Series> = Vec::new();
                        let mut viol = 0u64;
                        let mut first: Option<Outcome> = None;
                        for &n in &SETS {
                            let o = replay(
                                &trace,
                                &rules(n, share, leg, price, COST_MONTH, None, 4, None),
                            );
                            viol += o.charter_violations;
                            ser.push(Series::from_outcome(n, price, COST_DAY, &o));
                            if first.is_none() {
                                first = Some(o);
                            }
                        }
                        let first = first.expect("one replay");
                        out.push(mk("class", share, leg, price, 0, class_rows(&first)));
                        let sets: [Series; 3] = [ser[0].clone(), ser[1].clone(), ser[2].clone()];
                        for s in &ser {
                            let len = s.earned.len();
                            let y = |a: usize, b: usize| yr_mean(s, a, b.min(len.max(a + 1)));
                            let cum = |days: usize| (0..days).map(|t| s.need(t)).sum::<f64>();
                            let (be, be_paid) = breakeven_paid(s);
                            let (bk, bk_paid) = breakeven_kept(s);
                            let earned_y1 = s.mean(&s.earned, 30, 365.min(len));
                            let body = json!({
                                "gross_day": f64::from(s.n) * s.cost_day,
                                "need_y1": y(0, 365), "need_y2": y(365, 730), "need_y3": y(730, 1080),
                                "need_last": y(len.saturating_sub(365), len),
                                "cum_365": cum(365), "cum_1080": cum(1080), "cum_3650": cum(3650),
                                "breakeven_day": be, "breakeven_paid_day": be_paid,
                                "breakeven_kept_day": bk, "breakeven_kept_paid_day": bk_paid,
                                "paid_day": s.mean(&s.paid, 0, len),
                                "earned_each_y1": earned_y1,
                                "kept_each_y1": s.mean(&s.kept, 30, 365.min(len)) / f64::from(s.n.max(1)),
                                "frac_pos": (0..len).filter(|t| s.need(*t) > 1e-9).count() as f64 / len.max(1) as f64,
                                "active_min": s.active.iter().copied().fold(f64::INFINITY, f64::min),
                                "charter_violations": viol,
                                "burn_tnzo_year": (0..YEARS).map(|yv| (yv*365..(yv+1)*365).map(|t| at(&s.fee, t)*0.5/price).sum::<f64>()).collect::<Vec<_>>(),
                            });
                            out.push(mk("cost", share, leg, price, s.n, body));
                            // runway
                            let mut rw = serde_json::Map::new();
                            for &r0 in &RESERVES {
                                for (nm, lim) in [("free", false), ("limited", true)] {
                                    let f = fund(
                                        s,
                                        &FundCfg {
                                            r0,
                                            b0: 0.0,
                                            price,
                                            stable_limit: lim,
                                            tnzo_limit: true,
                                            grant_pct: 0.0,
                                            ..FundCfg::default()
                                        },
                                    );
                                    rw.insert(format!("stable_{nm}_{}", r0 as u64), fund_json(&f));
                                }
                            }
                            for (nm, b0) in [
                                ("tnzo95", TREASURY_TNZO - ANGEL_TNZO),
                                ("tnzo100", TREASURY_TNZO),
                            ] {
                                let f = fund(
                                    s,
                                    &FundCfg {
                                        r0: 0.0,
                                        b0,
                                        price,
                                        stable_limit: true,
                                        tnzo_limit: true,
                                        grant_pct: 0.0,
                                        ..FundCfg::default()
                                    },
                                );
                                rw.insert(nm.into(), fund_json(&f));
                            }
                            let f = fund(
                                s,
                                &FundCfg {
                                    r0: 1_000_000.0,
                                    b0: TREASURY_TNZO - ANGEL_TNZO,
                                    price,
                                    stable_limit: true,
                                    tnzo_limit: true,
                                    grant_pct: 0.0,
                                    ..FundCfg::default()
                                },
                            );
                            rw.insert("both_1m_tnzo95".into(), fund_json(&f));
                            out.push(mk("runway", share, leg, price, s.n, Value::Object(rw)));
                            // governance delay
                            let mut g = Vec::new();
                            for &delay in &DELAYS {
                                for &buffer in &BUFFERS {
                                    for statutory in [false, true] {
                                        let r = gov(
                                            s,
                                            &GovCfg {
                                                r0: 0.0,
                                                b0: TREASURY_TNZO - ANGEL_TNZO,
                                                price,
                                                delay,
                                                buffer_days: buffer,
                                                tranche_days: 30,
                                                grace: GRACE_DAYS,
                                                statutory,
                                            },
                                        );
                                        g.push(json!({"delay": delay, "buffer": buffer, "statutory": statutory,
                                            "unfunded": r.unfunded_days, "lapse": r.lapse_days, "events": r.lapse_events,
                                            "proposals": r.proposals, "tnzo": r.tnzo_paid, "stable": r.stable_paid,
                                            "first_lapse": r.first_lapse_day, "cap_ratio": r.max_cap_ratio}));
                                    }
                                }
                            }
                            out.push(mk("gov", share, leg, price, s.n, json!(g)));
                            // grants
                            if s.n == 7 || s.n == 21 {
                                let mut gr = Vec::new();
                                for &pct in &GRANT_PCT {
                                    let f = fund(
                                        s,
                                        &FundCfg {
                                            r0: 0.0,
                                            b0: TREASURY_TNZO - ANGEL_TNZO,
                                            price,
                                            stable_limit: true,
                                            tnzo_limit: true,
                                            grant_pct: pct,
                                            ..FundCfg::default()
                                        },
                                    );
                                    let mut j = fund_json(&f);
                                    j.as_object_mut()
                                        .expect("o")
                                        .insert("pct".into(), json!(pct));
                                    gr.push(j);
                                }
                                out.push(mk("grants", share, leg, price, s.n, json!(gr)));
                            }
                        }
                        // taper
                        let mut tp = Vec::new();
                        for &months in &TAPER_MONTHS {
                            for &bond in &BONDS_USD {
                                let r = taper(
                                    &sets,
                                    &TaperCfg {
                                        months,
                                        bond_usd: bond,
                                        price,
                                    },
                                );
                                tp.push(json!({"months": months, "bond": bond, "cost_year": arr(&r.cost_year),
                                    "bond_buy_usd_year": arr(&r.bond_buy_usd_year), "sold_tnzo_year": arr(&r.sold_tnzo_year),
                                    "burn_tnzo_year": arr(&r.burn_tnzo_year), "set_year": r.set_year, "sponsored_year": r.sponsored_year,
                                    "entrants": r.entrants, "sponsored_exits": r.sponsored_exits, "entrant_exits": r.entrant_exits,
                                    "lapse_days": r.lapse_days, "independent_month": r.independent_month}));
                            }
                        }
                        out.push(mk("taper", share, leg, price, 7, json!(tp)));
                    }
                }
            }
            // Self-sufficiency package.
            for &share in &SHARES {
                for &leg in &LEGS {
                    for &price in &PRICES {
                        let mut runs: Vec<(f64, u32, u64)> = Vec::new();
                        for &cm in &PKG_COSTS {
                            for &n in &[7u32, 9] {
                                runs.push((cm, n, 0));
                            }
                        }
                        if leg == 100 {
                            for &days in &BLACKOUTS {
                                for &cm in &[1500.0, 400.0, 150.0] {
                                    runs.push((cm, 7, days));
                                }
                            }
                        }
                        let cb = combos();
                        for (cm, n, bl) in runs {
                            let bo = if bl > 0 { Some((0u64, bl)) } else { None };
                            let o = replay(&trace, &rules(n, share, leg, price, cm, bo, 4, None));
                            let s = Series::from_outcome(n, price, cm * 12.0 / 365.0, &o);
                            let (be, be_paid) = breakeven_paid(&s);
                            let (bk, bk_paid) = breakeven_kept(&s);
                            let len = s.earned.len();
                            let res: Vec<Value> = cb
                                .iter()
                                .map(|c| {
                                    let e = eval_combo(&s, c, leg, bl);
                                    json!([c.id, e[0], e[1], e[2], e[3], e[4], e[5]])
                                })
                                .collect();
                            let body = json!({
                                "cost_month": cm, "blackout": bl,
                                "paid_day": s.mean(&s.paid, 0, len),
                                "kept_day": s.mean(&s.kept, 0, len),
                                "surplus_day": s.mean(&s.surplus, 0, len),
                                "earned_each_y1": s.mean(&s.earned, 30, 365.min(len)),
                                "breakeven_day": be, "breakeven_paid_day": be_paid,
                                "breakeven_kept_day": bk, "breakeven_kept_paid_day": bk_paid,
                                "need_y1": yr_mean(&s, 0, 365), "need_last": yr_mean(&s, len.saturating_sub(365), len),
                                "validators_min": o.validators_min, "regions_min": o.validator_regions_min,
                                "finality_lost": o.finality_lost_ticks, "charter_violations": o.charter_violations,
                                "combos": res,
                            });
                            out.push(mk("pkg", share, leg, price, n, body));
                        }
                    }
                }
            }
            // Region outage: exactly four regions against five.
            for &regions in &[4usize, 5] {
                for &n in &[7u32, 9] {
                    for outage in [None, Some(200u64)] {
                        let o = replay(
                            &trace,
                            &rules(n, 0.01, 100, 0.30, 400.0, None, regions, outage),
                        );
                        let body = json!({"regions": regions, "outage": outage.is_some(),
                            "validators_min": o.validators_min, "regions_min": o.validator_regions_min,
                            "finality_lost": o.finality_lost_ticks, "pass_finality": o.pass_finality,
                            "floor_ok": o.validators_min >= 7 && o.validator_regions_min >= 4});
                        out.push(mk("region", 0.01, 100, 0.30, n, body));
                    }
                }
            }
            Ok(out)
        },
        |(m, _), r| match r {
            Ok(v) => v.into_iter().for_each(&mut sink),
            Err(e) => bad(format!("{}: {e}", m.display())),
        },
    );
}

// ---- Self-sufficiency package -------------------------------------------

/// Validator running costs tested, USD a month (1,500 is the control).
pub const PKG_COSTS: [f64; 6] = [1500.0, 700.0, 400.0, 250.0, 150.0, 100.0];
/// Days with no paid usage at launch.
pub const BLACKOUTS: [u64; 3] = [30, 90, 180];
/// Share of a paid dollar the treasury keeps: the settlement fee's treasury half
/// less the insurance share, plus the treasury leg.
pub fn kept_rate(leg_bps: u64) -> f64 {
    0.001 * 0.5 * 0.9 + leg_bps as f64 / 1e4
}

/// One combination of the package's mechanisms.
#[derive(Debug, Clone)]
pub struct Combo {
    pub id: String,
    /// Validators of the set run in kind: they take nothing from the protocol.
    pub in_kind: u32,
    /// Anchor tenants, monthly commitment USD, reserved-capacity fee share of the commitment.
    pub tenants: u32,
    pub commit: f64,
    pub reserved_pct: f64,
    pub churn: f64,
    /// USD reserve: principal is never paid out, its yield funds verified work.
    pub reserve: f64,
    pub yield_: f64,
    /// Share of the reserve lost to a custodian failure at day 365.
    pub loss: f64,
}

fn combo(id: String) -> Combo {
    Combo {
        id,
        in_kind: 0,
        tenants: 0,
        commit: 0.0,
        reserved_pct: 0.0,
        churn: 0.3,
        reserve: 0.0,
        yield_: 0.0,
        loss: 0.0,
    }
}

pub fn combos() -> Vec<Combo> {
    let mut v = vec![combo("none".into())];
    for k in [1u32, 2, 3, 5] {
        let mut c = combo(format!("ik{k}"));
        c.in_kind = k;
        v.push(c);
    }
    for t in [1u32, 3, 5, 10] {
        for m in [500.0, 2500.0] {
            for pct in [0.0, 0.25, 0.5] {
                let mut c = combo(format!("t{t}/m{}/r{}", m as u64, (pct * 100.0) as u64));
                c.tenants = t;
                c.commit = m;
                c.reserved_pct = pct;
                v.push(c);
            }
        }
    }
    for ch in [0.1, 0.5] {
        let mut c = combo(format!("t10/m2500/r25/ch{}", (ch * 100.0) as u64));
        c.tenants = 10;
        c.commit = 2500.0;
        c.reserved_pct = 0.25;
        c.churn = ch;
        v.push(c);
    }
    for r in [250_000.0, 500_000.0, 1_000_000.0, 3_000_000.0] {
        for y in [0.01, 0.02, 0.035, 0.045] {
            let mut c = combo(format!(
                "res{}k/y{}",
                (r / 1000.0) as u64,
                (y * 1000.0) as u64
            ));
            c.reserve = r;
            c.yield_ = y;
            v.push(c);
        }
    }
    for r in [1_000_000.0, 3_000_000.0] {
        let mut c = combo(format!("res{}k/y35/loss50", (r / 1000.0) as u64));
        c.reserve = r;
        c.yield_ = 0.035;
        c.loss = 0.5;
        v.push(c);
    }
    // Combinations.
    for k in [2u32, 3] {
        for (t, m, pct) in [(0u32, 0.0f64, 0.0f64), (3, 1000.0, 0.25), (10, 2500.0, 0.5)] {
            for (rn, r) in [0.0, 1_000_000.0, 3_000_000.0].iter().enumerate() {
                let mut c = combo(format!(
                    "ik{k}+t{t}/m{}/r{}+res{}",
                    m as u64,
                    (pct * 100.0) as u64,
                    rn
                ));
                c.in_kind = k;
                c.tenants = t;
                c.commit = m;
                c.reserved_pct = pct;
                c.reserve = *r;
                c.yield_ = if *r > 0.0 { 0.035 } else { 0.0 };
                v.push(c);
            }
        }
    }
    v
}

/// Stable income a day from tenants and the reserve, USD. Tenants and their
/// reserved-capacity fee stop during a no-usage launch; the reserve's yield
/// does not.
pub fn extra_inflow(c: &Combo, leg_bps: u64, blackout_days: u64) -> Vec<f64> {
    let kr = kept_rate(leg_bps);
    (0..HORIZON)
        .map(|t| {
            let alive = f64::from(c.tenants) * (1.0 - c.churn).powf(t as f64 / 365.0);
            let on = if (t as u64) < blackout_days { 0.0 } else { 1.0 };
            let paid = alive * c.commit / 30.0 * on;
            let reserved = paid * c.reserved_pct;
            let principal = if t >= 365 {
                c.reserve * (1.0 - c.loss)
            } else {
                c.reserve
            };
            paid * kr + reserved + principal * c.yield_ / 365.0
        })
        .collect()
}

/// A combination on one series. Returns
/// [peak deficit USD, last-year net USD a day, treasury-run unpaid USD,
///  TNZO drawn in ten years, TNZO drawn in year one, mean sponsored need USD a day].
pub fn eval_combo(s: &Series, c: &Combo, leg_bps: u64, blackout_days: u64) -> [f64; 6] {
    let scale = (f64::from(s.n) - f64::from(c.in_kind)).max(0.0) / f64::from(s.n);
    let extra = extra_inflow(c, leg_bps, blackout_days);
    let (mut bal, mut peak, mut last, mut need_sum) = (0.0f64, 0.0f64, 0.0f64, 0.0f64);
    for t in 0..HORIZON {
        let need = s.need(t) * scale;
        need_sum += need;
        let inflow = at(&s.surplus, t) + at(&extra, t);
        bal += inflow - need;
        peak = peak.max(-bal);
        if t >= HORIZON - 365 {
            last += inflow - need;
        }
    }
    let f = fund(
        s,
        &FundCfg {
            b0: TREASURY_TNZO - ANGEL_TNZO,
            price: s.price,
            need_scale: scale,
            extra,
            ..FundCfg::default()
        },
    );
    [
        peak,
        last / 365.0,
        f.unpaid_usd,
        f.sponsor_tnzo_year.iter().sum(),
        f.sponsor_tnzo_year[0],
        need_sum / HORIZON as f64,
    ]
}

/// In-kind operators leaving at once: days below the floor until the
/// sponsored pool replaces them, and the daily cost the treasury then takes on.
pub fn exit_shock(n: u32, leaving: u32, replace_days: usize, cost_day: f64) -> (usize, f64) {
    (
        revocation_lapse_days(n, leaving, replace_days),
        f64::from(leaving) * cost_day,
    )
}

/// Hours a region outage halts the chain when finality needs `need` regions of
/// the `regions` the set sits in, evenly: one region lost.
pub fn region_halt_hours(regions: u32, need: u32, outage_hours: f64) -> f64 {
    if regions.saturating_sub(1) >= need {
        0.0
    } else {
        outage_hours
    }
}

/// A wash through a sponsored validator: it pays `volume` USD to itself.
/// Its income rises by what is left after the fee and leg, its top-up falls
/// by the same, and the fee and leg are lost: the net is always negative.
pub fn wash_net(volume: f64, fee_and_leg: f64, shortfall: f64) -> f64 {
    let income = volume * (1.0 - fee_and_leg);
    let topup_lost = income.min(shortfall.max(0.0));
    income - volume - topup_lost
}

/// Deterministic tables that need no trace: the outflow limit, the bond
/// purchase in a thin pool, revocation, concentration and the payout rules.
pub fn side() -> Value {
    let drain_year = 1.0 - (1.0 - PERIOD_CAP).powf(365.0 / PERIOD_DAYS as f64);
    let mut bal = vec![];
    for y in [1.0, 2.0, 3.0, 5.0, 10.0] {
        bal.push(json!({"years": y, "left_at_max_drain": (1.0 - PERIOD_CAP).powf(365.0 * y / PERIOD_DAYS as f64)}));
    }
    let mut slip = vec![];
    for depth in [100_000.0, 1_000_000.0, 10_000_000.0] {
        for bond in [5_000.0, 10_000.0, 25_000.0, 50_000.0, 100_000.0, 250_000.0] {
            let u0 = depth / 2.0;
            let mult = 1.0 + bond / u0;
            slip.push(
                json!({"depth": depth, "bond_usd": bond, "cost_multiple": mult,
                "pool_share_bought": bond / (u0 + bond),
                "tnzo": PRICES.iter().map(|p| bond / (p * mult)).collect::<Vec<_>>()}),
            );
        }
    }
    let mut rev = vec![];
    for &n in &SETS {
        for k in 0..=4u32 {
            for &d in &DELAYS {
                rev.push(json!({"n": n, "revoked": k, "delay": d, "lapse_days": revocation_lapse_days(n, k, d)}));
            }
        }
    }
    let mut conc = vec![];
    for &n in &SETS {
        let cap = n / 3;
        for ops in 1..=(cap + 2) {
            // one operator runs `ops` validators; the others one each
            let others = n as usize - ops as usize;
            let mut by_op = vec![COST_DAY * f64::from(ops)];
            by_op.extend(std::iter::repeat_n(COST_DAY, others));
            let capped = cap_shares(&by_op, 1.0 / 3.0);
            let total: f64 = by_op.iter().sum();
            conc.push(json!({"n": n, "validators_one_operator": ops, "share": f64::from(ops) / f64::from(n),
                "paid_share_after_cap": capped[0] / capped.iter().sum::<f64>(),
                "withheld_usd_day": total - capped.iter().sum::<f64>()}));
        }
    }
    let mut exits = vec![];
    for &n in &[7u32, 9] {
        for &k in &[0u32, 1, 2, 3, 5] {
            for &j in &[1u32, 2, 3] {
                if j > k {
                    continue;
                }
                for &rd in &[7usize, 30] {
                    let (lapse, extra) = exit_shock(n, j, rd, COST_DAY);
                    exits.push(json!({"n": n, "in_kind": k, "leave": j, "replace_days": rd,
                        "lapse_days": lapse, "treasury_cost_day_after": extra}));
                }
            }
        }
    }
    let mut cloud = vec![];
    for &n in &[7u32, 9] {
        for &g in &[1u32, 2, 3] {
            for &h in &[1.0f64, 6.0, 24.0] {
                let halt = if n.saturating_sub(g) >= 7 { 0.0 } else { h };
                cloud.push(
                    json!({"n": n, "sharing_one_cloud": g, "outage_hours": h, "halt_hours": halt}),
                );
            }
        }
    }
    let mut regions = vec![];
    for &r in &[4u32, 5, 6] {
        for &h in &[1.0f64, 6.0, 24.0] {
            regions.push(json!({"regions": r, "need": 4, "outage_hours": h, "halt_hours": region_halt_hours(r, 4, h)}));
        }
    }
    let mut wash = vec![];
    for &fl in &[kept_rate(0) + 0.0005, kept_rate(100) + 0.0005] {
        for &sf in &[0.0f64, COST_DAY / 2.0, COST_DAY] {
            wash.push(json!({"fee_and_leg": fl, "shortfall_day": sf, "net_per_1000_usd": wash_net(1000.0, fl, sf)}));
        }
    }
    let rules_ok = json!({
        "unapproved_gets": sponsor_payout(false, 1.0, 40.0),
        "no_verified_work_gets": sponsor_payout(true, 0.0, 40.0),
        "no_shortfall_gets": sponsor_payout(true, 1.0, 0.0),
        "approved_verified_gets": sponsor_payout(true, 1.0, 40.0),
        "half_verified_gets": sponsor_payout(true, 0.5, 40.0),
        "grant_unapproved": grant_payout(false, true, 1000.0),
        "grant_no_milestone": grant_payout(true, false, 1000.0),
        "grant_ok": grant_payout(true, true, 1000.0),
    });
    json!({
        "cost_day": COST_DAY, "cost_month": COST_MONTH,
        "max_drain_year": drain_year, "balance_left": bal,
        "treasury_tnzo": TREASURY_TNZO, "angel_tnzo": ANGEL_TNZO,
        "after_angel": TREASURY_TNZO - ANGEL_TNZO,
        "slippage": slip, "exit_shocks": exits, "cloud_sharing": cloud, "region_rule": regions, "wash_through_sponsored": wash, "revocation": rev, "concentration": conc, "payout_rules": rules_ok,
    })
}
