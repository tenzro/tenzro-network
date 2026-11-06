//! TNZO listed on a thin constant-product pool, outside the protocol.
//!
//! The pool is not chain code: nothing in the protocol reads it. It is the
//! market an attacker buys stake in and sells winnings into, and the price
//! the populations see. The questions it answers:
//! - what controlling a third, two thirds or the large-spend share of bonded
//!   stake costs through the pool, against what that control can take out
//!   of the treasury within the chain's treasury guards;
//! - how far the pool price moves for a given trade, and whether any
//!   protocol rule follows it;
//! - how the economy behaves through price shocks, with agents that keep
//!   transacting and agents that leave at once.

use serde::Serialize;

use crate::economy::{Economy, Market, RunConfig};

/// A constant-product pool of USD and TNZO.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct Pool {
    /// USD reserve.
    pub usd: f64,
    /// TNZO reserve.
    pub tnzo: f64,
}

impl Pool {
    /// A pool holding `depth_usd` in total at `price` USD per TNZO.
    pub fn new(depth_usd: f64, price: f64) -> Self {
        Self {
            usd: depth_usd / 2.0,
            tnzo: depth_usd / 2.0 / price,
        }
    }

    /// Price, USD per TNZO.
    pub fn price(&self) -> f64 {
        self.usd / self.tnzo
    }

    /// USD it costs to buy `q` TNZO, or `None` when the pool cannot supply it.
    pub fn buy_cost(&self, q: f64) -> Option<f64> {
        (q < self.tnzo).then(|| self.usd * q / (self.tnzo - q))
    }

    /// USD selling `q` TNZO brings.
    pub fn sell_proceeds(&self, q: f64) -> f64 {
        self.usd * q / (self.tnzo + q)
    }

    /// USD it costs to push the price up by `factor` (> 1).
    pub fn pump_cost(&self, factor: f64) -> f64 {
        self.usd * (factor.sqrt() - 1.0)
    }

    /// TNZO it takes to push the price down by `factor` (< 1).
    pub fn dump_tnzo(&self, factor: f64) -> f64 {
        self.tnzo * (1.0 / factor.sqrt() - 1.0)
    }
    /// Trades `net` TNZO into the pool (negative: out of it); at most 90%
    /// of the TNZO reserve leaves in one trade. Returns the USD that moved
    /// the other way.
    pub fn trade(&mut self, net: f64) -> f64 {
        let k = self.usd * self.tnzo;
        let q = net.max(-0.9 * self.tnzo);
        let tnzo = self.tnzo + q;
        let usd = k / tnzo;
        let moved = (self.usd - usd).abs();
        self.tnzo = tnzo;
        self.usd = usd;
        moved
    }

    /// Moves the price by `factor` with an outside trade.
    pub fn move_price(&mut self, factor: f64) {
        let k = self.usd * self.tnzo;
        let p = self.price() * factor.max(1e-6);
        self.tnzo = (k / p).sqrt();
        self.usd = k / self.tnzo;
    }

    /// Adds liquidity at the current price: `usd` and its TNZO match.
    pub fn add(&mut self, usd: f64) {
        let p = self.price();
        self.usd += usd;
        self.tnzo += usd / p;
    }
}

/// What control of a share of stake costs and can take, at one pool depth.
#[derive(Debug, Clone, Serialize)]
pub struct Corruption {
    /// Pool depth, USD.
    pub depth_usd: f64,
    /// Share of bonded stake controlled after the purchase.
    pub share: f64,
    /// TNZO bonded by everyone else.
    pub honest_bonded_tnzo: f64,
    /// TNZO the attacker must bond.
    pub stake_needed_tnzo: f64,
    /// USD buying it through the pool costs; `None` when the pool cannot supply it.
    pub cost_usd: Option<f64>,
    /// What the control can take, TNZO: what the treasury guards let it
    /// pay out (see [`capture_take`]) plus the whole insurance pool and
    /// running-cost reserve.
    pub payoff_tnzo: f64,
    /// That payoff valued at the price before the attack, USD.
    pub payoff_usd_at_price: f64,
    /// What selling the payoff into the same pool (after the purchase) brings, USD.
    pub payoff_exit_usd: f64,
    /// Exit value less cost, USD.
    pub net_usd: Option<f64>,
}

/// The least a capture must cost for each unit it can take, both in USD
/// through the same pool. The economics stage fails below it.
pub const CAPTURE_MARGIN: f64 = 2.0;

/// What stake holding `share` of the eligible vote can take, TNZO, from a
/// treasury of `treasury` TNZO and from `rest` TNZO held beside it (the
/// insurance pool and the running-cost reserve), under the treasury guards
/// the chain starts with.
///
/// No other validator votes, and no holder, guardian or steward acts. Every
/// payment needs the approval share of all eligible stake, so stake short of
/// it pays nothing out of the treasury. Stake above it proposes from the
/// moment it is eligible, with the shorter timelock, and enacts the period
/// cap until a change loosening a guard could first apply
/// (`governance.guard_loosening_grace_epochs`): before then the guards in
/// force bind, and the loosening is on chain for everyone to see. `rest` is
/// counted whole, though the insurance pool pays only claims that prove a
/// loss and the reserve pays running costs at a rate bound by revenue.
pub fn capture_take(share: f64, treasury: f64, rest: f64) -> f64 {
    use tenzro_vm::governance as g;
    let p = |key: &str| g::genesis_param(key) as f64;
    let horizon = p(g::GUARD_LOOSENING_GRACE_PARAM) * tenzro_vm::native::MARKET_EPOCH_MS as f64;
    if share < p(g::LARGE_SPEND_APPROVAL_PARAM) / 10_000.0 {
        return rest;
    }
    let first = p(g::VOTING_PERIOD_PARAM) + p(g::TIMELOCK_PARAM);
    if first >= horizon {
        return rest;
    }
    let periods = ((horizon - first) / p(g::OUTFLOW_PERIOD_PARAM)).ceil() as u32;
    let cap = p(g::MAX_PERIOD_OUTFLOW_PARAM) / 10_000.0;
    let mut left = treasury;
    for _ in 0..periods {
        left -= left * cap;
    }
    treasury - left + rest
}

/// Shares of bonded stake a capture study buys: just over a third (halts
/// the chain, meets quorum alone), just over two thirds (orders blocks), and
/// just over the large-spend approval when that is higher still.
pub fn capture_shares() -> Vec<f64> {
    let mut shares = vec![1.0 / 3.0 + 1e-4, 2.0 / 3.0 + 1e-4];
    let large =
        tenzro_vm::governance::genesis_param(tenzro_vm::governance::LARGE_SPEND_APPROVAL_PARAM)
            as f64
            / 10_000.0
            + 1e-4;
    if large > shares[1] {
        shares.push(large);
    }
    shares
}

/// Cost and payoff of controlling `share` of stake when everyone else holds
/// `honest_bonded` TNZO and the control can take `payoff` TNZO.
pub fn corruption(
    depth_usd: f64,
    price: f64,
    share: f64,
    honest_bonded: f64,
    payoff: f64,
) -> Corruption {
    let pool = Pool::new(depth_usd, price);
    let need = honest_bonded * share / (1.0 - share);
    let cost = pool.buy_cost(need);
    let after = cost.map(|c| Pool {
        usd: pool.usd + c,
        tnzo: pool.tnzo - need,
    });
    let exit = after.map_or(pool.sell_proceeds(payoff), |p| p.sell_proceeds(payoff));
    Corruption {
        depth_usd,
        share,
        honest_bonded_tnzo: honest_bonded,
        stake_needed_tnzo: need,
        cost_usd: cost,
        payoff_tnzo: payoff,
        payoff_usd_at_price: payoff * price,
        payoff_exit_usd: exit,
        net_usd: cost.map(|c| exit - c),
    }
}

/// One shock run's outcome.
#[derive(Debug, Clone, Serialize)]
pub struct ShockRun {
    /// Price change at the shock, as a fraction (-0.8 is an 80% fall).
    pub shock: f64,
    /// Whether agents leave at the shock.
    pub agents_leave: bool,
    /// How the fee rate follows the market: "governance weekly", "never"
    /// or "validator reports".
    pub rate_path: String,
    /// Largest gap between the chain's rate and the market in the 30 days
    /// after the shock, as market over chain.
    pub worst_rate_gap: f64,
    /// Seed.
    pub seed: u64,
    /// Bonded validators before the shock and at the end.
    pub validators_before: u32,
    /// At the end.
    pub validators_after: u32,
    /// Bonded stake at the end, TNZO.
    pub bonded_after: f64,
    /// Mean USD fee of a transfer in the 30 days after the shock.
    pub transfer_fee_usd_after: f64,
    /// Insurance pool at the end, TNZO.
    pub insurance_pool: f64,
    /// Treasury runway at the end, months of grants.
    pub treasury_runway_months: f64,
    /// Share of validators covering costs over the last 30 days.
    pub validators_profitable: f64,
    /// Blocks the ledger refused.
    pub ledger_failures: usize,
}

/// Runs each shock with agents staying and leaving, on the flat market.
pub fn shocks(
    shocks: &[f64],
    days: u32,
    shock_day: u32,
    seeds: u64,
    threads: usize,
) -> Vec<ShockRun> {
    let mut cfgs = Vec::new();
    let mut keys = Vec::new();
    for &s in shocks {
        for leave in [false, true] {
            for path in ["governance weekly", "never", "validator reports"] {
                for seed in 0..seeds {
                    let mut c = RunConfig::scenario(Market::Flat, 700 + seed, days);
                    c.assumptions.outside_flow_vol = 0.0;
                    c.assumptions.governance_tracks_price = path == "governance weekly";
                    c.rate_reports = path == "validator reports";
                    c.shock = Some((shock_day, 1.0 + s));
                    c.agents_leave_day = leave.then_some(shock_day);
                    cfgs.push(c);
                    keys.push((s, leave, path, 700 + seed));
                }
            }
        }
    }
    let outs = crate::gsa::run_all(cfgs, threads);
    outs.iter()
        .zip(keys)
        .map(|(o, (shock, leave, path, seed))| {
            let before = o.days.get(shock_day.saturating_sub(1) as usize);
            let after: Vec<_> = o.days.iter().skip(shock_day as usize).take(30).collect();
            let last = o.days.last().cloned().unwrap_or_default();
            let tail: Vec<_> = o.days.iter().rev().take(30).collect();
            ShockRun {
                shock,
                agents_leave: leave,
                rate_path: path.into(),
                worst_rate_gap: after
                    .iter()
                    .map(|d| {
                        if d.chain_rate_usd > 0.0 {
                            (d.price_usd / d.chain_rate_usd).max(d.chain_rate_usd / d.price_usd)
                        } else {
                            1.0
                        }
                    })
                    .fold(1.0, f64::max),
                seed,
                validators_before: before.map_or(0, |d| d.snap.bonded_validators),
                validators_after: last.snap.bonded_validators,
                bonded_after: last.snap.bonded,
                transfer_fee_usd_after: after
                    .iter()
                    .map(|d| d.human_fee_tnzo * d.price_usd)
                    .sum::<f64>()
                    / after.len().max(1) as f64,
                insurance_pool: last.snap.insurance_pool,
                treasury_runway_months: last.treasury_runway_months.min(1_200.0),
                validators_profitable: tail.iter().map(|d| d.validators_profitable).sum::<f64>()
                    / tail.len().max(1) as f64,
                ledger_failures: o.ledger_failures.len(),
            }
        })
        .collect()
}

/// A validator cartel moving the reported rate.
#[derive(Debug, Clone, Serialize)]
pub struct RateCartelRun {
    /// Cartel validators, of the bonded set.
    pub cartel: u32,
    /// Share of bonded stake.
    pub stake_share: f64,
    /// Factor the cartel reports the market rate at.
    pub factor: f64,
    /// Chain rate over market rate after 1 and 7 days of the attack.
    pub rate_ratio_day1: f64,
    /// After 7 days.
    pub rate_ratio_day7: f64,
    /// A transfer's fee in USD before the attack and after 7 days.
    pub transfer_fee_usd_before: f64,
    /// After 7 days.
    pub transfer_fee_usd_day7: f64,
}

/// Runs rate cartels of `sizes` validators (of 31) reporting each factor
/// from day `from`.
pub fn rate_cartels(
    sizes: &[u32],
    factors: &[f64],
    from: u32,
    threads: usize,
) -> Vec<RateCartelRun> {
    let mut cfgs = Vec::new();
    let mut keys = Vec::new();
    for &n in sizes {
        for &f in factors {
            let mut c = RunConfig::scenario(Market::Flat, 800, from + 8);
            c.assumptions.outside_flow_vol = 0.0;
            c.assumptions.governance_tracks_price = false;
            c.rate_reports = true;
            c.rate_cartel = Some((n, f, from));
            cfgs.push(c);
            keys.push((n, f));
        }
    }
    let outs = crate::gsa::run_all(cfgs, threads);
    outs.iter()
        .zip(keys)
        .map(|(o, (n, f))| {
            let at = |d: usize| o.days.get(d).cloned().unwrap_or_default();
            let ratio = |d: &crate::economy::Day| d.chain_rate_usd / d.price_usd.max(1e-12);
            let fee = |d: &crate::economy::Day| d.human_fee_tnzo * d.price_usd;
            let before = at(from as usize - 1);
            RateCartelRun {
                cartel: n,
                stake_share: n as f64 / before.snap.bonded_validators.max(1) as f64,
                factor: f,
                rate_ratio_day1: ratio(&at(from as usize)),
                rate_ratio_day7: ratio(&at(from as usize + 6)),
                transfer_fee_usd_before: fee(&before),
                transfer_fee_usd_day7: fee(&at(from as usize + 6)),
            }
        })
        .collect()
}

/// The thin-pool study: corruption cost at each depth, manipulation cost,
/// and the shock runs.
#[derive(Debug, Clone, Serialize, Default)]
pub struct DexStudy {
    /// Bonded stake and payoffs the corruption rows use, from a genesis-like run.
    pub bonded_tnzo: f64,
    /// Treasury, TNZO.
    pub treasury_tnzo: f64,
    /// Insurance pool, TNZO.
    pub insurance_tnzo: f64,
    /// Price, USD.
    pub price_usd: f64,
    /// Corruption rows.
    pub corruption: Vec<Corruption>,
    /// (depth USD, USD to double the price, TNZO to halve it).
    pub manipulation: Vec<(f64, f64, f64)>,
    /// Shock runs.
    pub shocks: Vec<ShockRun>,
    /// Treasury lever grid.
    pub levers: Vec<LeverRow>,
    /// Cross-chain liquidity grid.
    pub cross_chain: Vec<CrossChainRow>,
    /// Rate cartels.
    pub rate_cartels: Vec<RateCartelRun>,
}

/// Runs the study. The stake and payoffs come from day `at_day` of a flat
/// run with default inputs.
pub fn study(
    depths: &[f64],
    at_day: u32,
    shock_list: &[f64],
    shock_days: u32,
    seeds: u64,
    threads: usize,
) -> DexStudy {
    let probe = Economy::new(RunConfig::scenario(Market::Flat, 1, at_day)).run();
    let d = probe.days.last().cloned().unwrap_or_default();
    let price = crate::economy::Assumptions::default().price0_usd;
    let mut out = DexStudy {
        bonded_tnzo: d.snap.bonded,
        treasury_tnzo: d.snap.treasury,
        insurance_tnzo: d.snap.insurance_pool,
        price_usd: price,
        ..DexStudy::default()
    };
    for &depth in depths {
        for share in capture_shares() {
            out.corruption.push(corruption(
                depth,
                price,
                share,
                d.snap.bonded,
                capture_take(
                    share,
                    d.snap.treasury,
                    d.snap.insurance_pool + d.snap.reserve,
                ),
            ));
        }
        let pool = Pool::new(depth, price);
        out.manipulation
            .push((depth, pool.pump_cost(2.0), pool.dump_tnzo(0.5)));
    }
    out.shocks = shocks(shock_list, shock_days, shock_days / 3, seeds, threads);
    // The independent set before a shock is the probe's; after a 95% fall
    // the shock runs show what remains.
    let before = Independents {
        validators: d.snap.bonded_validators.max(1),
        stake_each: d.snap.bonded / d.snap.bonded_validators.max(1) as f64,
    };
    let fallen = out
        .shocks
        .iter()
        .filter(|r| r.shock <= -0.95)
        .map(|r| (r.validators_after, r.bonded_after))
        .min_by_key(|(v, _)| *v)
        .unwrap_or((before.validators, d.snap.bonded));
    let after_95 = Independents {
        validators: fallen.0.max(1),
        stake_each: fallen.1 / fallen.0.max(1) as f64,
    };
    let mut all_shocks = vec![0.0];
    all_shocks.extend_from_slice(shock_list);
    out.levers = levers(
        depths,
        &[0.0, 0.05, 0.10, 0.20],
        &[0.0, 0.10, 0.25, 0.40],
        &[0.0, 0.5, 1.0],
        &all_shocks,
        price,
        before,
        after_95,
        capture_take(
            1.0 / 3.0 + 1e-4,
            d.snap.treasury,
            d.snap.insurance_pool + d.snap.reserve,
        ),
    );
    out.rate_cartels = rate_cartels(&[6, 11, 16], &[0.1, 10.0], 30, threads);
    out.cross_chain = cross_chain(
        &[250_000.0, 1_000_000.0, 5_000_000.0],
        &[0.0, 0.5, 0.8, 0.95],
        &[(0.0, true), (0.005, true), (0.005, false)],
        &[0.05, 0.15, 0.30],
        &[100_000.0, 1_000_000.0],
        &[20.0, 60.0],
        &all_shocks,
        price,
        d.snap.bonded,
    );
    out
}

/// One setting of the treasury levers: protocol-owned liquidity and
/// treasury stake, at a third-party pool depth, a price shock and a point
/// of the stake handover.
#[derive(Debug, Clone, Serialize)]
pub struct LeverRow {
    /// Third-party pool depth at launch price, USD.
    pub depth_usd: f64,
    /// Protocol-owned liquidity, share of supply in TNZO (paired with equal USD).
    pub pol_share: f64,
    /// Treasury stake, share of supply.
    pub stake_share: f64,
    /// Share of the treasury stake already handed to independent stakers.
    pub handover: f64,
    /// Price change at the shock.
    pub shock: f64,
    /// Price after the shock, USD.
    pub price: f64,
    /// Combined pool depth after the shock, USD.
    pub pool_usd: f64,
    /// USD to move the price up 10%.
    pub move_up_10_usd: f64,
    /// USD worth of TNZO to sell to move the price down 50%.
    pub move_down_50_usd: f64,
    /// USD worth of TNZO to sell to move the price down 80%.
    pub move_down_80_usd: f64,
    /// USD to buy a third of the stake through the pool; `None` when it cannot supply it.
    pub corrupt_third_usd: Option<f64>,
    /// USD to buy two thirds; `None` when the pool cannot supply it.
    pub corrupt_two_thirds_usd: Option<f64>,
    /// Lower bound on buying a third anywhere: the stake at the price, USD.
    pub corrupt_third_floor_usd: f64,
    /// What capture of the treasury and insurance pool sells for, USD.
    pub payoff_exit_usd: f64,
    /// Fewest entities holding more than a third of stake, the treasury counted as one.
    pub nakamoto_treasury_one_entity: u32,
    /// The same, each validator holding its delegation counted as its own entity.
    pub nakamoto_delegations_locked: u32,
    /// Largest entity's share of voting power, the treasury counted as one.
    pub largest_share: f64,
    /// Whether one entity can halt (above a third) or control (above two thirds).
    pub flag: String,
    /// Impermanent loss of the protocol-owned liquidity at the shock, share of its value.
    pub pol_impermanent_loss: f64,
    /// USD the protocol-owned liquidity paid out to sellers in the shock.
    pub pol_usd_depleted: f64,
    /// Treasury value committed (liquidity both sides plus stake), USD at launch price.
    pub treasury_committed_usd: f64,
    /// Cost to corrupt a third per committed treasury dollar.
    pub cost_per_treasury_usd: Option<f64>,
}

/// Independent validators and their stake before and after a shock.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct Independents {
    /// Validators.
    pub validators: u32,
    /// Stake each, TNZO.
    pub stake_each: f64,
}

/// Fewest entities whose stakes sum above a third of the total.
pub fn nakamoto(mut stakes: Vec<f64>) -> u32 {
    let total: f64 = stakes.iter().sum();
    stakes.sort_by(|a, b| b.partial_cmp(a).unwrap_or(std::cmp::Ordering::Equal));
    let mut acc = 0.0;
    for (i, s) in stakes.iter().enumerate() {
        acc += s;
        if acc > total / 3.0 {
            return i as u32 + 1;
        }
    }
    stakes.len() as u32
}

/// The lever grid. `before` and `after_95` are the independent validator
/// sets before a shock and after a 95% fall (the runs show the set
/// shrinking only then); `payoff` is what a captured third can take out of
/// the treasury and insurance pool, TNZO ([`capture_take`]).
#[allow(clippy::too_many_arguments)]
pub fn levers(
    depths: &[f64],
    pol: &[f64],
    stakes: &[f64],
    handovers: &[f64],
    shocks: &[f64],
    price0: f64,
    before: Independents,
    after_95: Independents,
    payoff: f64,
) -> Vec<LeverRow> {
    const SUPPLY: f64 = 1_000_000_000.0;
    let mut out = Vec::new();
    for &depth in depths {
        for &pl in pol {
            for &st in stakes {
                for &h in handovers {
                    for &sh in shocks {
                        let r = 1.0 + sh;
                        let price = price0 * r;
                        let pol_tnzo = pl * SUPPLY;
                        let pol_usd = pol_tnzo * price0;
                        let base = Pool::new(depth, price0);
                        let pool0 = Pool {
                            usd: base.usd + pol_usd,
                            tnzo: base.tnzo + pol_tnzo,
                        };
                        let pool = Pool {
                            usd: pool0.usd * r.sqrt(),
                            tnzo: pool0.tnzo / r.sqrt(),
                        };
                        let ind = if sh <= -0.95 { after_95 } else { before };
                        let treasury_stake = st * SUPPLY * (1.0 - h);
                        let handed_each = st * SUPPLY * h / ind.validators.max(1) as f64;
                        let mut entities: Vec<f64> = (0..ind.validators)
                            .map(|_| ind.stake_each + handed_each)
                            .collect();
                        let honest: f64 = entities.iter().sum::<f64>() + treasury_stake;
                        let mut one = entities.clone();
                        if treasury_stake > 0.0 {
                            one.push(treasury_stake);
                        }
                        let per = treasury_stake / ind.validators.max(1) as f64;
                        for e in entities.iter_mut() {
                            *e += per;
                        }
                        let largest = one.iter().cloned().fold(0.0, f64::max) / honest.max(1.0);
                        let flag = if largest > 2.0 / 3.0 {
                            "one entity controls the chain"
                        } else if largest > 1.0 / 3.0 {
                            "one entity can halt the chain"
                        } else {
                            ""
                        };
                        let need = |share: f64| honest * share / (1.0 - share);
                        let third = pool.buy_cost(need(1.0 / 3.0 + 1e-4));
                        let two = pool.buy_cost(need(2.0 / 3.0 + 1e-4));
                        let after = third.map(|c| Pool {
                            usd: pool.usd + c,
                            tnzo: pool.tnzo - need(1.0 / 3.0 + 1e-4),
                        });
                        let exit = after.unwrap_or(pool).sell_proceeds(payoff);
                        let down = |f: f64| pool.tnzo * (1.0 / (1.0 - f).sqrt() - 1.0) * price;
                        let committed = 2.0 * pol_usd + st * SUPPLY * price0;
                        out.push(LeverRow {
                            depth_usd: depth,
                            pol_share: pl,
                            stake_share: st,
                            handover: h,
                            shock: sh,
                            price,
                            pool_usd: pool.usd * 2.0,
                            move_up_10_usd: pool.pump_cost(1.1),
                            move_down_50_usd: down(0.5),
                            move_down_80_usd: down(0.8),
                            corrupt_third_usd: third,
                            corrupt_two_thirds_usd: two,
                            corrupt_third_floor_usd: need(1.0 / 3.0 + 1e-4) * price,
                            payoff_exit_usd: exit,
                            nakamoto_treasury_one_entity: nakamoto(one),
                            nakamoto_delegations_locked: nakamoto(entities),
                            largest_share: largest,
                            flag: flag.into(),
                            pol_impermanent_loss: if pl > 0.0 {
                                1.0 - 2.0 * r.sqrt() / (1.0 + r)
                            } else {
                                0.0
                            },
                            pol_usd_depleted: pol_usd * (1.0 - r.sqrt()),
                            treasury_committed_usd: committed,
                            cost_per_treasury_usd: (committed > 0.0).then(|| {
                                third.unwrap_or(need(1.0 / 3.0 + 1e-4) * price) / committed
                            }),
                        });
                    }
                }
            }
        }
    }
    out
}

/// One setting of TNZO liquidity split between a home vault pool on
/// another chain (reached through a cross-chain token) and the native pool.
/// Nothing in the protocol reads either price.
#[derive(Debug, Clone, Serialize)]
pub struct CrossChainRow {
    /// Third-party liquidity across both venues, USD.
    pub liquidity_usd: f64,
    /// Share of it in the home vault pool.
    pub home_share: f64,
    /// Protocol-owned liquidity, share of supply, and where it sits.
    pub pol_share: f64,
    /// Whether the protocol-owned liquidity sits in the home vault pool.
    pub pol_home: bool,
    /// Bridged-supply cap, share of supply.
    pub bridged_cap: f64,
    /// Cross-chain rate limit, TNZO per hour.
    pub rate_limit_tnzo_hour: f64,
    /// Arbitrage latency between venues, minutes.
    pub latency_min: f64,
    /// Price shock.
    pub shock: f64,
    /// USD to lift the native pool 10%, and the home pool 10%.
    pub native_up_10_usd: f64,
    /// Home pool.
    pub home_up_10_usd: f64,
    /// USD worth of TNZO to cut the native pool 50% and 80%.
    pub native_down_50_usd: f64,
    /// 80%.
    pub native_down_80_usd: f64,
    /// Home pool, 50% and 80%.
    pub home_down_50_usd: f64,
    /// 80%.
    pub home_down_80_usd: f64,
    /// The venue cheapest to move.
    pub cheapest: String,
    /// Hours a 50% gap opened on the native pool lasts before rate-limited
    /// arbitrage closes it.
    pub gap_hours: f64,
    /// USD to buy a third of stake on the cheaper route.
    pub corrupt_third_usd: Option<f64>,
    /// Hours the rate limit adds to bringing that stake across.
    pub corrupt_third_bridge_hours: f64,
    /// Most the bridge can lose if the cross-chain token fails: the capped
    /// bridged supply at the price plus the home pool's USD, USD.
    pub bridge_loss_cap_usd: f64,
    /// Ratio of the cost to move the cheapest venue 10% to the cost with
    /// all liquidity in one pool.
    pub fragmentation_ratio: f64,
}

/// The cross-chain liquidity grid.
#[allow(clippy::too_many_arguments)]
pub fn cross_chain(
    liquidity: &[f64],
    home_shares: &[f64],
    pol: &[(f64, bool)],
    caps: &[f64],
    rate_limits: &[f64],
    latencies: &[f64],
    shocks: &[f64],
    price0: f64,
    honest_bonded: f64,
) -> Vec<CrossChainRow> {
    const SUPPLY: f64 = 1_000_000_000.0;
    let mut out = Vec::new();
    for &l in liquidity {
        for &hs in home_shares {
            for &(pl, at_home) in pol {
                for &cap in caps {
                    for &rl in rate_limits {
                        for &lat in latencies {
                            for &sh in shocks {
                                let r = 1.0 + sh;
                                let price = price0 * r;
                                let pol_usd = pl * SUPPLY * price0;
                                let mut home = Pool::new(l * hs, price0);
                                let mut native = Pool::new(l * (1.0 - hs), price0);
                                let target = if at_home { &mut home } else { &mut native };
                                target.usd += pol_usd;
                                target.tnzo += pl * SUPPLY;
                                // The home pool holds bridged TNZO, so the cap bounds it.
                                home.tnzo = home.tnzo.min(cap * SUPPLY);
                                home.usd = home.usd.min(home.tnzo * price0);
                                let moved = |p: Pool| Pool {
                                    usd: p.usd * r.sqrt(),
                                    tnzo: p.tnzo / r.sqrt(),
                                };
                                let (home, native) = (moved(home), moved(native));
                                let down = |p: &Pool, f: f64| {
                                    p.tnzo * (1.0 / (1.0 - f).sqrt() - 1.0) * price
                                };
                                let one = Pool {
                                    usd: home.usd + native.usd,
                                    tnzo: home.tnzo + native.tnzo,
                                };
                                let cheapest = if native.pump_cost(1.1) <= home.pump_cost(1.1) {
                                    "native"
                                } else {
                                    "home"
                                };
                                let cheapest_cost = native.pump_cost(1.1).min(home.pump_cost(1.1));
                                // Closing a 50% gap on the native pool takes the TNZO that
                                // restores its price, carried at the rate limit after the latency.
                                let to_close = native.tnzo * (1.0 - (0.5f64).sqrt());
                                let gap_hours = lat / 60.0 + to_close / rl.max(1.0);
                                let need = honest_bonded * (1.0 / 3.0 + 1e-4) / (2.0 / 3.0 - 1e-4);
                                let via_native = native.buy_cost(need);
                                let via_home = home.buy_cost(need);
                                let (third, hours) = match (via_native, via_home) {
                                    (Some(a), Some(b)) if b < a => {
                                        (Some(b), lat / 60.0 + need / rl.max(1.0))
                                    }
                                    (Some(a), _) => (Some(a), 0.0),
                                    (None, Some(b)) => (Some(b), lat / 60.0 + need / rl.max(1.0)),
                                    (None, None) => (None, 0.0),
                                };
                                out.push(CrossChainRow {
                                    liquidity_usd: l,
                                    home_share: hs,
                                    pol_share: pl,
                                    pol_home: at_home,
                                    bridged_cap: cap,
                                    rate_limit_tnzo_hour: rl,
                                    latency_min: lat,
                                    shock: sh,
                                    native_up_10_usd: native.pump_cost(1.1),
                                    home_up_10_usd: home.pump_cost(1.1),
                                    native_down_50_usd: down(&native, 0.5),
                                    native_down_80_usd: down(&native, 0.8),
                                    home_down_50_usd: down(&home, 0.5),
                                    home_down_80_usd: down(&home, 0.8),
                                    cheapest: cheapest.into(),
                                    gap_hours,
                                    corrupt_third_usd: third,
                                    corrupt_third_bridge_hours: hours,
                                    bridge_loss_cap_usd: cap * SUPPLY * price + home.usd,
                                    fragmentation_ratio: cheapest_cost
                                        / one.pump_cost(1.1).max(1e-9),
                                });
                            }
                        }
                    }
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod capture_tests {
    use super::*;

    /// Stake, holdings and price of the day-90 probe the economics stage
    /// reads, with the insurance pool and reserve rounded well up.
    const BONDED: f64 = 5.21e6;
    const TREASURY: f64 = 4.376e7;
    const INSURANCE: f64 = 1.0e5;
    const PRICE: f64 = 0.10;

    #[test]
    fn a_capture_costs_at_least_the_margin_over_what_it_can_take_at_every_depth() {
        let mut priced = 0;
        for depth in [5.0e4, 2.5e5, 1.0e6, 5.0e6, 2.0e7, 1.0e8] {
            for share in capture_shares() {
                let take = capture_take(share, TREASURY, INSURANCE);
                let c = corruption(depth, PRICE, share, BONDED, take);
                if let Some(cost) = c.cost_usd {
                    priced += 1;
                    assert!(
                        cost >= CAPTURE_MARGIN * c.payoff_exit_usd,
                        "depth {depth}, share {share:.4}: cost {cost:.0} against {:.0}",
                        c.payoff_exit_usd
                    );
                }
            }
        }
        assert!(
            priced >= 9,
            "the study must price captures at the deep pools"
        );
    }

    #[test]
    fn stake_short_of_the_approval_takes_nothing_from_the_treasury() {
        for share in [0.30, 1.0 / 3.0 + 1e-4, 2.0 / 3.0 + 1e-4, 0.7499] {
            assert_eq!(capture_take(share, TREASURY, INSURANCE), INSURANCE);
        }
        // Above the approval the period cap binds, for at most the grace.
        let all = capture_take(0.99, TREASURY, 0.0);
        assert!(all > 0.0 && all < 0.12 * TREASURY, "{all}");
        assert_eq!(capture_shares().len(), 3);
    }

    #[test]
    fn the_guards_the_model_reads_are_registered() {
        use tenzro_vm::governance as g;
        for key in [
            g::GUARD_LOOSENING_GRACE_PARAM,
            g::LARGE_SPEND_APPROVAL_PARAM,
            g::TIMELOCK_PARAM,
            g::VOTING_PERIOD_PARAM,
            g::OUTFLOW_PERIOD_PARAM,
            g::MAX_PERIOD_OUTFLOW_PARAM,
        ] {
            assert!(g::genesis_param(key) > 0, "{key}");
        }
    }
}
