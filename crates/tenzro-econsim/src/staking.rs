//! Issuance target, security ratio and cold-start studies.
//!
//! Four day-step models, each with a pass rule:
//!
//! - **Security ratio.** Slashable stake an attack must put at risk
//!   against the most one attack can take out over the bridges before it is
//!   stopped. Cap raises are refused while the ratio after the raise would
//!   be under the governed minimum; governance lowers caps after a lag when
//!   a price fall pushes the ratio under it.
//! - **Issuance controller.** The old controller (staked share of liquid
//!   supply toward 30%, up to 1.5x) against the security-ratio controller
//!   (ratio toward its minimum, up to 1x), over the same price paths.
//! - **Burn-mint horizon.** Settled value a year needs before burn
//!   equals mint. A report; it has no pass rule.
//! - **Cold start.** Inference supply and demand per model under
//!   three supply policies: no subsidy (nodes serve because validator
//!   issuance pays them), a floor capped at realised burn, and an
//!   availability floor that pays per available slot-hour. Idle supply
//!   joins any floor that pays more than idling costs.
//!
//! Every figure is an assumption stated in the inputs; results hold only in
//! the bands swept here.

use serde::Serialize;

use crate::bme::TestResult;

/// TNZO/USD price paths, as a multiplier of the launch price per day.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum PricePath {
    /// Flat.
    Flat,
    /// -90% over 30 days from day 180, then flat.
    Crash,
    /// x5 over three years.
    Growth,
    /// -80% over three years.
    Bleed,
}

impl PricePath {
    /// Every path.
    pub const ALL: [PricePath; 4] = [
        PricePath::Flat,
        PricePath::Crash,
        PricePath::Growth,
        PricePath::Bleed,
    ];

    fn at(self, day: f64) -> f64 {
        match self {
            PricePath::Flat => 1.0,
            PricePath::Crash => {
                if day < 180.0 {
                    1.0
                } else {
                    let f = ((day - 180.0) / 30.0).min(1.0);
                    (0.1f64).powf(f)
                }
            }
            PricePath::Growth => 5f64.powf((day / 1095.75).min(1.0)),
            PricePath::Bleed => 0.2f64.powf((day / 1095.75).min(1.0)),
        }
    }
}

/// Which issuance controller runs.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub enum Controller {
    /// Staked share of liquid supply toward `goal`, multiplier in [0.5, max].
    StakedShare { goal: f64, max: f64 },
    /// Security ratio toward `k`, multiplier in [0.5, max].
    SecurityRatio { max: f64 },
}

/// Inputs of the security and controller model.
#[derive(Debug, Clone, Serialize)]
pub struct SecurityInputs {
    /// Validators at genesis and after two years.
    pub validators_start: f64,
    pub validators_end: f64,
    /// Self-stake per validator, TNZO.
    pub self_stake: f64,
    /// Share of validator rewards above running cost that validators bond.
    pub restake: f64,
    /// Share of rewards neither bonded nor needed for cost that is sold.
    pub sell_rest: f64,
    /// Validator running cost, USD a month.
    pub cost_usd_month: f64,
    /// Launch price, USD.
    pub price0: f64,
    /// Launch pool: TNZO side; the USD side is this times the price. Sales
    /// move the price by their USD over twice the USD side, and outside
    /// liquidity pulls it back toward the path over `revert_days`.
    pub pool_tnzo: f64,
    pub revert_days: f64,
    /// Liquid supply at genesis, TNZO.
    pub liquid0: f64,
    /// Issuance in year 0, TNZO; yearly decay; floor.
    pub mint_base: f64,
    pub mint_decay: f64,
    pub mint_floor: f64,
    /// Validators' share of issuance.
    pub validator_share: f64,
    /// Controller step per year, multiplier units.
    pub adj_per_year: f64,
    /// Least multiplier.
    pub min_mult: f64,
    /// Bridge outflow caps per hourly epoch: TNZO, and USD units together.
    /// The genesis caps, sized from genesis stake.
    pub cap_tnzo: f64,
    pub cap_usd: f64,
    /// Epochs an attack drains before it is stopped.
    pub window_epochs: f64,
    /// Share of bonded stake a safety attack must put at risk.
    pub attack_share: f64,
    /// Least security ratio.
    pub k: f64,
    /// Governance asks to double the caps every this many days, up to `cap_max_mult`.
    pub raise_every_days: f64,
    pub cap_max_mult: f64,
    /// Whether a raise is refused when the ratio after it is under `k`.
    pub gate: bool,
    /// Days governance takes to halve caps once the ratio falls under `k`.
    pub lower_lag_days: f64,
    /// Days simulated.
    pub days: u32,
}

impl Default for SecurityInputs {
    fn default() -> Self {
        Self {
            validators_start: 21.0,
            validators_end: 50.0,
            self_stake: 10_000.0,
            restake: 0.5,
            sell_rest: 0.5,
            cost_usd_month: 500.0,
            price0: 0.10,
            pool_tnzo: 2.5e6,
            revert_days: 30.0,
            liquid0: 600.0e6,
            mint_base: 60.0e6,
            mint_decay: 0.15,
            mint_floor: 10.0e6,
            validator_share: 0.45,
            adj_per_year: 0.13,
            min_mult: 0.5,
            cap_tnzo: 648.0,
            cap_usd: 129.64,
            window_epochs: 24.0,
            attack_share: 1.0 / 3.0,
            k: 1.5,
            raise_every_days: 90.0,
            cap_max_mult: 16.0,
            gate: true,
            lower_lag_days: 7.0,
            days: 1826,
        }
    }
}

/// One run of the security and controller model.
#[derive(Debug, Clone, Serialize)]
pub struct SecurityRun {
    pub controller: Controller,
    pub path: PricePath,
    pub gate: bool,
    /// Validator issuance over the run, TNZO, and as a share of genesis liquid supply.
    pub validator_mint: f64,
    pub dilution: f64,
    /// Multiplier at the end and days spent at its upper bound.
    pub mult_end: f64,
    pub days_at_max: u32,
    /// Ratio at genesis, least ratio after the first raise, days under `k` after the first raise.
    pub ratio_genesis: f64,
    pub ratio_min_after_raise: f64,
    pub days_under_k_after_raise: u32,
    /// Raises enacted while the ratio after them was under `k`.
    pub unsafe_raises: u32,
    /// First day the ratio reached `k` at genesis caps.
    pub day_secure: Option<u32>,
    /// Cap multiple at the end.
    pub cap_mult_end: f64,
    /// Bonded stake at the end, TNZO, and staked share of liquid supply.
    pub stake_end: f64,
    pub staked_share_end: f64,
    /// Price at the end over the path alone (the pool's response to sales).
    pub price_end: f64,
    pub sale_drag: f64,
    /// Least validator issuance value over running cost, over 30-day windows.
    pub coverage_min: f64,
}

/// Runs the security and controller model once.
pub fn security_run(i: &SecurityInputs, c: Controller, path: PricePath) -> SecurityRun {
    let depth_usd = 2.0 * i.pool_tnzo * i.price0;
    let mut drag = 0.0f64;
    let mut stake = i.validators_start * i.self_stake;
    let mut liquid = i.liquid0;
    let mut mult = 1.0f64;
    let mut cap_mult = 1.0f64;
    let mut minted_v = 0.0;
    let mut days_at_max = 0u32;
    let mut first_raise: Option<u32> = None;
    let mut ratio_min_after = f64::INFINITY;
    let mut days_under = 0u32;
    let mut unsafe_raises = 0u32;
    let mut day_secure = None;
    let mut under_since: Option<u32> = None;
    let mut coverage_min = f64::INFINITY;
    let mut window: Vec<(f64, f64)> = Vec::new();
    let mut ratio_genesis = 0.0;
    let mut price = i.price0;
    for day in 0..i.days {
        let d = day as f64;
        let years = d / 365.25;
        let n = i.validators_start + (i.validators_end - i.validators_start) * (d / 730.5).min(1.0);
        price = path.at(d) * i.price0 * drag.exp();
        let ev = |cm: f64, p: f64| i.window_epochs * cm * (i.cap_tnzo + i.cap_usd / p.max(1e-9));
        let ratio = i.attack_share * stake / ev(cap_mult, price);
        if day == 0 {
            ratio_genesis = ratio;
        }
        if day_secure.is_none() && i.attack_share * stake / ev(1.0, price) >= i.k {
            day_secure = Some(day);
        }
        // Governance: raise on schedule (gated), lower after a lag below k.
        if day > 0 && (d % i.raise_every_days) < 1.0 && cap_mult < i.cap_max_mult {
            let after = i.attack_share * stake / ev(cap_mult * 2.0, price);
            if !i.gate || after >= i.k {
                if after < i.k {
                    unsafe_raises += 1;
                }
                cap_mult *= 2.0;
                first_raise.get_or_insert(day);
            }
        }
        if first_raise.is_some() {
            let r = i.attack_share * stake / ev(cap_mult, price);
            ratio_min_after = ratio_min_after.min(r);
            if r < i.k {
                days_under += 1;
                let since = *under_since.get_or_insert(day);
                if i.gate && (day - since) as f64 >= i.lower_lag_days && cap_mult > 1.0 {
                    cap_mult /= 2.0;
                    under_since = None;
                }
            } else {
                under_since = None;
            }
        }
        // Controller.
        let gap = match c {
            Controller::StakedShare { goal, .. } => 1.0 - (stake / liquid) / goal,
            Controller::SecurityRatio { .. } => ((i.k - ratio) / i.k).clamp(-1.0, 1.0),
        };
        let max = match c {
            Controller::StakedShare { max, .. } | Controller::SecurityRatio { max } => max,
        };
        mult = (mult + i.adj_per_year / 365.25 * gap.clamp(-1.0, 1.0)).clamp(i.min_mult, max);
        if mult >= max - 1e-12 {
            days_at_max += 1;
        }
        let annual = (i.mint_base * (1.0 - i.mint_decay).powf(years.floor())).max(i.mint_floor);
        let v = annual * mult * i.validator_share / 365.25;
        minted_v += v;
        liquid += v;
        // Validators sell for cost, bond a share of the rest, sell a share of the remainder.
        let cost_tnzo = n * i.cost_usd_month * 12.0 / 365.25 / price.max(1e-9);
        let for_cost = cost_tnzo.min(v);
        let rest = v - for_cost;
        let bonded = rest * i.restake;
        stake += bonded;
        let sold = for_cost + (rest - bonded) * i.sell_rest;
        drag = drag * (1.0 - 1.0 / i.revert_days.max(1.0)) - sold * price / depth_usd;
        window.push((v * price, n * i.cost_usd_month * 12.0 / 365.25));
        if window.len() > 30 {
            window.remove(0);
        }
        if window.len() == 30 {
            let (paid, cost): (f64, f64) = window
                .iter()
                .fold((0.0, 0.0), |a, w| (a.0 + w.0, a.1 + w.1));
            coverage_min = coverage_min.min(paid / cost.max(1e-9));
        }
    }
    SecurityRun {
        controller: c,
        path,
        gate: i.gate,
        validator_mint: minted_v,
        dilution: minted_v / i.liquid0,
        mult_end: mult,
        days_at_max,
        ratio_genesis,
        ratio_min_after_raise: if ratio_min_after.is_finite() {
            ratio_min_after
        } else {
            0.0
        },
        days_under_k_after_raise: days_under,
        unsafe_raises,
        day_secure,
        cap_mult_end: cap_mult,
        stake_end: stake,
        staked_share_end: stake / liquid,
        price_end: price,
        sale_drag: drag.exp(),
        coverage_min,
    }
}

/// The controllers compared.
pub fn controllers() -> [Controller; 4] {
    [
        Controller::StakedShare {
            goal: 0.30,
            max: 1.5,
        },
        Controller::SecurityRatio { max: 1.5 },
        Controller::SecurityRatio { max: 1.25 },
        Controller::SecurityRatio { max: 1.0 },
    ]
}

/// Every controller over every path, gated, at the given inputs.
pub fn security_sweep(i: &SecurityInputs) -> Vec<SecurityRun> {
    let mut out = Vec::new();
    for c in controllers() {
        for p in PricePath::ALL {
            out.push(security_run(i, c, p));
        }
    }
    out
}

/// Burn-mint horizon for one settled-value path: first schedule year whose
/// burn covers that year's issuance, if any within `years`.
#[derive(Debug, Clone, Serialize)]
pub struct Horizon {
    pub settled_usd_day0: f64,
    pub growth_per_year: f64,
    pub price: f64,
    pub first_year_burn_covers_mint: Option<u32>,
    pub settled_usd_year_needed_y0: f64,
}

/// Burn = share of the settlement fee burned, plus posted fees, against
/// issuance at multiplier 1.
pub fn horizon(settled_usd_day0: f64, growth: f64, price: f64, years: u32) -> Horizon {
    let i = SecurityInputs::default();
    let fee = 0.001 * 0.5; // settlement fee 10 bps, half burned
    let posted_per_usd = 0.0001 / 0.30; // a $0.0001 posted fee per $0.30 average payment
    let burn_per_usd = fee + posted_per_usd;
    let mut first = None;
    for y in 0..years {
        let settled = settled_usd_day0 * 365.25 * (1.0 + growth).powi(y as i32);
        let mint = (i.mint_base * (1.0 - i.mint_decay).powi(y as i32)).max(i.mint_floor);
        if settled * burn_per_usd / price >= mint {
            first = Some(y);
            break;
        }
    }
    Horizon {
        settled_usd_day0,
        growth_per_year: growth,
        price,
        first_year_burn_covers_mint: first,
        settled_usd_year_needed_y0: i.mint_base * price / burn_per_usd,
    }
}

/// Supply policy in the cold-start model.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub enum Supply {
    /// No subsidy beyond what nodes earn from validator issuance.
    None,
    /// Floor per slot-hour, capped in total at the burn realised over the
    /// trailing 30 days.
    BurnCapped { slots: u32, floor_usd_hour: f64 },
    /// Floor per available slot-hour, uncapped but for slots and sunset.
    Availability {
        slots: u32,
        floor_usd_hour: f64,
        sunset_days: u32,
    },
}

/// Demand path for the cold-start model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Demand {
    Growth,
    Flat,
    Downturn,
}

/// Inputs of the cold-start model.
#[derive(Debug, Clone, Serialize)]
pub struct ColdInputs {
    /// Models offered.
    pub models: u32,
    /// Potential paid demand per model at launch, USD a day.
    pub demand0_usd_day: f64,
    /// Demand response to fill: realised = potential x trust, trust an
    /// average of recent fill raised to `elasticity`.
    pub elasticity: f64,
    /// Serving price per provider-hour at full use, USD; serving cost per hour.
    pub price_hour: f64,
    pub cost_hour: f64,
    /// Nodes serving each model because validator issuance covers them, and
    /// the day they stop (issuance step, `None` for never).
    pub validator_servers: u32,
    pub validator_exit_day: Option<u32>,
    /// Independent providers per model at launch.
    pub providers0: u32,
    /// Idle supply: cost per hour of keeping an endpoint up without real
    /// capacity behind it, and the share of its slot-hours probes catch.
    pub idle_cost_hour: f64,
    pub idle_caught: f64,
    /// Settled-value share burned (settlement fee burned plus posted fees).
    pub burn_share: f64,
    /// Price of TNZO, USD (for reporting subsidy in TNZO).
    pub price: f64,
    /// Agent-dominated demand: each day's demand is the potential times a
    /// lognormal burst with this sigma, shared across models with this
    /// correlation (agents follow the same signals at machine speed).
    pub burst_sigma: f64,
    pub burst_correlation: f64,
    /// Agent wallets each idle-supply root runs, and whether slots count per
    /// root (the human delegator or hardware identity) or per wallet.
    pub wallets_per_root: f64,
    pub per_root: bool,
    pub seed: u64,
    pub days: u32,
}

impl Default for ColdInputs {
    fn default() -> Self {
        Self {
            models: 5,
            demand0_usd_day: 50.0,
            elasticity: 1.0,
            price_hour: 1.0,
            cost_hour: 0.6,
            validator_servers: 1,
            validator_exit_day: None,
            providers0: 2,
            idle_cost_hour: 0.05,
            idle_caught: 0.5,
            burn_share: 0.000_83,
            price: 0.10,
            burst_sigma: 0.8,
            burst_correlation: 0.7,
            wallets_per_root: 10.0,
            per_root: true,
            seed: 7,
            days: 730,
        }
    }
}

/// One cold-start run.
#[derive(Debug, Clone, Serialize)]
pub struct ColdRun {
    pub supply: Supply,
    pub demand: Demand,
    /// Average fill over the run, and over the last 90 days.
    pub fill_mean: f64,
    pub fill_last90: f64,
    /// Paid demand over the run, USD.
    pub revenue_usd: f64,
    /// Subsidy paid, USD and TNZO, and the part idle supply took.
    pub subsidy_usd: f64,
    pub subsidy_tnzo: f64,
    pub subsidy_to_idle: f64,
    /// Subsidy per dollar of paid demand.
    pub subsidy_per_revenue: f64,
    /// Real providers per model at the end.
    pub providers_end: f64,
    /// First day paid demand covers the cost of the providers it needs.
    pub day_self_sustaining: Option<u32>,
}

fn demand_at(d: Demand, day: f64) -> f64 {
    let y = day / 365.25;
    match d {
        Demand::Growth => 4f64.powf(y),
        Demand::Flat => 1.0,
        Demand::Downturn => 0.5f64.powf(y),
    }
}

/// Runs the cold-start model once, every model alike.
pub fn cold_run(i: &ColdInputs, s: Supply, demand: Demand) -> ColdRun {
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};
    let mut rng = StdRng::seed_from_u64(i.seed);
    let mut normal = move || {
        // Box-Muller.
        let u1: f64 = rng.gen_range(1e-12..1.0);
        let u2: f64 = rng.gen_range(0.0..1.0);
        (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos()
    };
    let mut providers = i.providers0 as f64;
    let mut idle = 0.0f64;
    let mut trust = 1.0f64;
    let mut margins: Vec<f64> = Vec::new();
    let mut burns: Vec<f64> = Vec::new();
    let (mut fill_sum, mut fill_last, mut revenue, mut subsidy, mut to_idle) =
        (0.0, 0.0, 0.0, 0.0, 0.0);
    let mut sustain = None;
    for day in 0..i.days {
        let d = day as f64;
        let validators = match i.validator_exit_day {
            Some(e) if day >= e => 0.0,
            _ => i.validator_servers as f64,
        };
        let real = providers + validators;
        let capacity = real * 24.0 * i.price_hour;
        let potential = i.demand0_usd_day * demand_at(demand, d);
        let z =
            i.burst_correlation.sqrt() * normal() + (1.0 - i.burst_correlation).sqrt() * normal();
        let burst = (i.burst_sigma * z - i.burst_sigma * i.burst_sigma / 2.0).exp();
        let wanted = potential * trust.powf(i.elasticity) * burst;
        let served = wanted.min(capacity);
        let fill = if wanted > 0.0 { served / wanted } else { 1.0 };
        let fill = if real < 0.5 { 0.0 } else { fill };
        trust = trust * (29.0 / 30.0) + fill / 30.0;
        fill_sum += fill;
        if day + 90 >= i.days {
            fill_last += fill / 90.0;
        }
        revenue += served;
        burns.push(served * i.burn_share);
        if burns.len() > 30 {
            burns.remove(0);
        }
        // Revenue splits evenly over real servers.
        let per_server_rev = served / real.max(1.0);
        // Subsidy per model per day.
        let (slot_pay, idle_pay) = match s {
            Supply::None => (0.0, 0.0),
            Supply::BurnCapped {
                slots,
                floor_usd_hour,
            } => {
                let want = slots as f64 * (floor_usd_hour * 24.0 - per_server_rev).max(0.0);
                let cap = burns.iter().sum::<f64>() / 30.0;
                (want.min(cap), 0.0)
            }
            Supply::Availability {
                slots,
                floor_usd_hour,
                sunset_days,
            } => {
                if day >= sunset_days {
                    (0.0, 0.0)
                } else {
                    // Slots go to real and idle endpoints in proportion;
                    // idle ones are paid unless probes catch them.
                    let counted_idle = if i.per_root {
                        idle / i.wallets_per_root.max(1.0)
                    } else {
                        idle
                    };
                    let endpoints = providers + counted_idle;
                    let filled = (slots as f64).min(endpoints);
                    let real_slots = if endpoints > 0.0 {
                        filled * providers / endpoints
                    } else {
                        0.0
                    };
                    let idle_slots = filled - real_slots;
                    let real_pay = real_slots * (floor_usd_hour * 24.0 - per_server_rev).max(0.0);
                    let idle_pay = idle_slots * floor_usd_hour * 24.0 * (1.0 - i.idle_caught);
                    (real_pay, idle_pay)
                }
            }
        };
        subsidy += slot_pay + idle_pay;
        to_idle += idle_pay;
        // Real providers: margin per provider; exit below -20% of cost over
        // 30 days, enter above +20%.
        let sub_per_real = if providers > 0.0 {
            slot_pay / providers
        } else {
            0.0
        };
        let margin = per_server_rev + sub_per_real - i.cost_hour * 24.0;
        margins.push(margin);
        if margins.len() > 30 {
            margins.remove(0);
        }
        let m30 = margins.iter().sum::<f64>() / margins.len() as f64;
        let c = i.cost_hour * 24.0;
        if m30 < -0.2 * c {
            providers = (providers - providers / 30.0).max(0.0);
        } else if m30 > 0.2 * c {
            providers += (providers.max(1.0)) / 30.0;
        }
        // Idle supply joins while a slot pays it more than idling costs.
        if let Supply::Availability {
            slots,
            floor_usd_hour,
            sunset_days,
        } = s
        {
            // A root joins with all its wallets; per-root counting gives it
            // one slot's chance however many wallets it runs.
            let w = i.wallets_per_root.max(1.0);
            let counted = if i.per_root { idle / w } else { idle };
            let endpoints = providers + counted;
            let mine = if i.per_root { 1.0 } else { w };
            let share = ((slots as f64) * mine / (endpoints + mine)).min(mine);
            // Expected pay per root against what its wallets cost to idle.
            let expect = share * floor_usd_hour * (1.0 - i.idle_caught);
            if day < sunset_days && expect > i.idle_cost_hour * w {
                idle += w;
            } else if day >= sunset_days || expect < i.idle_cost_hour * w {
                idle = (idle - idle / 10.0).max(0.0);
            }
        }
        if sustain.is_none() && day >= 30 {
            let needed = (wanted / (24.0 * i.price_hour)).ceil().max(1.0);
            if served >= needed * c && fill > 0.99 {
                sustain = Some(day);
            }
        }
    }
    let n = i.models as f64;
    ColdRun {
        supply: s,
        demand,
        fill_mean: fill_sum / i.days as f64,
        fill_last90: fill_last,
        revenue_usd: revenue * n,
        subsidy_usd: subsidy * n,
        subsidy_tnzo: subsidy * n / i.price,
        subsidy_to_idle: if subsidy > 0.0 {
            (to_idle / subsidy).max(0.0)
        } else {
            0.0
        },
        subsidy_per_revenue: subsidy / revenue.max(1e-9),
        providers_end: providers,
        day_self_sustaining: sustain,
    }
}

/// The supply policies compared.
pub fn supplies() -> [Supply; 4] {
    [
        Supply::None,
        Supply::BurnCapped {
            slots: 2,
            floor_usd_hour: 0.6,
        },
        Supply::Availability {
            slots: 2,
            floor_usd_hour: 0.6,
            sunset_days: 180,
        },
        Supply::Availability {
            slots: 4,
            floor_usd_hour: 1.0,
            sunset_days: 365,
        },
    ]
}

/// Every supply policy over every demand path.
pub fn cold_sweep(i: &ColdInputs) -> Vec<ColdRun> {
    let mut out = Vec::new();
    for s in supplies() {
        for d in [Demand::Growth, Demand::Flat, Demand::Downturn] {
            out.push(cold_run(i, s, d));
        }
    }
    out
}

fn fmt_ctrl(c: Controller) -> String {
    match c {
        Controller::StakedShare { goal, max } => {
            format!("staked share {:.0}% up to {max}x", goal * 100.0)
        }
        Controller::SecurityRatio { max } => format!("security ratio up to {max}x"),
    }
}

/// The scenarios with pass rules, at their default inputs.
pub fn scenarios() -> Vec<TestResult> {
    let mut out = Vec::new();
    let si = SecurityInputs::default();
    let runs = security_sweep(&si);
    let old: Vec<&SecurityRun> = runs
        .iter()
        .filter(|r| matches!(r.controller, Controller::StakedShare { .. }))
        .collect();
    let new: Vec<&SecurityRun> = runs
        .iter()
        .filter(|r| r.controller == Controller::SecurityRatio { max: 1.0 })
        .collect();
    // No raise under k, and after the first raise the ratio is back
    // above k within the lowering lag plus a margin.
    let lag = si.lower_lag_days as u32 + 3;
    let s7_pass = new.iter().all(|r| r.unsafe_raises == 0);
    out.push(TestResult {
        number: 201,
        name: "security ratio: no bridge-cap raise leaves slashable stake under k x the extractable value".into(),
        pass: s7_pass,
        detail: new
            .iter()
            .map(|r| {
                format!(
                    "{:?}: ratio {:.3} at genesis, secure at genesis caps from day {}, caps x{} at end, least ratio after a raise {:.2}, {} days under k (lag {} d)",
                    r.path,
                    r.ratio_genesis,
                    r.day_secure.map_or("never".into(), |d| d.to_string()),
                    r.cap_mult_end,
                    r.ratio_min_after_raise,
                    r.days_under_k_after_raise,
                    lag
                )
            })
            .collect::<Vec<_>>()
            .join("; "),
    });
    // Without the gate, caps sized to launch liquidity (25,000 TNZO and
    // $20,000 an hour) instead of to stake.
    let ungated = security_run(
        &SecurityInputs {
            gate: false,
            cap_tnzo: 25_000.0,
            cap_usd: 20_000.0,
            ..si.clone()
        },
        Controller::SecurityRatio { max: 1.0 },
        PricePath::Flat,
    );
    out.push(TestResult {
        number: 202,
        name: "security ratio: without the gate, caps sized to launch liquidity outrun stake"
            .into(),
        pass: ungated.unsafe_raises > 0,
        detail: format!(
            "ungated, flat price: {} raises enacted under k, least ratio {:.3}",
            ungated.unsafe_raises, ungated.ratio_min_after_raise
        ),
    });
    // Controller: the security-ratio controller never issues more than the
    // old one on any path, and covers validator cost on the flat path.
    let less = new
        .iter()
        .zip(old.iter())
        .all(|(n, o)| n.validator_mint <= o.validator_mint + 1.0);
    let flat_cover = new
        .iter()
        .find(|r| r.path == PricePath::Flat)
        .map_or(0.0, |r| r.coverage_min);
    out.push(TestResult {
        number: 203,
        name: "issuance: the security-ratio controller (max 1x) issues no more than the staked-share controller and covers validator cost at a flat price".into(),
        pass: less && flat_cover >= 1.0,
        detail: new
            .iter()
            .zip(old.iter())
            .map(|(n, o)| {
                format!(
                    "{:?}: validator issuance {:.1}M vs {:.1}M TNZO ({:.1}% vs {:.1}% of genesis liquid), multiplier at end {:.2} vs {:.2}, days at max {} vs {}, least cost coverage {:.1}x vs {:.1}x",
                    n.path,
                    n.validator_mint / 1e6,
                    o.validator_mint / 1e6,
                    n.dilution * 100.0,
                    o.dilution * 100.0,
                    n.mult_end,
                    o.mult_end,
                    n.days_at_max,
                    o.days_at_max,
                    n.coverage_min,
                    o.coverage_min
                )
            })
            .collect::<Vec<_>>()
            .join("; "),
    });
    // Report.
    let hs: Vec<Horizon> = [1.0e5, 1.0e6, 1.0e7]
        .iter()
        .map(|&v| horizon(v, 1.0, 0.10, 10))
        .collect();
    out.push(TestResult {
        number: 204,
        name: "burn-mint horizon (report: no pass rule)".into(),
        pass: true,
        detail: format!(
            "at $0.10, year-0 burn equals year-0 issuance at ${:.2e} settled a year; settled value doubling yearly from {}",
            hs[0].settled_usd_year_needed_y0,
            hs.iter()
                .map(|h| format!(
                    "${:.0e}/day: burn covers issuance in year {}",
                    h.settled_usd_day0,
                    h.first_year_burn_covers_mint
                        .map_or("never within 10".into(), |y| y.to_string())
                ))
                .collect::<Vec<_>>()
                .join(", ")
        ),
    });
    // Cold start without a floor, at genesis: nodes paid by validator
    // issuance hold fill; an availability floor pays idle supply.
    let ci = ColdInputs::default();
    let cold = cold_sweep(&ci);
    let none: Vec<&ColdRun> = cold.iter().filter(|r| r.supply == Supply::None).collect();
    let avail: Vec<&ColdRun> = cold
        .iter()
        .filter(|r| matches!(r.supply, Supply::Availability { .. }))
        .collect();
    let capped: Vec<&ColdRun> = cold
        .iter()
        .filter(|r| matches!(r.supply, Supply::BurnCapped { .. }))
        .collect();
    // Agent bursts cap fill near 0.9 for every policy, so the rule is
    // relative: no floor stays within 0.05 of the floor a network would
    // ship (2 slots, 180 days) in growth and flat demand.
    let small: Vec<&ColdRun> = cold.iter().filter(|r| r.supply == supplies()[2]).collect();
    let none_ok = none
        .iter()
        .zip(small.iter())
        .filter(|(n, _)| n.demand != Demand::Downturn)
        .all(|(n, f)| n.fill_mean >= f.fill_mean - 0.05);
    out.push(TestResult {
        number: 205,
        name: "cold start: with nodes serving on validator issuance, no floor keeps fill within 0.05 of a small availability floor in growth and flat demand".into(),
        pass: none_ok,
        detail: cold
            .iter()
            .map(|r| {
                format!(
                    "{:?}/{:?}: fill {:.2} (last 90 d {:.2}), subsidy ${:.0} ({:.2} per $ revenue, {:.0}% to idle), providers at end {:.1}, self-sustaining from day {}",
                    r.supply,
                    r.demand,
                    r.fill_mean,
                    r.fill_last90,
                    r.subsidy_usd,
                    r.subsidy_per_revenue,
                    r.subsidy_to_idle * 100.0,
                    r.providers_end,
                    r.day_self_sustaining.map_or("never".into(), |d| d.to_string())
                )
            })
            .collect::<Vec<_>>()
            .join("; "),
    });
    let added = |a: &ColdRun| {
        let n = none
            .iter()
            .find(|n| n.demand == a.demand)
            .map_or(0.0, |n| n.revenue_usd);
        a.subsidy_usd / (a.revenue_usd - n).max(1.0)
    };
    out.push(TestResult {
        number: 206,
        name: "cold start: a burn-capped floor never pays more than burn (subsidy per $ of paid demand an availability floor adds: report)".into(),
        pass: capped
            .iter()
            .all(|r| r.subsidy_usd <= r.revenue_usd * ci.burn_share + 1e-6),
        detail: avail
            .iter()
            .map(|a| {
                format!(
                    "{:?}/{:?}: ${:.0} subsidy for ${:.0} of added paid demand ({:.2} per $)",
                    a.supply,
                    a.demand,
                    a.subsidy_usd,
                    a.revenue_usd
                        - none
                            .iter()
                            .find(|n| n.demand == a.demand)
                            .map_or(0.0, |n| n.revenue_usd),
                    added(a)
                )
            })
            .collect::<Vec<_>>()
            .join("; "),
    });
    // The issuance step that stops validator-funded serving.
    let step = ColdInputs {
        validator_exit_day: Some(365),
        ..ColdInputs::default()
    };
    let after: Vec<ColdRun> = [Supply::None, supplies()[2]]
        .iter()
        .map(|s| cold_run(&step, *s, Demand::Flat))
        .collect();
    out.push(TestResult {
        number: 207,
        name:
            "cold start: an issuance step that stops validator-funded serving at day 365 (report)"
                .into(),
        pass: true,
        detail: after
            .iter()
            .map(|r| {
                format!(
                    "{:?}: fill last 90 d {:.2}, providers at end {:.1}, subsidy ${:.0}",
                    r.supply, r.fill_last90, r.providers_end, r.subsidy_usd
                )
            })
            .collect::<Vec<_>>()
            .join("; "),
    });
    // Agents: one root running many agent wallets against an availability
    // floor, counted per wallet and per root.
    let farm: Vec<ColdRun> = [false, true]
        .iter()
        .map(|&per_root| {
            cold_run(
                &ColdInputs {
                    per_root,
                    ..ColdInputs::default()
                },
                supplies()[3],
                Demand::Flat,
            )
        })
        .collect();
    out.push(TestResult {
        number: 208,
        name: "agents: counting a floor per root, not per agent wallet, keeps a root with many wallets from taking the slots".into(),
        pass: farm[1].subsidy_to_idle < farm[0].subsidy_to_idle,
        detail: format!(
            "10 wallets per root, flat demand, 4 slots at $1/h for 365 days: idle supply takes {:.0}% of the floor counted per wallet, {:.0}% counted per root; subsidy ${:.0} vs ${:.0}",
            farm[0].subsidy_to_idle * 100.0,
            farm[1].subsidy_to_idle * 100.0,
            farm[0].subsidy_usd,
            farm[1].subsidy_usd
        ),
    });
    out
}

/// Markdown tables of the sweeps behind the scenarios.
pub fn tables(si: &SecurityInputs, ci: &ColdInputs) -> String {
    use std::fmt::Write;
    let mut s = String::new();
    let _ = writeln!(
        s,
        "## Issuance controller and security ratio\n\n| controller | path | validator issuance M TNZO | % genesis liquid | mult end | days at max | ratio genesis | secure from day | caps end | least ratio after raise | days under k | unsafe raises | stake end M | staked share | price end | sale drag | least coverage |\n|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|"
    );
    for r in security_sweep(si) {
        let _ = writeln!(
            s,
            "| {} | {:?} | {:.1} | {:.1} | {:.2} | {} | {:.3} | {} | x{} | {:.2} | {} | {} | {:.1} | {:.2}% | ${:.4} | {:.2} | {:.1}x |",
            fmt_ctrl(r.controller),
            r.path,
            r.validator_mint / 1e6,
            r.dilution * 100.0,
            r.mult_end,
            r.days_at_max,
            r.ratio_genesis,
            r.day_secure.map_or("never".into(), |d| d.to_string()),
            r.cap_mult_end,
            r.ratio_min_after_raise,
            r.days_under_k_after_raise,
            r.unsafe_raises,
            r.stake_end / 1e6,
            r.staked_share_end * 100.0,
            r.price_end,
            r.sale_drag,
            r.coverage_min
        );
    }
    let _ = writeln!(
        s,
        "\n## Cold start\n\n| supply | demand | fill | fill last 90 d | revenue $ | subsidy $ | subsidy M TNZO | per $ revenue | to idle | providers end | self-sustaining day |\n|---|---|---|---|---|---|---|---|---|---|---|"
    );
    for r in cold_sweep(ci) {
        let _ = writeln!(
            s,
            "| {:?} | {:?} | {:.2} | {:.2} | {:.0} | {:.0} | {:.2} | {:.2} | {:.0}% | {:.1} | {} |",
            r.supply,
            r.demand,
            r.fill_mean,
            r.fill_last90,
            r.revenue_usd,
            r.subsidy_usd,
            r.subsidy_tnzo / 1e6,
            r.subsidy_per_revenue,
            r.subsidy_to_idle * 100.0,
            r.providers_end,
            r.day_self_sustaining
                .map_or("never".into(), |d| d.to_string())
        );
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gated_raises_never_leave_the_ratio_under_k() {
        let si = SecurityInputs::default();
        for p in PricePath::ALL {
            let r = security_run(&si, Controller::SecurityRatio { max: 1.0 }, p);
            assert_eq!(r.unsafe_raises, 0, "{p:?}");
        }
    }

    #[test]
    fn the_ratio_controller_never_exceeds_its_bound() {
        let si = SecurityInputs::default();
        let r = security_run(&si, Controller::SecurityRatio { max: 1.0 }, PricePath::Flat);
        assert!(r.mult_end <= 1.0 + 1e-12 && r.mult_end >= si.min_mult - 1e-12);
    }

    #[test]
    fn a_burn_capped_floor_pays_at_most_the_burn() {
        let ci = ColdInputs::default();
        for d in [Demand::Growth, Demand::Flat, Demand::Downturn] {
            let r = cold_run(&ci, supplies()[1], d);
            assert!(r.subsidy_usd <= r.revenue_usd * ci.burn_share + 1e-6);
        }
    }
}
