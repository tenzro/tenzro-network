//! Crash and reflexivity study.
//!
//! Extends the day-step fee-design model in `bme::run` with: a multi-day
//! crash path, a separate cap on how fast the rate may fall, validators that
//! sell part of their rewards, a cap on how fast stake may leave, unbonded
//! stake sold on release, a provider floor paid in USD at the chain rate
//! (with and without a cap in TNZO), correlated demand loss, a bridge whose
//! foreign-asset cap is fixed in USD with and without automatic shrinking to
//! stake value, and safety checks at the safety rate. With every extension
//! off it reproduces `bme::run` exactly; the parity check is a test.
//!
//! Rows, crash on day 60 of 730:
//! - **Z**: no crash and no outside buyers (report).
//! - **A**: depth and speed of the crash. Pass: with buyers staying, the
//!   protocol's flows never deepen the fall (amplification at least 0.99).
//! - **B**: validators sell every reward; issuance controller on and off;
//!   correlated loss of demand. Pass: the same rule with buyers staying.
//! - **C**: a provider floor in USD paid at the chain rate. Pass: a floor
//!   capped in TNZO never drains the pool (the uncapped rows are a report).
//! - **D**: a 95% fall in a day with a 1% or 5% hourly fall cap, and the
//!   stake-backed bridge cap off or on, valued at the safety rate. Pass, at
//!   5%: a USD fee is worth under 90% of its target on at most two days, the
//!   chain never reads the bridge as safe while it is not, and shrinking the
//!   cap leaves the least true ratio no lower than not shrinking it.
//! - **E**: exit churn caps (report).
//!
//! Results hold only for the inputs swept here.

use crate::bme::{self, Design, Stress, TestResult, World};

#[derive(Clone, Debug)]
pub struct Ext {
    /// Day the crash starts.
    crash_day: u32,
    /// Total fall over the crash, as the factor left (0.05 is -95%).
    crash_factor: f64,
    /// Days the crash is spread over.
    crash_days: u32,
    /// Rate may fall at most this fraction per hourly epoch.
    fall_cap: f64,
    /// Share of validator rewards sold beyond cost cover (0 = costs only).
    sell_share: f64,
    /// Most stake may shrink in a day, fraction (1.0 = no limit).
    exit_cap_day: f64,
    /// Unbonding days before exiting stake is released.
    unbond_days: u32,
    /// Share of released stake sold into the pool.
    unbond_sell: f64,
    /// Provider floor, USD per day, paid in TNZO at the chain rate.
    retainer_usd_day: f64,
    /// Cap on the floor's payout per day, TNZO (infinite = no cap).
    retainer_cap_tnzo_day: f64,
    /// Demand left after the crash, factor.
    demand_after: f64,
    /// Foreign-asset bridge cap, USD per detection window.
    bridge_usd: f64,
    /// Security margin gamma.
    gamma: f64,
    /// Automatic de-risking: the cap follows stake value at the chain rate.
    derisk: bool,
    /// Agents buy the TNZO they burn (fee / rate) rather than fee USD.
    buy_at_rate: bool,
    /// Outside buyers' USD per day after the crash, as a factor of before.
    outside_after: f64,
    /// Safety checks value TNZO at the safety rate, not the rate in force.
    safety_rate: bool,
}

impl Ext {
    fn off() -> Self {
        Self {
            crash_day: u32::MAX,
            crash_factor: 1.0,
            crash_days: 1,
            fall_cap: 0.01,
            sell_share: 0.0,
            exit_cap_day: 1.0,
            unbond_days: 0,
            unbond_sell: 0.0,
            retainer_usd_day: 0.0,
            retainer_cap_tnzo_day: f64::INFINITY,
            demand_after: 1.0,
            bridge_usd: 0.0,
            gamma: 0.5,
            derisk: false,
            buy_at_rate: false,
            outside_after: 1.0,
            safety_rate: false,
        }
    }
}

#[derive(Clone, Debug, Default)]
struct Day {
    price: f64,
    rate: f64,
    stake: f64,
    supply: f64,
    /// Cost of a third of stake at the market, USD.
    coc_usd: f64,
    /// Security ratio at the market price: two thirds of stake (USD) over the
    /// bridge cap in force (USD).
    ratio_true: f64,
    /// The same ratio as the chain sees it, at its own rate.
    ratio_chain: f64,
    /// USD a fee or penalty set in USD is actually worth, over its target.
    usd_realised: f64,
    /// Protocol-driven net USD into the pool this day (buys minus sells).
    net_usd: f64,
    /// TNZO paid by the provider floor.
    retainer_tnzo: f64,
}

fn run(d: &Design, w: &World, s: &Stress, x: &Ext, days: u32) -> Vec<Day> {
    let mut usd = w.pool_depth_usd / 2.0;
    let mut tnzo = usd / w.price0;
    let mut supply = w.supply;
    let mut stake = w.stake0;
    let mut rate = w.price0;
    let mut anchor = w.price0;
    let mut cong = 1.0;
    let mut mint_mult = 1.0;
    let mut demand_factor = 1.0;
    let mut unbonding: Vec<(u32, f64)> = Vec::new();
    let mut outside = 1.0;
    let mut out = Vec::with_capacity(days as usize);
    let per_day_crash = x.crash_factor.powf(1.0 / x.crash_days.max(1) as f64);
    for day in 0..days {
        let years = day as f64 / 365.25;
        if let Some((sd, f)) = s.demand_shock
            && day == sd
        {
            demand_factor *= f;
        }
        if day == x.crash_day {
            demand_factor *= x.demand_after;
            outside *= x.outside_after;
        }
        let mut shocks: Vec<f64> = Vec::new();
        if let Some((sd, f)) = s.price_shock
            && day == sd
        {
            shocks.push(f);
        }
        if day >= x.crash_day && day < x.crash_day.saturating_add(x.crash_days) {
            shocks.push(per_day_crash);
        }
        for f in shocks {
            let k = usd * tnzo;
            let p = (usd / tnzo) * f;
            usd = (k * p).sqrt();
            tnzo = k / usd;
        }
        let price = usd / tnzo;
        for _ in 0..d.rate_epochs_per_day as u32 {
            let (lo, hi) = match (s.governed_drift, s.rate_bias) {
                (Some(drift), _) => (price * drift, price * drift),
                (None, Some((share, bias))) if share >= 2.0 / 3.0 => (price * bias, price * bias),
                (None, Some((share, bias))) if share > 1.0 / 3.0 => {
                    (price.min(price * bias), price.max(price * bias))
                }
                _ => (price, price),
            };
            let target = rate.clamp(lo, hi);
            let step = (target / rate).clamp(1.0 - x.fall_cap, 1.0 + d.rate_move_cap);
            rate *= step;
        }
        let frozen = s.governed_drift.is_some() && (rate / price - 1.0).abs() > d.rate_band;
        let alpha = 1.0 / (d.anchor_days.max(1.0 / 144.0));
        anchor = anchor * (1.0 - alpha.min(1.0)) + rate * alpha.min(1.0);
        if frozen {
            anchor = anchor * 0.5 + price * 0.5;
        }
        let _ = anchor;
        let agents = w.agents * (1.0 + w.agent_growth).powf(years) * demand_factor;
        let mut wanted = agents * w.actions_per_agent;
        let fee_now = d.fee_floor_usd * cong;
        if let Some(th) = s.swarm_threshold
            && cong > th
        {
            wanted = 0.0;
        }
        let onchain = wanted / w.batching.max(1.0);
        let util = (onchain / d.capacity_per_day).min(1.0);
        let carried = onchain.min(d.capacity_per_day) * w.batching.max(1.0);
        cong = (cong
            * (1.0 + d.congestion_step * (util - d.congestion_target) / d.congestion_target))
            .clamp(1.0, d.congestion_max);
        let fees_usd =
            carried / w.batching.max(1.0) * fee_now + carried * d.settled_usd * d.settlement_share;
        let burned = fees_usd / rate;
        let mut net = 0.0;
        // Agents buy what they burn.
        let buy_usd = if x.buy_at_rate {
            let need = burned;
            // USD needed to take `need` TNZO out of the pool.
            if need < tnzo * 0.999 {
                usd * need / (tnzo - need)
            } else {
                usd * 1000.0
            }
        } else {
            fees_usd
        } + w.human_buy_usd_day * outside;
        let bought = tnzo * buy_usd / (usd + buy_usd);
        usd += buy_usd;
        tnzo -= bought;
        net += buy_usd;
        if s.controller {
            let ratio = stake / supply;
            mint_mult = (mint_mult + d.mint_adj_rate / 365.25 * (1.0 - ratio / d.stake_goal))
                .clamp(d.mint_min, d.mint_max);
        }
        let minted = d.mint_base * (1.0 - d.mint_decay).powf(years) / 365.25 * mint_mult;
        // Provider floor in USD, paid in TNZO at the chain rate, sold at once.
        let retainer = (x.retainer_usd_day / rate).min(x.retainer_cap_tnzo_day);
        supply += minted - burned + retainer;
        let to_stakers = minted * (1.0 - d.app_reward_share);
        let price = usd / tnzo;
        let cover = (w.validator_cost_usd_year / 365.25 / price).min(to_stakers);
        let sell = cover.max(x.sell_share * to_stakers).min(to_stakers) + retainer;
        let got = usd * sell / (tnzo + sell);
        usd -= got;
        tnzo += sell;
        net -= got;
        // Released unbonding stake.
        let mut release = 0.0;
        unbonding.retain(|&(at, amt)| {
            if at <= day {
                release += amt;
                false
            } else {
                true
            }
        });
        if release > 0.0 && x.unbond_sell > 0.0 {
            let q = release * x.unbond_sell;
            let g = usd * q / (tnzo + q);
            usd -= g;
            tnzo += q;
            net -= g;
        }
        let price = usd / tnzo;
        let yield_year = to_stakers * 365.25 / stake.max(1.0)
            - w.validator_cost_usd_year / (stake * price).max(1.0);
        let wanted_stake = (stake * (1.0 + 0.01 * (yield_year - w.required_yield)))
            .clamp(1.0e6, (supply * 0.9).max(1.0e6));
        let new_stake = wanted_stake.max(stake * (1.0 - x.exit_cap_day));
        if new_stake < stake && x.unbond_days > 0 {
            unbonding.push((day + x.unbond_days, stake - new_stake));
        }
        stake = new_stake;
        // The safety rate: the lower of the rate in force and the lowest
        // median of the window. The day's medians show the day's price.
        let safety = if x.safety_rate { rate.min(price) } else { rate };
        // Bridge: the foreign-asset cap in force, USD per window.
        let cap = if x.derisk {
            x.bridge_usd
                .min(stake * 2.0 / 3.0 * safety / (1.0 + x.gamma))
        } else {
            x.bridge_usd
        };
        let (rt, rc) = if cap > 0.0 {
            (
                stake * 2.0 / 3.0 * price / cap,
                stake * 2.0 / 3.0 * safety / cap,
            )
        } else {
            (f64::INFINITY, f64::INFINITY)
        };
        out.push(Day {
            price,
            rate,
            stake,
            supply,
            coc_usd: stake / 2.0 * price,
            ratio_true: rt,
            ratio_chain: rc,
            usd_realised: price / rate,
            net_usd: net,
            retainer_tnzo: retainer,
        });
    }
    out
}

fn parity() -> f64 {
    let d = Design::default();
    let w = World::default();
    let mut worst: f64 = 0.0;
    for controller in [true, false] {
        let s = Stress {
            price_shock: Some((30, 0.2)),
            controller,
            ..Default::default()
        };
        let a = bme::run(&d, &w, &s, 730);
        let b = run(&d, &w, &s, &Ext::off(), 730);
        for (p, q) in a.iter().zip(&b) {
            for (u, v) in [
                (p.price, q.price),
                (p.rate, q.rate),
                (p.stake, q.stake),
                (p.supply, q.supply),
            ] {
                worst = worst.max(((u - v) / u).abs());
            }
        }
    }
    worst
}

#[derive(Clone)]
struct Case {
    name: String,
    w: World,
    x: Ext,
    controller: bool,
}

/// What one case measured after its crash day.
#[derive(Clone, Debug)]
pub struct Measured {
    /// The case.
    pub name: String,
    /// Its row of the table.
    pub row: String,
    /// End price with the crash over end price without it, over the crash
    /// factor: below 1, protocol flows deepened the fall.
    pub amplification: f64,
    /// Least ratio of stake value to the bridge cap in force, at the market.
    pub min_true_ratio: f64,
    /// Days the chain read the bridge as safe while it was not.
    pub false_safe_days: usize,
    /// Days a USD-set fee was worth under 90% of its target.
    pub lag_days: usize,
    /// The pool was drained.
    pub pool_drained: bool,
}

fn measure(c: &Case, days: u32) -> Measured {
    let d = Design::default();
    let s = Stress {
        controller: c.controller,
        ..Default::default()
    };
    let v = run(&d, &c.w, &s, &c.x, days);
    let mut base_x = c.x.clone();
    base_x.crash_day = u32::MAX;
    base_x.demand_after = 1.0;
    base_x.outside_after = 1.0;
    let b = run(&d, &c.w, &s, &base_x, days);
    let cd = c.x.crash_day as usize;
    let pre = &v[cd - 1];
    let end = v.last().unwrap();
    let bend = b.last().unwrap();
    let amp = (end.price / bend.price) / c.x.crash_factor;
    let post = &v[cd..];
    let min_price = post.iter().map(|x| x.price).fold(f64::MAX, f64::min);
    let min_coc = post.iter().map(|x| x.coc_usd).fold(f64::MAX, f64::min);
    let min_true = post.iter().map(|x| x.ratio_true).fold(f64::MAX, f64::min);
    let false_safe = post
        .iter()
        .filter(|x| x.ratio_chain >= 1.0 + c.x.gamma && x.ratio_true < 1.0)
        .count();
    let worst_usd = post.iter().map(|x| x.usd_realised).fold(f64::MAX, f64::min);
    let lag_days = post.iter().filter(|x| x.usd_realised < 0.9).count();
    let pre_net = v[cd.saturating_sub(30)..cd]
        .iter()
        .map(|x| x.net_usd)
        .sum::<f64>()
        / 30.0;
    let post_net = post.iter().take(90).map(|x| x.net_usd).sum::<f64>() / 90.0;
    let ret_tnzo = post.iter().take(90).map(|x| x.retainer_tnzo).sum::<f64>();
    let pool_dead = end.price < pre.price * c.x.crash_factor * 1e-3;
    let row = format!(
        "| {} | {:.3} | {:.4} | {:.4} | {:.2} | {:.0}% | ${:.0}k -> ${:.0}k | {} | {} | {:.2} | {} | {:.0} / {:.0} | {:.2}M | {} |",
        c.name,
        pre.price,
        min_price,
        end.price,
        amp,
        100.0 * (1.0 - end.stake / pre.stake),
        pre.coc_usd / 1e3,
        min_coc / 1e3,
        if min_true < 1e300 {
            format!("{min_true:.2}")
        } else {
            "-".into()
        },
        false_safe,
        worst_usd,
        lag_days,
        pre_net,
        post_net,
        ret_tnzo / 1e6,
        if pool_dead { "POOL DRAINED" } else { "" }
    );
    Measured {
        name: c.name.clone(),
        row,
        amplification: amp,
        min_true_ratio: min_true,
        false_safe_days: false_safe,
        lag_days,
        pool_drained: pool_dead,
    }
}

/// Max relative difference between this model with every extension off and
/// `bme::run`.
pub fn parity_error() -> f64 {
    parity()
}

fn cases() -> Vec<Case> {
    let mut cases = Vec::new();
    // Outside holders buy what validators sell at the starting price, so the
    // market is level before the crash (cost cover only; sell-all cases set
    // their own level).
    let thin = |depth: f64| World {
        pool_depth_usd: depth,
        human_buy_usd_day: World::default().validator_cost_usd_year / 365.25,
        // Launch-sized demand: about $100 a day of fees, not a billion agents.
        agents: 5_000.0,
        actions_per_agent: 20.0,
        agent_growth: 0.0,
        ..World::default()
    };
    let base = |_depth: f64, f: f64, cdays: u32| Ext {
        crash_day: 60,
        crash_factor: f,
        crash_days: cdays,
        buy_at_rate: true,
        unbond_days: 7,
        ..Ext::off()
    };
    // Sell-all validators: outside holders buy the whole validator reward at
    // the starting price.
    let sell_all_buy = 60.0e6 / 365.25 * 0.8 * 0.10;
    // Z. No outside buyers at all: validators' cost cover against fee buying.
    for depth in [100_000.0, 1_000_000.0] {
        let mut w = thin(depth);
        w.human_buy_usd_day = 0.0;
        let mut x = base(depth, 1.0, 1);
        x.unbond_sell = 1.0;
        cases.push(Case {
            name: format!("Z depth ${:.0}k, no crash, no outside buyers", depth / 1e3),
            w,
            x,
            controller: true,
        });
    }
    // A. Depth and speed of the crash, protocol as on main.
    for depth in [100_000.0, 1_000_000.0] {
        for (f, cd) in [(0.5, 1), (0.2, 3), (0.05, 3), (0.05, 30)] {
            let mut x = base(depth, f, cd);
            x.unbond_sell = 1.0;
            for out in [1.0, 0.3] {
                let mut x = x.clone();
                x.outside_after = out;
                cases.push(Case {
                    name: format!(
                        "A depth ${:.0}k, -{:.0}% in {cd}d, outside buyers x{out}",
                        depth / 1e3,
                        (1.0 - f) * 100.0
                    ),
                    w: thin(depth),
                    x,
                    controller: true,
                });
            }
        }
    }
    // B. Validators sell all rewards; controller on/off; correlated demand loss.
    for (sell, ctl, dem) in [
        (1.0, true, 1.0),
        (1.0, false, 1.0),
        (1.0, true, 0.3),
        (0.0, true, 0.3),
    ] {
        let mut x = base(100_000.0, 0.05, 3);
        x.sell_share = sell;
        x.demand_after = dem;
        x.outside_after = dem;
        x.unbond_sell = 1.0;
        let mut w = thin(100_000.0);
        if sell > 0.0 {
            w.human_buy_usd_day = sell_all_buy;
        }
        cases.push(Case {
            name: format!(
                "B -95%/3d, sell {:.0}%, controller {}, demand x{dem}",
                sell * 100.0,
                if ctl { "on" } else { "off" }
            ),
            w,
            x,
            controller: ctl,
        });
    }
    // C. A provider floor in USD paid at the chain rate: uncapped vs TNZO-capped.
    for (usd_day, cap) in [
        (480.0, f64::INFINITY),
        (480.0, 4_800.0),
        (2_400.0, f64::INFINITY),
        (2_400.0, 24_000.0),
    ] {
        let mut x = base(100_000.0, 0.2, 3);
        x.retainer_usd_day = usd_day;
        x.retainer_cap_tnzo_day = cap;
        cases.push(Case {
            name: format!(
                "C -80%/3d, floor ${usd_day}/d, cap {}",
                if cap.is_finite() {
                    format!("{cap} TNZO/d")
                } else {
                    "none".into()
                }
            ),
            w: thin(100_000.0),
            x,
            controller: true,
        });
    }
    // D. Rate lag and the bridge: symmetric 1%/h vs fast fall 5%/h; de-risk off/on.
    for (fall, derisk) in [(0.01, false), (0.05, false), (0.01, true), (0.05, true)] {
        let mut x = base(1_000_000.0, 0.05, 1);
        x.fall_cap = fall;
        x.derisk = derisk;
        x.safety_rate = fall > 0.01;
        x.gamma = 1.0;
        // Foreign-asset cap sized so the ratio is 2x before the crash.
        x.bridge_usd = 50.0e6 * 2.0 / 3.0 * 0.10 / 2.0;
        cases.push(Case {
            name: format!(
                "D -95%/1d, fall cap {:.0}%/h, de-risk {}",
                fall * 100.0,
                if derisk { "on" } else { "off" }
            ),
            w: thin(1_000_000.0),
            x,
            controller: true,
        });
    }
    // E. Exit churn: no cap vs 4%/day, validators selling all, demand x0.3.
    for cap in [1.0, 0.04, 0.01] {
        let mut x = base(100_000.0, 0.05, 3);
        x.sell_share = 1.0;
        x.demand_after = 0.3;
        x.outside_after = 0.3;
        x.exit_cap_day = cap;
        x.unbond_sell = 1.0;
        let mut w = thin(100_000.0);
        w.human_buy_usd_day = sell_all_buy;
        cases.push(Case {
            name: format!(
                "E -95%/3d, sell all, buyers x0.3, exit cap {:.0}%/d",
                cap * 100.0
            ),
            w,
            x,
            controller: true,
        });
    }
    cases
}

/// Days each case runs.
pub const DAYS: u32 = 730;

/// Every case, measured.
pub fn measured() -> Vec<Measured> {
    cases().iter().map(|c| measure(c, DAYS)).collect()
}

/// The table of every case.
pub fn table(rows: &[Measured]) -> String {
    let mut table = String::from(
        "| case | price pre | min | end | amplification | stake lost | cost of 1/3 stake (pre -> min) | min true bridge ratio | days chain sees safe while true < 1 | worst USD realised | days USD realised < 0.9 | protocol net USD/day pre / post | floor TNZO paid 90d | flag |\n|---|---|---|---|---|---|---|---|---|---|---|---|---|---|\n",
    );
    for m in rows {
        table.push_str(&m.row);
        table.push('\n');
    }
    table
}

/// The pass rules, numbered 301 onwards.
pub fn scenarios(rows: &[Measured]) -> Vec<TestResult> {
    let mut out = Vec::new();
    let p = parity();
    out.push(TestResult {
        number: 301,
        name: "crash model reproduces bme::run with every extension off".into(),
        pass: p < 1e-9,
        detail: format!("max relative difference {p:.3e}"),
    });
    fn by<'a>(rows: &'a [Measured], prefix: &'a str) -> impl Iterator<Item = &'a Measured> {
        rows.iter().filter(move |m| m.name.starts_with(prefix))
    }
    let staying = |m: &&Measured| !m.name.contains("x0.3");
    let worst = by(rows, "A ")
        .chain(by(rows, "B "))
        .filter(staying)
        .map(|m| (m.amplification, m.name.clone()))
        .fold(
            (f64::MAX, String::new()),
            |a, b| if b.0 < a.0 { b } else { a },
        );
    out.push(TestResult {
        number: 302,
        name: "with buyers staying, protocol flows never deepen a crash (A, B)".into(),
        pass: worst.0 >= 0.99,
        detail: format!("least amplification {:.2} ({})", worst.0, worst.1),
    });
    let drained: Vec<String> = by(rows, "C ")
        .filter(|m| !m.name.contains("cap none") && m.pool_drained)
        .map(|m| m.name.clone())
        .collect();
    out.push(TestResult {
        number: 303,
        name: "a USD floor capped in TNZO never drains the pool (C)".into(),
        pass: drained.is_empty(),
        detail: if drained.is_empty() {
            "no capped floor drained the pool".into()
        } else {
            format!("drained: {}", drained.join("; "))
        },
    });
    let d5: Vec<&Measured> = by(rows, "D ").filter(|m| m.name.contains("5%/h")).collect();
    let lag = d5.iter().map(|m| m.lag_days).max().unwrap_or(usize::MAX);
    let fs = d5
        .iter()
        .map(|m| m.false_safe_days)
        .max()
        .unwrap_or(usize::MAX);
    out.push(TestResult {
        number: 304,
        name: "a 95% fall in a day: the 5%/h fall cap follows within 2 days and the safety rate never reads the bridge as safe while it is not (D)".into(),
        pass: !d5.is_empty() && lag <= 2 && fs == 0,
        detail: format!("days under 90%: {lag}; false-safe days: {fs}"),
    });
    let ratio = |on: bool| {
        d5.iter()
            .find(|m| m.name.ends_with(if on { "on" } else { "off" }))
            .map_or(f64::NAN, |m| m.min_true_ratio)
    };
    let (on, off) = (ratio(true), ratio(false));
    out.push(TestResult {
        number: 305,
        name: "stake-backed bridge caps leave the least true ratio no lower than fixed caps (D)"
            .into(),
        pass: on >= off,
        detail: format!("least true ratio {on:.2} shrinking, {off:.2} fixed"),
    });
    out
}
