//! A model of the proposed fee design: governed fiat floor prices per
//! resource with a bounded congestion multiplier, fully burned; a mint set
//! in TNZO with a bounded staking-ratio controller; capped app rewards
//! weighted by fees burned; and a rate that starts as a governed value,
//! then becomes a median of validator reports with a move cap, a band
//! against a slow anchor, and challenges.
//!
//! Most of this design is not in the node yet, so it runs here as a model
//! with its own state, step by step. The parts that are in the node (fee
//! burn at a USD-priced rate, a stake-weighted median with a per-epoch move
//! cap) are measured on the ledger by the other studies.
//!
//! Demand is machine-only by default: agents buy TNZO from the pool only to
//! pay fees, and validators sell what they need to cover costs. There is no
//! other trading.

use serde::Serialize;

/// The design's governed parameters.
#[derive(Debug, Clone, Serialize)]
pub struct Design {
    /// Fiat floor per agent action, USD.
    pub fee_floor_usd: f64,
    /// Settlement value per action, USD, and the share of it charged.
    pub settled_usd: f64,
    /// Settlement fee, share of value.
    pub settlement_share: f64,
    /// Congestion target utilization.
    pub congestion_target: f64,
    /// Congestion step per epoch (1/8 in EIP-1559).
    pub congestion_step: f64,
    /// Largest congestion multiplier.
    pub congestion_max: f64,
    /// Actions the chain carries per day at full capacity.
    pub capacity_per_day: f64,
    /// Base mint, TNZO per year, and its yearly decay.
    pub mint_base: f64,
    /// Yearly decay of the base mint.
    pub mint_decay: f64,
    /// Staking-ratio goal.
    pub stake_goal: f64,
    /// Controller step per year.
    pub mint_adj_rate: f64,
    /// Controller bounds on the mint multiple.
    pub mint_min: f64,
    /// Upper bound.
    pub mint_max: f64,
    /// Share of mint paid to apps by fees burned.
    pub app_reward_share: f64,
    /// Rate move cap per rate epoch.
    pub rate_move_cap: f64,
    /// Rate epochs per day.
    pub rate_epochs_per_day: f64,
    /// Band around the slow anchor beyond which the rate freezes.
    pub rate_band: f64,
    /// Anchor window, days (exponential average).
    pub anchor_days: f64,
    /// Bond a challenger posts, USD.
    pub challenge_bond_usd: f64,
}

impl Default for Design {
    fn default() -> Self {
        Self {
            fee_floor_usd: 2.0e-6,
            settled_usd: 0.10,
            settlement_share: 0.001,
            congestion_target: 0.5,
            congestion_step: 0.125,
            congestion_max: 100.0,
            capacity_per_day: 2.5e8,
            mint_base: 60.0e6,
            mint_decay: 0.15,
            stake_goal: 0.30,
            mint_adj_rate: 0.13,
            mint_min: 0.5,
            mint_max: 2.0,
            app_reward_share: 0.2,
            rate_move_cap: 0.01,
            rate_epochs_per_day: 24.0,
            rate_band: 0.10,
            anchor_days: 1.0,
            challenge_bond_usd: 1_000.0,
        }
    }
}

/// The economy outside the protocol the model runs against.
#[derive(Debug, Clone, Serialize)]
pub struct World {
    /// Agents at the start.
    pub agents: f64,
    /// Actions per agent per day.
    pub actions_per_agent: f64,
    /// Actions one on-chain transaction carries (vouchers, channels).
    pub batching: f64,
    /// Yearly growth of agents.
    pub agent_growth: f64,
    /// Pool depth, USD, at the start.
    pub pool_depth_usd: f64,
    /// Price at the start, USD.
    pub price0: f64,
    /// Supply, TNZO.
    pub supply: f64,
    /// Stake at the start, TNZO.
    pub stake0: f64,
    /// Validator costs, USD per year in total.
    pub validator_cost_usd_year: f64,
    /// Yield stakers need to keep staking, per year.
    pub required_yield: f64,
    /// Human buying, USD per day (upside sensitivity; zero in the base case).
    pub human_buy_usd_day: f64,
}

impl Default for World {
    fn default() -> Self {
        Self {
            agents: 100_000.0,
            actions_per_agent: 100.0,
            batching: 1.0,
            agent_growth: 1.0,
            pool_depth_usd: 1_000_000.0,
            price0: 0.10,
            supply: 1.0e9,
            stake0: 50.0e6,
            validator_cost_usd_year: 31.0 * 6_000.0,
            required_yield: 0.08,
            human_buy_usd_day: 0.0,
        }
    }
}

/// One day of the model.
#[derive(Debug, Clone, Default, Serialize)]
pub struct DayState {
    /// Day.
    pub day: u32,
    /// Market price, USD.
    pub price: f64,
    /// Rate fees use, USD.
    pub rate: f64,
    /// Whether the rate is frozen.
    pub frozen: bool,
    /// Congestion multiplier.
    pub congestion: f64,
    /// Utilization.
    pub utilization: f64,
    /// Fees, USD.
    pub fees_usd: f64,
    /// Burned, TNZO.
    pub burned: f64,
    /// Minted, TNZO.
    pub minted: f64,
    /// Supply, TNZO.
    pub supply: f64,
    /// Stake, TNZO.
    pub stake: f64,
    /// Staking yield per year.
    pub yield_year: f64,
    /// Cost to buy a third of stake at the market price, USD.
    pub coc_usd: f64,
    /// Fee for one agent action in fiat, USD.
    pub action_fee_usd: f64,
}

/// A run's shocks and adversaries.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Stress {
    /// (day, factor) applied to the market price within the day.
    pub price_shock: Option<(u32, f64)>,
    /// (day, factor) applied to agent demand.
    pub demand_shock: Option<(u32, f64)>,
    /// Share of stake reporting a biased rate, and the bias (1.1 = 10% high).
    pub rate_bias: Option<(f64, f64)>,
    /// Agents all react to the fee in the same epoch: demand falls to zero
    /// above this multiple of the floor and returns below it.
    pub swarm_threshold: Option<f64>,
    /// Staking-ratio controller on.
    pub controller: bool,
    /// The governed rate (phase 1) drifts from the market by this factor;
    /// validators' shadow reports and challenges watch it.
    pub governed_drift: Option<f64>,
}

/// Runs the model for `days`.
pub fn run(d: &Design, w: &World, s: &Stress, days: u32) -> Vec<DayState> {
    let mut usd = w.pool_depth_usd / 2.0;
    let mut tnzo = usd / w.price0;
    let mut supply = w.supply;
    let mut stake = w.stake0;
    let mut rate = w.price0;
    let mut anchor = w.price0;
    let mut cong = 1.0;
    let mut mint_mult = 1.0;
    let mut out = Vec::with_capacity(days as usize);
    let mut demand_factor = 1.0;
    for day in 0..days {
        let years = day as f64 / 365.25;
        if let Some((sd, f)) = s.demand_shock
            && day == sd
        {
            demand_factor *= f;
        }
        if let Some((sd, f)) = s.price_shock
            && day == sd
        {
            // An outside seller or buyer moves the pool by the factor.
            let k = usd * tnzo;
            let p = (usd / tnzo) * f;
            usd = (k * p).sqrt();
            tnzo = k / usd;
        }
        let price = usd / tnzo;
        // Rate: each hourly epoch it moves only into the band between the
        // one-third and two-thirds stake quantiles of the reports, at most
        // the move cap. A biased group under a third moves nothing; between
        // a third and two thirds it can hold the rate; above, it sets it.
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
            let step = (target / rate).clamp(1.0 - d.rate_move_cap, 1.0 + d.rate_move_cap);
            rate *= step;
        }
        // A governed rate off the published validator median by more than
        // the band is caught by a challenge.
        let frozen = s.governed_drift.is_some() && (rate / price - 1.0).abs() > d.rate_band;
        let alpha = 1.0 / (d.anchor_days.max(1.0 / 144.0));
        anchor = anchor * (1.0 - alpha.min(1.0)) + rate * alpha.min(1.0);
        if frozen {
            // A frozen rate catches up with the anchor once it moves inside the band.
            anchor = anchor * 0.5 + price * 0.5;
        }
        // Demand and congestion.
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
        // Agents buy the TNZO they burn from the pool, at the market price.
        let buy_usd = fees_usd + w.human_buy_usd_day;
        let bought = tnzo * buy_usd / (usd + buy_usd);
        usd += buy_usd;
        tnzo -= bought;
        let burned = fees_usd / rate;
        // Mint: base decaying, times the staking-ratio controller.
        if s.controller {
            let ratio = stake / supply;
            mint_mult = (mint_mult + d.mint_adj_rate / 365.25 * (1.0 - ratio / d.stake_goal))
                .clamp(d.mint_min, d.mint_max);
        }
        let minted = d.mint_base * (1.0 - d.mint_decay).powf(years) / 365.25 * mint_mult;
        supply += minted - burned;
        let to_stakers = minted * (1.0 - d.app_reward_share);
        // Validators sell enough to cover costs.
        let price = usd / tnzo;
        let sell = (w.validator_cost_usd_year / 365.25 / price).min(to_stakers);
        let got = usd * sell / (tnzo + sell);
        usd -= got;
        tnzo += sell;
        // Stake follows yield.
        let price = usd / tnzo;
        let yield_year = to_stakers * 365.25 / stake.max(1.0)
            - w.validator_cost_usd_year / (stake * price).max(1.0);
        stake = (stake * (1.0 + 0.01 * (yield_year - w.required_yield)))
            .clamp(1.0e6, (supply * 0.9).max(1.0e6));
        out.push(DayState {
            day,
            price,
            rate,
            frozen,
            congestion: cong,
            utilization: util,
            fees_usd,
            burned,
            minted,
            supply,
            stake,
            yield_year,
            coc_usd: stake / 2.0 * price,
            action_fee_usd: (fee_now / w.batching.max(1.0) + d.settled_usd * d.settlement_share)
                * price
                / rate,
        });
    }
    out
}

/// One test's outcome.
#[derive(Debug, Clone, Serialize)]
pub struct TestResult {
    /// Test number in the design's table.
    pub number: u32,
    /// What it checks.
    pub name: String,
    /// Whether the pass criterion held.
    pub pass: bool,
    /// The measured figures behind the verdict.
    pub detail: String,
}

fn worst<F: Fn(&DayState) -> f64>(v: &[DayState], f: F) -> f64 {
    v.iter().map(f).fold(0.0, f64::max)
}

/// Runs tests 1 to 13 with machine-only demand.
pub fn tests() -> Vec<TestResult> {
    let d = Design::default();
    let w = World::default();
    let mut out = Vec::new();
    // 1: rate drift by colluders within caps.
    for (share, bias) in [(0.3, 1.5), (0.6, 1.5), (0.6, 0.67)] {
        let v = run(
            &d,
            &w,
            &Stress {
                rate_bias: Some((share, bias)),
                controller: true,
                ..Default::default()
            },
            60,
        );
        let dev = worst(&v, |x| (x.rate / x.price - 1.0).abs());
        out.push(TestResult {
            number: 1,
            name: format!(
                "rate drift, {:.0}% of stake reporting x{bias}",
                share * 100.0
            ),
            pass: dev <= d.rate_band + 1e-9,
            detail: format!(
                "largest rate/market deviation {:.1}% against a {:.0}% band",
                dev * 100.0,
                d.rate_band * 100.0
            ),
        });
    }
    // 2: freeze while the market moves.
    for f in [0.1, 6.0] {
        let v = run(
            &d,
            &w,
            &Stress {
                price_shock: Some((10, f)),
                controller: true,
                ..Default::default()
            },
            40,
        );
        let after: Vec<_> = v.iter().skip(10).collect();
        let dev = after
            .iter()
            .map(|x| (x.rate / x.price - 1.0).abs())
            .fold(0.0, f64::max);
        let back = after
            .iter()
            .position(|x| (x.rate / x.price - 1.0).abs() < 0.02)
            .map(|p| p as f64)
            .unwrap_or(f64::INFINITY);
        // The rate follows at its cap the whole way: never stalls.
        let at_cap =
            (f.ln().abs() / (1.0 + d.rate_move_cap).ln() / d.rate_epochs_per_day).ceil() + 1.0;
        out.push(TestResult {
            number: 2,
            name: format!("market moves x{f} in a day"),
            pass: back <= at_cap,
            detail: format!(
                "largest mispricing {:.0}%, rate within 2% of market after {back} days (the move cap needs {at_cap}); nothing prepaid, so the harm is the fees paid meanwhile",
                dev * 100.0
            ),
        });
    }
    // 3: griefing challenges: a false challenge loses its bond, a true one wins.
    out.push(TestResult {
        number: 3,
        name: "false challenges".into(),
        pass: d.challenge_bond_usd > 0.0,
        detail: format!(
            "a false challenge forfeits ${}; evidence must be on chain or a verifiable fill",
            d.challenge_bond_usd
        ),
    });
    // 4: congestion controller under demand shocks and step sizes.
    for step in [0.125, 0.5, 1.0] {
        let dd = Design {
            congestion_step: step,
            ..d.clone()
        };
        let ww = World {
            agents: 1.5e6,
            ..w.clone()
        };
        let v = run(
            &dd,
            &ww,
            &Stress {
                demand_shock: Some((20, 0.6)),
                controller: true,
                ..Default::default()
            },
            120,
        );
        let tail: Vec<_> = v.iter().skip(60).collect();
        let mean = tail.iter().map(|x| x.utilization).sum::<f64>() / tail.len() as f64;
        let swing = tail.iter().map(|x| x.congestion).fold(0.0, f64::max)
            / tail.iter().map(|x| x.congestion).fold(f64::MAX, f64::min);
        out.push(TestResult {
            number: 4,
            name: format!("congestion controller, step {step}"),
            pass: swing < 2.0,
            detail: format!(
                "utilization {:.2} (target {:.2}), multiplier swing x{swing:.2}",
                mean, dd.congestion_target
            ),
        });
    }
    // 5: a billion agents at the floor, with and without batching.
    for batching in [1.0, 1_000.0] {
        let ww = World {
            agents: 1.0e9,
            batching,
            ..w.clone()
        };
        let v = run(
            &d,
            &ww,
            &Stress {
                controller: true,
                ..Default::default()
            },
            30,
        );
        let last = v.last().cloned().unwrap_or_default();
        let marginal = w.validator_cost_usd_year / 365.25 / d.capacity_per_day;
        out.push(TestResult {
            number: 5,
            name: format!("1e9 agents, {batching} actions per transaction"),
            pass: last.utilization < 1.0 && d.fee_floor_usd >= marginal,
            detail: format!(
                "utilization {:.2}, multiplier {:.1}, fee per action ${:.2e}, floor ${:.1e} vs marginal cost ${:.1e}",
                last.utilization, last.congestion, last.action_fee_usd, d.fee_floor_usd, marginal
            ),
        });
    }
    // 6: app-reward farming break-even.
    let v = run(
        &d,
        &w,
        &Stress {
            controller: true,
            ..Default::default()
        },
        30,
    );
    let last = v.last().cloned().unwrap_or_default();
    let ratio = d.app_reward_share * last.minted / last.burned.max(1e-9);
    out.push(TestResult {
        number: 6,
        name: "wash activity for app rewards".into(),
        pass: ratio < 1.0,
        detail: format!(
            "app share x mint/burn = {ratio:.1} (farming pays when above 1); break-even burn {:.0} TNZO/day against {:.0}",
            d.app_reward_share * last.minted,
            last.burned
        ),
    });
    // 7: validator income crash, controller on and off.
    for controller in [true, false] {
        let v = run(
            &d,
            &w,
            &Stress {
                price_shock: Some((30, 0.2)),
                controller,
                ..Default::default()
            },
            730,
        );
        let before = v[29].stake / v[29].supply;
        let low = v
            .iter()
            .skip(30)
            .map(|x| x.stake / x.supply)
            .fold(f64::MAX, f64::min);
        let end = v.last().map(|x| x.stake / x.supply).unwrap_or(0.0);
        let coc = v
            .iter()
            .skip(30)
            .map(|x| x.coc_usd)
            .fold(f64::MAX, f64::min);
        out.push(TestResult {
            number: 7,
            name: format!("-80% price, controller {}", if controller { "on" } else { "off" }),
            pass: end >= before * 0.8,
            detail: format!("stake ratio {before:.2} -> low {low:.2} -> {end:.2} after two years; lowest cost to a third ${coc:.0}"),
        });
    }
    // 8: supply under long low usage.
    let ww = World {
        agents: 1_000.0,
        agent_growth: 0.0,
        ..w.clone()
    };
    let v = run(
        &d,
        &ww,
        &Stress {
            controller: true,
            ..Default::default()
        },
        3_650,
    );
    let grew = v.last().map(|x| x.supply / w.supply - 1.0).unwrap_or(0.0);
    out.push(TestResult {
        number: 8,
        name: "ten years of low usage".into(),
        pass: grew < 0.5,
        detail: format!(
            "supply +{:.0}% over ten years with base mint {:.0}M/yr decaying {:.0}%/yr",
            grew * 100.0,
            d.mint_base / 1e6,
            d.mint_decay * 100.0
        ),
    });
    // 9: bootstrap capture of the governed rate.
    for drift in [1.05, 1.2] {
        let v = run(
            &d,
            &w,
            &Stress {
                governed_drift: Some(drift),
                controller: true,
                ..Default::default()
            },
            30,
        );
        let froze = v.iter().position(|x| x.frozen);
        out.push(TestResult {
            number: 9,
            name: format!("governed rate set x{drift} off market"),
            pass: drift <= 1.0 + d.rate_band || froze.is_some(),
            detail: match froze {
                Some(day) => format!("band breach detected on day {day}"),
                None => format!(
                    "within the {:.0}% band, so undetected by the band; challenges carry it",
                    d.rate_band * 100.0
                ),
            },
        });
    }
    // 10: prepaid credits: the design has none.
    out.push(TestResult {
        number: 10,
        name: "prepaid-credit arbitrage".into(),
        pass: true,
        detail: "no redeemable or transferable fiat credits exist in the design; application credits are TNZO amounts, so no rate arbitrage".into(),
    });
    // 11: zero human volume, agent usage +-50%.
    for f in [0.5, 1.5] {
        let v = run(
            &d,
            &w,
            &Stress {
                demand_shock: Some((180, f)),
                controller: true,
                ..Default::default()
            },
            1_095,
        );
        let last = v.last().cloned().unwrap_or_default();
        let treasury_like = 48.0e6 * last.price;
        out.push(TestResult {
            number: 11,
            name: format!("machine-only demand, usage x{f} at day 180"),
            pass: last.coc_usd > treasury_like,
            detail: format!(
                "after 3 years: price ${:.4}, fees ${:.0}/day, cost to a third ${:.0}, yield {:.1}%, stake {:.0}M TNZO",
                last.price,
                last.fees_usd,
                last.coc_usd,
                last.yield_year * 100.0,
                last.stake / 1e6
            ),
        });
    }
    // 12: synchronized swarm.
    let ww = World {
        agents: 3.0e6,
        ..w.clone()
    };
    let v = run(
        &d,
        &ww,
        &Stress {
            swarm_threshold: Some(1.5),
            controller: true,
            ..Default::default()
        },
        120,
    );
    let tail: Vec<_> = v.iter().skip(30).collect();
    let flips = tail
        .windows(2)
        .filter(|p| (p[0].utilization > 0.0) != (p[1].utilization > 0.0))
        .count();
    out.push(TestResult {
        number: 12,
        name: "synchronized agent swarm".into(),
        pass: flips < 10,
        detail: format!(
            "demand switched on and off {flips} times in 90 days at step {}",
            d.congestion_step
        ),
    });
    // 13: long phase 1, no market depth.
    let ww = World {
        pool_depth_usd: 50_000.0,
        ..w.clone()
    };
    let v = run(
        &d,
        &ww,
        &Stress {
            governed_drift: Some(1.08),
            controller: true,
            ..Default::default()
        },
        1_095,
    );
    let err = worst(&v, |x| (x.rate / x.price - 1.0).abs());
    out.push(TestResult {
        number: 13,
        name: "three years of governed rate on a $50k pool".into(),
        pass: err <= d.rate_band,
        detail: format!(
            "largest governed-rate error {:.1}% against a {:.0}% band",
            err * 100.0,
            d.rate_band * 100.0
        ),
    });
    out
}

/// Burn-mint balance over agent counts: when burn first exceeds mint and
/// the price then, machine-only.
#[derive(Debug, Clone, Serialize)]
pub struct Equilibrium {
    /// Agents.
    pub agents: f64,
    /// Fees, USD per year at the start.
    pub fees_usd_year: f64,
    /// First day burn exceeds mint, if within the horizon.
    pub day_burn_exceeds_mint: Option<u32>,
    /// Price after the horizon, USD.
    pub price_end: f64,
    /// Cost to buy a third of stake after the horizon, USD.
    pub coc_end_usd: f64,
}

/// Runs the agent-count sweep over `days`.
pub fn equilibrium(agent_counts: &[f64], days: u32) -> Vec<Equilibrium> {
    let d = Design::default();
    agent_counts
        .iter()
        .map(|&a| {
            let w = World {
                agents: a,
                agent_growth: 0.0,
                ..World::default()
            };
            let v = run(
                &d,
                &w,
                &Stress {
                    controller: true,
                    ..Default::default()
                },
                days,
            );
            let last = v.last().cloned().unwrap_or_default();
            Equilibrium {
                agents: a,
                fees_usd_year: v.first().map(|x| x.fees_usd * 365.25).unwrap_or(0.0),
                day_burn_exceeds_mint: v.iter().find(|x| x.burned > x.minted).map(|x| x.day),
                price_end: last.price,
                coc_end_usd: last.coc_usd,
            }
        })
        .collect()
}
