//! Scenarios and pass criteria for the multi-tier economy, run on the
//! aggregate loop ([`crate::growth`]) and on closed forms of the fee rules.
//!
//! Each scenario states its expected result or pass rule beside what the
//! model gives, so a reader sees how far the two are apart.

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use serde::Serialize;

use crate::growth::{self, Class, GrowthInputs};

/// One point of the break-even surface.
#[derive(Debug, Clone, Serialize)]
pub struct BreakEvenPoint {
    /// Network take on service payments.
    pub take: f64,
    /// Fee per root task, USD.
    pub root_fee_usd: f64,
    /// Sub-agent settlements per root task.
    pub fan_out: f64,
    /// Yearly fall of tariffs.
    pub deflation: f64,
    /// Running costs, USD a month.
    pub running_cost_usd_month: f64,
    /// Unrelated volume a day at launch that covers running costs, USD.
    pub break_even_usd_day: f64,
    /// The same in year 3, when tariffs have fallen and units must grow to
    /// keep the USD volume: volume needed in launch-year units.
    pub break_even_units_year3: f64,
}

/// Mean root task, USD: what one request an app makes spends across its
/// sub-agents. An assumption.
pub const ROOT_TASK_USD: f64 = 0.10;
/// Gas of one settlement, USD.
pub const GAS_USD: f64 = 0.0005;
/// Settlement fee, share of value.
pub const SETTLEMENT_FEE: f64 = 0.001;

/// The network's revenue on one USD of volume: take, settlement fee, the
/// root fee and the settlements' gas spread over the root task.
pub fn revenue_per_usd(take: f64, root_fee: f64, fan_out: f64) -> f64 {
    take + SETTLEMENT_FEE + (root_fee + fan_out * GAS_USD) / ROOT_TASK_USD
}

/// Break-even surface over take, root fee, fan-out, deflation and running
/// costs ($18,000 a month of infrastructure; $100,000 and $200,000 with
/// staff).
pub fn break_even_surface() -> Vec<BreakEvenPoint> {
    let mut out = Vec::new();
    for running in [18_000.0f64, 100_000.0, 200_000.0] {
        for take in [0.01, 0.03, 0.05, 0.08, 0.10] {
            for root_fee in [0.0, 0.001, 0.005, 0.01] {
                for fan_out in [1.0, 5.0, 20.0] {
                    for deflation in [0.0f64, 0.3, 0.8] {
                        let r = revenue_per_usd(take, root_fee, fan_out);
                        let be = running / 30.44 / r;
                        // Tariffs fall, so the same USD needs more units; the
                        // root fee and gas do not fall with the tariff.
                        let tariff = (1.0 - deflation).powi(3);
                        let r3 = take * tariff
                            + SETTLEMENT_FEE * tariff
                            + (root_fee + fan_out * GAS_USD) / ROOT_TASK_USD;
                        out.push(BreakEvenPoint {
                            take,
                            root_fee_usd: root_fee,
                            fan_out,
                            deflation,
                            running_cost_usd_month: running,
                            break_even_usd_day: be,
                            break_even_units_year3: running / 30.44 / r3.max(1e-12),
                        });
                    }
                }
            }
        }
    }
    out
}

/// One workload's price check.
#[derive(Debug, Clone, Serialize)]
pub struct PriceCheck {
    /// Workload.
    pub workload: String,
    /// Unit.
    pub unit: String,
    /// The provider's tariff: cost per unit plus a 15% margin, USD.
    pub tariff_usd: f64,
    /// What a buyer pays through a reseller, USD.
    pub buyer_usd: f64,
    /// The cheapest aggregator or marketplace price, USD.
    pub aggregator_usd: f64,
    /// The direct API or cloud price, USD.
    pub direct_usd: f64,
    /// Below the cheaper of the two.
    pub below_both: bool,
    /// Below the direct price.
    pub below_direct: bool,
    /// Where the reference prices come from.
    pub source: String,
}

/// Seven workloads: the network's cost-plus tariff with the take and a
/// reseller commission against the cheapest aggregator and the direct API.
pub fn price_competitiveness(take: f64, commission: f64) -> Vec<PriceCheck> {
    let gpu = 1.20; // H100 cost an hour, used or idle
    let w = |name: &str, unit: &str, cost: f64, agg: f64, direct: f64, source: &str| {
        let tariff = cost * 1.15;
        let buyer = tariff * (1.0 + take + SETTLEMENT_FEE) * (1.0 + commission) + GAS_USD;
        PriceCheck {
            workload: name.into(),
            unit: unit.into(),
            tariff_usd: tariff,
            buyer_usd: buyer,
            aggregator_usd: agg,
            direct_usd: direct,
            below_both: buyer < agg.min(direct),
            below_direct: buyer < direct,
            source: source.into(),
        }
    };
    vec![
        // Mid-size open model: 12 million tokens a GPU-hour at 60% load.
        w(
            "chat, mid-size open model",
            "1M tokens",
            gpu / (12.0 * 0.6),
            0.12,
            0.23,
            "OpenRouter DeepSeek V4 Flash $0.098/$0.196 blended 3:1; Qwen3.8-Flash-Next $0.15/$0.47",
        ),
        // 8B: 40 million tokens a GPU-hour at 60% load.
        w(
            "chat, small open model",
            "1M tokens",
            gpu / (40.0 * 0.6),
            0.055,
            0.10,
            "OpenRouter gpt-oss-20b $0.03/$0.13 blended 3:1; about $0.10 direct",
        ),
        // Batch extraction on an 8B model at 90% load, against a batch API.
        w(
            "batch extraction",
            "1M tokens",
            gpu / (40.0 * 0.9),
            0.055,
            0.35,
            "GPT-4.1 mini batch $0.20/$0.80 blended; gpt-oss-20b on OpenRouter",
        ),
        // Coding on a 70B-class model against GPT-4.1 mini.
        w(
            "coding, mid-size",
            "1M tokens",
            gpu / (12.0 * 0.6),
            0.70,
            0.70,
            "GPT-4.1 mini $0.40/$1.60 blended 3:1, the same through OpenRouter",
        ),
        // Image generation on a consumer GPU: a 4B image model makes a
        // 1024x1024 image in about a second on an RTX 4090, at 60% load.
        w(
            "image generation, 4B open model on an RTX 4090",
            "image",
            (growth::RTX_COST_USD_DAY.0 + growth::RTX_COST_USD_DAY.1) / 2.0 / 86_400.0 / 0.6,
            0.014,
            0.035,
            "FLUX.2 [klein] 4B $0.014 an image; Qwen image 2.0 $0.035",
        ),
        // GPU rental at 60% utilisation.
        w(
            "GPU rental, H100",
            "GPU-hour",
            gpu / 0.6,
            1.65,
            2.69,
            "Vast.ai $1.47-1.79; RunPod $2.69; Akash $2.72",
        ),
        // Storage: 100 TB at $600 a month, 70% sold.
        w(
            "object storage",
            "TB-month",
            600.0 / 100.0 / 0.7,
            6.0,
            23.0,
            "Backblaze B2 about $6; AWS S3 standard about $23",
        ),
    ]
}

/// One tier's P&L at one utilisation.
#[derive(Debug, Clone, Serialize)]
pub struct UtilisationPnl {
    /// Tier.
    pub tier: String,
    /// Utilisation.
    pub utilisation: f64,
    /// Revenue a month, USD, at the blended rate (half on-demand, 30%
    /// reserved at 0.8x, 20% preemptible at 0.5x), net of the take.
    pub revenue_usd_month: f64,
    /// Cost a month, USD.
    pub cost_usd_month: f64,
    /// Margin over revenue.
    pub margin: f64,
}

/// P&L of each tier at 40%, 60% and 70% utilisation.
pub fn utilisation_pnl(take: f64) -> Vec<UtilisationPnl> {
    let blend = 0.5 + 0.3 * 0.8 + 0.2 * 0.5;
    let tiers: [(&str, f64, f64); 6] = [
        // (tier, list revenue a month at full use, cost a month)
        ("GPU rental, H100 at $2.20/h", 2.20 * 730.0, 1.20 * 730.0),
        (
            "inference host, H100 at $0.12/1M tokens and 12M/h",
            0.12 * 12.0 * 730.0,
            1.20 * 730.0,
        ),
        (
            "edge CPU (Pi 5), 6 slots at the VPS slot price",
            growth::PI_SLOTS * growth::PI_SLOT_REFERENCE_USD_DAY * 30.44,
            (growth::PI_COST_USD_DAY.0 + growth::PI_COST_USD_DAY.1) / 2.0 * 30.44,
        ),
        (
            "edge GPU (Jetson Orin Nano Super), 3 agent slots with a local 8B model",
            growth::JETSON_SLOTS
                * growth::slot_reference(growth::JETSON_MTOK_DAY / growth::JETSON_SLOTS)
                * 30.44,
            (growth::JETSON_COST_USD_DAY.0 + growth::JETSON_COST_USD_DAY.1) / 2.0 * 30.44,
        ),
        (
            "consumer GPU (RTX 4090), small open model batched",
            growth::RTX_MTOK_DAY * growth::SMALL_MODEL_REFERENCE_USD_MTOK * 30.44,
            (growth::RTX_COST_USD_DAY.0 + growth::RTX_COST_USD_DAY.1) / 2.0 * 30.44,
        ),
        (
            "edge AGX (Jetson AGX Orin 64 GB), 32 agent slots",
            growth::AGX_SLOTS
                * growth::slot_reference(growth::AGX_MTOK_DAY / growth::AGX_SLOTS)
                * 30.44,
            (growth::AGX_COST_USD_DAY.0 + growth::AGX_COST_USD_DAY.1) / 2.0 * 30.44,
        ),
    ];
    let mut out = Vec::new();
    for (tier, full, cost) in tiers {
        for u in [0.4, 0.6, 0.7] {
            let rev = full * u * blend * (1.0 - take - SETTLEMENT_FEE);
            out.push(UtilisationPnl {
                tier: tier.into(),
                utilisation: u,
                revenue_usd_month: rev,
                cost_usd_month: cost,
                margin: (rev - cost) / rev.max(1e-12),
            });
        }
    }
    out
}

/// One long run.
#[derive(Debug, Clone, Serialize)]
pub struct DecadeRun {
    /// Yearly tariff fall.
    pub deflation: f64,
    /// Yearly unit growth, as a multiple.
    pub unit_growth: f64,
    /// How fast unit costs fall against tariffs (1: as fast).
    pub cost_decline_ratio: f64,
    /// Outcome.
    pub outcome: String,
    /// Won share at the end.
    pub won_share_end: f64,
    /// Fees over running costs at the end.
    pub running_cost_coverage_end: f64,
    /// Day it first sustained itself.
    pub self_sustaining_day: Option<f64>,
}

/// Thirty-year runs over tariff deflation and unit growth.
pub fn decades(base: &GrowthInputs) -> Vec<DecadeRun> {
    let mut out = Vec::new();
    for ratio in [1.0, 0.75] {
        for deflation in [0.3, 0.5, 0.8] {
            for unit_growth in [1.5, 2.0, 3.0, 4.0] {
                let mut i = base.clone();
                i.days = (30.0 * 365.25) as u32;
                // Unit costs fall as fast as tariffs, or (the stress) three
                // quarters as fast: hardware and serving improve, but not as
                // fast as prices are cut.
                for c in &mut i.classes {
                    c.reference_decline = deflation;
                    c.cost_decline = deflation * ratio;
                }
                // Potential demand in USD grows with units and falls with price.
                i.potential_growth = unit_growth * (1.0 - deflation);
                let r = growth::run(&i);
                let last = r.years.last().cloned().unwrap_or_default();
                out.push(DecadeRun {
                    deflation,
                    unit_growth,
                    cost_decline_ratio: ratio,
                    outcome: r.outcome,
                    won_share_end: last.won_share,
                    running_cost_coverage_end: last.running_cost_coverage,
                    self_sustaining_day: r.self_sustaining_day,
                });
            }
        }
    }
    out
}

/// One input the global sensitivity analysis varies.
#[derive(Debug, Clone, Serialize)]
pub struct Factor {
    /// Name.
    pub name: String,
    /// Range.
    pub low: f64,
    /// Range.
    pub high: f64,
    /// First-order Sobol index of the growth outcome.
    pub first_order: f64,
    /// Total-order Sobol index.
    pub total_order: f64,
}

/// The global sensitivity analysis's result.
#[derive(Debug, Clone, Serialize)]
pub struct Gsa {
    /// The conclusion tested: the base run's outcome.
    pub conclusion: String,
    /// Share of sampled points whose outcome matches it.
    pub holds_share: f64,
    /// Samples per matrix.
    pub n: usize,
    /// Factors.
    pub factors: Vec<Factor>,
}

fn apply(i: &mut GrowthInputs, name: &str, v: f64) {
    match name {
        "potential_usd_day" => i.potential_usd_day = v,
        "potential_growth" => i.potential_growth = v,
        "tariff" => i.tariff = v,
        "owner_swarm_usd_day" => i.owner_swarm_usd_day = v,
        "running_cost_usd_month" => i.running_cost_usd_month = v,
        "take" => i.classes.iter_mut().for_each(|c| c.take = v),
        "reference_decline" => i.classes.iter_mut().for_each(|c| {
            c.cost_decline = v * c.cost_decline / c.reference_decline.max(1e-9);
            c.reference_decline = v;
        }),
        "cost_decline_ratio" => i
            .classes
            .iter_mut()
            .for_each(|c| c.cost_decline = c.reference_decline * v),
        "price_elasticity_scale" => i.channels.iter_mut().for_each(|c| c.price_elasticity *= v),
        "gpu_cost_scale" => i
            .classes
            .iter_mut()
            .filter(|c| matches!(c.class, Class::Inference | Class::Gpu))
            .for_each(|c| c.cost_usd_day *= v),
        "hardware_charge" => {
            i.sunk_hardware = true;
            i.hardware_charge = v;
        }
        "root_task_fee_usd" => i.root_task_fee_usd = v,
        "commission" => i
            .channels
            .iter_mut()
            .filter(|c| c.commission > 0.0)
            .for_each(|c| c.commission = v),
        _ => {}
    }
}

/// Saltelli first- and total-order indices of the growth outcome (1 grows,
/// 0 not) over the factors' ranges, with `n` samples per matrix, and the
/// share of the space where the base run's conclusion holds.
pub fn sobol(base: &GrowthInputs, n: usize, seed: u64) -> Gsa {
    sobol_fixed(base, n, seed, &[])
}

/// [`sobol`] with the factors named in `fixed` held at `base`'s values.
pub fn sobol_fixed(base: &GrowthInputs, n: usize, seed: u64, fixed: &[&str]) -> Gsa {
    let ranges: Vec<(&str, f64, f64)> = vec![
        ("potential_usd_day", 2_000.0, 200_000.0),
        ("potential_growth", 1.0, 3.0),
        ("tariff", 0.6, 1.4),
        ("owner_swarm_usd_day", 0.0, 20_000.0),
        ("running_cost_usd_month", 18_000.0, 300_000.0),
        ("take", 0.0, 0.10),
        ("reference_decline", 0.0, 0.6),
        ("cost_decline_ratio", 0.5, 1.0),
        ("price_elasticity_scale", 0.5, 2.0),
        ("gpu_cost_scale", 0.7, 1.5),
        ("commission", 0.0, 0.20),
        ("hardware_charge", 0.0, 1.0),
        ("root_task_fee_usd", 0.0, 0.002),
    ];
    let ranges: Vec<(&str, f64, f64)> = ranges
        .into_iter()
        .filter(|(name, _, _)| !fixed.contains(name))
        .collect();
    let k = ranges.len();
    let mut rng = StdRng::seed_from_u64(seed);
    let draw = |rng: &mut StdRng| -> Vec<f64> {
        ranges
            .iter()
            .map(|(_, lo, hi)| {
                let u: f64 = rng.gen_range(0.0..1.0);
                // Demand and costs spread over orders of magnitude: sample
                // them on a log scale.
                if *lo > 0.0 && hi / lo > 20.0 {
                    lo * (hi / lo).powf(u)
                } else {
                    lo + (hi - lo) * u
                }
            })
            .collect()
    };
    let f = |x: &[f64]| -> f64 {
        let mut i = base.clone();
        for ((name, _, _), v) in ranges.iter().zip(x) {
            apply(&mut i, name, *v);
        }
        if growth::run(&i).outcome == "growth" {
            1.0
        } else {
            0.0
        }
    };
    let conclusion = growth::run(base).outcome;
    let a: Vec<Vec<f64>> = (0..n).map(|_| draw(&mut rng)).collect();
    let b: Vec<Vec<f64>> = (0..n).map(|_| draw(&mut rng)).collect();
    let fa: Vec<f64> = a.iter().map(|x| f(x)).collect();
    let fb: Vec<f64> = b.iter().map(|x| f(x)).collect();
    let all: Vec<f64> = fa.iter().chain(&fb).copied().collect();
    let mean = all.iter().sum::<f64>() / all.len() as f64;
    let var = all.iter().map(|y| (y - mean).powi(2)).sum::<f64>() / all.len() as f64;
    let mut factors = Vec::new();
    for (j, (name, lo, hi)) in ranges.iter().enumerate() {
        let fab: Vec<f64> = a
            .iter()
            .zip(&b)
            .map(|(x, y)| {
                let mut z = x.clone();
                z[j] = y[j];
                f(&z)
            })
            .collect();
        let s1 = (0..n).map(|r| fb[r] * (fab[r] - fa[r])).sum::<f64>() / n as f64;
        let st = (0..n).map(|r| (fa[r] - fab[r]).powi(2)).sum::<f64>() / (2 * n) as f64;
        factors.push(Factor {
            name: name.to_string(),
            low: *lo,
            high: *hi,
            first_order: if var > 0.0 { s1 / var } else { 0.0 },
            total_order: if var > 0.0 { st / var } else { 0.0 },
        });
    }
    let target = if conclusion == "growth" { 1.0 } else { 0.0 };
    let holds = all.iter().filter(|y| (**y - target).abs() < 0.5).count() as f64 / all.len() as f64;
    let _ = k;
    Gsa {
        conclusion,
        holds_share: holds,
        n,
        factors,
    }
}

/// The reseller channel carrying a share of GMV, then leaving at year 3:
/// months of running costs the fees earned before still hold after a 50%
/// demand shock.
#[derive(Debug, Clone, Serialize)]
pub struct Concentration {
    /// The reseller channel's share of GMV.
    pub reseller_share: f64,
    /// Outcome after the reseller channel leaves.
    pub outcome: String,
    /// Fees over running costs the year before it leaves and the last year.
    pub coverage_before_after: (f64, f64),
    /// Months of running costs the fees above running costs accumulated
    /// before the exit hold, after a 50% shock to the rest.
    pub reserve_months_after_shock: f64,
}

/// Reseller concentration: the reseller channel at 50%, 80% and 95% of
/// GMV, leaving at year 3, with a 50% shock to the rest of demand. The
/// reserve is the fees above running costs accumulated until the exit (none
/// is spent first).
pub fn concentration(base: &GrowthInputs) -> Vec<Concentration> {
    let mut out = Vec::new();
    for reseller_share in [0.5, 0.8, 0.95] {
        let mut before = base.clone();
        before.days = (3.0 * 365.25) as u32;
        let rest: f64 = before
            .channels
            .iter()
            .filter(|c| c.name != "resellers")
            .map(|c| c.share)
            .sum();
        for c in &mut before.channels {
            c.share = if c.name == "resellers" {
                reseller_share
            } else {
                c.share / rest.max(1e-12) * (1.0 - reseller_share)
            };
        }
        let r0 = growth::run(&before);
        let surplus: f64 = r0
            .years
            .iter()
            .map(|y| (y.fees_usd_month - before.running_cost_usd_month).max(0.0) * 12.0)
            .sum();
        let mut after = before.clone();
        after.days = base.days;
        for c in &mut after.channels {
            if c.name == "resellers" {
                c.share = 0.0;
            } else {
                c.share *= 0.5;
            }
        }
        let r1 = growth::run(&after);
        let shortfall = r1.years.last().map_or(0.0, |y| {
            (after.running_cost_usd_month - y.fees_usd_month).max(0.0)
        });
        out.push(Concentration {
            reseller_share,
            outcome: r1.outcome,
            coverage_before_after: (
                r0.years.last().map_or(0.0, |y| y.running_cost_coverage),
                r1.years.last().map_or(0.0, |y| y.running_cost_coverage),
            ),
            reserve_months_after_shock: if shortfall > 0.0 {
                surplus / shortfall
            } else {
                f64::INFINITY
            },
        });
    }
    out
}

/// One way to make a Pi operator profitable.
#[derive(Debug, Clone, Serialize)]
pub struct PiLever {
    /// The lever.
    pub lever: String,
    /// The Pi's cost a day, USD (middle of its range).
    pub cost_usd_day: f64,
    /// What one agent slot earns a day, USD.
    pub slot_usd_day: f64,
    /// Slots a Pi must fill each day to cover its cost.
    pub break_even_slots: f64,
    /// Share of Pi operators who cover cost with five of six slots filled,
    /// across the cost range.
    pub profitable_share_at_5_slots: f64,
}

/// Levers that move a Pi operator from loss to profit, alone and together:
/// hardware already owned, connectivity already paid (a home line), a
/// premium for residency and privacy over a datacentre VPS, and a smaller
/// network take on the edge tier.
pub fn pi_levers() -> Vec<PiLever> {
    let hw = growth::PI_HARDWARE_USD_DAY;
    let (lo, hi) = growth::PI_COST_USD_DAY;
    let power = (0.018, 0.036);
    let slot = growth::PI_SLOT_REFERENCE_USD_DAY;
    let case = |lever: &str, range: (f64, f64), price: f64, take: f64| {
        let earn = price * (1.0 - take - SETTLEMENT_FEE);
        let mid = (range.0 + range.1) / 2.0;
        let rev5 = 5.0 * earn;
        PiLever {
            lever: lever.into(),
            cost_usd_day: mid,
            slot_usd_day: earn,
            break_even_slots: mid / earn.max(1e-12),
            profitable_share_at_5_slots: ((rev5 - range.0) / (range.1 - range.0).max(1e-12))
                .clamp(0.0, 1.0),
        }
    };
    vec![
        case(
            "new Pi, paid connectivity, VPS price, 10% take",
            (lo, hi),
            slot,
            0.10,
        ),
        case("hardware already owned", (lo - hw, hi - hw), slot, 0.10),
        case("home line already paid", (lo, hw + power.1), slot, 0.10),
        case("owned and home line", (power.0, power.1), slot, 0.10),
        case("2x residency premium", (lo, hi), 2.0 * slot, 0.10),
        case("2% edge take", (lo, hi), slot, 0.02),
        case(
            "owned, home line, 1.5x premium, 2% take",
            (power.0, power.1),
            1.5 * slot,
            0.02,
        ),
    ]
}

/// What a root-task fee adds to a token-priced workload.
#[derive(Debug, Clone, Serialize)]
pub struct RootFeeCheck {
    /// Workload.
    pub workload: String,
    /// Aggregator price, USD per million tokens.
    pub aggregator_usd_mtok: f64,
    /// Fee per root task, USD.
    pub root_task_fee_usd: f64,
    /// Million tokens one root task spends.
    pub mtok_per_root_task: f64,
    /// What the fee adds per million tokens, USD.
    pub added_usd_mtok: f64,
    /// That, as a share of the aggregator price today.
    pub added_share_now: f64,
    /// The same after five years of the workload's price falling.
    pub added_share_year5: f64,
}

/// A root-task fee against cheap and mid-size models, now and after five
/// years of price falls.
pub fn root_fee_checks(fees: &[f64]) -> Vec<RootFeeCheck> {
    let rows: [(&str, f64, f64, f64); 4] = [
        // (workload, $/Mtok, Mtok per root task, yearly price fall)
        ("mid-size model, agent task of 20k tokens", 0.12, 0.02, 0.40),
        ("small model, agent task of 20k tokens", 0.055, 0.02, 0.30),
        ("small model, chat turn of 2k tokens", 0.055, 0.002, 0.30),
        (
            "cheapest listed model, chat turn of 2k tokens",
            0.015,
            0.002,
            0.30,
        ),
    ];
    let mut out = Vec::new();
    for &fee in fees {
        for (w, price, mtok, fall) in rows {
            let added = fee / mtok;
            out.push(RootFeeCheck {
                workload: w.into(),
                aggregator_usd_mtok: price,
                root_task_fee_usd: fee,
                mtok_per_root_task: mtok,
                added_usd_mtok: added,
                added_share_now: added / price,
                added_share_year5: added / (price * (1.0f64 - fall).powi(5)),
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn break_even_matches_the_closed_form() {
        // $18,000 a month at a 5% take and the settlement fee: about
        // $11,600 a day.
        let be = 18_000.0 / 30.44 / revenue_per_usd(0.05, 0.0, 0.0);
        assert!((be - 11_594.0).abs() < 10.0, "{be}");
    }

    #[test]
    fn seven_workloads_are_priced() {
        assert_eq!(price_competitiveness(0.10, 0.10).len(), 7);
    }
}
