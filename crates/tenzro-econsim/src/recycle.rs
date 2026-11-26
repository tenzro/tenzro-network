//! Pool release bound to the fee burn, and validator tiers, replayed on the
//! market-stress traces.
//!
//! Every setting here is a parameterised mode of the usage replay
//! ([`crate::usage::replay`]); this module lists the settings, runs them over
//! the traces, and reads the operator income of the device classes off the
//! replay's own book. Nothing here generates a population, a market or a
//! shock: the traces are exports of market-stress runs.
//!
//! Price: a setting is run with the TNZO price left to the pool's depth, and
//! with the price held at constants. Release under the cap is sized in USD at
//! the tick's rate, so operator income in USD does not depend on the price
//! unless the yearly schedule or the pool's yearly limit binds in tokens.

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde_json::{Value, json};

use crate::device_classes::units_per_day;
use crate::earnings::LIST_RATE_USD_GPU_HOUR;
use crate::growth::{
    AGX_COST_USD_DAY, AGX_MTOK_DAY, JETSON_COST_USD_DAY, JETSON_MTOK_DAY, PI_COST_USD_DAY,
    RTX_COST_USD_DAY, RTX_MTOK_DAY, SMALL_MODEL_REFERENCE_USD_MTOK,
};
use crate::usage::{Basis, Outcome, PricePath, Recycle, Rules, Tiers, Trace, replay};

pub const SHARES: [f64; 3] = [0.001, 0.01, 0.1];
/// TNZO prices held constant, USD.
pub const PRICES: [f64; 3] = [0.03, 0.30, 3.00];
/// Regions validators are placed in: the market's three and one more.
pub const VALIDATOR_REGIONS: [&str; 4] = ["region-a", "region-b", "region-c", "region-v"];

/// One setting of the sweep.
#[derive(Clone)]
pub struct Cfg {
    pub name: String,
    pub group: &'static str,
    pub leg: u64,
    pub avail: f64,
    pub recycle: Option<Recycle>,
    pub tiers: Option<Tiers>,
    pub blackout: Option<(u64, u64)>,
    pub pool_tnzo: Option<f64>,
    /// Device classes paid by tier weight {1,2,4} for the provider release.
    pub class_tiers: bool,
    /// Run at the constant prices as well as the pool's.
    pub all_prices: bool,
    /// A price path from outside the pool for the run that is not at a constant price.
    pub path: Option<PricePath>,
    pub shares: Vec<f64>,
}

fn cfg(name: &str, group: &'static str, leg: u64) -> Cfg {
    Cfg {
        name: name.into(),
        group,
        leg,
        avail: 0.0,
        recycle: None,
        tiers: None,
        blackout: None,
        pool_tnzo: None,
        class_tiers: false,
        all_prices: true,
        path: None,
        shares: SHARES.to_vec(),
    }
}

fn tiers(name: &str) -> Tiers {
    // Slots in turn: seven at genesis, then standby; the same pattern repeats.
    let pattern = vec![0, 0, 0, 1, 1, 2, 2];
    match name {
        "linear" => Tiers {
            weights: [1.0, 2.0, 4.0],
            cost_mult: [0.5, 1.0, 2.0],
            pattern,
            share_cap: 1.0 / 3.0,
        },
        "sublinear" => Tiers {
            weights: [1.0, 2.0, 4.0],
            cost_mult: [0.7, 1.0, 1.4],
            pattern,
            share_cap: 1.0 / 3.0,
        },
        "stake" => Tiers {
            weights: [1.0, 3.0, 10.0],
            cost_mult: [0.7, 1.0, 1.4],
            pattern,
            share_cap: 1.0,
        },
        _ => Tiers {
            weights: [1.0, 1.0, 1.0],
            cost_mult: [1.0, 1.0, 1.0],
            pattern: vec![0],
            share_cap: 1.0,
        },
    }
}

/// Every setting the sweep runs.
pub fn configs() -> Vec<Cfg> {
    let mut v = Vec::new();
    // A: the current rules.
    for leg in [0, 100] {
        v.push(cfg(&format!("A/leg{leg}"), "A", leg));
        let mut c = cfg(&format!("A/leg{leg}/avail1"), "A", leg);
        c.avail = 1.0;
        v.push(c);
    }
    // B: release at most r times the burn, per job (each tick) and USD-sized.
    for leg in [0, 100] {
        for r in [0.25, 0.5, 0.75, 0.9, 1.0] {
            let mut c = cfg(&format!("B/r{r}/pertick/leg{leg}"), "B", leg);
            c.recycle = Some(Recycle::new(r));
            v.push(c);
        }
    }
    let leg = 100;
    // Pooled period cap against the per-job cap.
    for r in [0.25, 0.5, 1.0] {
        for (nm, basis) in [
            ("win7", Basis::Window(7)),
            ("win30", Basis::Window(30)),
            ("helium", Basis::Helium),
        ] {
            let mut rc = Recycle::new(r);
            rc.basis = basis;
            let mut c = cfg(&format!("B/r{r}/{nm}/leg{leg}"), "B", leg);
            c.recycle = Some(rc);
            v.push(c);
        }
    }
    // Cap held as a TNZO count against the USD value.
    for r in [0.5, 1.0] {
        let mut rc = Recycle::new(r);
        rc.usd_cap = false;
        rc.basis = Basis::Helium;
        let mut c = cfg(&format!("B/r{r}/helium-tnzo/leg{leg}"), "B", leg);
        c.recycle = Some(rc);
        v.push(c);
    }
    // Yearly limit as a share of the pool.
    for f in [0.01, 0.02, 0.05, 0.10] {
        let mut rc = Recycle::new(1.0);
        rc.yearly_limit_frac = Some(f);
        let mut c = cfg(&format!("B/r1.0/ylimit{f}/leg{leg}"), "B", leg);
        c.recycle = Some(rc);
        v.push(c);
    }
    // The pool low: a small pool, with and without the switch to fees.
    for (nm, fd) in [("pool1pct", None), ("pool1pct-feedirect", Some(0.10))] {
        let mut rc = Recycle::new(1.0);
        rc.fee_direct_below = fd;
        let mut c = cfg(&format!("B/r1.0/{nm}/leg{leg}"), "B", leg);
        c.recycle = Some(rc);
        c.pool_tnzo = Some(4_000_000.0);
        v.push(c);
    }
    // The pool low at higher volume: a 400k pool, with the yearly limit and the switch to fees.
    for (nm, yl, fd) in [
        ("pool0.1pct", None, None),
        ("pool0.1pct-feedirect", None, Some(0.10)),
        ("pool0.1pct-ylimit5pct-feedirect", Some(0.05), Some(0.10)),
    ] {
        let mut rc = Recycle::new(1.0);
        rc.yearly_limit_frac = yl;
        rc.fee_direct_below = fd;
        let mut c = cfg(&format!("POOL/r1.0/{nm}/leg{leg}"), "POOL", leg);
        c.recycle = Some(rc);
        c.pool_tnzo = Some(400_000.0);
        c.shares = vec![0.01, 0.1];
        v.push(c);
    }
    // The pool low with the switch to fees at 2%, and the ratio stepped down as the pool falls.
    for (nm, steps, fd) in [
        ("pool0.1pct-feedirect2pct", false, Some(0.02)),
        ("pool0.1pct-steps", true, None),
        ("pool0.1pct-steps-feedirect", true, Some(0.10)),
        ("pool0.1pct-steps-feedirect2pct", true, Some(0.02)),
    ] {
        let mut rc = Recycle::new(1.0);
        rc.fee_direct_below = fd;
        if steps {
            rc.ratio_steps = vec![(0.5, 0.7), (0.25, 0.5), (0.10, 0.25)];
        }
        let mut c = cfg(&format!("POOL/r1.0/{nm}/leg{leg}"), "POOL", leg);
        c.recycle = Some(rc);
        c.pool_tnzo = Some(400_000.0);
        c.shares = vec![0.01, 0.1];
        v.push(c);
    }
    // Price paths from outside the pool: a fall of a half and of nine tenths inside a week,
    // a doubling, and a random walk at 100% yearly volatility; the cap sized in USD and as
    // a TNZO count, against the current rules.
    for (pn, path) in price_paths() {
        let mut settings = vec![("A".to_string(), None)];
        for r in [0.5, 0.7, 0.9, 1.0] {
            settings.push((format!("B-r{r}-usd"), Some(Recycle::new(r))));
        }
        for r in [0.5, 1.0] {
            let mut rc = Recycle::new(r);
            rc.usd_cap = false;
            settings.push((format!("B-r{r}-tnzo"), Some(rc)));
        }
        for (sn, rc) in settings {
            let mut c = cfg(&format!("PRICE/{pn}/{sn}/leg{leg}"), "PRICE", leg);
            c.recycle = rc;
            c.path = Some(path);
            c.all_prices = false;
            c.shares = vec![0.01, 0.1];
            v.push(c);
        }
    }
    // Matched start on paid jobs only, falling to the ratio.
    for (nm, br, days, budget) in [
        ("boot2x12m", 2.0, 365.0, 0.02),
        ("boot3x24m", 3.0, 730.0, 0.05),
    ] {
        let mut rc = Recycle::new(0.5);
        rc.boot_ratio = br;
        rc.boot_days = days;
        rc.boot_budget_frac = budget;
        let mut c = cfg(&format!("B/r0.5/{nm}/leg{leg}"), "B", leg);
        c.recycle = Some(rc);
        v.push(c);
    }
    // Bootstrap with no paid usage at the start: floor and accrual.
    for days in [30u64, 90, 180] {
        for (fl, fname) in [(0.0, "floor0"), (200.0, "floor200"), (2000.0, "floor2000")] {
            let r = 1.0;
            let mut rc = Recycle::new(r);
            rc.floor_tnzo_day = fl;
            rc.accrual_max_tnzo = 0.0;
            let mut c = cfg(&format!("BOOT/{days}d/r{r}/{fname}"), "BOOT", leg);
            c.recycle = Some(rc);
            c.blackout = Some((0, days));
            c.shares = vec![0.01, 0.1];
            v.push(c);
        }
        let mut c = cfg(&format!("BOOT/{days}d/A"), "BOOT", leg);
        c.blackout = Some((0, days));
        c.shares = vec![0.01, 0.1];
        v.push(c);
    }
    // C: validator tiers, with the set growing from 7 up to 21.
    for tn in ["flat", "linear", "sublinear", "stake"] {
        for r in [None, Some(0.5)] {
            let nm = match r {
                None => format!("C/{tn}/A/leg{leg}"),
                Some(x) => format!("C/{tn}/B-r{x}/leg{leg}"),
            };
            let mut c = cfg(&nm, "C", leg);
            c.tiers = Some(tiers(tn));
            c.class_tiers = tn != "flat";
            c.recycle = r.map(Recycle::new);
            v.push(c);
        }
    }
    v
}

/// The price paths of the PRICE group, from 0.30 USD.
pub fn price_paths() -> [(&'static str, PricePath); 4] {
    let shock = |factor| PricePath::Shock {
        from: 0.30,
        factor,
        at_day: 30.0,
        over_days: 7.0,
    };
    [
        ("fall50", shock(0.5)),
        ("fall90", shock(0.1)),
        ("rise100", shock(2.0)),
        (
            "walk100",
            PricePath::Walk {
                from: 0.30,
                annual_vol: 1.0,
                seed: 1,
            },
        ),
    ]
}

fn rules_for(c: &Cfg, share: f64, price: Option<PricePath>) -> Rules {
    let mut r = Rules {
        availability_tnzo_hour: c.avail,
        market_share: share,
        pool_depth_usd: Some(1_000_000.0),
        rails: Some(BTreeMap::from([
            ("USDA".to_string(), 0.6),
            ("USDB".to_string(), 0.4),
        ])),
        validator_regions: Some(VALIDATOR_REGIONS.iter().map(|s| s.to_string()).collect()),
        recycle: c.recycle.clone(),
        tiers: c.tiers.clone(),
        price_path: price,
        blackout: c.blackout,
        pool_tnzo: c.pool_tnzo,
        ..Rules::default()
    };
    r.overrides.insert(
        tenzro_vm::native::economy::TREASURY_LEG_INFERENCE_PARAM.into(),
        c.leg,
    );
    r
}

/// The six device classes: units a day (in the trace's accelerator-hours),
/// cost a day at the low and high end (hardware, energy, connectivity), and
/// the tier a capability class puts it in.
pub(crate) fn classes() -> Vec<(&'static str, f64, (f64, f64), usize, f64)> {
    let small = |mtok: f64| mtok * SMALL_MODEL_REFERENCE_USD_MTOK / LIST_RATE_USD_GPU_HOUR;
    // The last number is the class's share of the paid units (the growth model's demand mix).
    vec![
        ("pi5", units_per_day(20.0), PI_COST_USD_DAY, 0, 0.03),
        (
            "orin_nano",
            small(JETSON_MTOK_DAY),
            JETSON_COST_USD_DAY,
            0,
            0.015,
        ),
        ("agx", small(AGX_MTOK_DAY), AGX_COST_USD_DAY, 1, 0.005),
        ("rtx4090", small(RTX_MTOK_DAY), RTX_COST_USD_DAY, 1, 0.10),
        // An H100 owned by the operator: $1.00-1.50 an hour.
        ("datacenter", 24.0, (24.0, 36.0), 2, 0.60),
        // The same card rented in at the reference $2.20 an hour.
        ("neocloud", 24.0, (52.8, 52.8), 2, 0.20),
    ]
}

/// Net income of a device a day from the replay's book: service payments
/// and provider release for the units it delivers, less its cost. Returns
/// (name, net at the middle cost, release part), USD a day.
fn class_income(o: &Outcome, tier_weights: Option<[f64; 3]>) -> Vec<(&'static str, f64, f64, f64)> {
    let tb: Vec<_> = o.tick_book.iter().skip(30).collect();
    let units: f64 = tb.iter().map(|t| t.units).sum();
    let svc: f64 = tb.iter().map(|t| t.paid_usd * t.provider_share).sum();
    let rel: f64 = tb.iter().map(|t| t.provider_release_usd).sum();
    let cl = classes();
    let wbar = match tier_weights {
        Some(w) => {
            let tot: f64 = cl.iter().map(|c| c.4).sum();
            cl.iter().map(|c| c.4 * w[c.3]).sum::<f64>() / tot
        }
        None => 1.0,
    };
    let (svc_u, rel_u) = if units > 0.0 {
        (svc / units, rel / units)
    } else {
        (0.0, 0.0)
    };
    cl.iter()
        .map(|c| {
            let w = tier_weights.map_or(1.0, |w| w[c.3]) / wbar;
            let util = o.utilisation_mean;
            let earn = util * c.1 * (svc_u + rel_u * w);
            let cost = (c.2.0 + c.2.1) / 2.0;
            let cost_hi = c.2.1;
            (c.0, earn - cost, util * c.1 * rel_u * w, earn - cost_hi)
        })
        .collect()
}

fn cv(v: &[f64]) -> f64 {
    let n = v.len() as f64;
    if n == 0.0 {
        return 0.0;
    }
    let m = v.iter().sum::<f64>() / n;
    if m <= 0.0 {
        return 0.0;
    }
    (v.iter().map(|x| (x - m).powi(2)).sum::<f64>() / n).sqrt() / m
}

fn record(
    base: &Value,
    c: &Cfg,
    share: f64,
    price: Option<f64>,
    o: &Outcome,
    ticks_per_year: f64,
) -> Value {
    let mut r = base.clone();
    let m = r.as_object_mut().expect("object");
    m.insert("cfg".into(), json!(c.name));
    m.insert("group".into(), json!(c.group));
    m.insert("leg".into(), json!(c.leg));
    m.insert("share".into(), json!(share));
    m.insert("price".into(), json!(price));
    m.insert(
        "floor_ok".into(),
        json!(o.validators_min >= 7 && o.validator_regions_min >= 4),
    );
    m.insert("validators_min".into(), json!(o.validators_min));
    m.insert("validators_mean".into(), json!(o.validators_mean));
    m.insert("validators_end".into(), json!(o.validators_end));
    m.insert("regions_min".into(), json!(o.validator_regions_min));
    m.insert("nakamoto_min".into(), json!(o.nakamoto_min));
    m.insert("max_weight_share".into(), json!(o.max_weight_share));
    m.insert("income_cv".into(), json!(o.income_cv));
    m.insert("val_income_day".into(), json!(o.validator_income_day_usd));
    m.insert(
        "income_ratio_min".into(),
        json!(o.validator_income_ratio_min),
    );
    m.insert("cover_mean".into(), json!(o.cover_ratio_mean));
    m.insert("paid_day".into(), json!(o.paid_usd / o.ticks.max(1) as f64));
    m.insert("released".into(), json!(o.released_tnzo));
    m.insert("burned".into(), json!(o.burned_tnzo_eq));
    m.insert("release_over_burn".into(), json!(o.release_over_burn));
    m.insert("floor_rel".into(), json!(o.floor_released_tnzo));
    m.insert("boot_rel".into(), json!(o.boot_released_tnzo));
    m.insert("accrual_rel".into(), json!(o.accrual_released_tnzo));
    m.insert("direct_usd".into(), json!(o.direct_paid_usd));
    m.insert("circ_peak".into(), json!(o.circulating_peak_tnzo));
    m.insert("circ_change".into(), json!(o.circulating_change_tnzo));
    m.insert("supply_change".into(), json!(o.supply_change_tnzo));
    m.insert("pool_start".into(), json!(o.pool_start_tnzo));
    m.insert("pool_end".into(), json!(o.pool_end_tnzo));
    // Years until the pool is empty at the last full year's draw.
    let ye = &o.pool_year_end;
    let draw = if ye.len() <= 1 {
        (o.pool_start_tnzo - o.pool_end_tnzo) / (o.ticks.max(1) as f64 / ticks_per_year)
    } else if ye.len() >= 3 {
        ye[ye.len() - 3] - ye[ye.len() - 2]
    } else if ye.len() == 2 {
        o.pool_start_tnzo - ye[0]
    } else {
        0.0
    };
    let years = if draw > 1e-9 {
        o.pool_end_tnzo / draw
            + if ye.len() <= 1 {
                0.0
            } else {
                o.ticks as f64 / ticks_per_year
            }
    } else {
        f64::INFINITY
    };
    m.insert(
        "pool_years".into(),
        if years.is_finite() {
            json!(years)
        } else {
            Value::Null
        },
    );
    m.insert("holds".into(), json!(o.holds()));
    m.insert("finality".into(), json!(o.pass_finality));
    m.insert("charter".into(), json!(o.pass_charter));
    m.insert("charter_violations".into(), json!(o.charter_violations));
    m.insert("unmet".into(), json!(o.unmet_share));
    let rel_day: Vec<f64> = o
        .tick_book
        .iter()
        .skip(30)
        .map(|t| t.provider_release_usd)
        .collect();
    m.insert("provider_release_cv".into(), json!(cv(&rel_day)));
    m.insert(
        "provider_release_day".into(),
        json!(rel_day.iter().sum::<f64>() / rel_day.len().max(1) as f64),
    );
    let tw = c
        .tiers
        .as_ref()
        .filter(|_| c.class_tiers)
        .map(|t| t.weights);
    let mut net = serde_json::Map::new();
    for (name, n, rel, hi) in class_income(o, tw) {
        net.insert(name.into(), json!([n, rel, hi]));
    }
    m.insert("classes".into(), Value::Object(net));
    r
}

/// Replays every trace under `dirs` under every setting; one JSON record per replay.
pub fn sweep(
    dirs: &[PathBuf],
    threads: usize,
    only: Option<&str>,
    mut sink: impl FnMut(Value),
    mut bad: impl FnMut(String),
) {
    let files = crate::usage_lw::find(dirs);
    let cfgs: Vec<Cfg> = configs()
        .into_iter()
        .filter(|c| only.is_none_or(|g| c.group == g))
        .collect();
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
            let tpy = 365.0 * 86_400.0 / trace.manifest.tick_seconds.max(1) as f64;
            let mut out = Vec::new();
            for c in &cfgs {
                for &share in &c.shares {
                    let mut prices: Vec<Option<f64>> = vec![None];
                    if c.all_prices {
                        prices.extend(PRICES.iter().map(|p| Some(*p)));
                    }
                    for price in prices {
                        let o = replay(
                            &trace,
                            &rules_for(c, share, price.map(PricePath::Held).or(c.path)),
                        );
                        out.push(record(&base, c, share, price, &o, tpy));
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

/// Governed values the wash analysis reads.
pub fn governed() -> BTreeMap<&'static str, f64> {
    use tenzro_vm::native::{economy as ve, rewards as vr};
    let g = tenzro_vm::governance::genesis_param;
    BTreeMap::from([
        ("settlement_fee_bps", g(ve::SETTLEMENT_FEE_PARAM) as f64),
        ("fee_burn_bps", g(ve::SETTLEMENT_FEE_BURN_PARAM) as f64),
        (
            "insurance_share_bps",
            g(tenzro_vm::native::insurance::POOL_FEE_SHARE_PARAM) as f64,
        ),
        (
            "treasury_leg_bps",
            g(ve::TREASURY_LEG_INFERENCE_PARAM) as f64,
        ),
        (
            "provider_ceiling_bps",
            g(vr::PROVIDER_REWARD_COST_PARAM) as f64,
        ),
        (
            "activity_ceiling_bps",
            g(ve::ACTIVITY_REWARD_FEE_PARAM) as f64,
        ),
        ("revenue_peg_bps", g(vr::MINT_REVENUE_PEG_PARAM) as f64),
        (
            "cover_share_bps",
            g(tenzro_vm::native::validator_cover::FEE_SHARE_PARAM) as f64,
        ),
        (
            "validator_burn_share_bps",
            g(vr::VALIDATOR_BURN_SHARE_PARAM) as f64,
        ),
        (
            "validator_cost_usd_month",
            g(vr::VALIDATOR_BASE_COST_PARAM) as f64,
        ),
        ("schedule_base_tnzo_year", g(vr::MINT_BASE_PARAM) as f64),
    ])
}

/// Who the cap sees paying in a wash.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum WashPayer {
    /// The operator's own key, device or funding source: its burn is not counted.
    Own,
    /// A second wallet no check ties to the operator. Its volume is `volume_share` of all
    /// paid volume, and one operator's release is held to `share_cap` of the total.
    Hidden {
        volume_share: f64,
        share_cap: Option<f64>,
    },
}

/// A wash attack: an operator buys its own service at the USD price, to burn
/// fees and unlock release. Returns, per USD of self-paid volume, the cost
/// (fee and leg), the release the cap allows in USD, what comes back as a
/// share `s` of the validator cover, and the net.
pub fn wash(ratio: Option<f64>, s: f64, unit_price_slippage: f64, payer: WashPayer) -> Value {
    let g = governed();
    let fee = g["settlement_fee_bps"] / 1e4;
    let burn = g["fee_burn_bps"] / 1e4;
    let ins = g["insurance_share_bps"] / 1e4;
    let leg = g["treasury_leg_bps"] / 1e4;
    let ceil = (g["provider_ceiling_bps"] + g["activity_ceiling_bps"]) / 1e4;
    let peg = (g["revenue_peg_bps"] / 1e4).min(1.0);
    let cover = g["cover_share_bps"] / 1e4;
    let cost = fee + leg;
    let burned = fee * burn;
    let pegged = fee * ceil * peg;
    let capped = ratio.map_or(pegged, |r| pegged.min(r * burned));
    // What of the release the attacker's own operator may collect.
    let collected = match payer {
        WashPayer::Own => 0.0,
        WashPayer::Hidden {
            volume_share,
            share_cap,
        } => share_cap.map_or(1.0, |cap| (cap / volume_share.max(cap)).min(1.0)),
    };
    let kept = fee - burned - (fee - burned) * ins + leg;
    let back = s * kept * cover;
    let release = capped * collected * (1.0 - unit_price_slippage);
    json!({
        "ratio": ratio, "validator_share": s, "payer": format!("{payer:?}"),
        "cost": cost, "burned": burned, "release_pegged": pegged,
        "release": release, "cover_back": back, "net": release + back - cost,
    })
}
