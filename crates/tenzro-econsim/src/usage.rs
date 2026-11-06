//! Paid usage replayed through the chain's accounting rules.
//!
//! Demand, supply and shocks are not made here. They arrive as a usage
//! trace: what buyers in each segment paid for, what each provider served
//! and at what cost, and the shock schedule, tick by tick. This module only
//! applies the chain's rules to them: the settlement fee and its split, the
//! burn netted against the rewards pool's releases, releases pegged to paid
//! work (TNZO's supply is fixed and nothing is minted), the
//! validator cover from stable fees, the base reward from the burn, the
//! verified-availability reward, the payment rails' peg breakers, and the
//! charter check on every payout. The TNZO price is an outcome: a pool that
//! only paid usage and the network's own payouts trade on.
//!
//! # Trace format
//!
//! A run is a manifest (JSON) and a trace (JSON lines).
//!
//! Trace rows, one per tick and actor:
//!
//! | field | meaning |
//! |---|---|
//! | `tick` | tick number from 0; a tick lasts the manifest's `tick_seconds` |
//! | `actor_id` | stable id of the actor |
//! | `actor_kind` | `buyer` or `provider` |
//! | `segment` | buyers: `regulated_critical`, `agents_for_people`, `autonomous` or `developers_resellers` |
//! | `region` | the actor's region; buyers are served there when residency binds them |
//! | `demand` | units the actor asked for in the tick (buyers) |
//! | `supply` | units the actor delivered in the tick (providers) |
//! | `clearing_price` | USD per unit the tick cleared at, for this actor |
//! | `utilisation` | providers: `supply / capacity` |
//! | `unmet_demand` | buyers: units asked for and not served |
//! | `capacity` | providers: units the actor could deliver in the tick |
//! | `cost` | providers: marginal USD per delivered unit |
//! | `residency` | buyers, optional: `true` when the demand may only be served in `region` |
//!
//! A buyer paid `(demand - unmet_demand) * clearing_price` USD; a provider
//! earned `supply * clearing_price` before fees.
//!
//! Manifest: `seed`, `tick_seconds`, `parameters` (any values, kept for the
//! record; the keys below are read), and `shock_schedule`, a list of
//! `{tick, until, kind, region, regions, asset, value}` entries (all but
//! `tick` and `kind` optional). The accounting acts on these kinds:
//! `stable_depeg` (`asset` trades at `value` USD), `sanction` (`asset` may
//! not settle for buyers in `region`), `partition` (`regions` are cut off
//! from the rest), `region_offline` (`region`'s validators and providers are
//! gone) and `liquidity` (TNZO pool depth times `value`). Other kinds
//! (demand falls, price falls, provider exits, energy prices) are already in
//! the rows and are kept as labels. Parameters read: `pool_depth_usd`,
//! `rewards_pool_tnzo`,
//! `price0_usd`, `treasury_tnzo`, `validator_cost_usd_month`, `rails`
//! (region to asset to share of that region's payments) and `chain.<key>`
//! overrides of governed parameters.

use std::collections::{BTreeMap, BTreeSet};
use std::io::BufRead;

use serde::{Deserialize, Serialize};

/// The buyer segments, least elastic first.
pub const SEGMENTS: [&str; 4] = [
    "regulated_critical",
    "agents_for_people",
    "autonomous",
    "developers_resellers",
];

/// One row of a usage trace.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TraceRow {
    pub tick: u64,
    pub actor_id: String,
    pub actor_kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub segment: Option<String>,
    pub region: String,
    #[serde(default)]
    pub demand: f64,
    #[serde(default)]
    pub supply: f64,
    #[serde(default)]
    pub clearing_price: f64,
    #[serde(default)]
    pub utilisation: f64,
    #[serde(default)]
    pub unmet_demand: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capacity: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cost: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub residency: Option<bool>,
}

/// One scheduled shock.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ShockEntry {
    pub tick: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until: Option<u64>,
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub regions: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asset: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<f64>,
}

impl ShockEntry {
    fn on(&self, tick: u64) -> bool {
        tick >= self.tick && self.until.is_none_or(|u| tick < u)
    }
}

/// A run's manifest.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Manifest {
    #[serde(default)]
    pub seed: u64,
    #[serde(default = "day_seconds")]
    pub tick_seconds: u64,
    #[serde(default)]
    pub parameters: BTreeMap<String, serde_json::Value>,
    #[serde(default)]
    pub shock_schedule: Vec<ShockEntry>,
}

fn day_seconds() -> u64 {
    86_400
}

impl Manifest {
    fn num(&self, key: &str, default: f64) -> f64 {
        self.parameters
            .get(key)
            .and_then(serde_json::Value::as_f64)
            .unwrap_or(default)
    }

    /// Region to asset to share of the region's payments; every region
    /// without an entry pays in one asset, `USD1`.
    fn rails(&self) -> BTreeMap<String, BTreeMap<String, f64>> {
        self.parameters
            .get("rails")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default()
    }
}

/// A trace grouped by tick.
#[derive(Debug, Clone, Default)]
pub struct Trace {
    pub manifest: Manifest,
    pub ticks: Vec<Vec<TraceRow>>,
}

impl Trace {
    /// Builds a trace from rows in any order.
    pub fn from_rows(manifest: Manifest, rows: Vec<TraceRow>) -> Trace {
        let n = rows.iter().map(|r| r.tick + 1).max().unwrap_or(0) as usize;
        let mut ticks = vec![Vec::new(); n];
        for r in rows {
            let t = r.tick as usize;
            ticks[t].push(r);
        }
        Trace { manifest, ticks }
    }

    /// Reads a manifest file and a JSON-lines trace file. Blank lines and
    /// lines starting with `#` are skipped; a malformed row is an error
    /// naming its line.
    pub fn read(manifest: &std::path::Path, rows: &std::path::Path) -> Result<Trace, String> {
        let m: Manifest = serde_json::from_slice(
            &std::fs::read(manifest).map_err(|e| format!("{}: {e}", manifest.display()))?,
        )
        .map_err(|e| format!("{}: {e}", manifest.display()))?;
        let f = std::fs::File::open(rows).map_err(|e| format!("{}: {e}", rows.display()))?;
        let mut out = Vec::new();
        for (i, line) in std::io::BufReader::new(f).lines().enumerate() {
            let line = line.map_err(|e| format!("{}: {e}", rows.display()))?;
            let t = line.trim();
            if t.is_empty() || t.starts_with('#') {
                continue;
            }
            let row: TraceRow = serde_json::from_str(t)
                .map_err(|e| format!("{} line {}: {e}", rows.display(), i + 1))?;
            if row.actor_kind != "buyer" && row.actor_kind != "provider" {
                return Err(format!(
                    "{} line {}: actor_kind {:?} is neither buyer nor provider",
                    rows.display(),
                    i + 1,
                    row.actor_kind
                ));
            }
            out.push(row);
        }
        Ok(Trace::from_rows(m, out))
    }

    /// Writes the trace as a manifest and JSON lines.
    pub fn write(&self, manifest: &std::path::Path, rows: &std::path::Path) -> std::io::Result<()> {
        use std::io::Write;
        std::fs::write(manifest, serde_json::to_vec_pretty(&self.manifest)?)?;
        let mut w = std::io::BufWriter::new(std::fs::File::create(rows)?);
        for t in &self.ticks {
            for r in t {
                serde_json::to_writer(&mut w, r)?;
                w.write_all(b"\n")?;
            }
        }
        w.flush()
    }
}

/// The post-downturn mechanisms, each switchable.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Mechanisms {
    /// Buyers prepay capacity into a refundable escrow, paid out per
    /// delivered unit, instead of crediting a provider ahead of delivery.
    pub prepaid_escrow: bool,
    /// A share of the stable fees, while paid usage is at or above its
    /// yearly mean, fills a reserve that pays the verified-availability
    /// reward in stable when it falls below.
    pub countercyclical_reserve: bool,
    /// The rewards pool releases in a tick at most a governed multiple of
    /// the trailing month's verified activity (the paid weight).
    pub activity_release_cap: bool,
    /// Borrowing against TNZO is offered (the charter forbids it; on only to
    /// measure what it would do).
    pub leverage: bool,
    /// Each region's price card follows its energy cost.
    pub energy_price_cards: bool,
}

impl Mechanisms {
    /// Every switch setting a sweep compares: all off, then each one on.
    pub fn sweep() -> Vec<(&'static str, Mechanisms)> {
        let off = Mechanisms::default();
        vec![
            ("none", off),
            (
                "prepaid_escrow",
                Mechanisms {
                    prepaid_escrow: true,
                    ..off
                },
            ),
            (
                "countercyclical_reserve",
                Mechanisms {
                    countercyclical_reserve: true,
                    ..off
                },
            ),
            (
                "activity_release_cap",
                Mechanisms {
                    activity_release_cap: true,
                    ..off
                },
            ),
            (
                "leverage",
                Mechanisms {
                    leverage: true,
                    ..off
                },
            ),
            (
                "energy_price_cards",
                Mechanisms {
                    energy_price_cards: true,
                    ..off
                },
            ),
        ]
    }
}

/// Inputs of the accounting beyond the trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rules {
    /// Governed values (the registry's genesis, then the manifest's
    /// `chain.<key>` entries, then these overrides).
    pub overrides: BTreeMap<String, u64>,
    /// Verified-availability reward per validator-hour, TNZO, before the
    /// demand offset; zero is the genesis (off). Bounded by the governed
    /// maximum, 1 TNZO an hour.
    pub availability_tnzo_hour: f64,
    /// Paid usage, USD a day, at which the demand offset has phased the
    /// availability reward to zero; zero: no offset.
    pub availability_demand_target_usd_day: f64,
    pub mechanisms: Mechanisms,
    /// Validators at genesis and on standby, and their regions in turn.
    pub validators: u32,
    pub standby: u32,
    pub regions: Vec<String>,
    /// A validator leaves when its trailing month's income is under this
    /// share of its cost, and a standby one joins over `join_ratio`.
    pub exit_ratio: f64,
    pub join_ratio: f64,
    /// Share of TNZO income each earner sells into the pool.
    pub provider_sell: f64,
    pub validator_sell: f64,
    /// Share of countercyclical fills, bps of the stable fees kept.
    pub countercyclical_bps: u64,
    /// Releases at most this multiple of the trailing paid weight.
    pub release_cap_multiple: f64,
    /// Share of bonded TNZO borrowed against when leverage is on.
    pub leverage_share: f64,
    pub warmup_ticks: u64,
    /// Share of the trace's market that pays through the network: every
    /// payment and every served unit is scaled by it.
    pub market_share: f64,
    /// TNZO pool depth at the start, USD, over the manifest's.
    pub pool_depth_usd: Option<f64>,
    /// Payment assets and their shares, for every region, over the
    /// manifest's rails.
    pub rails: Option<BTreeMap<String, f64>>,
    /// Payment-rail shocks laid over the trace's own (a depeg, a sanction):
    /// the rails are the chain's, not the market's.
    pub extra_shocks: Vec<ShockEntry>,
    /// Regions validators are placed in, in turn, over the trace's regions.
    pub validator_regions: Option<Vec<String>>,
}

impl Default for Rules {
    fn default() -> Self {
        Rules {
            overrides: BTreeMap::new(),
            availability_tnzo_hour: 0.0,
            availability_demand_target_usd_day: 0.0,
            mechanisms: Mechanisms::default(),
            validators: 7,
            standby: 14,
            regions: ["na", "eu", "apac", "mea", "latam"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
            exit_ratio: 1.0,
            join_ratio: 1.2,
            provider_sell: 0.9,
            validator_sell: 1.0,
            countercyclical_bps: 2_000,
            release_cap_multiple: 1.0,
            leverage_share: 0.3,
            warmup_ticks: 30,
            market_share: 1.0,
            pool_depth_usd: None,
            rails: None,
            extra_shocks: Vec::new(),
            validator_regions: None,
        }
    }
}

/// A payout path of the accounting, and what ties it to paid work.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Payout {
    /// Validators' running cost from the stable fee reserve.
    ValidatorCover,
    /// The base reward: the burn's governed share.
    ValidatorBase,
    /// Validators' pool release, pegged to the paid weight.
    ValidatorRelease,
    /// Providers' pool release, pegged to their settlements' reward ceilings.
    ProviderRelease,
    /// Apps' pool release, pegged to the activity share of paid fees.
    EcosystemRelease,
    /// The verified-availability reward, TNZO from the treasury.
    Availability,
    /// The verified-availability reward, stable from the countercyclical
    /// reserve.
    AvailabilityStable,
    /// Providers' service payments: buyers' own money per delivered unit.
    ServicePayment,
}

impl Payout {
    pub const ALL: [Payout; 8] = [
        Payout::ValidatorCover,
        Payout::ValidatorBase,
        Payout::ValidatorRelease,
        Payout::ProviderRelease,
        Payout::EcosystemRelease,
        Payout::Availability,
        Payout::AvailabilityStable,
        Payout::ServicePayment,
    ];

    /// The paid, verified unit the path pays for.
    pub fn tie(self) -> &'static str {
        match self {
            Payout::ValidatorCover => {
                "an epoch of consensus work, from stable fees of paid settlements"
            }
            Payout::ValidatorBase => {
                "an epoch of consensus work, from the burn of paid settlements"
            }
            Payout::ValidatorRelease => "an epoch of consensus work, at most the paid weight",
            Payout::ProviderRelease => "a delivered, paid unit, at most its reward ceiling",
            Payout::EcosystemRelease => "a paid settlement's activity share",
            Payout::Availability | Payout::AvailabilityStable => {
                "a verified-available verdict on unpredictable challenges"
            }
            Payout::ServicePayment => "a delivered unit the buyer paid for",
        }
    }
}

/// Per-path totals and the charter's verdict on them.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PathBook {
    /// USD paid on the path.
    pub paid_usd: f64,
    /// Ticks the path paid in.
    pub ticks_paid: u64,
    /// Ticks the path paid with no unit of its tie in the tick.
    pub violations: u64,
}

/// What one run gave.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Outcome {
    pub ticks: u64,
    /// Paid usage, USD, total and per segment.
    pub paid_usd: f64,
    pub paid_by_segment: BTreeMap<String, f64>,
    /// Least and last tick's paid usage per segment, USD a tick.
    pub segment_min_tick: BTreeMap<String, f64>,
    pub segment_last_tick: BTreeMap<String, f64>,
    /// Units asked for and not served, share.
    pub unmet_share: f64,
    /// Payments refused because their asset could not settle, USD; and
    /// settled through any other asset than the one paid in (must be 0).
    pub suspended_usd: f64,
    pub substituted_usd: f64,
    /// Residency demand above the in-region served supply, units.
    pub residency_violations: f64,
    pub validators_min: u32,
    pub validators_end: u32,
    /// Share of the floor seats' cost the stable cover paid, least over a
    /// trailing month after warmup, and over the run.
    pub cover_ratio_min: f64,
    pub cover_ratio_mean: f64,
    /// Validators' income over cost, least trailing month after warmup.
    pub validator_income_ratio_min: f64,
    /// Ticks with no side holding more than two thirds of validators.
    pub finality_lost_ticks: u64,
    pub treasury_stable_min: f64,
    pub treasury_tnzo_min: f64,
    pub treasury_value_end_usd: f64,
    pub availability_forfeits: u64,
    pub price_min: f64,
    pub price_end: f64,
    pub price_max: f64,
    /// Regions that had demand, and those among them with no provider
    /// online at or above its marginal cost for a tick after warmup.
    pub regions: BTreeSet<String>,
    pub regions_without_operator: BTreeSet<String>,
    /// Providers online at the end, and least after warmup.
    pub operators_end: u32,
    pub operators_min: u32,
    pub utilisation_mean: f64,
    /// Providers' net earnings per delivered unit (payment less fee and
    /// cost), mean per region at the end.
    pub operator_margin_by_region: BTreeMap<String, f64>,
    pub operator_earnings_usd: f64,
    /// Prepaid balances lost to a provider's exit (0 with the escrow).
    pub stranded_prepaid_usd: f64,
    /// Released from the genesis rewards pool and burned (netted), TNZO.
    pub released_tnzo: f64,
    pub burned_tnzo_eq: f64,
    /// Circulating supply's change over the run: releases less burns, TNZO.
    pub circulating_change_tnzo: f64,
    /// The rewards pool left at the end, TNZO.
    pub pool_end_tnzo: f64,
    /// Availability budget over the stable fees kept, whole run.
    pub availability_over_fees: f64,
    pub paths: BTreeMap<Payout, PathBook>,
    pub charter_violations: u64,
    pub pass_floor: bool,
    pub pass_treasury: bool,
    pub pass_operators: bool,
    pub pass_charter: bool,
    pub pass_finality: bool,
    pub pass_residency: bool,
    pub pass_payments: bool,
    /// Each tick's paid work and what the accounting paid for it, in tick
    /// order: what a split of the work between kinds of operator reads.
    #[serde(skip)]
    pub tick_book: Vec<TickBook>,
}

/// One tick's paid work and its payouts.
#[derive(Debug, Clone, Default)]
pub struct TickBook {
    /// Settled paid usage, USD, and the units it bought.
    pub paid_usd: f64,
    pub units: f64,
    /// Of the units, those bought by the regulated, critical segment.
    pub critical_units: f64,
    /// Share of a payment the provider keeps after the fee and the leg.
    pub provider_share: f64,
    /// Providers' pool release, TNZO, and its USD value at the tick's price.
    pub provider_release_tnzo: f64,
    pub provider_release_usd: f64,
    /// Validators active on the finalizing side, the income of each and the
    /// running cost of each, USD.
    pub validators_active: u32,
    pub validator_income_each_usd: f64,
    pub validator_cost_each_usd: f64,
    /// The trace's providers: capacity online and marginal cost of what they
    /// served, USD, and what each served, units.
    pub provider_capacity_units: f64,
    pub provider_cost_usd: f64,
    pub served_by: Vec<(String, f64)>,
}

impl Outcome {
    /// Every check of the run held.
    pub fn holds(&self) -> bool {
        self.pass_floor
            && self.pass_treasury
            && self.pass_operators
            && self.pass_charter
            && self.pass_finality
            && self.pass_residency
            && self.pass_payments
    }
}

fn param(rules: &Rules, m: &Manifest, key: &str) -> u64 {
    if let Some(v) = rules.overrides.get(key) {
        return *v;
    }
    if let Some(v) = m
        .parameters
        .get(&format!("chain.{key}"))
        .and_then(serde_json::Value::as_u64)
    {
        return v;
    }
    tenzro_vm::governance::genesis_param(key)
}

struct Validator {
    region: String,
    bonded: bool,
    income: Vec<f64>,
}

/// Replays `trace` under `rules`.
pub fn replay(trace: &Trace, rules: &Rules) -> Outcome {
    use tenzro_vm::native::{economy as ve, rewards as vr, validator_cover as vc};
    let m = &trace.manifest;
    let p = |k: &str| param(rules, m, k) as f64;
    let ticks_per_day = 86_400.0 / m.tick_seconds.max(1) as f64;
    let ticks_per_year = ticks_per_day * 365.0;
    let fee_bps = p(ve::SETTLEMENT_FEE_PARAM) / 1e4;
    let burn_bps = p(ve::SETTLEMENT_FEE_BURN_PARAM) / 1e4;
    let insurance_bps = p(tenzro_vm::native::insurance::POOL_FEE_SHARE_PARAM) / 1e4;
    let leg_bps = p(ve::TREASURY_LEG_INFERENCE_PARAM) / 1e4;
    let cover_share = p(vc::FEE_SHARE_PARAM) / 1e4;
    let target_months = p(vc::TARGET_MONTHS_PARAM);
    let burn_share = p(vr::VALIDATOR_BURN_SHARE_PARAM) / 1e4;
    let base_cap_tnzo_month = p(vr::VALIDATOR_BASE_CAP_PARAM);
    let mint_base = p(vr::MINT_BASE_PARAM);
    let mint_decay = p(vr::MINT_DECAY_PARAM) / 1e4;
    let mint_floor = p(vr::MINT_FLOOR_PARAM);
    let (v_share, p_share, e_share) = (
        p(vr::MINT_VALIDATOR_SHARE_PARAM) / 1e4,
        p(vr::MINT_PROVIDER_SHARE_PARAM) / 1e4,
        p(vr::MINT_ECOSYSTEM_SHARE_PARAM) / 1e4,
    );
    let peg = (p(vr::MINT_REVENUE_PEG_PARAM) / 1e4).min(1.0);
    let provider_ceiling = p(vr::PROVIDER_REWARD_COST_PARAM) / 1e4;
    let activity_ceiling = p(ve::ACTIVITY_REWARD_FEE_PARAM) / 1e4;
    let suspend_ticks = (p(tenzro_vm::native::settlement_asset::BREAKER_SUSPEND_PARAM) / 24.0
        * ticks_per_day)
        .ceil()
        .max(1.0) as u64;
    let resume_ticks = (p(tenzro_vm::native::settlement_asset::BREAKER_RESUME_PARAM) / 24.0
        * ticks_per_day)
        .ceil()
        .max(1.0) as u64;
    let validator_cost_tick =
        m.num("validator_cost_usd_month", p(vr::VALIDATOR_BASE_COST_PARAM)) * 12.0 / ticks_per_year;
    let availability_tnzo_tick =
        rules.availability_tnzo_hour.clamp(0.0, 1.0) * 24.0 / ticks_per_day;

    // The pool: TNZO against USD, constant product.
    let price0 = m.num("price0_usd", 0.10);
    let depth0 = rules
        .pool_depth_usd
        .unwrap_or_else(|| m.num("pool_depth_usd", 1_000_000.0));
    let mut pool_usd = depth0 / 2.0;
    let mut pool_tnzo = pool_usd / price0;
    let mut treasury_tnzo = m.num("treasury_tnzo", 100_000_000.0);
    let mut treasury_stable = 0.0f64;
    let mut pool = m.num(
        "rewards_pool_tnzo",
        tenzro_token::rewards::NETWORK_REWARDS_POOL as f64 / 1e18,
    );
    let mut cover_reserve = 0.0f64;
    let mut cc_reserve = 0.0f64;
    let mut rails = m.rails();
    let share = rules.market_share.max(0.0);
    let regions: Vec<String> = m
        .parameters
        .get("regions")
        .and_then(|v| serde_json::from_value::<Vec<String>>(v.clone()).ok())
        .filter(|r| !r.is_empty())
        .unwrap_or_else(|| rules.regions.clone());
    if let Some(r) = &rules.rails {
        for reg in &regions {
            rails.insert(reg.clone(), r.clone());
        }
    }
    let regions = rules.validator_regions.clone().unwrap_or(regions);
    let all_shocks: Vec<ShockEntry> = m
        .shock_schedule
        .iter()
        .chain(rules.extra_shocks.iter())
        .cloned()
        .collect();

    let mut vals: Vec<Validator> = (0..rules.validators + rules.standby)
        .map(|i| Validator {
            region: regions[i as usize % regions.len().max(1)].clone(),
            bonded: i < rules.validators,
            income: Vec::new(),
        })
        .collect();

    let mut o = Outcome {
        validators_min: u32::MAX,
        cover_ratio_min: f64::INFINITY,
        validator_income_ratio_min: f64::INFINITY,
        treasury_stable_min: f64::INFINITY,
        treasury_tnzo_min: f64::INFINITY,
        price_min: f64::INFINITY,
        operators_min: u32::MAX,
        ..Outcome::default()
    };
    for path in Payout::ALL {
        o.paths.insert(path, PathBook::default());
    }
    let mut breaker: BTreeMap<String, (u64, u64, bool)> = BTreeMap::new();
    let mut paid_hist: Vec<f64> = Vec::new();
    let mut weight_hist: Vec<f64> = Vec::new();
    let mut cover_hist: Vec<(f64, f64)> = Vec::new();
    let mut asked = 0.0;
    let mut unmet = 0.0;
    let mut util_sum = 0.0;
    let mut util_n = 0.0;
    let mut price_high = price0;
    let mut prepaid: BTreeMap<String, f64> = BTreeMap::new();
    let mut last_supply: BTreeMap<String, (String, f64)> = BTreeMap::new();
    let mut fees_kept_total = 0.0;
    // The set changes at most once a trailing window, so every validator's
    // income is read over a window the last change already shaped.
    let mut last_change: Option<u64> = None;
    let mut availability_paid_usd = 0.0;

    for (t, rows) in trace.ticks.iter().enumerate() {
        let t = t as u64;
        let after_warmup = t >= rules.warmup_ticks;
        let shocks: Vec<&ShockEntry> = all_shocks.iter().filter(|s| s.on(t)).collect();
        let offline: BTreeSet<String> = shocks
            .iter()
            .filter(|s| s.kind == "region_offline")
            .filter_map(|s| s.region.clone())
            .collect();
        let cut: BTreeSet<String> = shocks
            .iter()
            .filter(|s| s.kind == "partition")
            .flat_map(|s| s.regions.clone().unwrap_or_default())
            .collect();
        if let Some(f) = shocks
            .iter()
            .filter(|s| s.kind == "liquidity")
            .filter_map(|s| s.value)
            .reduce(f64::min)
        {
            // Depth falls to `f` of launch depth at the price in force.
            let price = pool_usd / pool_tnzo;
            let want_usd = (depth0 * f / 2.0).min(pool_usd);
            pool_usd = want_usd;
            pool_tnzo = want_usd / price;
        }

        // Peg breakers: an asset off its peg for the governed span is
        // suspended until it holds the band for the resume span.
        let mut assets: BTreeSet<String> = rails.values().flat_map(|r| r.keys().cloned()).collect();
        assets.insert("USD1".into());
        for a in &assets {
            let off = shocks.iter().any(|s| {
                s.kind == "stable_depeg"
                    && s.asset.as_deref() == Some(a)
                    && s.value.is_some_and(|v| (v - 1.0).abs() > 0.005)
            });
            let e = breaker.entry(a.clone()).or_insert((0, 0, false));
            if off {
                e.0 += 1;
                e.1 = 0;
                if e.0 >= suspend_ticks {
                    e.2 = true;
                }
            } else {
                e.0 = 0;
                e.1 += 1;
                if e.2 && e.1 >= resume_ticks {
                    e.2 = false;
                }
            }
        }
        let may_settle = |region: &str, asset: &str| -> bool {
            let suspended = breaker.get(asset).is_some_and(|b| b.2);
            let sanctioned = shocks.iter().any(|s| {
                s.kind == "sanction"
                    && s.asset.as_deref() == Some(asset)
                    && s.region.as_deref().is_none_or(|r| r == region)
            });
            !suspended && !sanctioned
        };

        // Buyers: what settles, by segment and region.
        let mut paid_tick = 0.0;
        let mut units_tick = 0.0;
        let mut critical_units_tick = 0.0;
        let mut paid_region: BTreeMap<String, f64> = BTreeMap::new();
        let mut residency_units: BTreeMap<String, f64> = BTreeMap::new();
        let mut partitioned_usd = 0.0;
        for r in rows.iter().filter(|r| r.actor_kind == "buyer") {
            asked += r.demand;
            unmet += r.unmet_demand;
            if offline.contains(&r.region) {
                continue;
            }
            let units = (r.demand - r.unmet_demand).max(0.0);
            let mut usd = units * r.clearing_price * share;
            if rules.mechanisms.energy_price_cards
                && let Some(f) = shocks
                    .iter()
                    .filter(|s| s.kind == "energy" && s.region.as_deref() == Some(&r.region))
                    .filter_map(|s| s.value)
                    .reduce(f64::max)
            {
                // The card prices the energy share of the unit (a third)
                // at the region's index.
                usd *= 1.0 + (f - 1.0) / 3.0;
            }
            let rail = rails
                .get(&r.region)
                .cloned()
                .unwrap_or_else(|| BTreeMap::from([("USD1".to_string(), 1.0)]));
            let total: f64 = rail.values().sum::<f64>().max(1e-12);
            let mut settled = 0.0;
            for (asset, share) in &rail {
                let part = usd * share / total;
                if may_settle(&r.region, asset) {
                    settled += part;
                } else {
                    o.suspended_usd += part;
                }
            }
            if cut.contains(&r.region) {
                // Cut off from the side that finalizes: held, not settled.
                partitioned_usd += settled;
                o.suspended_usd += settled;
                continue;
            }
            let seg = r.segment.clone().unwrap_or_else(|| "unknown".into());
            *o.paid_by_segment.entry(seg.clone()).or_default() += settled;
            paid_tick += settled;
            let settled_units = if usd > 0.0 {
                units * share * settled / usd
            } else {
                0.0
            };
            units_tick += settled_units;
            if seg == "regulated_critical" {
                critical_units_tick += settled_units;
            }
            *paid_region.entry(r.region.clone()).or_default() += settled;
            if r.residency == Some(true) {
                *residency_units.entry(r.region.clone()).or_default() += units;
            }
        }
        let _ = partitioned_usd;
        for s in SEGMENTS {
            let v: f64 = rows
                .iter()
                .filter(|r| r.actor_kind == "buyer" && r.segment.as_deref() == Some(s))
                .map(|r| (r.demand - r.unmet_demand).max(0.0) * r.clearing_price)
                .sum();
            let e = o
                .segment_min_tick
                .entry(s.to_string())
                .or_insert(f64::INFINITY);
            if after_warmup {
                *e = e.min(v);
            }
            o.segment_last_tick.insert(s.to_string(), v);
        }
        o.paid_usd += paid_tick;
        paid_hist.push(paid_tick);

        // Providers: served supply, cost, the operator base per region.
        let mut served_region: BTreeMap<String, f64> = BTreeMap::new();
        let mut online_ok: BTreeMap<String, u32> = BTreeMap::new();
        let mut operators = 0u32;
        let mut service_units = 0.0;
        let mut capacity_units = 0.0;
        let mut provider_cost_usd = 0.0;
        let mut served_by: Vec<(String, f64)> = Vec::new();
        for r in rows.iter().filter(|r| r.actor_kind == "provider") {
            if offline.contains(&r.region) {
                continue;
            }
            let cap = r.capacity.unwrap_or(r.supply);
            if cap <= 0.0 {
                continue;
            }
            operators += 1;
            util_sum += r.utilisation;
            util_n += 1.0;
            *served_region.entry(r.region.clone()).or_default() += r.supply;
            service_units += r.supply * share;
            capacity_units += cap * share;
            let cost = r.cost.unwrap_or(0.0);
            provider_cost_usd += r.supply * share * cost;
            if r.supply > 0.0 {
                served_by.push((r.actor_id.clone(), r.supply * share));
            }
            if r.clearing_price >= cost {
                *online_ok.entry(r.region.clone()).or_default() += 1;
            }
            let net = r.supply * share * (r.clearing_price * (1.0 - fee_bps - leg_bps) - cost);
            o.operator_earnings_usd += net;
            if r.supply > 0.0 {
                o.operator_margin_by_region.insert(
                    r.region.clone(),
                    r.clearing_price * (1.0 - fee_bps - leg_bps) - cost,
                );
            }
            last_supply.insert(
                r.actor_id.clone(),
                (r.region.clone(), r.supply * r.clearing_price),
            );
        }
        // A provider that served last tick and is gone now: what buyers had
        // credited it ahead of delivery is lost, unless it sat in escrow.
        let present: BTreeSet<&str> = rows
            .iter()
            .filter(|r| r.actor_kind == "provider" && r.capacity.unwrap_or(r.supply) > 0.0)
            .map(|r| r.actor_id.as_str())
            .collect();
        let gone: Vec<String> = last_supply
            .keys()
            .filter(|k| !present.contains(k.as_str()))
            .cloned()
            .collect();
        for g in gone {
            if let Some((_, usd)) = last_supply.remove(&g)
                && !rules.mechanisms.prepaid_escrow
            {
                // A month of its service, prepaid on credit.
                o.stranded_prepaid_usd += usd * 30.0 * ticks_per_day;
            }
            prepaid.remove(&g);
        }
        let ops = (online_ok.values().sum::<u32>()).min(operators);
        o.operators_end = ops;
        if after_warmup {
            o.operators_min = o.operators_min.min(ops);
        }
        for region in paid_region.keys() {
            o.regions.insert(region.clone());
            if after_warmup
                && !offline.contains(region)
                && online_ok.get(region).copied().unwrap_or(0) == 0
            {
                o.regions_without_operator.insert(region.clone());
            }
        }
        for (region, need) in &residency_units {
            let served = served_region.get(region).copied().unwrap_or(0.0);
            if *need > served + 1e-9 {
                o.residency_violations += need - served;
            }
        }
        if paid_tick > 0.0 {
            let b = o.paths.get_mut(&Payout::ServicePayment).expect("path");
            b.paid_usd += paid_tick * (1.0 - fee_bps - leg_bps);
            b.ticks_paid += 1;
            if service_units <= 0.0 {
                b.violations += 1;
            }
        }

        // Fees: the settlement fee and the treasury leg, in the stable
        // assets they were paid in.
        let price = pool_usd / pool_tnzo;
        let fee = paid_tick * fee_bps;
        let leg = paid_tick * leg_bps;
        let burn_eq_usd = fee * burn_bps;
        let insurance = (fee - burn_eq_usd) * insurance_bps;
        let kept = fee - burn_eq_usd - insurance + leg;
        fees_kept_total += kept;
        let burn_eq_tnzo = burn_eq_usd / price;
        o.burned_tnzo_eq += burn_eq_tnzo;
        treasury_stable += burn_eq_usd; // held against the netted burn
        let mut kept_left = kept;
        if rules.mechanisms.countercyclical_reserve {
            let n = paid_hist.len();
            let month = mean_tail(&paid_hist, (30.0 * ticks_per_day) as usize);
            let year = mean_tail(&paid_hist, (365.0 * ticks_per_day) as usize);
            if n > 0 && month >= year {
                let fill = kept * rules.countercyclical_bps as f64 / 1e4;
                cc_reserve += fill;
                kept_left -= fill;
            }
        }

        // Validators online and on the finalizing side.
        let bonded: Vec<usize> = (0..vals.len()).filter(|i| vals[*i].bonded).collect();
        let reachable: Vec<usize> = bonded
            .iter()
            .copied()
            .filter(|i| !offline.contains(&vals[*i].region) && !cut.contains(&vals[*i].region))
            .collect();
        let cut_side = bonded
            .iter()
            .filter(|i| cut.contains(&vals[**i].region) && !offline.contains(&vals[**i].region))
            .count();
        let finalizes = 3 * reachable.len() > 2 * bonded.len() || 3 * cut_side > 2 * bonded.len();
        if !finalizes {
            o.finality_lost_ticks += 1;
        }
        let n_active = if finalizes { reachable.len() } else { 0 };

        // Cover: fill from the stable fees kept, then pay each active
        // validator its cost as far as the reserve goes.
        let target =
            validator_cost_tick * n_active.max(1) as f64 * ticks_per_year / 12.0 * target_months;
        let fill = (kept_left * cover_share).min((target - cover_reserve).max(0.0));
        cover_reserve += fill;
        treasury_stable += kept_left - fill;
        let need = validator_cost_tick * n_active as f64;
        let cover_paid = need.min(cover_reserve);
        cover_reserve -= cover_paid;
        let cover_each = if n_active > 0 {
            cover_paid / n_active as f64
        } else {
            0.0
        };
        book(
            &mut o,
            Payout::ValidatorCover,
            cover_paid,
            n_active > 0 && paid_hist.iter().any(|v| *v > 0.0),
        );
        if after_warmup && n_active > 0 {
            cover_hist.push((cover_paid, validator_cost_tick * 7.0));
        }

        // Pool releases: the schedule, pegged to the paid weight, the burn
        // netted against them; never more than the pool holds.
        let year = (t as f64 / ticks_per_year).floor();
        let annual = (mint_base * (1.0 - mint_decay).powf(year)).max(mint_floor);
        let scheduled = annual / ticks_per_year;
        let fee_tnzo = fee / price;
        let provider_weight = fee_tnzo * provider_ceiling;
        let activity_weight = fee_tnzo * activity_ceiling;
        let paid_weight = provider_weight + activity_weight;
        weight_hist.push(paid_weight);
        let mut pr = (scheduled * p_share).min(provider_weight * peg);
        let mut er = (scheduled * e_share).min(activity_weight * peg);
        let mut vr_ = if n_active > 0 {
            (scheduled * v_share).min(paid_weight * peg)
        } else {
            0.0
        };
        let uncovered = (need - cover_paid).max(0.0);
        let base_each_cap = base_cap_tnzo_month * 12.0 / ticks_per_year;
        let mut base = (uncovered / price)
            .min(base_each_cap * n_active as f64)
            .min(burn_eq_tnzo * burn_share);
        if rules.mechanisms.activity_release_cap {
            let cap = mean_tail(&weight_hist, (30.0 * ticks_per_day) as usize)
                * rules.release_cap_multiple;
            let total = pr + er + vr_ + base;
            if total > cap && total > 0.0 {
                let k = cap / total;
                pr *= k;
                er *= k;
                vr_ *= k;
                base *= k;
            }
        }
        let gross = pr + er + vr_ + base;
        if gross > pool && gross > 0.0 {
            let k = pool / gross;
            pr *= k;
            er *= k;
            vr_ *= k;
            base *= k;
        }
        let gross = pr + er + vr_ + base;
        // The burn's netted share withholds releases; it never mints.
        pool -= gross;
        o.released_tnzo += gross;
        o.circulating_change_tnzo += gross - burn_eq_tnzo;
        let release_price = price;
        book(
            &mut o,
            Payout::ProviderRelease,
            pr * price,
            provider_weight > 0.0,
        );
        book(
            &mut o,
            Payout::EcosystemRelease,
            er * price,
            activity_weight > 0.0,
        );
        book(
            &mut o,
            Payout::ValidatorRelease,
            vr_ * price,
            paid_weight > 0.0,
        );
        book(
            &mut o,
            Payout::ValidatorBase,
            base * price,
            burn_eq_tnzo > 0.0,
        );

        // Verified availability: validators on the finalizing side answer
        // the challenges; one cut off or offline fails them and earns
        // nothing.
        let offset = if rules.availability_demand_target_usd_day > 0.0 {
            (1.0 - paid_tick * ticks_per_day / rules.availability_demand_target_usd_day).max(0.0)
        } else {
            1.0
        };
        let avail_each = availability_tnzo_tick * offset;
        let mut avail_paid_tnzo = 0.0;
        if avail_each > 0.0 && n_active > 0 {
            let due = avail_each * n_active as f64;
            if treasury_tnzo >= due {
                treasury_tnzo -= due;
                avail_paid_tnzo = due;
            } else {
                o.availability_forfeits += 1;
            }
        }
        book(
            &mut o,
            Payout::Availability,
            avail_paid_tnzo * price,
            n_active > 0,
        );
        availability_paid_usd += avail_paid_tnzo * price;
        let mut cc_each = 0.0;
        if rules.mechanisms.countercyclical_reserve && n_active > 0 {
            let month = mean_tail(&paid_hist, (30.0 * ticks_per_day) as usize);
            let yr = mean_tail(&paid_hist, (365.0 * ticks_per_day) as usize);
            if month < 0.8 * yr {
                let short = (validator_cost_tick - cover_each).max(0.0) * n_active as f64;
                let pay = short.min(cc_reserve * 0.1 / (30.0 * ticks_per_day));
                cc_reserve -= pay;
                cc_each = pay / n_active as f64;
                book(&mut o, Payout::AvailabilityStable, pay, true);
                availability_paid_usd += pay;
            }
        }

        // TNZO income is sold into the pool; the price is what is left.
        let validator_tnzo = vr_ + base + avail_paid_tnzo;
        let sell = (pr + er) * rules.provider_sell + validator_tnzo * rules.validator_sell;
        let mut usd_out = sell_into(&mut pool_usd, &mut pool_tnzo, sell);
        if rules.mechanisms.leverage {
            let p_now = pool_usd / pool_tnzo;
            price_high = price_high.max(p_now);
            if p_now < 0.7 * price_high {
                // Loans against bonded TNZO cross their limit and are sold.
                let bonded_tnzo = 1_000_000.0 * bonded.len() as f64;
                let forced = bonded_tnzo * rules.leverage_share * 0.01;
                sell_into(&mut pool_usd, &mut pool_tnzo, forced);
            }
        }
        let validator_usd_from_tnzo = if sell > 0.0 {
            usd_out * validator_tnzo * rules.validator_sell / sell
        } else {
            0.0
        };
        usd_out = 0.0;
        let _ = usd_out;

        // Each active validator's income, USD, against its cost.
        let each_income = cover_each
            + cc_each
            + if n_active > 0 {
                validator_usd_from_tnzo / n_active as f64
            } else {
                0.0
            };
        for (i, v) in vals.iter_mut().enumerate() {
            if !v.bonded {
                continue;
            }
            let earns = reachable.contains(&i) && finalizes;
            v.income.push(if earns { each_income } else { 0.0 });
        }
        let window = (30.0 * ticks_per_day) as usize;
        let settled = last_change.is_none_or(|c| t >= c + window as u64);
        if after_warmup {
            let cost_w = validator_cost_tick * window as f64;
            let mut ratio_min = f64::INFINITY;
            let mut leave: Option<usize> = None;
            for (i, v) in vals.iter().enumerate() {
                if !v.bonded || v.income.len() < window {
                    continue;
                }
                let r: f64 = v.income[v.income.len() - window..].iter().sum::<f64>() / cost_w;
                ratio_min = ratio_min.min(r);
                if r < rules.exit_ratio && leave.is_none() {
                    leave = Some(i);
                }
            }
            if ratio_min.is_finite() {
                o.validator_income_ratio_min = o.validator_income_ratio_min.min(ratio_min);
                if leave.is_none()
                    && settled
                    && ratio_min >= rules.join_ratio
                    && let Some(j) = vals.iter().position(|v| !v.bonded)
                {
                    vals[j].bonded = true;
                    vals[j].income.clear();
                    last_change = Some(t);
                }
            }
            if let Some(i) = leave.filter(|_| settled) {
                vals[i].bonded = false;
                vals[i].income.clear();
                last_change = Some(t);
            }
        }
        let count = vals.iter().filter(|v| v.bonded).count() as u32;
        if after_warmup {
            o.validators_min = o.validators_min.min(count);
        }
        o.validators_end = count;

        let price = pool_usd / pool_tnzo;
        o.price_min = o.price_min.min(price);
        o.price_max = o.price_max.max(price);
        o.price_end = price;
        o.treasury_stable_min = o.treasury_stable_min.min(treasury_stable);
        o.treasury_tnzo_min = o.treasury_tnzo_min.min(treasury_tnzo);
        o.treasury_value_end_usd =
            treasury_stable + treasury_tnzo * price + cover_reserve + cc_reserve;
        o.pool_end_tnzo = pool;
        o.ticks += 1;
        o.tick_book.push(TickBook {
            paid_usd: paid_tick,
            units: units_tick,
            critical_units: critical_units_tick,
            provider_share: 1.0 - fee_bps - leg_bps,
            provider_release_tnzo: pr,
            provider_release_usd: pr * release_price,
            validators_active: n_active as u32,
            validator_income_each_usd: each_income,
            validator_cost_each_usd: validator_cost_tick,
            provider_capacity_units: capacity_units,
            provider_cost_usd,
            served_by,
        });
    }

    o.unmet_share = if asked > 0.0 { unmet / asked } else { 0.0 };
    o.utilisation_mean = if util_n > 0.0 { util_sum / util_n } else { 0.0 };
    let w = 30usize;
    if cover_hist.len() >= w {
        let mut least = f64::INFINITY;
        for win in cover_hist.windows(w) {
            let paid: f64 = win.iter().map(|x| x.0).sum();
            let need: f64 = win.iter().map(|x| x.1).sum();
            least = least.min(if need > 0.0 { paid / need } else { 1.0 });
        }
        o.cover_ratio_min = least;
        let paid: f64 = cover_hist.iter().map(|x| x.0).sum();
        let need: f64 = cover_hist.iter().map(|x| x.1).sum();
        o.cover_ratio_mean = if need > 0.0 { paid / need } else { 1.0 };
    } else {
        o.cover_ratio_min = 0.0;
    }
    if !o.validator_income_ratio_min.is_finite() {
        o.validator_income_ratio_min = 0.0;
    }
    if o.validators_min == u32::MAX {
        o.validators_min = o.validators_end;
    }
    if o.operators_min == u32::MAX {
        o.operators_min = o.operators_end;
    }
    o.availability_over_fees = if fees_kept_total > 0.0 {
        availability_paid_usd / fees_kept_total
    } else if availability_paid_usd > 0.0 {
        f64::INFINITY
    } else {
        0.0
    };
    o.charter_violations = o.paths.values().map(|b| b.violations).sum::<u64>()
        + if rules.mechanisms.leverage { 1 } else { 0 };
    o.pass_charter = o.charter_violations == 0;
    o.pass_floor = o.validators_min >= 7;
    o.pass_treasury = o.treasury_stable_min >= 0.0
        && o.treasury_tnzo_min >= 0.0
        && o.availability_forfeits == 0
        && o.treasury_value_end_usd > 0.0;
    o.pass_operators = o.regions_without_operator.is_empty();
    o.pass_finality = o.finality_lost_ticks == 0;
    o.pass_residency = o.residency_violations <= 1e-6;
    o.pass_payments = o.substituted_usd == 0.0;
    o
}

fn book(o: &mut Outcome, path: Payout, usd: f64, tied: bool) {
    if usd <= 0.0 {
        return;
    }
    let b = o.paths.get_mut(&path).expect("path");
    b.paid_usd += usd;
    b.ticks_paid += 1;
    if !tied {
        b.violations += 1;
    }
}

fn mean_tail(v: &[f64], n: usize) -> f64 {
    let n = n.max(1).min(v.len());
    if n == 0 {
        return 0.0;
    }
    v[v.len() - n..].iter().sum::<f64>() / n as f64
}

/// Sells `tnzo` into the pool; returns the USD it took out.
fn sell_into(pool_usd: &mut f64, pool_tnzo: &mut f64, tnzo: f64) -> f64 {
    if tnzo <= 0.0 {
        return 0.0;
    }
    let k = *pool_usd * *pool_tnzo;
    let new_tnzo = *pool_tnzo + tnzo;
    let new_usd = k / new_tnzo;
    let out = *pool_usd - new_usd;
    *pool_tnzo = new_tnzo;
    *pool_usd = new_usd;
    out
}

/// The market-stress simulation format this reader takes.
pub const LW_FORMAT: &str = "lw.market-stress/1";

/// A simulated buyer archetype as the accounting names its segment.
pub fn lw_segment(archetype: &str) -> &'static str {
    match archetype {
        "critical" => "regulated_critical",
        "delegated" => "agents_for_people",
        "autonomous" => "autonomous",
        _ => "developers_resellers",
    }
}

#[derive(Deserialize)]
struct LwRow {
    tick: u64,
    actor: String,
    kind: String,
    #[serde(default)]
    segment: Option<String>,
    region: String,
    #[serde(default)]
    demand: f64,
    #[serde(default)]
    supply: f64,
    #[serde(default)]
    clearing_price: f64,
    #[serde(default)]
    utilisation: f64,
    #[serde(default)]
    unmet_demand: f64,
}

impl Trace {
    /// Reads a market-stress simulation `lw.market-stress/1` export: its manifest and
    /// JSON-lines trace. The trace's sha256 must match the manifest's. A
    /// segment row becomes a buyer (it received `supply` at
    /// `clearing_price`); a provider row's `supply` is its capacity online
    /// and `utilisation` the served share, its marginal cost is its opex
    /// plus its energy at the region's energy price, moved by the energy
    /// shock's path at its exposure and by the glut's cost fall; an
    /// intermediary row moves no payment and is left out. The shocks become
    /// the accounting's schedule: a partition cuts off its first group, a
    /// liquidity drought thins the TNZO pool by its depth factor over its
    /// rise, hold and decay, and every other kind is kept as a label.
    pub fn read_lw(manifest: &std::path::Path, rows: &std::path::Path) -> Result<Trace, String> {
        use sha2::{Digest, Sha256};
        let err = |e: &dyn std::fmt::Display| format!("{}: {e}", manifest.display());
        let raw: serde_json::Value =
            serde_json::from_slice(&std::fs::read(manifest).map_err(|e| err(&e))?)
                .map_err(|e| err(&e))?;
        if raw.get("format").and_then(|v| v.as_str()) != Some(LW_FORMAT) {
            return Err(format!("{}: not {LW_FORMAT}", manifest.display()));
        }
        let bytes = std::fs::read(rows).map_err(|e| format!("{}: {e}", rows.display()))?;
        let want = raw
            .pointer("/trace/sha256")
            .and_then(|v| v.as_str())
            .ok_or_else(|| format!("{}: no trace sha256", manifest.display()))?;
        let got = hex::encode(Sha256::digest(&bytes));
        if got != want {
            return Err(format!(
                "{}: sha256 {got}, the manifest says {want}",
                rows.display()
            ));
        }
        let params = raw.get("parameters").cloned().unwrap_or_default();
        let energy_price: BTreeMap<String, f64> = params
            .get("regions")
            .and_then(|r| r.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|r| {
                        Some((
                            r.get("id")?.as_str()?.to_string(),
                            r.get("energy_price")?.as_f64()?,
                        ))
                    })
                    .collect()
            })
            .unwrap_or_default();
        let providers: BTreeMap<String, (f64, f64)> = params
            .get("providers")
            .and_then(|r| r.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|p| {
                        Some((
                            p.get("id")?.as_str()?.to_string(),
                            (p.get("opex")?.as_f64()?, p.get("energy")?.as_f64()?),
                        ))
                    })
                    .collect()
            })
            .unwrap_or_default();
        let shocks = raw
            .get("shocks")
            .and_then(|s| s.as_array())
            .cloned()
            .unwrap_or_default();
        let num = |v: &serde_json::Value, k: &str| {
            v.pointer(&format!("/params/{k}")).and_then(|x| x.as_f64())
        };
        let mut schedule = Vec::new();
        // Energy multiple of a region on a tick, and the glut's cost factor.
        let mut energy_paths: Vec<(String, u64, u64, f64, Vec<f64>)> = Vec::new();
        let mut glut: Option<(u64, u64, f64)> = None;
        for s in &shocks {
            let at = s.get("at").and_then(|v| v.as_u64()).unwrap_or(0);
            let kind = s
                .get("kind")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let mut e = ShockEntry {
                tick: at,
                until: None,
                kind: kind.clone(),
                region: None,
                regions: None,
                asset: None,
                value: None,
            };
            match kind.as_str() {
                "partition" => {
                    let groups = s
                        .pointer("/params/groups")
                        .and_then(|g| g.as_array())
                        .cloned()
                        .unwrap_or_default();
                    let first: Vec<String> = groups
                        .first()
                        .and_then(|g| g.as_array())
                        .map(|g| {
                            g.iter()
                                .filter_map(|r| r.as_str().map(String::from))
                                .collect()
                        })
                        .unwrap_or_default();
                    e.regions = Some(first);
                    e.until = num(s, "duration").map(|d| at + d as u64);
                }
                "liquidity_drought" => {
                    let span = num(s, "rise").unwrap_or(0.0)
                        + num(s, "hold").unwrap_or(0.0)
                        + num(s, "decay").unwrap_or(0.0);
                    e.kind = "liquidity".into();
                    e.value = num(s, "depth");
                    e.until = Some(at + span as u64);
                }
                "energy_spike" => {
                    let region = s
                        .pointer("/params/region")
                        .and_then(|r| r.as_str())
                        .unwrap_or("")
                        .to_string();
                    let step = num(s, "step").unwrap_or(30.0).max(1.0) as u64;
                    let exposure = num(s, "exposure").unwrap_or(1.0);
                    let path: Vec<f64> = s
                        .pointer("/params/path")
                        .and_then(|p| p.as_array())
                        .map(|p| p.iter().filter_map(|x| x.as_f64()).collect())
                        .unwrap_or_default();
                    for (k, x) in path.iter().enumerate() {
                        schedule.push(ShockEntry {
                            tick: at + k as u64 * step,
                            until: Some(at + (k as u64 + 1) * step),
                            kind: "energy".into(),
                            region: Some(region.clone()),
                            regions: None,
                            asset: None,
                            value: Some(1.0 + exposure * (x - 1.0)),
                        });
                    }
                    energy_paths.push((region.clone(), at, step, exposure, path));
                    e.region = Some(region);
                }
                "supply_glut" => {
                    glut = Some((
                        at,
                        num(s, "over").unwrap_or(365.0) as u64,
                        num(s, "cost").unwrap_or(1.0),
                    ));
                }
                _ => {}
            }
            schedule.push(e);
        }
        let energy_mult = |region: &str, t: u64| -> f64 {
            energy_paths
                .iter()
                .filter(|(r, at, ..)| r == region && t >= *at)
                .map(|(_, at, step, exposure, path)| {
                    let k = ((t - at) / step) as usize;
                    path.get(k).map_or(1.0, |x| 1.0 + exposure * (x - 1.0))
                })
                .fold(1.0, f64::max)
        };
        let cost_factor = |t: u64| -> f64 {
            glut.map_or(1.0, |(at, over, f)| {
                if t < at {
                    1.0
                } else {
                    1.0 + (f - 1.0) * ((t - at) as f64 / over.max(1) as f64).min(1.0)
                }
            })
        };
        let mut out = Vec::new();
        for (i, line) in String::from_utf8_lossy(&bytes).lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            let r: LwRow = serde_json::from_str(line)
                .map_err(|e| format!("{} line {}: {e}", rows.display(), i + 1))?;
            match r.kind.as_str() {
                "segment" => {
                    let seg = lw_segment(r.segment.as_deref().unwrap_or(""));
                    out.push(TraceRow {
                        tick: r.tick,
                        actor_id: r.actor,
                        actor_kind: "buyer".into(),
                        segment: Some(seg.into()),
                        region: r.region,
                        demand: r.supply + r.unmet_demand,
                        supply: 0.0,
                        clearing_price: r.clearing_price,
                        utilisation: r.utilisation,
                        unmet_demand: r.unmet_demand,
                        capacity: None,
                        cost: None,
                        residency: Some(seg == "regulated_critical"),
                    });
                }
                "provider" => {
                    let (opex, energy) = providers.get(&r.actor).copied().unwrap_or((0.0, 0.0));
                    let ep = energy_price.get(&r.region).copied().unwrap_or(0.0);
                    let cost =
                        (opex + energy * ep * energy_mult(&r.region, r.tick)) * cost_factor(r.tick);
                    out.push(TraceRow {
                        tick: r.tick,
                        actor_id: r.actor,
                        actor_kind: "provider".into(),
                        segment: None,
                        region: r.region,
                        demand: r.demand,
                        supply: r.supply * r.utilisation,
                        clearing_price: r.clearing_price,
                        utilisation: r.utilisation,
                        unmet_demand: r.unmet_demand,
                        capacity: Some(r.supply),
                        cost: Some(cost),
                        residency: None,
                    });
                }
                "intermediary" => {}
                k => return Err(format!("{} line {}: kind {k:?}", rows.display(), i + 1)),
            }
        }
        let mut parameters = BTreeMap::new();
        parameters.insert(
            "regions".to_string(),
            serde_json::json!(energy_price.keys().collect::<Vec<_>>()),
        );
        for k in ["scenario", "mechanism", "engine", "seed"] {
            if let Some(v) = raw.get(k) {
                parameters.insert(format!("lw.{k}"), v.clone());
            }
        }
        parameters.insert(
            "lw.inside_band".into(),
            raw.pointer("/validation/inside_band")
                .cloned()
                .unwrap_or(serde_json::Value::Null),
        );
        let m = Manifest {
            seed: raw.get("seed").and_then(|v| v.as_u64()).unwrap_or(0),
            tick_seconds: 86_400,
            parameters,
            shock_schedule: schedule,
        };
        Ok(Trace::from_rows(m, out))
    }
}
