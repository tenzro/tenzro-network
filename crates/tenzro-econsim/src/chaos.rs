//! Combined and correlated shocks over decades, on the economy's ledger.
//!
//! Each seed draws a plan of shocks over the whole horizon, then runs the
//! economy ([`crate::economy::Economy`]) with the plan applied: every token
//! movement is still a transaction the VM executes, so conservation, fees,
//! issuance, staking, the reserve and the fee rate are the chain's own
//! rules under the shocks. The run is then read for the invariants it kept
//! or broke.
//!
//! The shocks, each a Poisson arrival with a size and a span drawn from
//! the seed:
//! - a TNZO price crash, falling over days and recovering part of the fall
//!   over months;
//! - a demand collapse lasting months;
//! - a temporary depeg of the stable unit, and its permanent failure;
//! - a validator exit wave: a share of bonded stake asks to leave at once;
//! - an operator exodus: a share of serving operators stops serving for a
//!   span;
//! - rate-source manipulation: a share of validators skews its reports, or
//!   one venue's quote is manipulated for every reporter;
//! - a governance-capture attempt by an accumulating holder;
//! - a bridge loss of up to the attack window of the outflow caps.
//!
//! Correlation: a price crash lifts the rate of every other shock for a
//! span after it, and may bring a depeg and an exit wave with it within
//! days.
//!
//! A seed's result is a pure function of the seed and the settings: the
//! plan and the economy draw from their own generators seeded from it, so
//! any seed replays byte for byte.
//!
//! ```text
//! tenzro-econsim chaos [--seeds N] [--first S] [--years Y] [--threads T] [--out DIR]
//! tenzro-econsim chaos --replay SEED [--years Y] [--out DIR]
//! ```

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::attack::Adversary;
use crate::economy::{
    Assumptions, Economy, MAX_SUPPLY_TNZO, Market, RunConfig, RunOutcome, YEAR_DAYS,
};

/// A kind of shock.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    /// The TNZO market price falls, then recovers part of the fall.
    PriceCrash,
    /// Demand for the network's services falls for months.
    DemandCollapse,
    /// The stable unit trades under its peg for days.
    StableDepeg,
    /// The stable unit fails for good.
    StableFailure,
    /// A share of bonded stake asks to leave at once.
    ValidatorExit,
    /// A share of serving operators stops serving for a span.
    OperatorExodus,
    /// A share of validators skews its rate reports.
    RateCartel,
    /// One venue's quote is manipulated for every reporter.
    VenueManipulation,
    /// An accumulating holder tries to pass a treasury grant to itself.
    GovernanceCapture,
    /// A bridge exploit takes up to the caps' attack window.
    BridgeLoss,
}

impl Kind {
    /// Every kind, in the order a day draws them.
    pub const ALL: [Kind; 10] = [
        Kind::PriceCrash,
        Kind::DemandCollapse,
        Kind::StableDepeg,
        Kind::StableFailure,
        Kind::ValidatorExit,
        Kind::OperatorExodus,
        Kind::RateCartel,
        Kind::VenueManipulation,
        Kind::GovernanceCapture,
        Kind::BridgeLoss,
    ];

    /// Name.
    pub fn name(self) -> &'static str {
        match self {
            Kind::PriceCrash => "price_crash",
            Kind::DemandCollapse => "demand_collapse",
            Kind::StableDepeg => "stable_depeg",
            Kind::StableFailure => "stable_failure",
            Kind::ValidatorExit => "validator_exit",
            Kind::OperatorExodus => "operator_exodus",
            Kind::RateCartel => "rate_cartel",
            Kind::VenueManipulation => "venue_manipulation",
            Kind::GovernanceCapture => "governance_capture",
            Kind::BridgeLoss => "bridge_loss",
        }
    }
}

/// One shock of a plan.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Event {
    /// Kind.
    pub kind: Kind,
    /// Day it starts.
    pub day: u32,
    /// Days it lasts: the fall of a crash, the cut of demand, the depeg,
    /// the operators' absence, the skew, the capture's accumulation.
    pub days: u32,
    /// Size: crash depth, demand cut, the stable unit's value, the share of
    /// stake, operators or validators, the share of the bridge window lost.
    pub size: f64,
    /// Second figure: the share of a crash's fall recovered, the factor a
    /// rate shock applies, the honest turnout against a capture.
    pub factor: f64,
    /// Days a crash takes to recover.
    pub tail_days: u32,
    /// Grant a capture asks for, whole TNZO.
    pub amount: f64,
    /// Whether a price crash brought it.
    pub joint: bool,
}

/// Arrival rates (per year), sizes and spans of the shocks, and how they
/// correlate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Shocks {
    /// Price crash: rate, depth, days of the fall, share of the fall
    /// recovered, days of the recovery.
    pub crash_per_year: f64,
    pub crash_depth: (f64, f64),
    pub crash_days: (u32, u32),
    pub crash_recovery: (f64, f64),
    pub crash_recovery_days: (u32, u32),
    /// Demand collapse: rate, cut, months.
    pub demand_per_year: f64,
    pub demand_cut: (f64, f64),
    pub demand_months: (u32, u32),
    /// Temporary depeg: rate, value of the unit, days.
    pub depeg_per_year: f64,
    pub depeg_to: (f64, f64),
    pub depeg_days: (u32, u32),
    /// Permanent failure of the stable unit: rate, value of the unit.
    pub failure_per_year: f64,
    pub failure_to: (f64, f64),
    /// Validator exit wave: rate, share of bonded stake.
    pub exit_per_year: f64,
    pub exit_share: (f64, f64),
    /// Operator exodus: rate, share of serving operators, days away.
    pub exodus_per_year: f64,
    pub exodus_share: (f64, f64),
    pub exodus_days: (u32, u32),
    /// Rate cartel: rate, share of validators, factor, days.
    pub cartel_per_year: f64,
    pub cartel_share: (f64, f64),
    pub cartel_factor: (f64, f64),
    pub cartel_days: (u32, u32),
    /// Venue manipulation: rate, factor on one venue, days.
    pub venue_per_year: f64,
    pub venue_factor: (f64, f64),
    pub venue_days: (u32, u32),
    /// Governance capture: rate, share of validators reached, honest
    /// turnout, grant asked (log10 of whole TNZO), days of accumulation.
    pub capture_per_year: f64,
    pub capture_share: (f64, f64),
    pub capture_turnout: (f64, f64),
    pub capture_grant_log10: (f64, f64),
    pub capture_days: u32,
    /// Bridge loss: rate, share of the attack window's caps.
    pub bridge_per_year: f64,
    pub bridge_share: (f64, f64),
    /// Correlation: a crash multiplies every other rate by `lift` for
    /// `lift_days`, and brings a depeg and an exit wave within `joint_lag`
    /// days with these probabilities. `correlated: false` draws every kind
    /// independently.
    pub correlated: bool,
    pub lift: f64,
    pub lift_days: u32,
    pub joint_depeg: f64,
    pub joint_exit: f64,
    pub joint_lag: u32,
}

impl Default for Shocks {
    fn default() -> Self {
        Self {
            crash_per_year: 0.3,
            crash_depth: (0.5, 0.95),
            crash_days: (1, 30),
            crash_recovery: (0.0, 1.0),
            crash_recovery_days: (90, 720),
            demand_per_year: 0.1,
            demand_cut: (0.5, 0.95),
            demand_months: (6, 36),
            depeg_per_year: 0.2,
            depeg_to: (0.85, 0.97),
            depeg_days: (1, 5),
            failure_per_year: 0.02,
            failure_to: (0.0, 0.3),
            exit_per_year: 0.1,
            exit_share: (0.1, 0.4),
            exodus_per_year: 0.1,
            exodus_share: (0.1, 0.5),
            exodus_days: (30, 365),
            cartel_per_year: 0.25,
            cartel_share: (0.1, 0.45),
            cartel_factor: (0.85, 1.15),
            cartel_days: (1, 90),
            venue_per_year: 0.25,
            venue_factor: (0.5, 2.0),
            venue_days: (1, 30),
            capture_per_year: 0.05,
            capture_share: (0.2, 0.4),
            capture_turnout: (0.3, 0.9),
            capture_grant_log10: (3.0, 7.0),
            capture_days: 365,
            bridge_per_year: 0.05,
            bridge_share: (0.2, 1.0),
            correlated: true,
            lift: 3.0,
            lift_days: 90,
            joint_depeg: 0.3,
            joint_exit: 0.3,
            joint_lag: 7,
        }
    }
}

impl Shocks {
    /// No shocks at all: the baseline the shocked runs are read against.
    pub fn calm() -> Self {
        Self {
            crash_per_year: 0.0,
            demand_per_year: 0.0,
            depeg_per_year: 0.0,
            failure_per_year: 0.0,
            exit_per_year: 0.0,
            exodus_per_year: 0.0,
            cartel_per_year: 0.0,
            venue_per_year: 0.0,
            capture_per_year: 0.0,
            bridge_per_year: 0.0,
            ..Self::default()
        }
    }

    fn rate(&self, k: Kind) -> f64 {
        match k {
            Kind::PriceCrash => self.crash_per_year,
            Kind::DemandCollapse => self.demand_per_year,
            Kind::StableDepeg => self.depeg_per_year,
            Kind::StableFailure => self.failure_per_year,
            Kind::ValidatorExit => self.exit_per_year,
            Kind::OperatorExodus => self.exodus_per_year,
            Kind::RateCartel => self.cartel_per_year,
            Kind::VenueManipulation => self.venue_per_year,
            Kind::GovernanceCapture => self.capture_per_year,
            Kind::BridgeLoss => self.bridge_per_year,
        }
    }

    /// One event of kind `k` starting on `day`.
    fn event(&self, k: Kind, day: u32, rng: &mut StdRng) -> Event {
        let u = |rng: &mut StdRng, (a, b): (f64, f64)| {
            if b > a { rng.gen_range(a..b) } else { a }
        };
        let n = |rng: &mut StdRng, (a, b): (u32, u32)| {
            if b > a { rng.gen_range(a..=b) } else { a }
        };
        let mut e = Event {
            kind: k,
            day,
            days: 1,
            size: 0.0,
            factor: 1.0,
            tail_days: 0,
            amount: 0.0,
            joint: false,
        };
        match k {
            Kind::PriceCrash => {
                e.size = u(rng, self.crash_depth);
                e.days = n(rng, self.crash_days);
                e.factor = u(rng, self.crash_recovery);
                e.tail_days = n(rng, self.crash_recovery_days);
            }
            Kind::DemandCollapse => {
                e.size = u(rng, self.demand_cut);
                e.days = (n(rng, self.demand_months) as f64 * 30.44).round() as u32;
            }
            Kind::StableDepeg => {
                e.size = u(rng, self.depeg_to);
                e.days = n(rng, self.depeg_days);
            }
            Kind::StableFailure => {
                e.size = u(rng, self.failure_to);
                e.days = u32::MAX - day;
            }
            Kind::ValidatorExit => e.size = u(rng, self.exit_share),
            Kind::OperatorExodus => {
                e.size = u(rng, self.exodus_share);
                e.days = n(rng, self.exodus_days);
            }
            Kind::RateCartel => {
                e.size = u(rng, self.cartel_share);
                e.factor = u(rng, self.cartel_factor);
                e.days = n(rng, self.cartel_days);
            }
            Kind::VenueManipulation => {
                e.size = 1.0;
                e.factor = u(rng, self.venue_factor);
                e.days = n(rng, self.venue_days);
            }
            Kind::GovernanceCapture => {
                e.size = u(rng, self.capture_share);
                e.factor = u(rng, self.capture_turnout);
                e.amount = 10f64.powf(u(rng, self.capture_grant_log10)).round();
                e.days = self.capture_days;
            }
            Kind::BridgeLoss => e.size = u(rng, self.bridge_share),
        }
        e
    }
}

/// A rate shock in force.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RateShock {
    /// Share of bonded validators that skew (a cartel).
    pub share: f64,
    /// Factor on the reported rate.
    pub factor: f64,
    /// Whether one venue's quote is manipulated for every reporter.
    pub venue: bool,
}

/// The shocks of one run, in start order.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Plan {
    /// Days the run lasts.
    pub days: u32,
    /// Events by start day.
    pub events: Vec<Event>,
}

/// The plan's generator seed: its own stream, apart from the economy's.
fn plan_seed(seed: u64) -> u64 {
    seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ 0x6368_616f_7370_6c61
}

impl Plan {
    /// Draws the plan of `seed` over `days`.
    pub fn draw(seed: u64, days: u32, s: &Shocks) -> Plan {
        let mut rng = StdRng::seed_from_u64(plan_seed(seed));
        let mut events = Vec::new();
        let mut lift_until: Option<u32> = None;
        let mut captured = false;
        for day in 0..days {
            let lifted = s.correlated && lift_until.is_some_and(|d| day <= d);
            for k in Kind::ALL {
                let mult = if lifted && k != Kind::PriceCrash {
                    s.lift
                } else {
                    1.0
                };
                let p = 1.0 - (-s.rate(k) * mult / YEAR_DAYS).exp();
                let hit = rng.gen_range(0.0..1.0) < p;
                if !hit || (k == Kind::GovernanceCapture && captured) {
                    continue;
                }
                captured |= k == Kind::GovernanceCapture;
                events.push(s.event(k, day, &mut rng));
                if k == Kind::PriceCrash && s.correlated {
                    lift_until = Some(day + s.lift_days);
                    for (kind, p) in [
                        (Kind::StableDepeg, s.joint_depeg),
                        (Kind::ValidatorExit, s.joint_exit),
                    ] {
                        let joins = rng.gen_range(0.0..1.0) < p;
                        let lag = rng.gen_range(0..=s.joint_lag);
                        if joins && day + lag < days {
                            let mut e = s.event(kind, day + lag, &mut rng);
                            e.joint = true;
                            events.push(e);
                        }
                    }
                }
            }
        }
        events.sort_by_key(|e| (e.day, e.kind));
        Plan { days, events }
    }

    fn active(&self, day: f64) -> impl Iterator<Item = &Event> {
        self.events
            .iter()
            .filter(move |e| day >= e.day as f64 && day < e.day as f64 + e.days as f64)
    }

    /// Demand multiple the shocks leave on `day`.
    pub fn demand_factor(&self, day: f64) -> f64 {
        self.active(day)
            .filter(|e| e.kind == Kind::DemandCollapse)
            .fold(1.0, |f, e| f * (1.0 - e.size))
    }

    /// Price move at the open of `day`: the crashes falling that day, and
    /// the recoveries under way.
    pub fn price_factor(&self, day: u32) -> f64 {
        let mut f = 1.0;
        for e in self.events.iter().filter(|e| e.kind == Kind::PriceCrash) {
            let fall_end = e.day + e.days.max(1);
            let keep = (1.0 - e.size).max(1e-6);
            if day >= e.day && day < fall_end {
                f *= keep.powf(1.0 / e.days.max(1) as f64);
            } else if e.tail_days > 0 && day >= fall_end && day < fall_end + e.tail_days {
                f *= keep.powf(-e.factor / e.tail_days as f64);
            }
        }
        f
    }

    /// The stable unit's value on `day`, USD.
    pub fn peg(&self, day: f64) -> f64 {
        self.active(day)
            .filter(|e| matches!(e.kind, Kind::StableDepeg | Kind::StableFailure))
            .fold(1.0, |p: f64, e| p.min(e.size))
    }

    /// Share of bonded stake that asks to leave at the open of `day`.
    pub fn validator_exit(&self, day: u32) -> Option<f64> {
        let s: f64 = self
            .events
            .iter()
            .filter(|e| e.kind == Kind::ValidatorExit && e.day == day)
            .map(|e| e.size)
            .sum();
        (s > 0.0).then_some(s.min(0.9))
    }

    /// Share of serving operators that leave at the open of `day`, and the
    /// days they stay away.
    pub fn operator_exit(&self, day: u32) -> Option<(f64, u32)> {
        self.events
            .iter()
            .filter(|e| e.kind == Kind::OperatorExodus && e.day == day)
            .map(|e| (e.size, e.days))
            .reduce(|a, b| ((a.0 + b.0).min(0.9), a.1.max(b.1)))
    }

    /// The rate shock in force on `day`: the one that moves the rate most.
    pub fn rate_shock(&self, day: f64) -> Option<RateShock> {
        self.active(day)
            .filter(|e| matches!(e.kind, Kind::RateCartel | Kind::VenueManipulation))
            .max_by(|a, b| {
                (a.factor.ln().abs())
                    .total_cmp(&b.factor.ln().abs())
                    .then(a.day.cmp(&b.day))
            })
            .map(|e| RateShock {
                share: e.size,
                factor: e.factor,
                venue: e.kind == Kind::VenueManipulation,
            })
    }

    /// The governance-capture attempt, if the plan has one.
    pub fn capture(&self) -> Option<&Event> {
        self.events
            .iter()
            .find(|e| e.kind == Kind::GovernanceCapture)
    }

    /// Events of each kind.
    pub fn counts(&self) -> BTreeMap<String, u32> {
        let mut m: BTreeMap<String, u32> = Kind::ALL
            .iter()
            .map(|k| (k.name().to_string(), 0))
            .collect();
        for e in &self.events {
            *m.entry(e.kind.name().to_string()).or_default() += 1;
        }
        m
    }
}

/// Bounds the invariants are read against.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Limits {
    /// Days after genesis before operator, security and rate figures count.
    pub warmup_days: u32,
    /// The fee rate counts as off when further than this from the market.
    pub rate_band: f64,
    /// Most consecutive days the fee rate may sit off.
    pub rate_off_days: u32,
    /// Most consecutive days the running-cost reserve may sit empty.
    pub reserve_empty_days: u32,
    /// Fewest serving operators.
    pub operators_min: u32,
    /// Fewest bonded validators after warmup: the governed floor seats of
    /// the run, filled in when it starts.
    #[serde(default)]
    pub validators_floor: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            warmup_days: 30,
            rate_band: 0.10,
            rate_off_days: 30,
            reserve_empty_days: 30,
            operators_min: 1,
            validators_floor: SECURITY_FLOOR,
        }
    }
}

/// Everything a chaos run depends on besides its seed.
#[derive(Debug, Clone)]
pub struct Settings {
    /// Days each run lasts.
    pub days: u32,
    /// Market, assumptions, governed parameters and sampling of each run.
    pub base: RunConfig,
    /// The shocks.
    pub shocks: Shocks,
    /// The invariants' bounds.
    pub limits: Limits,
}

impl Settings {
    /// `years` of the flat market under the realistic assumptions, with
    /// payments and the treasury leg in the stable unit, the fee rate
    /// following validators' reports, and the default shocks. One sampled
    /// human transfer a block and two sampled streams stand for the rest
    /// by weight, as every run samples them: decades of hourly blocks over
    /// many seeds need the lighter sample.
    pub fn new(years: f64) -> Settings {
        let days = (years * YEAR_DAYS).round() as u32;
        let mut base = RunConfig::scenario(Market::Flat, 0, days);
        base.assumptions = Assumptions::preset("realistic").expect("preset");
        base.assumptions.stable_settlement = true;
        base.assumptions.stable_asset = true;
        // The treasury leg is collected by the chain in the payment token,
        // on every settled payment, and the chain pays the validators'
        // running cost from it through the validator cover reserve.
        base.assumptions.stable_leg = false;
        // At launch the treasury sponsors the floor's seats with the TNZO it
        // already holds, until paid usage covers them: SPONSORED_SEATS
        // approved operators, topped up to the governed cost, and sponsorship
        // plus grants together held to SPONSOR_CAP_BPS_YEAR of the opening
        // treasury a year. Governance sets both; nothing is issued.
        base.assumptions.sponsor_seats = SPONSORED_SEATS;
        base.assumptions.sponsor_cap_bps_year = SPONSOR_CAP_BPS_YEAR;
        // The sponsorship runs through the chain's gates: the seats are
        // approved operators, a verified hour is worth the governed running
        // cost of an hour, and the yearly USD caps and the one-payment
        // exception are set by governance, from the cost the seats are
        // sponsored to.
        base.assumptions.sponsor_gated = true;
        base.assumptions.reserve_seed_tnzo = RESERVE_SEED_TNZO;
        base.rate_reports = true;
        base.human_sample_per_block = 1;
        base.stream_sample = 2;
        base.network_params.insert("fees.usd_rate_mode".into(), 1);
        // The treasury legs on inference and compute payments are the
        // governed values in force at launch (set by the genesis
        // parameter proposals): TREASURY_LEG_BPS.
        base.network_params
            .insert("fees.treasury_leg_inference_bps".into(), TREASURY_LEG_BPS);
        base.network_params
            .insert("fees.treasury_leg_compute_bps".into(), TREASURY_LEG_BPS);
        let mut s = Settings {
            days,
            base,
            shocks: Shocks::default(),
            limits: Limits::default(),
        };
        s.govern_sponsorship();
        s
    }

    /// Governance sets the sponsorship's USD terms from the running cost the
    /// seats are sponsored to: a verified hour is worth an hour of that cost,
    /// the yearly caps cover the seats' whole year, and the one-payment
    /// exception is the governed [`PROPOSAL_EXCEPTION_BPS`].
    pub fn govern_sponsorship(&mut self) {
        let hourly_usd = self.base.assumptions.validator_cost_usd_month * 12.0 / (365.0 * 24.0);
        let yearly_usd = (SPONSORED_SEATS as f64 * hourly_usd * 365.0 * 24.0).ceil() as u64;
        for (key, value) in [
            (
                "sponsorship.running_cost_per_verified_epoch_usd_e6",
                (hourly_usd * 1e6).floor() as u64,
            ),
            ("sponsorship.yearly_max_usd", yearly_usd),
            ("treasury.sponsorship_grants_yearly_max_usd", yearly_usd),
            ("grants.per_grantee_yearly_max_usd", yearly_usd / 12),
            (
                "treasury.proposal_outflow_exception_bps",
                PROPOSAL_EXCEPTION_BPS,
            ),
        ] {
            self.base.network_params.insert(key.into(), value);
        }
    }

    /// The same settings with no sponsorship: what the validator floor does
    /// when paid usage alone has to fund the seats.
    pub fn without_sponsorship(&self) -> Settings {
        let mut s = self.clone();
        s.base.assumptions.sponsor_seats = 0;
        s.base.assumptions.sponsor_cap_bps_year = 0.0;
        s
    }

    /// The run configuration of `seed`, with its plan.
    pub fn config(&self, seed: u64) -> RunConfig {
        let plan = Plan::draw(seed, self.days, &self.shocks);
        let mut c = self.base.clone();
        c.seed = seed;
        c.days = self.days;
        if c.adversary.is_none()
            && let Some(e) = plan.capture().filter(|e| e.day + e.days < self.days)
        {
            c.adversary = Some(Adversary::GovernanceCapture {
                start_day: e.day + e.days,
                attackers: ((c.assumptions.validators as f64 * e.size).round() as u32).max(1),
                honest_turnout: e.factor,
                grant_tnzo: e.amount,
                stake_share: e.size,
            });
        }
        c.chaos = Some(Arc::new(plan));
        c
    }
}

/// What one seed's run kept and broke.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SeedResult {
    /// At the end of each simulated year: bonded validators, the security
    /// ratio (bps) and the price (USD).
    pub yearly: Vec<YearEnd>,
    /// Seed.
    pub seed: u64,
    /// Days simulated.
    pub days: u32,
    /// Shocks of each kind.
    pub shocks: BTreeMap<String, u32>,
    /// Every invariant held.
    pub pass: bool,
    /// The invariants it broke.
    pub broken: Vec<String>,
    /// Value conservation: blocks the VM's value check refused, reserve
    /// rules and stable-token conservation broken.
    pub conservation_breaks: u64,
    pub first_break: Option<String>,
    /// Supply bounds: least and most total supply, TNZO; days burned fell.
    pub supply_min_tnzo: f64,
    pub supply_max_tnzo: f64,
    pub burned_fell_days: u32,
    /// Security budget: least security ratio and the governed least, bps;
    /// days under it; days the ratio could not be read.
    pub security_ratio_min_bps: u64,
    pub min_ratio_bps: u64,
    pub security_days_under: u32,
    pub security_days_unknown: u32,
    /// Least bonded stake and bonded validators.
    pub bonded_min_tnzo: f64,
    pub validators_min: u32,
    /// First day after warmup with fewer bonded validators than the floor
    /// (`None`: never).
    #[serde(default)]
    pub floor_first_miss_day: Option<u32>,
    /// Least share of validators whose trailing income covered cost.
    pub validators_profitable_min: f64,
    /// The governed floor seats the run was measured against.
    #[serde(default)]
    pub validators_floor: u32,
    /// Least months of grants the treasury held, and least rewards pool,
    /// TNZO, after warmup.
    #[serde(default)]
    pub treasury_runway_min_months: f64,
    #[serde(default)]
    pub rewards_pool_min_tnzo: f64,
    /// Sponsorship the treasury paid to validators, TNZO; the most it paid
    /// out in any year in sponsorship and grants together, and the combined
    /// cap (zero: none set).
    #[serde(default)]
    pub sponsored_tnzo_total: f64,
    /// Sponsorship the treasury paid in the stable asset through the
    /// chain's gates, USD.
    pub sponsored_usd_total: f64,
    #[serde(default)]
    pub sponsor_grant_outflow_year_max_tnzo: f64,
    #[serde(default)]
    pub sponsor_grant_cap_tnzo: f64,
    /// Operator viability: fewest serving operators, longest run of days
    /// with none, least share of operators whose income covered cost.
    pub operators_min: u32,
    pub operators_none_days_max: u32,
    pub operators_profitable_min: f64,
    /// Treasury and insurance: least treasury and insurance pool, TNZO;
    /// longest run of days with the running-cost reserve empty; the
    /// treasury's most share in the stable unit by value; bridge losses,
    /// the largest, and the least cover of one by the insurance pool.
    pub treasury_min_tnzo: f64,
    pub insurance_min_tnzo: f64,
    pub reserve_empty_days_max: u32,
    pub treasury_stable_share_max: f64,
    pub bridge_losses: u32,
    pub bridge_loss_max_tnzo: f64,
    pub bridge_cover_min: Option<f64>,
    /// Fee-rate stability: longest run of days the chain's rate sat
    /// further than the band from the market price; largest gap.
    pub rate_off_days_max: u32,
    pub rate_gap_max: f64,
    /// Governance: whether a capture was attempted and whether it paid.
    pub capture_attempted: bool,
    pub capture_succeeded: bool,
    /// The capture attempt's parameters and what it measured.
    pub capture: Option<serde_json::Value>,
    /// Price and demand extremes.
    pub price_min_usd: f64,
    pub price_end_usd: f64,
    pub demand_min: f64,
    /// Transactions the ledger refused.
    pub refused: u64,
    /// SHA-256 over the daily records, the failures and the adversary's
    /// outcome: equal digests mean the same run.
    pub digest: String,
}

/// One year-end of a run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct YearEnd {
    /// Year, from 1.
    pub year: u32,
    /// Bonded validators.
    pub validators: u32,
    /// Security ratio, bps (`None`: a unit unpriced).
    pub security_ratio_bps: Option<u64>,
    /// Price, USD.
    pub price_usd: f64,
    /// Rewards pool and treasury, TNZO; months of grants the treasury holds.
    #[serde(default)]
    pub rewards_pool_tnzo: f64,
    #[serde(default)]
    pub treasury_tnzo: f64,
    #[serde(default)]
    pub treasury_runway_months: f64,
}

/// Months of runway as a finite figure: a treasury that grants nothing has
/// no end to its runway.
fn runway(m: f64) -> f64 {
    if m.is_finite() { m.min(1e9) } else { 1e9 }
}

/// Longest run of consecutive `true`s.
fn longest(it: impl Iterator<Item = bool>) -> u32 {
    let (mut run, mut best) = (0u32, 0u32);
    for b in it {
        run = if b { run + 1 } else { 0 };
        best = best.max(run);
    }
    best
}

/// Reads a finished run for its invariants.
pub fn measure(seed: u64, plan: &Plan, o: &RunOutcome, l: &Limits) -> SeedResult {
    let days = &o.days;
    let warm = |i: usize| i as u32 >= l.warmup_days;
    let mut h = Sha256::new();
    h.update(serde_json::to_vec(days).expect("days serialise"));
    h.update(serde_json::to_vec(&o.ledger_failures).expect("failures serialise"));
    h.update(serde_json::to_vec(&o.reserve_breaks).expect("breaks serialise"));
    h.update(serde_json::to_vec(&o.adversary).expect("adversary serialises"));
    let digest = hex::encode(h.finalize());

    let conservation_breaks = (o.ledger_failures.len() + o.reserve_breaks.len()) as u64;
    let first_break = o
        .ledger_failures
        .first()
        .or(o.reserve_breaks.first())
        .cloned();
    let fold = |f: &dyn Fn(&crate::economy::Day) -> f64, min: bool| {
        days.iter()
            .enumerate()
            .filter(|(i, _)| warm(*i))
            .map(|(_, d)| f(d))
            .fold(
                if min {
                    f64::INFINITY
                } else {
                    f64::NEG_INFINITY
                },
                |a, b| if min { a.min(b) } else { a.max(b) },
            )
    };
    let finite = |x: f64| if x.is_finite() { x } else { 0.0 };
    let supply_min = days
        .iter()
        .map(|d| d.snap.supply)
        .fold(f64::INFINITY, f64::min);
    let supply_max = days.iter().map(|d| d.snap.supply).fold(0.0, f64::max);
    let burned_fell_days = days
        .windows(2)
        .filter(|w| w[1].snap.burned + 1e-9 < w[0].snap.burned)
        .count() as u32;
    let mut ratio_min = u64::MAX;
    let mut under = 0;
    let mut unknown = 0;
    let mut min_ratio = 0;
    for (i, d) in days.iter().enumerate() {
        min_ratio = min_ratio.max(d.min_ratio_bps);
        if !warm(i) {
            continue;
        }
        match d.security_ratio_bps {
            Some(r) => {
                ratio_min = ratio_min.min(r);
                if r < d.min_ratio_bps {
                    under += 1;
                }
            }
            None => unknown += 1,
        }
    }
    let rate_off =
        |d: &crate::economy::Day| (d.chain_rate_usd / d.price_usd.max(1e-12) - 1.0).abs();
    let rate_off_days_max = longest(
        days.iter()
            .enumerate()
            .map(|(i, d)| warm(i) && rate_off(d) > l.rate_band),
    );
    let reserve_empty_days_max = longest(
        days.iter()
            .enumerate()
            .map(|(i, d)| warm(i) && d.snap.reserve < 1.0),
    );
    let operators_none_days_max = longest(
        days.iter()
            .enumerate()
            .map(|(i, d)| warm(i) && d.providers == 0),
    );
    let last = days.last();
    let treasury_stable_share_max = fold(
        &|d| {
            let total = d.treasury_stable_usd + d.snap.treasury * d.price_usd;
            if total > 0.0 {
                d.treasury_stable_usd / total
            } else {
                0.0
            }
        },
        false,
    );
    let mut bridge_losses = 0;
    let mut bridge_loss_max_tnzo: f64 = 0.0;
    let mut bridge_cover_min: Option<f64> = None;
    for e in plan.events.iter().filter(|e| e.kind == Kind::BridgeLoss) {
        let Some(d) = days.get(e.day as usize) else {
            continue;
        };
        let loss = e.size * d.extractable_tnzo;
        bridge_losses += 1;
        bridge_loss_max_tnzo = bridge_loss_max_tnzo.max(loss);
        if loss > 0.0 {
            let cover = d.snap.insurance_pool / loss;
            bridge_cover_min = Some(bridge_cover_min.map_or(cover, |c: f64| c.min(cover)));
        }
    }
    // An attempt counts once its proposal went in.
    let (capture_attempted, capture_succeeded) = match &o.adversary {
        Some(a)
            if plan.capture().is_some() && a.detail.contains_key("treasury_at_proposal_tnzo") =>
        {
            (true, a.succeeded)
        }
        _ => (false, false),
    };

    let yearly: Vec<YearEnd> = (1..)
        .map(|y: u32| (y, (y as f64 * YEAR_DAYS).round() as usize))
        .take_while(|(_, i)| *i <= days.len())
        .map(|(year, i)| {
            let d = &days[i - 1];
            YearEnd {
                year,
                validators: d.snap.bonded_validators,
                security_ratio_bps: d.security_ratio_bps,
                price_usd: d.price_usd,
                rewards_pool_tnzo: d.snap.rewards_pool,
                treasury_tnzo: d.snap.treasury,
                treasury_runway_months: runway(d.treasury_runway_months),
            }
        })
        .collect();
    let mut r = SeedResult {
        yearly,
        seed,
        days: days.len() as u32,
        shocks: plan.counts(),
        pass: true,
        broken: Vec::new(),
        conservation_breaks,
        first_break,
        supply_min_tnzo: finite(supply_min),
        supply_max_tnzo: supply_max,
        burned_fell_days,
        security_ratio_min_bps: ratio_min,
        min_ratio_bps: min_ratio,
        security_days_under: under,
        security_days_unknown: unknown,
        bonded_min_tnzo: finite(fold(&|d| d.snap.bonded, true)),
        validators_min: finite(fold(&|d| d.snap.bonded_validators as f64, true)) as u32,
        floor_first_miss_day: days
            .iter()
            .enumerate()
            .find(|(i, d)| warm(*i) && d.snap.bonded_validators < l.validators_floor)
            .map(|(i, _)| i as u32),
        validators_profitable_min: finite(fold(&|d| d.validators_profitable, true)),
        validators_floor: l.validators_floor,
        treasury_runway_min_months: runway(fold(&|d| runway(d.treasury_runway_months), true)),
        rewards_pool_min_tnzo: finite(fold(&|d| d.snap.rewards_pool, true)),
        sponsored_tnzo_total: days.last().map_or(0.0, |d| d.sponsored_tnzo_total),
        sponsored_usd_total: days.last().map_or(0.0, |d| d.sponsored_usd_total),
        sponsor_grant_outflow_year_max_tnzo: days
            .iter()
            .map(|d| d.sponsor_grant_outflow_year_tnzo)
            .fold(0.0, f64::max),
        sponsor_grant_cap_tnzo: days.last().map_or(0.0, |d| d.sponsor_grant_cap_tnzo),
        operators_min: finite(fold(&|d| d.providers as f64, true)) as u32,
        operators_none_days_max,
        operators_profitable_min: finite(fold(&|d| d.providers_profitable, true)),
        treasury_min_tnzo: finite(fold(&|d| d.snap.treasury, true)),
        insurance_min_tnzo: finite(fold(&|d| d.snap.insurance_pool, true)),
        reserve_empty_days_max,
        treasury_stable_share_max: finite(treasury_stable_share_max),
        bridge_losses,
        bridge_loss_max_tnzo,
        bridge_cover_min,
        rate_off_days_max,
        rate_gap_max: finite(fold(&rate_off, false)),
        capture_attempted,
        capture_succeeded,
        capture: o
            .adversary
            .as_ref()
            .filter(|_| capture_attempted)
            .map(|a| serde_json::json!({ "params": a.params, "profit_tnzo": a.profit_tnzo, "detail": a.detail })),
        price_min_usd: finite(
            days.iter()
                .map(|d| d.price_usd)
                .fold(f64::INFINITY, f64::min),
        ),
        price_end_usd: last.map_or(0.0, |d| d.price_usd),
        demand_min: finite(days.iter().map(|d| d.demand).fold(f64::INFINITY, f64::min)),
        refused: o.refusals.values().sum(),
        digest,
    };
    let mut broken = Vec::new();
    if r.conservation_breaks > 0 {
        broken.push("value_conservation");
    }
    if r.supply_max_tnzo > MAX_SUPPLY_TNZO || r.supply_min_tnzo <= 0.0 || r.burned_fell_days > 0 {
        broken.push("supply_bounds");
    }
    if r.security_days_under > 0 {
        broken.push("security_budget");
    }
    if r.operators_min < l.operators_min {
        broken.push("operator_viability");
    }
    if r.validators_min < l.validators_floor {
        broken.push("validator_floor");
    }
    if r.reserve_empty_days_max > l.reserve_empty_days || r.capture_succeeded {
        broken.push("treasury_insurance_solvency");
    }
    if r.rate_off_days_max > l.rate_off_days {
        broken.push("fee_rate_stability");
    }
    r.pass = broken.is_empty();
    r.broken = broken.into_iter().map(String::from).collect();
    r
}

/// Runs one seed.
pub fn run_seed(seed: u64, s: &Settings) -> SeedResult {
    run_config(s.config(seed), &s.limits)
}

/// Runs a configuration that carries its plan.
pub fn run_config(c: RunConfig, l: &Limits) -> SeedResult {
    let seed = c.seed;
    let mut l = l.clone();
    l.validators_floor = l.validators_floor.min(c.assumptions.validators);
    let l = &l;
    let plan = c.chaos.clone().expect("a chaos run carries its plan");
    let o = Economy::new(c).run();
    measure(seed, &plan, &o, l)
}

/// Runs `jobs` on `threads` threads; `sink` receives each result as it
/// finishes, on the calling thread. Each result depends on its job alone,
/// whatever the thread count or the order jobs finish in.
pub fn run_parallel<J: Sync, R: Send>(
    jobs: &[J],
    threads: usize,
    run: impl Fn(&J) -> R + Sync,
    mut sink: impl FnMut(&J, R),
) {
    let next = AtomicU64::new(0);
    let (tx, rx) = std::sync::mpsc::channel::<(usize, R)>();
    std::thread::scope(|scope| {
        for _ in 0..threads.max(1).min(jobs.len().max(1)) {
            let tx = tx.clone();
            let (next, run) = (&next, &run);
            scope.spawn(move || {
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed) as usize;
                    let Some(job) = jobs.get(i) else {
                        break;
                    };
                    if tx.send((i, run(job))).is_err() {
                        break;
                    }
                }
            });
        }
        drop(tx);
        for (i, r) in rx {
            sink(&jobs[i], r);
        }
    });
}

/// Runs `seeds` on `threads` threads; `sink` receives each result as it
/// finishes, on the calling thread.
pub fn run_many(seeds: &[u64], s: &Settings, threads: usize, mut sink: impl FnMut(SeedResult)) {
    run_parallel(seeds, threads, |seed| run_seed(*seed, s), |_, r| sink(r));
}

/// Validators the set must keep after warmup: two faults tolerated.
pub const SECURITY_FLOOR: u32 = 7;

/// Validators the treasury sponsors at launch: the floor's seats and the
/// most one exit shock takes from a set (40% of the stake), so a single
/// exodus leaves the floor standing: 12 seats lose 5 and keep 7.
pub const SPONSORED_SEATS: u32 = 12;

/// The running-cost reserve the treasury seeds at launch, whole TNZO. With
/// fees settled in a stable asset the reserve is not filled from fee
/// revenue, and the chain holds every discretionary treasury payment,
/// sponsorship included, while the reserve is under half its target; the
/// seed keeps it above that floor.
pub const RESERVE_SEED_TNZO: f64 = 3_000_000.0;

/// Governed treasury leg on inference and compute payments, bps of what the
/// provider is credited: the share of paid usage that fills the validator
/// cover reserve. The flat market pays about 5,500 USD a day; 2,500 bps
/// holds the validator floor over seeds 1 to 3 (2,000 holds it at seed 1).
pub const TREASURY_LEG_BPS: u64 = 2_500;

/// Governed headroom above the stable period outflow limit one sponsorship
/// payment may ask for, bps of the period's opening stable holdings: a fifth
/// of the 500 bps the registry allows, zero at genesis until governance
/// sets it.
pub const PROPOSAL_EXCEPTION_BPS: u64 = 100;

/// Combined yearly cap on sponsorship and grants, bps of the opening
/// treasury: the runway simulation's recommended 10%, below the chain's
/// 31% yearly drain limit.
pub const SPONSOR_CAP_BPS_YEAR: f64 = 1_000.0;
/// Outside holders' demand levels of the sweep: none. Demand is paid usage
/// only; nobody's net buying of TNZO is an input any run needs.
pub const HOLDER_DEMAND: [(&str, f64); 1] = [("none", 0.0)];
/// Grant sell shares of the sweep.
pub const GRANT_SELL: [f64; 3] = [0.0, 0.25, 1.0];
/// Validator running costs of the sweep, USD a month.
pub const VALIDATOR_COST: [f64; 3] = [0.0, 750.0, 1_500.0];
/// Network demand multiples of the sweep (compute, agent tasks and human
/// transfers together).
pub const NETWORK_DEMAND: [f64; 3] = [1.0, 10.0, 100.0];

/// One cell of the input sweep: inputs the economy's result depends on
/// and nobody can know in advance.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Cell {
    /// Position in [`sweep_cells`].
    pub index: usize,
    /// Share of each treasury grant its grantee sells.
    pub grant_sell_share: f64,
    /// Each validator's running cost, USD a month.
    pub validator_cost_usd_month: f64,
    /// Outside holders' demand level and its net buying, USD a day.
    pub holder_demand: String,
    pub holder_buy_usd_day: f64,
    /// Multiple of the preset's network demand.
    pub network_demand: f64,
}

/// Every cell, grant share slowest, network demand fastest.
pub fn sweep_cells() -> Vec<Cell> {
    let mut cells = Vec::new();
    for g in GRANT_SELL {
        for c in VALIDATOR_COST {
            for (h, usd) in HOLDER_DEMAND {
                for k in NETWORK_DEMAND {
                    cells.push(Cell {
                        index: cells.len(),
                        grant_sell_share: g,
                        validator_cost_usd_month: c,
                        holder_demand: h.to_string(),
                        holder_buy_usd_day: usd,
                        network_demand: k,
                    });
                }
            }
        }
    }
    cells
}

impl Cell {
    /// The middle level of every axis: a quarter of grants sold, $750 a
    /// month per validator, no holder demand, ten times the preset's
    /// network demand.
    pub fn central() -> Cell {
        sweep_cells()
            .into_iter()
            .find(|c| {
                c.grant_sell_share == GRANT_SELL[1]
                    && c.validator_cost_usd_month == VALIDATOR_COST[1]
                    && c.holder_buy_usd_day == HOLDER_DEMAND[0].1
                    && c.network_demand == NETWORK_DEMAND[1]
            })
            .expect("central cell")
    }

    /// Short name.
    pub fn label(&self) -> String {
        format!(
            "grants sold {:.0}%, validator ${:.0}/month, holders {}, demand {}x",
            self.grant_sell_share * 100.0,
            self.validator_cost_usd_month,
            self.holder_demand,
            self.network_demand
        )
    }

    /// `base` with this cell's inputs.
    pub fn settings(&self, base: &Settings) -> Settings {
        let mut s = base.clone();
        let a = &mut s.base.assumptions;
        a.grant_sell_share = self.grant_sell_share;
        a.validator_cost_usd_month = self.validator_cost_usd_month;
        a.holder_buy_usd_day = self.holder_buy_usd_day;
        a.compute_usd_per_day *= self.network_demand;
        a.agent_tasks_per_day *= self.network_demand;
        a.human_tx_per_day *= self.network_demand;
        if s.base.assumptions.sponsor_gated {
            s.govern_sponsorship();
        }
        s
    }
}

/// What one cell gave over its seeds.
#[derive(Debug, Clone, Serialize)]
pub struct CellSummary {
    pub cell: Cell,
    pub seeds: usize,
    pub passed: usize,
    /// Every invariant held in every seed.
    pub holds: bool,
    /// Seeds that broke each invariant.
    pub broken: BTreeMap<String, usize>,
    /// Per year: bonded validators, median and least across seeds.
    pub validators_by_year: Vec<(f64, f64)>,
    /// Per year: security ratio (x, not bps), median and least.
    pub security_ratio_by_year: Vec<(f64, f64)>,
    /// Per year: median price, USD.
    pub price_by_year: Vec<f64>,
    /// Up to five failing seeds, worst first.
    pub worst: Vec<u64>,
}

/// Summarises one cell's results.
pub fn summarise_cell(cell: &Cell, results: &[SeedResult]) -> CellSummary {
    let mut broken: BTreeMap<String, usize> = BTreeMap::new();
    for r in results {
        for b in &r.broken {
            *broken.entry(b.clone()).or_default() += 1;
        }
    }
    let years = results.iter().map(|r| r.yearly.len()).min().unwrap_or(0);
    let by_year = |f: &dyn Fn(&YearEnd) -> f64| -> Vec<(f64, f64)> {
        (0..years)
            .map(|y| {
                let mut v: Vec<f64> = results.iter().map(|r| f(&r.yearly[y])).collect();
                v.sort_by(f64::total_cmp);
                (quantile(&v, 0.5), v.first().copied().unwrap_or(f64::NAN))
            })
            .collect()
    };
    let mut failing: Vec<&SeedResult> = results.iter().filter(|r| !r.pass).collect();
    failing.sort_by(|a, b| badness(b).total_cmp(&badness(a)).then(a.seed.cmp(&b.seed)));
    let passed = results.iter().filter(|r| r.pass).count();
    CellSummary {
        cell: cell.clone(),
        seeds: results.len(),
        passed,
        holds: !results.is_empty() && passed == results.len(),
        broken,
        validators_by_year: by_year(&|e| e.validators as f64),
        security_ratio_by_year: by_year(&|e| {
            e.security_ratio_bps
                .map_or(f64::NAN, |b| b.min(u64::MAX / 2) as f64 / 10_000.0)
        }),
        price_by_year: by_year(&|e| e.price_usd).into_iter().map(|p| p.0).collect(),
        worst: failing.iter().take(5).map(|r| r.seed).collect(),
    }
}

/// The sweep as a Markdown report: the cells where every invariant held,
/// then every cell.
pub fn sweep_table(cells: &[CellSummary], days: u32) -> String {
    let holding = cells.iter().filter(|c| c.holds).count();
    let mut t = format!(
        "# Economic chaos sweep: {} cells, {} days each\n\nEvery invariant held in every seed of {holding} of {} cells.\n\n",
        cells.len(),
        days,
        cells.len()
    );
    t.push_str("| cell | grants sold | validator $/month | holders | demand | seeds kept all | holds | broken (seeds) | validators by year (median/least) | security ratio by year (median/least) | worst seeds |\n|---|---|---|---|---|---|---|---|---|---|---|\n");
    for c in cells {
        let broken: Vec<String> = c.broken.iter().map(|(k, v)| format!("{k} {v}")).collect();
        let vals: Vec<String> = c
            .validators_by_year
            .iter()
            .map(|(m, l)| format!("{m:.0}/{l:.0}"))
            .collect();
        let sec: Vec<String> = c
            .security_ratio_by_year
            .iter()
            .map(|(m, l)| format!("{m:.1}/{l:.1}"))
            .collect();
        t.push_str(&format!(
            "| {} | {:.0}% | {:.0} | {} | {}x | {}/{} | {} | {} | {} | {} | {} |\n",
            c.cell.index,
            c.cell.grant_sell_share * 100.0,
            c.cell.validator_cost_usd_month,
            c.cell.holder_demand,
            c.cell.network_demand,
            c.passed,
            c.seeds,
            if c.holds { "yes" } else { "no" },
            broken.join(", "),
            vals.join(" "),
            sec.join(" "),
            c.worst
                .iter()
                .map(u64::to_string)
                .collect::<Vec<_>>()
                .join(" "),
        ));
    }
    t
}

/// Percentiles of a figure across seeds.
#[derive(Debug, Clone, Serialize)]
pub struct Spread {
    pub p0_1: f64,
    pub p1: f64,
    pub p5: f64,
    pub p50: f64,
    pub p95: f64,
    pub p99: f64,
    pub p99_9: f64,
}

fn quantile(sorted: &[f64], q: f64) -> f64 {
    if sorted.is_empty() {
        return f64::NAN;
    }
    let i = ((sorted.len() - 1) as f64 * q).round() as usize;
    sorted[i.min(sorted.len() - 1)]
}

fn spread(mut v: Vec<f64>) -> Spread {
    v.sort_by(f64::total_cmp);
    Spread {
        p0_1: quantile(&v, 0.001),
        p1: quantile(&v, 0.01),
        p5: quantile(&v, 0.05),
        p50: quantile(&v, 0.5),
        p95: quantile(&v, 0.95),
        p99: quantile(&v, 0.99),
        p99_9: quantile(&v, 0.999),
    }
}

/// The table over every seed.
#[derive(Debug, Clone, Serialize)]
pub struct Summary {
    pub seeds: usize,
    pub passed: usize,
    /// Seeds that broke each invariant.
    pub broken: BTreeMap<String, usize>,
    /// The acceptance rules over all seeds and whether each held.
    pub rules: Vec<(String, bool)>,
    /// Percentiles of each figure.
    pub spreads: BTreeMap<String, Spread>,
    /// For each shock kind: its mean count in the worst 1% of seeds over its
    /// mean count in all of them.
    pub tail_lift: BTreeMap<String, f64>,
    /// The worst seeds, worst first: (seed, broken, score).
    pub worst: Vec<(u64, Vec<String>, f64)>,
}

/// How badly a seed fared: each broken invariant counts 10, then the
/// shortfall of the security ratio, the days the rate sat off and the
/// reserve sat empty, and a year without operators.
pub fn badness(r: &SeedResult) -> f64 {
    let ratio = if r.min_ratio_bps > 0 && r.security_ratio_min_bps != u64::MAX {
        (r.security_ratio_min_bps as f64 / r.min_ratio_bps as f64).min(1.0)
    } else {
        1.0
    };
    10.0 * r.broken.len() as f64
        + (1.0 - ratio)
        + r.rate_off_days_max as f64 / 365.0
        + r.reserve_empty_days_max as f64 / 365.0
        + r.operators_none_days_max as f64 / 365.0
}

/// Summarises results; `worst` seeds listed.
pub fn summarise(results: &[SeedResult], worst: usize) -> Summary {
    let n = results.len();
    let mut broken: BTreeMap<String, usize> = BTreeMap::new();
    for r in results {
        for b in &r.broken {
            *broken.entry(b.clone()).or_default() += 1;
        }
    }
    let col = |f: &dyn Fn(&SeedResult) -> f64| results.iter().map(f).collect::<Vec<_>>();
    let mut spreads = BTreeMap::new();
    let ratio = |r: &SeedResult| {
        if r.security_ratio_min_bps == u64::MAX {
            f64::INFINITY
        } else {
            r.security_ratio_min_bps as f64 / 10_000.0
        }
    };
    spreads.insert("security_ratio_min".into(), spread(col(&ratio)));
    spreads.insert(
        "security_days_under".into(),
        spread(col(&|r| r.security_days_under as f64)),
    );
    spreads.insert(
        "bonded_min_tnzo".into(),
        spread(col(&|r| r.bonded_min_tnzo)),
    );
    spreads.insert(
        "validators_min".into(),
        spread(col(&|r| r.validators_min as f64)),
    );
    spreads.insert(
        "operators_min".into(),
        spread(col(&|r| r.operators_min as f64)),
    );
    spreads.insert(
        "operators_profitable_min".into(),
        spread(col(&|r| r.operators_profitable_min)),
    );
    spreads.insert(
        "reserve_empty_days_max".into(),
        spread(col(&|r| r.reserve_empty_days_max as f64)),
    );
    spreads.insert(
        "treasury_min_tnzo".into(),
        spread(col(&|r| r.treasury_min_tnzo)),
    );
    spreads.insert(
        "insurance_min_tnzo".into(),
        spread(col(&|r| r.insurance_min_tnzo)),
    );
    spreads.insert(
        "treasury_stable_share_max".into(),
        spread(col(&|r| r.treasury_stable_share_max)),
    );
    spreads.insert(
        "bridge_cover_min".into(),
        spread(results.iter().filter_map(|r| r.bridge_cover_min).collect()),
    );
    spreads.insert(
        "rate_off_days_max".into(),
        spread(col(&|r| r.rate_off_days_max as f64)),
    );
    spreads.insert("rate_gap_max".into(), spread(col(&|r| r.rate_gap_max)));
    spreads.insert("price_min_usd".into(), spread(col(&|r| r.price_min_usd)));
    spreads.insert("price_end_usd".into(), spread(col(&|r| r.price_end_usd)));
    spreads.insert(
        "supply_max_tnzo".into(),
        spread(col(&|r| r.supply_max_tnzo)),
    );

    let mut ranked: Vec<&SeedResult> = results.iter().collect();
    ranked.sort_by(|a, b| badness(b).total_cmp(&badness(a)).then(a.seed.cmp(&b.seed)));
    let tail = (n / 100).max(1).min(n);
    let mut tail_lift = BTreeMap::new();
    let mean = |rs: &[&SeedResult], k: Kind| {
        rs.iter()
            .map(|r| r.shocks.get(k.name()).copied().unwrap_or(0) as f64)
            .sum::<f64>()
            / rs.len().max(1) as f64
    };
    for k in Kind::ALL {
        let all = mean(&ranked, k);
        let worst_mean = mean(&ranked[..tail], k);
        tail_lift.insert(
            k.name().to_string(),
            if all > 0.0 { worst_mean / all } else { 0.0 },
        );
    }

    let ratios = {
        let mut v = col(&ratio);
        v.sort_by(f64::total_cmp);
        v
    };
    let k = results.iter().map(|r| r.min_ratio_bps).max().unwrap_or(0) as f64 / 10_000.0;
    let mut empty = col(&|r| r.reserve_empty_days_max as f64);
    empty.sort_by(f64::total_cmp);
    let rules = vec![
        (
            "zero value-conservation breaks across all seeds".to_string(),
            !broken.contains_key("value_conservation"),
        ),
        (
            format!("security ratio at least k ({k}) at p99.9"),
            n == 0 || quantile(&ratios, 0.001) >= k,
        ),
        (
            "reserve never empty more than 30 consecutive days at p99".to_string(),
            n == 0 || quantile(&empty, 0.99) <= 30.0,
        ),
    ];
    Summary {
        seeds: n,
        passed: results.iter().filter(|r| r.pass).count(),
        broken,
        rules,
        spreads,
        tail_lift,
        worst: ranked
            .iter()
            .take(worst)
            .map(|r| (r.seed, r.broken.clone(), badness(r)))
            .collect(),
    }
}

/// The summary as a Markdown report.
pub fn table(s: &Summary, settings: &Settings) -> String {
    let mut t = format!(
        "# Economic chaos: {} seeds over {} days\n\n{} of {} seeds kept every invariant.\n\n",
        s.seeds, settings.days, s.passed, s.seeds
    );
    t.push_str("## Acceptance\n\n| rule | held |\n|---|---|\n");
    for (rule, ok) in &s.rules {
        t.push_str(&format!(
            "| {rule} | {} |\n",
            if *ok { "yes" } else { "NO" }
        ));
    }
    t.push_str("\n## Seeds that broke each invariant\n\n| invariant | seeds |\n|---|---|\n");
    for name in [
        "value_conservation",
        "supply_bounds",
        "security_budget",
        "operator_viability",
        "treasury_insurance_solvency",
        "fee_rate_stability",
    ] {
        t.push_str(&format!(
            "| {name} | {} |\n",
            s.broken.get(name).copied().unwrap_or(0)
        ));
    }
    t.push_str("\n## Percentiles across seeds\n\n| figure | p0.1 | p1 | p5 | p50 | p95 | p99 | p99.9 |\n|---|---|---|---|---|---|---|---|\n");
    for (k, v) in &s.spreads {
        t.push_str(&format!(
            "| {k} | {:.4} | {:.4} | {:.4} | {:.4} | {:.4} | {:.4} | {:.4} |\n",
            v.p0_1, v.p1, v.p5, v.p50, v.p95, v.p99, v.p99_9
        ));
    }
    t.push_str("\n## Shocks in the worst 1% of seeds (mean count over all seeds)\n\n| shock | lift |\n|---|---|\n");
    for (k, v) in &s.tail_lift {
        t.push_str(&format!("| {k} | {v:.2} |\n"));
    }
    t.push_str("\n## Worst seeds (replay: `tenzro-econsim chaos --replay SEED`)\n\n| seed | broken | score |\n|---|---|---|\n");
    for (seed, broken, score) in &s.worst {
        t.push_str(&format!(
            "| {seed} | {} | {score:.3} |\n",
            broken.join(", ")
        ));
    }
    t
}

/// Seeds already in a results file of JSON lines.
pub fn done_seeds(path: &std::path::Path) -> BTreeSet<u64> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter_map(|l| serde_json::from_str::<SeedResult>(l).ok())
        .map(|r| r.seed)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_plan_follows_from_its_seed() {
        let s = Shocks::default();
        let days = (30.0 * YEAR_DAYS) as u32;
        assert_eq!(
            Plan::draw(7, days, &s).events,
            Plan::draw(7, days, &s).events
        );
        assert_ne!(
            Plan::draw(7, days, &s).events,
            Plan::draw(8, days, &s).events
        );
    }

    #[test]
    fn the_sweep_covers_every_level_once_and_names_its_centre() {
        let cells = sweep_cells();
        assert_eq!(cells.len(), 27);
        assert!(cells.iter().enumerate().all(|(i, c)| c.index == i));
        let c = Cell::central();
        assert_eq!(
            (
                c.grant_sell_share,
                c.validator_cost_usd_month,
                c.holder_demand.as_str(),
                c.network_demand
            ),
            (0.25, 750.0, "none", 10.0)
        );
        let s = c.settings(&Settings::new(1.0));
        let base = Settings::new(1.0);
        assert_eq!(
            s.base.assumptions.compute_usd_per_day,
            10.0 * base.base.assumptions.compute_usd_per_day
        );
    }

    #[test]
    fn a_crash_lifts_the_other_shocks() {
        let days = (30.0 * YEAR_DAYS) as u32;
        let count = |correlated: bool| {
            let s = Shocks {
                correlated,
                ..Shocks::default()
            };
            (1..400u64)
                .map(|seed| {
                    Plan::draw(seed, days, &s)
                        .events
                        .iter()
                        .filter(|e| e.kind != Kind::PriceCrash)
                        .count()
                })
                .sum::<usize>()
        };
        assert!(count(true) as f64 > 1.2 * count(false) as f64);
    }

    #[test]
    fn a_crash_falls_then_recovers_its_share() {
        let plan = Plan {
            days: 400,
            events: vec![Event {
                kind: Kind::PriceCrash,
                day: 10,
                days: 5,
                size: 0.8,
                factor: 0.5,
                tail_days: 100,
                amount: 0.0,
                joint: false,
            }],
        };
        let path: Vec<f64> = (0..400)
            .scan(1.0, |p, d| {
                *p *= plan.price_factor(d);
                Some(*p)
            })
            .collect();
        assert!((path[14] - 0.2).abs() < 1e-9);
        // Half the fall in log terms: back to sqrt(0.2).
        assert!((path[114] - 0.2f64.sqrt()).abs() < 1e-9);
        assert_eq!(path[300], path[114]);
    }
}
