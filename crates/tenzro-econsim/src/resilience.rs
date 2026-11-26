//! S2 "source-venue manipulation" (TENZRO-ECONOMY-RESILIENCE-2026-10-25.md,
//! proves B2, T2).
//!
//! Drives the real TNZO/USD fee-rate oracle in
//! [`tenzro_vm::native::economy`] -- the commit-reveal reports, the
//! stake-weighted band, the per-epoch step cap, the governed source-count
//! floor, the dispersion breaker and its fallback to the governance rate --
//! while one venue every reporter reads is pumped or crashed, and compares
//! the four arms the scenario names:
//!
//! - [`Arm::TodayMode1`]: mode 1 at the protocol's bare source floor (2
//!   independent sources), with the dispersion breaker parked at the
//!   loosest bound `tenzro-vm/src/governance.rs` lets governance set
//!   (`usd_rate_breaker_spread_bps` 5,000, `usd_rate_breaker_gap_bps`
//!   50,000, `usd_rate_breaker_epochs` 24), so it never trips inside the
//!   scenario's 1 hour to 7 day window. Stands for the mechanism as it ran
//!   before the breaker and the min-sources guard were adopted, without
//!   inventing a toggle to turn code that now always runs back off.
//! - [`Arm::MinSources`]: mode 1 with `fees.usd_rate_min_sources` raised to
//!   3 and reporters actually reading a third, honest venue, so a report's
//!   own median is no longer the median of exactly the honest and the
//!   manipulated quote. The breaker is parked exactly as in `TodayMode1`,
//!   so this arm shows the min-sources guard's own effect alone.
//! - [`Arm::DispersionBreaker`]: mode 1 at the governed genesis defaults --
//!   the breaker and its fallback are in force, at the bare 2-source floor.
//! - [`Arm::GovernanceOnly`]: `fees.usd_rate_mode` 0, the governance rate,
//!   untouched by any report.
//!
//! Every run is a small chain of its own ([`Chain`], not the full
//! [`crate::economy::Economy`] -- S2 is about the oracle, not the rest of
//! the ledger): `R` reporters bonded equally at genesis, each opening a
//! report every hour from its venues (`venue-a`, the one the event moves;
//! the rest held steady), through the real `tenzro_feeRateSubmit`
//! commit-reveal native call. Nothing here is a model of the mechanism:
//! the VM's own `submit_rate` and `tally_rates` decide every epoch's rate,
//! exactly as the production chain would.
//!
//! The salt a report seals its commitment with is derived from the
//! validator and the epoch rather than drawn from an RNG: no adversary in
//! this harness reads chain state between a seal and its reveal to front
//! run it, so there is nothing for randomness to hide here, and a
//! deterministic salt keeps a run byte for byte reproducible.
//!
//! `burn_equivalent_error_ratio` reads the spec's "total burn-equivalent
//! error over the window under 1% of the window's fees" against a stated
//! assumption of constant USD fee volume per epoch over the window (this
//! harness does not simulate settlement volume at all): under that
//! assumption the volume itself cancels out of the ratio, leaving
//! `sum(|1/r_e - 1/h|) / sum(1/h)` over the window's epochs, where `h` is
//! the honest rate and `r_e` the rate in force at epoch `e`.

use std::collections::BTreeMap;

use tenzro_sim::ledger::{self, SimTx};
use tenzro_vm::native as n;

use crate::chain::{Chain, Clock, GenesisPlan, HOUR_MS};

/// One validator's sealed report, carried to the next epoch so it can open
/// it: the epoch it was sealed for, its quotes and its salt.
type Sealed = Option<(u64, Vec<(String, String, u128)>, [u8; 32])>;

/// Venues every reporter reads, in report order. `venue-a` is the one a
/// [`VenueEvent`] moves; the rest always quote the honest rate.
const VENUES: [&str; 3] = ["venue-a", "venue-b", "venue-c"];

/// The widest bound `fees.usd_rate_breaker_spread_bps` may be set to
/// (`tenzro-vm/src/governance.rs`'s registered range for the key).
const BREAKER_SPREAD_MAX_BPS: u64 = 5_000;
/// The widest bound `fees.usd_rate_breaker_gap_bps` may be set to.
const BREAKER_GAP_MAX_BPS: u64 = 50_000;
/// The most `fees.usd_rate_breaker_epochs` may be set to.
const BREAKER_EPOCHS_MAX: u64 = 24;
/// The source count [`Arm::MinSources`] raises the floor to, within
/// `fees.usd_rate_min_sources`'s registered range (2 to 16).
const RAISED_MIN_SOURCES: u64 = 3;

/// The arm of S2's four-way comparison a run drives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arm {
    /// Mode 1 at the bare 2-source floor, breaker parked loose.
    TodayMode1,
    /// Mode 1, `usd_rate_min_sources` raised to 3, breaker parked loose.
    MinSources,
    /// Mode 1 at the governed defaults: the breaker is live.
    DispersionBreaker,
    /// Mode 0: the governance rate only.
    GovernanceOnly,
}

impl Arm {
    /// Venues one reporter reads under this arm.
    fn venues(self) -> usize {
        match self {
            Arm::MinSources => 3,
            _ => 2,
        }
    }

    /// Genesis network parameters this arm sets beyond the registry
    /// defaults.
    fn network_params(self, governance_rate_nano_usd: u64) -> BTreeMap<String, u64> {
        let mut p = BTreeMap::new();
        p.insert(
            n::economy::GOVERNANCE_RATE_PARAM.to_string(),
            governance_rate_nano_usd,
        );
        match self {
            Arm::GovernanceOnly => {
                p.insert(n::economy::RATE_MODE_PARAM.to_string(), 0);
            }
            Arm::TodayMode1 | Arm::MinSources => {
                p.insert(n::economy::RATE_MODE_PARAM.to_string(), 1);
                p.insert(
                    n::economy::RATE_BREAKER_SPREAD_PARAM.to_string(),
                    BREAKER_SPREAD_MAX_BPS,
                );
                p.insert(
                    n::economy::RATE_BREAKER_GAP_PARAM.to_string(),
                    BREAKER_GAP_MAX_BPS,
                );
                p.insert(
                    n::economy::RATE_BREAKER_EPOCHS_PARAM.to_string(),
                    BREAKER_EPOCHS_MAX,
                );
                if self == Arm::MinSources {
                    p.insert(
                        n::economy::RATE_MIN_SOURCES_PARAM.to_string(),
                        RAISED_MIN_SOURCES,
                    );
                }
            }
            Arm::DispersionBreaker => {
                p.insert(n::economy::RATE_MODE_PARAM.to_string(), 1);
                // Left at the registry's genesis defaults (500 / 5,000 / 3):
                // the breaker and its fallback are in force.
            }
        }
        p
    }
}

/// One venue event: `factor` on the honest rate (0.5 to 3.0 for a pump or a
/// crash; a value the report keeps unreachable for a frozen venue is left
/// to the caller -- this harness only moves the rate, which covers a
/// pump, a crash and, at `factor` 1.0 outside `[start_epoch,
/// start_epoch + duration_epochs)`, a venue back to normal) applied to
/// `venue-a` alone, for every reporter, for `duration_epochs` hourly
/// epochs starting at `start_epoch`.
#[derive(Debug, Clone, Copy)]
pub struct VenueEvent {
    /// Epoch the event starts.
    pub start_epoch: u64,
    /// Epochs it lasts: 1 (an hour) to 168 (seven days) per the spec.
    pub duration_epochs: u64,
    /// Factor on the honest rate `venue-a` quotes while the event is in
    /// force.
    pub factor: f64,
}

impl VenueEvent {
    fn factor_at(&self, epoch: u64) -> f64 {
        if epoch >= self.start_epoch && epoch < self.start_epoch + self.duration_epochs {
            self.factor
        } else {
            1.0
        }
    }
}

/// A run's genesis and schedule.
#[derive(Debug, Clone, Copy)]
pub struct Scenario {
    /// Bonded reporters, equally staked.
    pub validators: u32,
    /// Hourly market epochs the run covers (one per produced block).
    pub total_epochs: u64,
    /// The venue event `venue-a` carries.
    pub event: VenueEvent,
    /// The honest TNZO/USD rate: the genesis governance rate and what
    /// every venue but `venue-a` always quotes.
    pub governance_rate_nano_usd: u64,
}

impl Scenario {
    /// `validators` reporters at the production genesis rate
    /// (`fees.tnzo_usd_nano`'s own default), running `total_epochs` hourly
    /// epochs with `event` applied to `venue-a`.
    pub fn new(validators: u32, total_epochs: u64, event: VenueEvent) -> Self {
        Self {
            validators,
            total_epochs,
            event,
            governance_rate_nano_usd: n::economy::DEFAULT_TNZO_USD_NANO,
        }
    }
}

/// Builds genesis for `arm` and `scenario`: `scenario.validators` bonded
/// reporters at the production minimum validator bond, nothing else.
fn genesis_chain(arm: Arm, scenario: &Scenario) -> Chain {
    let bond = tenzro_vm::governance::genesis_param("stake.validator_tnzo").max(1);
    let plan = GenesisPlan {
        validators: scenario.validators,
        standby: 0,
        bond_tnzo: bond,
        balance_tnzo: 1_000,
        users: 0,
        treasury_tnzo: 0,
        insurance_tnzo: 0,
        reserve_tnzo: 0,
        opening_accounts: Vec::new(),
        network_params: arm.network_params(scenario.governance_rate_nano_usd),
    };
    Chain::new(&plan, Clock::HOURLY)
}

/// The market epoch the next produced block will close.
fn current_epoch(chain: &Chain) -> u64 {
    (chain.now_ms().max(0) / n::MARKET_EPOCH_MS) as u64
}

/// Every bonded reporter seals this epoch's quotes and opens the epoch
/// before's, through the real `tenzro_feeRateSubmit` native call, then
/// produces the block. `venue-a` quotes `honest * factor_a`; every other
/// venue in `venues` quotes `honest`.
fn step_epoch(
    chain: &mut Chain,
    sealed: &mut [Sealed],
    venues: &[&str],
    honest: u128,
    factor_a: f64,
) {
    let closed = current_epoch(chain);
    let rate_a = ((honest as f64) * factor_a).max(1.0) as u128;
    for v in 0..sealed.len() as u32 {
        let mut quotes: Vec<(String, String, u128)> = Vec::with_capacity(venues.len());
        for (i, venue) in venues.iter().enumerate() {
            let rate = if i == 0 { rate_a } else { honest };
            quotes.push((
                n::economy::FEE_SYMBOL.to_string(),
                (*venue).to_string(),
                rate,
            ));
        }
        let mut salt = [0u8; 32];
        for (i, b) in salt.iter_mut().enumerate() {
            *b = (u64::from(v) ^ closed.wrapping_add(i as u64)) as u8;
        }
        let addr = ledger::account(v);
        let commitment = tenzro_types::fee_rate_commitment(
            &addr,
            closed,
            &salt,
            quotes
                .iter()
                .map(|(s, src, r)| (s.as_str(), src.as_str(), *r)),
        );
        let reveal = sealed[v as usize]
            .take()
            .filter(|(e, _, _)| *e + 1 == closed)
            .map(|(_, q, salt)| {
                serde_json::json!({
                    "quotes": q.iter().map(|(sym, src, r)| serde_json::json!({
                        "symbol": sym, "source": src, "rate_nano_usd": r.to_string(),
                    })).collect::<Vec<_>>(),
                    "salt": hex::encode(salt),
                })
            });
        sealed[v as usize] = Some((closed, quotes, salt));
        let payload = serde_json::json!({
            "epoch": closed,
            "commitment": hex::encode(commitment),
            "reveal": reveal,
        });
        chain.call(
            v,
            None,
            0,
            n::SELECTOR_FEE_RATE_SUBMIT,
            payload.to_string().as_bytes(),
            crate::economy::NATIVE_GAS,
            None,
        );
    }
    chain.produce();
}

/// What a run recorded.
#[derive(Debug, Clone)]
pub struct RunResult {
    /// The arm the run drove.
    pub arm: Arm,
    /// `(epoch, rate in force, nano-USD)` after every epoch the run
    /// covered.
    pub rate_history: Vec<(u64, u128)>,
    /// The epoch the dispersion breaker tripped, if it ever did.
    pub tripped_epoch: Option<u64>,
    /// The honest TNZO/USD rate the whole run: the genesis governance rate.
    pub honest_rate_nano_usd: u128,
    /// The governed per-epoch step cap in force, bps: the larger of
    /// `fees.usd_rate_max_change_bps` and `fees.usd_rate_max_fall_bps`.
    pub step_cap_bps: u64,
}

impl RunResult {
    fn window(&self, start: u64, end: u64) -> impl Iterator<Item = &(u64, u128)> {
        self.rate_history
            .iter()
            .filter(move |(e, _)| *e >= start && *e < end)
    }

    /// The largest the rate in force strayed from the honest rate over
    /// `[start, end)`, bps of the honest rate.
    pub fn max_deviation_bps(&self, start: u64, end: u64) -> u64 {
        self.window(start, end)
            .map(|(_, r)| {
                let dev = r.abs_diff(self.honest_rate_nano_usd);
                (dev.saturating_mul(10_000) / self.honest_rate_nano_usd.max(1)) as u64
            })
            .max()
            .unwrap_or(0)
    }

    /// Total burn-equivalent error over `[start, end)` as a share of what a
    /// steady per-epoch USD fee volume would have burned at the honest
    /// rate throughout (module docs: the volume assumption cancels out of
    /// this ratio).
    pub fn burn_equivalent_error_ratio(&self, start: u64, end: u64) -> f64 {
        let h = self.honest_rate_nano_usd as f64;
        if h <= 0.0 {
            return 0.0;
        }
        let (err, n) = self
            .window(start, end)
            .fold((0.0, 0u64), |(err, n), (_, r)| {
                (err + (1.0 / (*r as f64) - 1.0 / h).abs(), n + 1)
            });
        if n == 0 {
            return 0.0;
        }
        err / (f64::from(n as u32) / h)
    }
}

/// Runs `scenario` on a fresh chain for `arm`: every bonded reporter opens
/// a commit-reveal rate report every hourly epoch, `venue-a` carrying
/// `scenario.event` and every other venue steady, and returns the rate the
/// chain priced fees at after every epoch.
pub fn run(arm: Arm, scenario: &Scenario) -> RunResult {
    let mut chain = genesis_chain(arm, scenario);
    let venues = &VENUES[..arm.venues()];
    let honest = u128::from(scenario.governance_rate_nano_usd);
    let mut sealed: Vec<Sealed> = vec![None; scenario.validators as usize];
    let mut rate_history = Vec::with_capacity(scenario.total_epochs as usize);
    let mut tripped_epoch = None;

    for _ in 0..scenario.total_epochs {
        let closed = current_epoch(&chain);
        let factor_a = scenario.event.factor_at(closed);
        step_epoch(&mut chain, &mut sealed, venues, honest, factor_a);
        rate_history.push((
            closed,
            n::economy::read_fee_rate(chain.state()).rate_nano_usd,
        ));
        if tripped_epoch.is_none() {
            tripped_epoch =
                n::economy::rate_breaker(chain.state(), n::economy::FEE_SYMBOL).tripped_epoch;
        }
    }

    let step_cap_bps = n::network_param(chain.state(), n::economy::RATE_MAX_FALL_PARAM).max(
        n::network_param(chain.state(), n::economy::RATE_MAX_CHANGE_PARAM),
    );

    RunResult {
        arm,
        rate_history,
        tripped_epoch,
        honest_rate_nano_usd: honest,
        step_cap_bps,
    }
}

/// Advances `chain` by `ms` of calendar time at the honest rate (no venue
/// event), one hourly epoch at a time.
fn advance_quiet(chain: &mut Chain, sealed: &mut [Sealed], venues: &[&str], honest: u128, ms: i64) {
    let epochs = (ms / crate::chain::HOUR_MS).max(0) as u64 + 1;
    for _ in 0..epochs {
        step_epoch(chain, sealed, venues, honest, 1.0);
    }
}

/// What [`run_rearm`] found.
#[derive(Debug, Clone, Copy)]
pub struct RearmResult {
    /// The breaker had tripped by the end of the venue event.
    pub tripped_after_event: bool,
    /// It was still tripped after `quiet_epochs` of honest, unmanipulated
    /// reports with no governance action: proves it does not clear
    /// itself.
    pub still_tripped_after_quiet_epochs: bool,
    /// It cleared once (and only once) the `fees.usd_rate_mode = 1`
    /// governance proposal actually enacted.
    pub cleared_after_governance: bool,
}

/// Runs [`Arm::DispersionBreaker`] through `scenario`'s event, holds
/// `quiet_epochs` of honest reports with no governance action to show the
/// breaker does not re-arm itself, then files, votes and enacts a real
/// `fees.usd_rate_mode = 1` governance proposal -- the only path that
/// clears it (`rearm_rate_breaker` is called nowhere else; see
/// `tenzro-vm/src/native/mod.rs`'s `ProposalAction::ParameterChange`
/// handling) -- and reports what happened at each stage.
pub fn run_rearm(scenario: &Scenario, quiet_epochs: u64) -> RearmResult {
    let arm = Arm::DispersionBreaker;
    let mut chain = genesis_chain(arm, scenario);
    let venues = &VENUES[..arm.venues()];
    let honest = u128::from(scenario.governance_rate_nano_usd);
    let mut sealed: Vec<Sealed> = vec![None; scenario.validators as usize];

    for _ in 0..scenario.total_epochs {
        let closed = current_epoch(&chain);
        let factor_a = scenario.event.factor_at(closed);
        step_epoch(&mut chain, &mut sealed, venues, honest, factor_a);
    }
    let tripped_after_event = breaker_tripped(&chain);

    for _ in 0..quiet_epochs {
        step_epoch(&mut chain, &mut sealed, venues, honest, 1.0);
    }
    let still_tripped_after_quiet_epochs = breaker_tripped(&chain);

    // File the proposal, then every reporter votes for it, through the
    // real governance path the chain exposes to any sender.
    let action = ledger::parameter_change(n::economy::RATE_MODE_PARAM, 1);
    chain.submit(0, crate::economy::NATIVE_GAS, |nonce| SimTx::Propose {
        from: 0,
        action,
        nonce,
    });
    let results = chain.produce();
    let proposal_id = results
        .into_iter()
        .find_map(|r| match r.tx {
            SimTx::Propose { .. } if r.applied => Some(r.output),
            _ => None,
        })
        .expect("the re-arm proposal was filed");
    for v in 0..scenario.validators {
        let id = proposal_id.clone();
        chain.submit(v, crate::economy::NATIVE_GAS, move |nonce| SimTx::Vote {
            from: v,
            proposal: id,
            nonce,
        });
    }
    chain.produce();

    // Past the voting window: decide and queue it.
    let rules = tenzro_vm::governance::GovernanceRules::GENESIS;
    advance_quiet(
        &mut chain,
        &mut sealed,
        venues,
        honest,
        rules.voting_period_ms + HOUR_MS,
    );
    {
        let id = proposal_id.clone();
        chain.submit(0, crate::economy::NATIVE_GAS, move |nonce| SimTx::Execute {
            from: 0,
            proposal: id,
            nonce,
        });
    }
    chain.produce();

    // Past its timelock: enact it. This is the only call in this run that
    // can clear the breaker.
    advance_quiet(
        &mut chain,
        &mut sealed,
        venues,
        honest,
        rules.timelock_ms + HOUR_MS,
    );
    chain.submit(0, crate::economy::NATIVE_GAS, move |nonce| SimTx::Execute {
        from: 0,
        proposal: proposal_id,
        nonce,
    });
    chain.produce();

    RearmResult {
        tripped_after_event,
        still_tripped_after_quiet_epochs,
        cleared_after_governance: !breaker_tripped(&chain),
    }
}

fn breaker_tripped(chain: &Chain) -> bool {
    n::economy::rate_breaker(chain.state(), n::economy::FEE_SYMBOL)
        .tripped_epoch
        .is_some()
}
