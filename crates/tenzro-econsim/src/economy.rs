//! The populations and the run loop of one economy.
//!
//! Behaviour is a set of simple rules with ranges, not a prediction: every
//! number in [`Assumptions`] is an input the sensitivity analysis sweeps.
//! Everything that moves tokens is a transaction the ledger executes.

use std::collections::BTreeMap;

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use serde::Serialize;
use tenzro_sim::ledger::{self, SimTx, TNZO, TxResult, USER_BASE};
use tenzro_types::primitives::Address;
use tenzro_vm::native as n;

use crate::chain::{Chain, Clock, DAY_MS, GenesisPlan, HOUR_MS, Snapshot, tnzo};

/// Gas allowance of a native call the populations send.
pub const NATIVE_GAS: u64 = 2_000_000;
/// Machines one provider account runs. Chain state grows with the number
/// of bonded providers (one SLA record per provider per hour), so a provider
/// account stands for a fleet to keep multi-year runs within memory.
pub const MACHINES_PER_PROVIDER: f64 = 64.0;
/// Calendar days in a year.
pub const YEAR_DAYS: f64 = 365.25;

/// The market path a scenario follows. Demand and the TNZO price are
/// outside the protocol, so they are inputs, not outputs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Market {
    /// Demand grows strongly for two years, then slowly.
    Growth,
    /// Demand stays at its launch level.
    Flat,
    /// Demand and price fall hard in the first year, then stay low.
    Downturn,
}

impl Market {
    /// Every scenario.
    pub const ALL: [Market; 3] = [Market::Growth, Market::Flat, Market::Downturn];

    /// Name.
    pub fn name(self) -> &'static str {
        match self {
            Market::Growth => "growth",
            Market::Flat => "flat",
            Market::Downturn => "downturn",
        }
    }

    /// Demand multiple on `day` relative to launch.
    pub fn demand(self, day: f64) -> f64 {
        let y = day / YEAR_DAYS;
        match self {
            Market::Growth => {
                if y < 2.0 {
                    4f64.powf(y)
                } else {
                    16.0 * 1.3f64.powf(y - 2.0)
                }
            }
            Market::Flat => 1.0,
            Market::Downturn => {
                if y < 1.0 {
                    1.0 - 0.7 * y
                } else {
                    0.3
                }
            }
        }
    }
}

/// Behaviour and cost inputs. Every field is an assumption with a range
/// ([`Assumptions::ranges`]); none is a measured fact about Tenzro.
#[derive(Debug, Clone, Serialize)]
pub struct Assumptions {
    /// TNZO price at launch, USD.
    pub price0_usd: f64,
    /// Daily outside trading on the pool (market makers, arbitrage), as a
    /// standard deviation in shares of pool depth. Zero-mean: the base case
    /// has no outside buyers or sellers, only machines and agents.
    pub outside_flow_vol: f64,
    /// Third-party pool depth at launch, USD (both sides).
    pub pool_depth_usd: f64,
    /// How far above its usage value the market lets TNZO trade before
    /// holders sell into it, as a multiple. Usage value is the launch price
    /// scaled by the market's demand: at a steady velocity a token's value
    /// tracks the volume it settles.
    pub valuation_headroom: f64,
    /// Share of the log gap above `valuation_headroom` times usage value
    /// that holders sell away each day.
    pub holder_sell_elasticity: f64,
    /// Protocol-owned liquidity the treasury adds at launch, USD of depth
    /// (half raised USD, half treasury TNZO). Zero in the base case: the
    /// launch assumes no raised funds.
    pub pol_usd: f64,
    /// Treasury TNZO staked across the genesis validators, locked.
    pub treasury_stake_tnzo: f64,
    /// Share of their TNZO income providers sell.
    pub provider_sell_share: f64,
    /// Share of granted TNZO grantees sell.
    pub grant_sell_share: f64,
    /// Outside holders' net buying of TNZO on the pool, USD a day: demand
    /// for the token beyond what the network's users pay with.
    pub holder_buy_usd_day: f64,
    /// Human transfers per day at launch. Zero in the base case: demand is
    /// machines and agents; people are an upside sensitivity.
    pub human_tx_per_day: f64,
    /// Mean human transfer, USD.
    pub human_tx_usd: f64,
    /// Compute bought through streaming escrows per day at launch, USD.
    pub compute_usd_per_day: f64,
    /// Agent tasks per day at launch: one request a person or machine makes
    /// of a harness, which fans out to sub-agents the requester never sees.
    /// Zero in the base case.
    pub agent_tasks_per_day: f64,
    /// Sub-agents one task fans out to; each pays its provider through one
    /// session, settled once.
    pub agent_fanout: f64,
    /// What one task spends on compute, USD, across all its sub-agents.
    pub agent_task_usd: f64,
    /// Price of one compute hour, USD.
    pub compute_hour_usd: f64,
    /// Provider's cost of one served hour, USD.
    pub provider_hour_cost_usd: f64,
    /// Hours one provider can sell per day.
    pub provider_hours_per_day: f64,
    /// Mean share of hours a provider is available.
    pub provider_availability: f64,
    /// Compute bond a provider posts, whole TNZO.
    pub provider_bond_tnzo: f64,
    /// Validator running cost, USD per month.
    pub validator_cost_usd_month: f64,
    /// Validators at genesis.
    pub validators: u32,
    /// Validators registered and free to join later.
    pub standby: u32,
    /// Trailing annual yield below which a validator leaves.
    pub validator_exit_yield: f64,
    /// Trailing annual yield above which a standby validator joins.
    pub validator_join_yield: f64,
    /// Treasury at genesis, whole TNZO.
    pub treasury_genesis_tnzo: f64,
    /// Insurance pool at genesis, whole TNZO.
    pub insurance_genesis_tnzo: f64,
    /// Treasury grants governance approves, whole TNZO per month.
    pub grants_tnzo_month: f64,
    /// Most one month's grants take of the treasury, bps.
    pub grant_cap_bps_month: f64,
    /// Grants' monthly budget in USD: the TNZO cap binds when the price falls.
    pub grants_usd_month: f64,
    /// Approved validators the treasury sponsors with TNZO it already holds
    /// (the lowest-numbered seats): each is topped up to the governed
    /// running cost on the days its own income falls short, while it is
    /// bonded and serving. Zero sponsors none. Nothing is issued.
    pub sponsor_seats: u32,
    /// Most the treasury pays out in a year in sponsorship and grants
    /// together, bps of the treasury at genesis; sponsorship is paid first
    /// and grants take the remainder. Zero sets no combined cap.
    pub sponsor_cap_bps_year: f64,
    /// Sponsorship runs through the chain's gates: the sponsored seats are
    /// approved operators, each verified hour is a frozen availability
    /// verdict, and the treasury pays running costs in the stable asset
    /// through `SponsorOperatorStable` proposals, in arrears, against
    /// verified hours only, inside the governed USD caps. Off, the
    /// treasury tops a sponsor account up in TNZO.
    pub sponsor_gated: bool,
    /// Days of the sponsored need the sponsor account holds before
    /// governance files the next tranche: the approval delay's buffer. A
    /// tranche covers the buffer and a month more. The default, 35 days,
    /// is the 7-day vote and the 14-day timelock of a spend of 100,000
    /// TNZO or more, with a margin for a proposal already in flight and a
    /// falling price.
    pub sponsor_buffer_days: f64,
    /// Gated sponsorship: days of verified hours a seat claim covers, and
    /// the days between its claims. Each claim is a proposal with the vote
    /// and the long stable-payout timelock, so a shorter interval keeps the
    /// payment pipeline fuller, not faster.
    pub sponsor_claim_days: f64,
    /// Stable asset the treasury is given once, on the first day, from
    /// outside holders of the stable unit (a transfer; nothing is issued),
    /// USD. Zero: none.
    pub stable_seed_usd: f64,
    /// Governance files proposals setting the treasury legs on inference and
    /// compute payments to this many bps (zero: none), the first on
    /// `leg_proposal_day`, the second once the first is enacted. The legs
    /// fill the validator cover reserve in the payment token.
    pub leg_proposal_bps: f64,
    /// Day governance files the leg proposals.
    pub leg_proposal_day: f64,
    /// Share of the sponsored seats monthly running cost, after the stable
    /// legs the treasury received in the month, that outside holders give
    /// the treasury in the stable asset at each month close: a bootstrap
    /// gift that falls as paid usage grows. Zero: none.
    pub stable_topup_share: f64,
    /// Running costs governance asks the reserve to pay, USD a month: what
    /// the network's operators would like covered, not a funding amount.
    /// What is paid is what the reserve's governed caps allow.
    pub running_cost_ask_usd_month: f64,
    /// Running-cost reserve at genesis, whole TNZO. Zero is a valid launch.
    pub reserve_seed_tnzo: f64,
    /// Gap between chain rate and market, as a share, that outside price
    /// evidence counts as a successful challenge.
    pub challenge_band: f64,
    /// Whether governance keeps the fee rate at the market price.
    pub governance_tracks_price: bool,
    /// Most the fully diluted value may be as a multiple of the network's
    /// annualised fee revenue (trailing 30 days). The launch value is always
    /// allowed, so the multiple only bounds how far usage lifts the price
    /// above it. Zero: no bound.
    pub max_price_to_revenue: f64,
    /// Most the fully diluted value may be, USD. Zero: no bound.
    pub max_fdv_usd: f64,
    /// Fall of the fully diluted value over the first year, as a share of the
    /// launch value: the value allowed declines linearly to `1 - this` of
    /// launch by the end of year one and stays there, unless revenue at
    /// `max_price_to_revenue` supports more. Zero: no stress.
    pub fdv_stress_year1: f64,
    /// Share of the circulating supply at genesis (the fixed supply less the
    /// rewards pool, treasury, insurance pool and reserve) bonded to
    /// validators, own and delegated stake together. Zero: only the minimum
    /// validator stake and the treasury stake, about 0.5% of supply.
    pub staking_ratio: f64,
    /// Share of the rewards on delegated stake a validator keeps; the rest
    /// goes to its delegators. Applies only to stake added by `staking_ratio`.
    pub validator_commission: f64,
    /// Yearly demand multiple of the growth market. Zero: the growth path of
    /// [`Market::demand`].
    pub demand_growth_per_year: f64,
    /// Payments settle in a stable unit: agents do not buy TNZO to pay and
    /// providers do not sell TNZO they are paid. TNZO is bought only for the
    /// fees, gas and bonds the network charges in it.
    pub stable_settlement: bool,
    /// How strongly buyers route away from a dearer provider: each provider
    /// is chosen with weight `price_factor ^ -this`. Zero: uniform routing.
    /// Used only by the provider collusion strategy.
    pub buyer_price_elasticity: f64,
    /// Providers claim the reward coupons their settlements earn, once a
    /// day, and count them as income. Off: their coupons expire unclaimed
    /// and the activity reward share changes nothing they hold.
    pub providers_claim_rewards: bool,
    /// Scale the reserve's per-epoch sale ceiling to the chain's hourly
    /// epochs: this clock's epoch is a day, so the genesis ceiling would
    /// otherwise allow a twenty-fourth of what the chain allows a day.
    pub reserve_cap_per_hour: bool,
    /// Days of its TNZO income a provider keeps at most; it sells what it
    /// holds above that. Zero: no limit, it keeps `1 - provider_sell_share`
    /// of every day's income for good.
    pub provider_hold_days: f64,
    /// Payments to providers settle in a stable token on the ledger
    /// ([`crate::stable`]): agents fund escrows in it and providers are paid
    /// in it and redeem it. TNZO pays the settlement fee, gas and bonds.
    /// The treasury leg is charged as the VM charges it on a token payment,
    /// in TNZO from the provider, unless `stable_leg` is set.
    pub stable_asset: bool,
    /// The treasury leg of a payment in the stable token is taken in the
    /// token. Implies `stable_asset`.
    pub stable_leg: bool,
    /// Governance sells back the treasury's TNZO above
    /// `sellback_target_tnzo`: a monthly grant to the sell-back desk, within
    /// the treasury's outflow limits, which the desk sells into the market
    /// at most `sellback_max_tnzo_day` a day.
    pub treasury_sellback: bool,
    /// Treasury balance the sell-back keeps, whole TNZO.
    pub sellback_target_tnzo: f64,
    /// Most the sell-back desk sells in a day (an epoch on this clock),
    /// whole TNZO.
    pub sellback_max_tnzo_day: f64,
    /// The closed phase before a public listing: payments, escrows and the
    /// treasury leg settle in the stable token (`stable_asset`,
    /// `stable_leg`), TNZO has no public market (no price discovery, no
    /// reserve or grant sales, the price stays at launch), the bootstrap funder
    /// pays the running costs, and validators are contracted in USD, so they
    /// neither leave nor join on their yield.
    pub closed_phase: bool,
    /// Share of the demand that is related-party anchor demand: the bootstrap
    /// funder's own products buying from the network. The listing gate counts only
    /// the rest as unrelated demand.
    pub anchor_share: f64,
    /// Cost and split inputs of the per-class accounts.
    pub classes: crate::classes::ClassInputs,
    /// Demand read from a population trace: the agent sessions follow its
    /// payments per day, size and daily profile, times the market path.
    #[serde(skip)]
    pub trace: Option<std::sync::Arc<crate::trace::TraceDemand>>,
}

impl Default for Assumptions {
    fn default() -> Self {
        Self {
            price0_usd: 0.10,
            outside_flow_vol: 0.02,
            pool_depth_usd: 250_000.0,
            valuation_headroom: 10.0,
            holder_sell_elasticity: 0.2,
            pol_usd: 0.0,
            treasury_stake_tnzo: 5_000_000.0,
            provider_sell_share: 0.6,
            grant_sell_share: 1.0,
            holder_buy_usd_day: 0.0,
            human_tx_per_day: 0.0,
            human_tx_usd: 20.0,
            compute_usd_per_day: 5_000.0,
            agent_tasks_per_day: 0.0,
            agent_fanout: 6.0,
            agent_task_usd: 0.5,
            compute_hour_usd: 1.2,
            provider_hour_cost_usd: 0.7,
            provider_hours_per_day: 20.0,
            provider_availability: 0.985,
            provider_bond_tnzo: 1_000.0,
            validator_cost_usd_month: 500.0,
            validators: 21,
            standby: 10,
            validator_exit_yield: 0.0,
            validator_join_yield: 0.25,
            treasury_genesis_tnzo: 50_000_000.0,
            insurance_genesis_tnzo: 0.0,
            grants_tnzo_month: 1_000_000.0,
            grant_cap_bps_month: 150.0,
            grants_usd_month: 100_000.0,
            sponsor_seats: 0,
            sponsor_cap_bps_year: 0.0,
            sponsor_gated: false,
            sponsor_buffer_days: 35.0,
            sponsor_claim_days: 7.0,
            stable_seed_usd: 0.0,
            leg_proposal_bps: 0.0,
            leg_proposal_day: 1.0,
            stable_topup_share: 0.0,
            running_cost_ask_usd_month: 18_000.0,
            reserve_seed_tnzo: 0.0,
            challenge_band: 0.10,
            governance_tracks_price: true,
            max_price_to_revenue: 0.0,
            max_fdv_usd: 0.0,
            fdv_stress_year1: 0.0,
            staking_ratio: 0.0,
            validator_commission: 0.10,
            demand_growth_per_year: 0.0,
            stable_settlement: false,
            buyer_price_elasticity: 0.0,
            providers_claim_rewards: false,
            provider_hold_days: 0.0,
            reserve_cap_per_hour: false,
            stable_asset: false,
            stable_leg: false,
            treasury_sellback: false,
            sellback_target_tnzo: 50_000_000.0,
            sellback_max_tnzo_day: 1_000_000.0,
            closed_phase: false,
            anchor_share: 0.0,
            classes: crate::classes::ClassInputs::default(),
            trace: None,
        }
    }
}

impl Assumptions {
    /// Range each assumption is swept over: (name, low, high).
    pub fn ranges() -> Vec<(&'static str, f64, f64)> {
        vec![
            ("price0_usd", 0.02, 0.5),
            ("outside_flow_vol", 0.0, 0.08),
            ("pool_depth_usd", 50_000.0, 5_000_000.0),
            ("valuation_headroom", 2.0, 50.0),
            ("holder_sell_elasticity", 0.02, 0.8),
            ("pol_usd", 0.0, 2_000_000.0),
            ("treasury_stake_tnzo", 0.0, 25_000_000.0),
            ("provider_sell_share", 0.2, 1.0),
            ("grant_sell_share", 0.3, 1.0),
            ("human_tx_per_day", 0.0, 200_000.0),
            ("compute_usd_per_day", 500.0, 50_000.0),
            ("compute_hour_usd", 0.6, 3.0),
            ("provider_hour_cost_usd", 0.3, 1.5),
            ("provider_availability", 0.9, 0.999),
            ("validator_cost_usd_month", 150.0, 1_500.0),
            ("treasury_genesis_tnzo", 0.0, 200_000_000.0),
            ("grants_tnzo_month", 100_000.0, 5_000_000.0),
            ("grant_cap_bps_month", 50.0, 500.0),
            ("grants_usd_month", 10_000.0, 500_000.0),
            ("running_cost_ask_usd_month", 0.0, 200_000.0),
            ("reserve_seed_tnzo", 0.0, 10_000_000.0),
        ]
    }

    /// Sets an assumption by name.
    pub fn set(&mut self, name: &str, v: f64) {
        match name {
            "price0_usd" => self.price0_usd = v,
            "outside_flow_vol" => self.outside_flow_vol = v,
            "pool_depth_usd" => self.pool_depth_usd = v,
            "valuation_headroom" => self.valuation_headroom = v,
            "holder_sell_elasticity" => self.holder_sell_elasticity = v,
            "pol_usd" => self.pol_usd = v,
            "treasury_stake_tnzo" => self.treasury_stake_tnzo = v,
            "provider_sell_share" => self.provider_sell_share = v,
            "grant_sell_share" => self.grant_sell_share = v,
            "holder_buy_usd_day" => self.holder_buy_usd_day = v,
            "human_tx_per_day" => self.human_tx_per_day = v,
            "compute_usd_per_day" => self.compute_usd_per_day = v,
            "agent_tasks_per_day" => self.agent_tasks_per_day = v,
            "agent_fanout" => self.agent_fanout = v,
            "agent_task_usd" => self.agent_task_usd = v,
            "compute_hour_usd" => self.compute_hour_usd = v,
            "provider_hour_cost_usd" => self.provider_hour_cost_usd = v,
            "provider_availability" => self.provider_availability = v,
            "validator_cost_usd_month" => self.validator_cost_usd_month = v,
            "treasury_genesis_tnzo" => self.treasury_genesis_tnzo = v,
            "insurance_genesis_tnzo" => self.insurance_genesis_tnzo = v,
            "grants_tnzo_month" => self.grants_tnzo_month = v,
            "grant_cap_bps_month" => self.grant_cap_bps_month = v,
            "grants_usd_month" => self.grants_usd_month = v,
            "sponsor_seats" => self.sponsor_seats = v as u32,
            "sponsor_cap_bps_year" => self.sponsor_cap_bps_year = v,
            "sponsor_gated" => self.sponsor_gated = v != 0.0,
            "sponsor_buffer_days" => self.sponsor_buffer_days = v,
            "sponsor_claim_days" => self.sponsor_claim_days = v.max(1.0),
            "stable_seed_usd" => self.stable_seed_usd = v.max(0.0),
            "leg_proposal_bps" => self.leg_proposal_bps = v.clamp(0.0, 5_000.0),
            "leg_proposal_day" => self.leg_proposal_day = v.max(0.0),
            "stable_topup_share" => self.stable_topup_share = v.clamp(0.0, 1.0),
            "running_cost_ask_usd_month" => self.running_cost_ask_usd_month = v,
            "reserve_seed_tnzo" => self.reserve_seed_tnzo = v,
            "human_tx_usd" => self.human_tx_usd = v,
            "provider_hours_per_day" => self.provider_hours_per_day = v,
            "provider_bond_tnzo" => self.provider_bond_tnzo = v,
            "validators" => self.validators = v as u32,
            "standby" => self.standby = v as u32,
            "validator_exit_yield" => self.validator_exit_yield = v,
            "validator_join_yield" => self.validator_join_yield = v,
            "challenge_band" => self.challenge_band = v,
            "governance_tracks_price" => self.governance_tracks_price = v != 0.0,
            "max_price_to_revenue" => self.max_price_to_revenue = v,
            "max_fdv_usd" => self.max_fdv_usd = v,
            "fdv_stress_year1" => self.fdv_stress_year1 = v,
            "staking_ratio" => self.staking_ratio = v,
            "validator_commission" => self.validator_commission = v,
            "demand_growth_per_year" => self.demand_growth_per_year = v,
            "stable_settlement" => self.stable_settlement = v != 0.0,
            "stable_asset" => self.stable_asset = v != 0.0,
            "stable_leg" => self.stable_leg = v != 0.0,
            "treasury_sellback" => self.treasury_sellback = v != 0.0,
            "sellback_target_tnzo" => self.sellback_target_tnzo = v,
            "sellback_max_tnzo_day" => self.sellback_max_tnzo_day = v,
            "buyer_price_elasticity" => self.buyer_price_elasticity = v,
            "providers_claim_rewards" => self.providers_claim_rewards = v != 0.0,
            "provider_hold_days" => self.provider_hold_days = v,
            "reserve_cap_per_hour" => self.reserve_cap_per_hour = v != 0.0,
            "closed_phase" => self.closed_phase = v != 0.0,
            "anchor_share" => self.anchor_share = v,
            "treasury_leg" => self.classes.treasury_leg = v,
            "gpu_cost_usd_hour" => self.classes.gpu_cost_usd_hour = v,
            "inference_usd_per_mtok" => self.classes.inference_usd_per_mtok = v,
            "mtok_per_gpu_hour" => self.classes.mtok_per_gpu_hour = v,
            "inference_share" => self.classes.inference_share = v,
            "agent_share" => self.classes.agent_share = v,
            "app_share" => self.classes.app_share = v,
            "agent_operators" => self.classes.agent_operators = v,
            "app_owners" => self.classes.app_owners = v,
            "agent_operator_cost_usd_month" => self.classes.agent_operator_cost_usd_month = v,
            "app_owner_cost_usd_month" => self.classes.app_owner_cost_usd_month = v,
            other => panic!("unknown assumption {other}"),
        }
    }

    /// Names of the presets [`Assumptions::preset`] knows.
    pub const PRESETS: [&'static str; 3] = ["default", "realistic", "closed"];

    /// A named set of assumptions: `default` is [`Assumptions::default`];
    /// `realistic` sets the costs, demand, staking and valuation bound to
    /// values comparable networks show at launch:
    /// - fully diluted value at most 44 times annualised fee revenue (or the
    ///   launch value);
    /// - 40% of supply bonded, validators keep 10% of delegated rewards;
    /// - validators cost $1,500 a month with operations and leave when their
    ///   trailing income does not cover it;
    /// - providers sell 14 hours a day and sell 90% of their income;
    /// - $500 a day of compute at launch and 10,000 agent tasks a day, the
    ///   growth market doubling each year;
    /// - running costs of $200,000 a month with staff;
    /// - compute at $2.00 a GPU-hour, the H100 marketplace range ($1.5-2.7 on
    ///   Vast.ai, RunPod and Akash), $1.20 of it the provider's cost;
    /// - providers claim the reward coupons their settlements earn.
    ///
    /// `closed` is `realistic` in the closed phase before a public listing
    /// ([`Assumptions::closed_phase`]).
    pub fn preset(name: &str) -> Option<Self> {
        match name {
            "default" => Some(Self::default()),
            "realistic" => Some(Self {
                max_price_to_revenue: 44.0,
                staking_ratio: 0.40,
                validator_commission: 0.10,
                validator_cost_usd_month: 1_500.0,
                validator_exit_yield: 0.0,
                provider_hours_per_day: 14.0,
                provider_sell_share: 0.9,
                compute_usd_per_day: 500.0,
                demand_growth_per_year: 2.0,
                agent_tasks_per_day: 10_000.0,
                running_cost_ask_usd_month: 200_000.0,
                compute_hour_usd: 2.0,
                provider_hour_cost_usd: 1.2,
                providers_claim_rewards: true,
                provider_hold_days: 30.0,
                reserve_cap_per_hour: true,
                ..Self::default()
            }),
            "closed" => Some(Self {
                closed_phase: true,
                stable_settlement: true,
                stable_asset: true,
                stable_leg: true,
                ..Self::preset("realistic")?
            }),
            _ => None,
        }
    }

    /// Applies a comma-separated `k=v` list; `preset=NAME` replaces every
    /// assumption with the preset first, wherever it appears in the list,
    /// and the other keys then apply in order.
    pub fn apply_list(&mut self, list: &str) -> Result<(), String> {
        let pairs: Vec<(&str, &str)> = list
            .split(',')
            .filter_map(|kv| kv.split_once('='))
            .map(|(k, v)| (k.trim(), v.trim()))
            .collect();
        for (k, v) in &pairs {
            if *k == "preset" {
                *self = Self::preset(v).ok_or_else(|| {
                    format!("unknown preset {v}; known: {}", Self::PRESETS.join(", "))
                })?;
            }
        }
        for (k, v) in pairs {
            if k == "preset" {
                continue;
            }
            let x: f64 = v
                .parse()
                .map_err(|_| format!("assumption {k}: not a number: {v}"))?;
            self.set(k, x);
        }
        Ok(())
    }

    /// Demand multiple of `market` on `day` relative to launch, with the
    /// growth market's yearly multiple when one is set, times the trace's
    /// daily profile when a trace drives demand.
    pub fn demand(&self, market: Market, day: f64) -> f64 {
        let path = if market == Market::Growth && self.demand_growth_per_year > 0.0 {
            self.demand_growth_per_year.powf(day / YEAR_DAYS)
        } else {
            market.demand(day)
        };
        match &self.trace {
            Some(t) => path * t.multiple(day),
            None => path,
        }
    }

    /// Drives demand by `trace`: every payment it records as delivered is
    /// one agent session of its mean size, and no compute streams run.
    pub fn use_trace(&mut self, trace: crate::trace::TraceDemand) {
        self.agent_tasks_per_day = trace.payments_per_day * trace.delivered_share;
        self.agent_task_usd = trace.mean_usd;
        self.agent_fanout = 1.0;
        self.compute_usd_per_day = 0.0;
        self.trace = Some(std::sync::Arc::new(trace));
    }
}

/// One mechanism of the design switched off, to measure what it adds. A
/// simulator setting only: the protocol has one path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Default)]
pub enum Ablation {
    /// The whole design.
    #[default]
    Full,
    /// Fees fixed in TNZO at launch instead of pegged to USD.
    NoFiatFees,
    /// Provider bonds fixed instead of sized to live escrow exposure.
    NoExposureBonds,
    /// No mint controller, no treasury stake, no protocol-owned liquidity.
    NoMintTreasuryLiquidity,
    /// The validator median with no challenge: outside prices unused.
    MedianOnly,
    /// One outside price feed (the thin pool) as the rate's source.
    FeedAsSource,
    /// No validator base reward from burned fees and no treasury stake
    /// delegated to validators.
    NoBaseReward,
    /// No running-cost reserve: running costs budgeted in USD and paid with
    /// the grants, by selling TNZO on the day.
    NoReserve,
    /// The rate follows the stake-weighted median, no quantile band.
    NoQuantileBand,
}

impl Ablation {
    /// Every ablation, the full design first.
    pub const ALL: [Ablation; 9] = [
        Ablation::Full,
        Ablation::NoFiatFees,
        Ablation::NoExposureBonds,
        Ablation::NoMintTreasuryLiquidity,
        Ablation::MedianOnly,
        Ablation::FeedAsSource,
        Ablation::NoBaseReward,
        Ablation::NoReserve,
        Ablation::NoQuantileBand,
    ];

    /// Name in reports.
    pub fn name(self) -> &'static str {
        match self {
            Ablation::Full => "full design",
            Ablation::NoFiatFees => "fees fixed in TNZO",
            Ablation::NoExposureBonds => "fixed provider bonds",
            Ablation::NoMintTreasuryLiquidity => {
                "no mint controller, treasury stake or owned liquidity"
            }
            Ablation::MedianOnly => "validator median, no challenge",
            Ablation::FeedAsSource => "outside feed as the rate source",
            Ablation::NoBaseReward => "no validator base reward or treasury delegation",
            Ablation::NoReserve => "no running-cost reserve, costs paid with grants",
            Ablation::NoQuantileBand => "median rate, no quantile band",
        }
    }
}

/// One run's configuration.
#[derive(Debug, Clone, Serialize)]
pub struct RunConfig {
    /// Market scenario.
    pub market: Market,
    /// Seed; the run follows from it.
    pub seed: u64,
    /// Simulated calendar days.
    pub days: u32,
    /// Behaviour and cost inputs.
    pub assumptions: Assumptions,
    /// Governed parameters set at genesis (others start at their registry value).
    pub network_params: BTreeMap<String, u64>,
    /// Sampled human transfers per block at most; each stands for the
    /// rest of the hour's transfers by weight.
    pub human_sample_per_block: u32,
    /// Sampled compute streams open at most at once. Every settled stream
    /// hour leaves records in chain state, so this bounds a run's memory.
    pub stream_sample: u32,
    /// Adversary that runs beside the honest populations.
    pub adversary: Option<crate::attack::Adversary>,
    /// Validators attest providers' SLA outcomes (off only to measure
    /// what the attestations cost in state).
    pub sla_attest: bool,
    /// A one-off price move: (day, factor), 0.2 being an 80% fall.
    pub shock: Option<(u32, f64)>,
    /// Day from which agents stop renting compute.
    pub agents_leave_day: Option<u32>,
    /// Validators report the market TNZO/USD rate every market epoch, and
    /// the fee rate follows their median (rate mode 1).
    pub rate_reports: bool,
    /// Validators with the lowest ids report the market rate times a
    /// factor from a day on: (validators, factor, day).
    pub rate_cartel: Option<(u32, f64, u32)>,
    /// Mechanism switched off, if any.
    pub ablation: Ablation,
    /// Who takes the populations' decisions ([`crate::decision`]).
    pub policy: crate::decision::Policy,
    /// Deciding agents per role; each speaks for an equal share of its
    /// role's population.
    pub decision_agents: u32,
    /// Shocks drawn for a chaos run ([`crate::chaos`]): demand cuts, price
    /// falls and recoveries, the stable unit's peg, validator and operator
    /// exits, and skewed rate reports.
    #[serde(skip)]
    pub chaos: Option<std::sync::Arc<crate::chaos::Plan>>,
}

impl RunConfig {
    /// A scenario run with default inputs.
    pub fn scenario(market: Market, seed: u64, days: u32) -> Self {
        Self {
            market,
            seed,
            days,
            assumptions: Assumptions::default(),
            network_params: BTreeMap::new(),
            human_sample_per_block: 12,
            stream_sample: 16,
            adversary: None,
            sla_attest: true,
            shock: None,
            agents_leave_day: None,
            rate_reports: false,
            rate_cartel: None,
            ablation: Ablation::Full,
            policy: crate::decision::Policy::default(),
            decision_agents: 1,
            chaos: None,
        }
    }
}

/// Account id layout of the populations.
/// Margin a sponsorship tranche carries over the recent daily need in
/// TNZO, since the price may fall between filing and arrival.
const SPONSOR_MARGIN: f64 = 1.5;

/// What every simulation account holds at genesis, base units.
const OPENING_BALANCE: u128 = 50_000 * TNZO;

pub mod ids {
    use tenzro_sim::ledger::USER_BASE;
    /// Probe account that sends one known transfer a block to measure the fee.
    pub const FEE_PROBE: u32 = USER_BASE;
    /// The account governance grants pay.
    pub const GRANTEE: u32 = USER_BASE + 1;
    /// The account running-cost payments from the reserve pay; it sells what
    /// it receives into the pool.
    pub const DESK: u32 = USER_BASE + 2;
    /// Everyone outside the simulation who holds the stable unit: it
    /// creates the stable token, funds agents and takes redemptions.
    pub const STABLE_OUTSIDE: u32 = USER_BASE + 3;
    /// The account the treasury sell-back pays; it sells what it receives
    /// into the pool.
    pub const SELLBACK: u32 = USER_BASE + 4;
    /// The account governance's sponsorship tranches pay; it pays approved
    /// validators their top-up and sells nothing.
    pub const SPONSOR: u32 = USER_BASE + 5;
    /// First human account.
    pub const HUMANS: u32 = USER_BASE + 10;
    /// Human accounts.
    pub const HUMAN_COUNT: u32 = 200;
    /// First agent (renter) account.
    pub const AGENTS: u32 = HUMANS + HUMAN_COUNT;
    /// Agent accounts.
    pub const AGENT_COUNT: u32 = 200;
    /// First provider account.
    pub const PROVIDERS: u32 = AGENTS + AGENT_COUNT;
    /// Provider accounts.
    pub const PROVIDER_COUNT: u32 = 120;
    /// First adversary account.
    pub const ADVERSARY: u32 = PROVIDERS + PROVIDER_COUNT;
    /// Adversary accounts.
    pub const ADVERSARY_COUNT: u32 = 40;
    /// Every population account.
    pub const TOTAL: u32 = ADVERSARY + ADVERSARY_COUNT - USER_BASE;
}

/// A provider's state.
#[derive(Debug, Clone)]
struct Provider {
    id: u32,
    did: String,
    bonded: bool,
    availability: f64,
    /// Availability of each closed market epoch not yet attested.
    hours: BTreeMap<u64, bool>,
    /// USD the provider realised selling its TNZO income.
    sold_usd: f64,
    earned_tnzo: f64,
    cost_usd: f64,
    gone: bool,
    /// Balance after the last day's sale.
    last_bal: f64,
    /// Compute stream payments opened to it, USD.
    stream_usd: f64,
    /// Agent session payments released to it, USD.
    session_usd: f64,
    /// Reward coupons it claimed, USD at the rate in force.
    coupons_usd: f64,
    /// (stream, session, coupons) USD when the class window opened.
    window_start: (f64, f64, f64),
    /// Daily TNZO income, smoothed.
    income_ema: f64,
    /// Paid out of stable-token escrows, USD.
    stable_in_usd: f64,
    /// Paid out of stable-token escrows at the last day's close, USD.
    stable_in_seen: f64,
    /// Daily stable-token income, smoothed, USD.
    stable_ema_usd: f64,
    /// Treasury leg owed in the stable token and not yet sent, base units.
    leg_owed: u128,
    /// Treasury leg sent in the stable token, USD.
    leg_sent_usd: f64,
    /// What the TNZO it bought for settlement fees cost, USD.
    fee_tnzo_cost_usd: f64,
    /// Day an operator that left in a chaos exodus comes back (0: not away).
    back_day: u32,
}

/// A streaming rental an agent holds.
#[derive(Debug, Clone)]
struct Stream {
    escrow: [u8; 32],
    agent: u32,
    provider: usize,
    created_ms: i64,
    expires_ms: i64,
}

/// A validator's running account.
#[derive(Debug, Clone, Default)]
struct Validator {
    income_tnzo: f64,
    income_usd: f64,
    cost_usd: f64,
    joined_day: f64,
    exiting: bool,
    exit_requested_ms: i64,
    /// Daily (income USD, cost USD) for the trailing window.
    trail: Vec<(f64, f64)>,
    /// Rates sealed for an epoch, opened with the next report:
    /// (epoch, quotes, salt).
    sealed: Option<(u64, Vec<(String, String, u128)>, [u8; 32])>,
    /// Delegators' share of rewards earned and not yet paid out, TNZO.
    owed_delegators: f64,
    /// Stable token held at the last close, base units: what the
    /// validator-cover reserve pays it adds to its income.
    stable_seen: u128,
    /// Sponsorship sent the day before, TNZO: in today's balance change and
    /// kept apart from what the validator earned itself.
    sponsor_sent: f64,
}

/// Governance in flight.
#[derive(Debug, Clone)]
struct Proposal {
    id: Option<Vec<u8>>,
    proposed_ms: i64,
    stage: u8,
    enact_after: i64,
    action: Vec<u8>,
    /// A stable sponsorship claim: the seat and how many verified hours.
    claim: Option<(u32, u32)>,
}

/// Daily record of one run.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Day {
    /// Ledger snapshot.
    #[serde(flatten)]
    pub snap: Snapshot,
    /// TNZO price, USD.
    pub price_usd: f64,
    /// Demand multiple.
    pub demand: f64,
    /// Fee one human transfer paid, TNZO (measured).
    pub human_fee_tnzo: f64,
    /// Fee one agent stream claim paid in settlement fee, TNZO per TNZO streamed.
    pub agent_fee_share: f64,
    /// Mean validator annualised yield over the trailing 30 days.
    pub validator_yield: f64,
    /// Share of bonded validators whose trailing 30-day income covers cost.
    pub validators_profitable: f64,
    /// Share of active providers whose income covers cost (cumulative).
    pub providers_profitable: f64,
    /// Active providers.
    pub providers: u32,
    /// Stake share of the supply.
    pub staking_ratio: f64,
    /// Months of grants the treasury holds at the current price.
    pub treasury_runway_months: f64,
    /// Transactions refused by the ledger today.
    pub refused: u64,
    /// TNZO/USD rate the chain charges fees at, USD.
    pub chain_rate_usd: f64,
    /// Price the pool would show without a manipulator, USD.
    pub fair_price_usd: f64,
    /// Treasury grants paid this day, USD at the day's price.
    pub grants_usd: f64,
    /// Sponsorship paid to validators this day, USD at the day's price, and
    /// in TNZO since genesis.
    pub sponsored_usd: f64,
    pub sponsored_tnzo_total: f64,
    /// Stable sponsorship enacted since genesis, USD.
    pub sponsored_usd_total: f64,
    /// Stable asset outside holders gave the treasury (seed and top-ups), USD.
    pub stable_given_usd: f64,
    /// Stable asset in the validator cover reserve, USD.
    pub cover_reserve_usd: f64,
    /// Stable cover the validators received since genesis, USD.
    pub cover_paid_usd_total: f64,
    /// TNZO the treasury paid out in sponsorship tranches and grants over
    /// the trailing year, and the combined cap (zero: none set).
    pub sponsor_grant_outflow_year_tnzo: f64,
    pub sponsor_grant_cap_tnzo: f64,
    /// Running costs paid over the trailing 30 days, USD.
    pub running_costs_paid_usd_30d: f64,
    /// Running costs asked over the trailing 30 days, USD.
    pub running_costs_asked_usd_30d: f64,
    /// Running costs paid since genesis, USD at each day's price.
    pub running_costs_paid_usd_total: f64,
    /// Running costs asked since genesis, USD.
    pub running_costs_asked_usd_total: f64,
    /// The reserve's on-chain target, TNZO.
    pub reserve_target_tnzo: f64,
    /// Months of the asked running costs the reserve holds at today's price.
    pub reserve_runway_months: f64,
    /// TNZO the pool traded over the day, both sides.
    pub volume_tnzo: f64,
    /// Running-cost TNZO sold into the pool over the day.
    pub reserve_sold_tnzo: f64,
    /// Running-cost TNZO the chain paid out over the day.
    pub reserve_paid_tnzo: f64,
    /// Most the sale cap allowed in one epoch at the day's close, TNZO.
    pub sale_cap_epoch_tnzo: f64,
    /// Running costs enacted and not yet paid, TNZO.
    pub running_costs_owed_tnzo: f64,
    /// Mint controller multiplier.
    pub mint_mult: f64,
    /// Whether governance holds the validator rate.
    pub rate_frozen: bool,
    /// Fee revenue the network collected, annualised from the trailing 30
    /// days, USD: settlement fees on the day's spend and the gas the day's
    /// transactions paid at the measured per-transfer fee.
    pub revenue_usd_year: f64,
    /// Fully diluted value at the day's price, USD.
    pub fdv_usd: f64,
    /// Most the valuation bound lets the price be, USD (infinite: no bound).
    pub price_ceiling_usd: f64,
    /// Bonded stake over the circulating supply at genesis.
    pub staking_ratio_circulating: f64,
    /// What a third of the bonded stake costs at the day's price, USD.
    pub attack_cost_usd: f64,
    /// What buying a third of the bonded stake on the pool would cost, USD;
    /// infinite when the pool does not hold that much.
    pub attack_cost_pool_usd: f64,
    /// TNZO held outside the simulated accounts: what people and agents can
    /// buy from, whole TNZO.
    pub outside_float_tnzo: f64,
    /// Where the rest of the liquid TNZO sits, whole TNZO: providers,
    /// agents, people, validators (liquid and vesting), and the adversary,
    /// probe, grantee and desk accounts.
    pub held_by: HeldBy,
    /// Payments the day settled to providers, less the related-party anchor
    /// share, USD.
    pub unrelated_demand_usd_day: f64,
    /// What the validators' share of the burned fees paid over the trailing
    /// 30 days at the day's price, USD: their income without the rewards
    /// pool's issuance.
    pub validator_fee_income_usd_30d: f64,
    /// Bonded validators' running costs over the trailing 30 days, USD.
    pub validator_cost_usd_30d: f64,
    /// The treasury's stable-token balance, USD.
    pub treasury_stable_usd: f64,
    /// Treasury legs providers sent in the stable token since genesis, USD.
    pub stable_legs_usd_total: f64,
    /// Stable token held outside the simulated accounts, USD.
    pub stable_outside_usd: f64,
    /// TNZO the sell-back desk sold since genesis.
    pub sellback_sold_tnzo_total: f64,
    /// Security ratio, bps: slashable stake against what the outflow caps
    /// in force (the default caps when none are set) let out over an
    /// attack window. `None` when a unit is unpriced.
    pub security_ratio_bps: Option<u64>,
    /// What those caps let out over an attack window, TNZO.
    pub extractable_tnzo: f64,
    /// The governed least security ratio, bps.
    pub min_ratio_bps: u64,
    /// The stable unit's market value, USD (1 at its peg).
    pub stable_peg_usd: f64,
}

/// Liquid TNZO by holder group, whole TNZO.
#[derive(Debug, Clone, Default, Serialize)]
pub struct HeldBy {
    /// Provider accounts.
    pub providers: f64,
    /// Agent accounts.
    pub agents: f64,
    /// Human accounts.
    pub humans: f64,
    /// Validator accounts, liquid.
    pub validators_liquid: f64,
    /// Validator accounts, vesting.
    pub validators_vesting: f64,
    /// Grantee, desk, probe and adversary accounts.
    pub other: f64,
}

/// Outcome of one run.
#[derive(Debug, Clone, Default, Serialize)]
pub struct RunOutcome {
    /// Scenario.
    pub market: String,
    /// Seed.
    pub seed: u64,
    /// Daily record.
    pub days: Vec<Day>,
    /// Transactions applied.
    pub applied: u64,
    /// Transactions refused, by reason (first 200 characters).
    pub refusals: BTreeMap<String, u64>,
    /// Blocks the ledger refused or whose duties failed.
    pub ledger_failures: Vec<String>,
    /// Running-cost reserve rules the chain broke, by block.
    pub reserve_breaks: Vec<String>,
    /// Volume the run stood for but did not execute, TNZO of gas fees,
    /// at the measured per-transfer fee.
    pub unexecuted_gas_fees_tnzo: f64,
    /// Agent sessions the demand called for, executed or represented.
    #[serde(default)]
    pub agent_sessions: f64,
    /// Agent sessions queued for settlement on chain, each standing for its
    /// share of the rest at their combined value; a session the chain
    /// refused (an over-exposed provider) still counts here.
    #[serde(default)]
    pub agent_sessions_settled: u64,
    /// USD the queued sessions carried.
    #[serde(default)]
    pub agent_spend_usd: f64,
    /// Agent sessions sent to the chain (each standing for its share).
    #[serde(default)]
    pub agent_sessions_sent: u64,
    /// Compute streams sent to the chain.
    #[serde(default)]
    pub streams_sent: u64,
    /// Per-class provider accounts and the user side over the last year.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub launch: Option<crate::classes::LaunchEconomics>,
    /// Adversary result, when one ran.
    pub adversary: Option<crate::attack::AttackOutcome>,
    /// Streams past their end that nobody closed when the run ended: what
    /// they hold stays locked and counts against the provider's bond.
    #[serde(default)]
    pub streams_left_open: u64,
    /// Why the run stopped early: a decision its policy could not take.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decision_error: Option<String>,
    /// When each listing-gate item was first met, in a closed-phase run.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub listing_gate: Option<crate::listing::ListingGate>,
    /// Wall-clock seconds.
    pub wall_s: f64,
}

/// One economy in motion.
pub struct Economy {
    /// The chain.
    pub chain: Chain,
    /// Configuration.
    pub cfg: RunConfig,
    /// Random source.
    pub rng: StdRng,
    /// TNZO price, USD.
    pub price: f64,
    genesis_supply: u128,
    providers: Vec<Provider>,
    streams: Vec<Stream>,
    validators: Vec<Validator>,
    proposal: Option<Proposal>,
    /// The sponsorship tranche in flight, beside `proposal`.
    sponsor_props: Vec<Proposal>,
    /// Per sponsored seat, the verified hours not yet paid, oldest first.
    sponsor_hours: Vec<std::collections::VecDeque<u64>>,
    /// Stable sponsorship enacted for a seat and not yet counted in its
    /// income, USD.
    sponsor_credit_usd: Vec<f64>,
    /// The stable seed has been given.
    stable_seeded: bool,
    /// Leg proposals filed (0, 1 or 2).
    legs_filed: u8,
    /// Stable asset given to the treasury, USD.
    stable_given_usd: f64,
    /// Stable cover validators received, USD.
    cover_paid_usd_total: f64,
    /// Stable legs received at the last month close, base units.
    legs_at_topup: u128,
    /// Day of the next month close.
    next_topup_day: f64,
    /// Per sponsored seat, when it may file its next claim.
    next_claim_ms: Vec<i64>,
    /// Whole days whose hours have been recorded as verified.
    verified_days: u64,
    /// Stable sponsorship enacted since genesis, USD.
    sponsored_usd_total: f64,
    next_grant_ms: i64,
    next_rate_ms: i64,
    next_cost_ms: i64,
    /// Outcome being built.
    pub out: RunOutcome,
    day_refused: u64,
    fee_probe_before: u128,
    fee_probe_sum: f64,
    fee_probe_n: u32,
    settle_paid: f64,
    settle_fee: f64,
    /// Adversary state.
    pub adv: Option<crate::attack::AdversaryState>,
    /// Routine proposals enacted.
    pub enacted: u32,
    /// Routine proposals that closed without passing.
    pub failed: u32,
    /// The thin pool TNZO trades on; its price is the market price.
    pool: crate::dex::Pool,
    /// The same pool without a manipulator's trades.
    fair: crate::dex::Pool,
    /// TNZO bought from and sold to the market since the last trade.
    flow_buy: f64,
    flow_sell: f64,
    grants_usd_day: f64,
    last_grant_tnzo: f64,
    /// Sponsorship paid today (USD) and since genesis (TNZO).
    sponsored_usd_day: f64,
    sponsored_tnzo_total: f64,
    /// Sponsorship tranches and grants the treasury paid out: (ms, TNZO).
    outflow_log: Vec<(i64, f64, bool)>,
    /// Daily sponsorship paid, smoothed, USD: what the next tranche covers,
    /// at the price of the day it is filed.
    sponsor_ema_usd: f64,
    /// Treasury at the first governance step, TNZO: the base of the cap.
    treasury_open: Option<f64>,
    /// The sponsorship tranche approved before launch, TNZO.
    sponsor_open_tnzo: f64,
    next_sponsor_ms: i64,
    off_band_days: u32,
    in_band_days: u32,
    /// TNZO the pool traded on its last trading day, both sides.
    volume_day_tnzo: f64,
    /// Running-cost TNZO the desk holds and has not sold yet.
    desk_inventory: u128,
    /// Running costs the desk turned into USD since the day's close.
    desk_proceeds_usd: f64,
    /// Running-cost TNZO sold in the last trade.
    desk_sold_tnzo: f64,
    /// Reserve payouts seen so far, wei.
    reserve_paid_seen: u128,
    /// Reserve payouts seen by the last block's check, wei.
    reserve_paid_checked: u128,
    /// Daily (paid USD, asked USD) of running costs, trailing 30 days.
    cost_trail: std::collections::VecDeque<(f64, f64)>,
    /// Running costs (paid USD, asked USD) since genesis.
    cost_total: (f64, f64),
    /// Standing action of each deciding agent, by role
    /// ([`crate::decision::Role::ALL`] order).
    standing: [Vec<usize>; 4],
    /// Price at each role's last decision.
    decided_price: [f64; 4],
    /// Stake delegated to each genesis validator above its own, TNZO.
    delegated_each: f64,
    /// A validator's own stake: the minimum and its share of the treasury
    /// stake, TNZO.
    own_bond: f64,
    /// Circulating supply at genesis, TNZO.
    circulating0: f64,
    /// Fully diluted value at launch, USD.
    launch_fdv: f64,
    /// Daily fee revenue, USD, trailing 30 days.
    revenue_trail: std::collections::VecDeque<f64>,
    /// Transactions applied at the last day's close.
    tx_seen: f64,
    /// Gas fees of unexecuted volume at the last day's close, TNZO.
    unexec_seen: f64,
    /// TNZO agents bought since the last day's close.
    agent_bought: f64,
    /// Agents' balances at the last day's close, TNZO.
    agent_held: f64,
    /// Most the price may be under the valuation bound, USD.
    price_ceiling: f64,
    /// TNZO the market takes from outside holders a day, net, smoothed.
    buy_ema: f64,
    /// Stream and session payments to providers at the last day's close, USD.
    settled_seen: f64,
    /// Burned since genesis at the last day's close, TNZO.
    burned_seen: f64,
    /// Daily (validator fee income USD, validator cost USD), trailing 30 days.
    validator_fee_trail: std::collections::VecDeque<(f64, f64)>,
    /// The stable token, when payments settle in it.
    stable: Option<crate::stable::Stable>,
    /// The governed settlement-asset entry for the stable token, until a
    /// vote has installed it: payments in a token with no entry are
    /// refused.
    asset_entry: Option<Vec<u8>>,
    /// What broke the stable token's conservation rule, by day.
    stable_breaks: Vec<String>,
    /// When governance next considers a treasury sell-back.
    next_sellback_ms: i64,
    /// TNZO the sell-back desk sold since genesis.
    sellback_sold: f64,
}

/// Days of the market's net buying that outside holders must hold before
/// the valuation bound holds the price down.
pub const FLOAT_BUFFER_DAYS: f64 = 30.0;

/// Fixed supply, whole TNZO.
pub const MAX_SUPPLY_TNZO: f64 = 1_000_000_000.0;

fn did(id: u32) -> String {
    format!("did:tenzro:machine:econsim-{id}")
}

impl Economy {
    /// Genesis of a run.
    pub fn new(mut cfg: RunConfig) -> Self {
        let set = |cfg: &mut RunConfig, k: &str, v: u64| {
            cfg.network_params.insert(k.into(), v);
        };
        match cfg.ablation {
            Ablation::Full | Ablation::NoExposureBonds => {}
            Ablation::NoBaseReward => {
                set(&mut cfg, "fees.validator_burn_share_bps", 0);
                cfg.assumptions.treasury_stake_tnzo = 0.0;
            }
            Ablation::NoReserve => {
                set(&mut cfg, n::treasury_reserve::FILL_SHARE_PARAM, 0);
                cfg.assumptions.grants_tnzo_month = f64::MAX;
                cfg.assumptions.grant_cap_bps_month = 10_000.0;
            }
            Ablation::NoQuantileBand => {
                set(&mut cfg, "fees.usd_rate_quantile_low_bps", 5_000);
                set(&mut cfg, "fees.usd_rate_quantile_high_bps", 5_000);
            }
            Ablation::NoFiatFees => {
                cfg.rate_reports = false;
                cfg.assumptions.governance_tracks_price = false;
            }
            Ablation::NoMintTreasuryLiquidity => {
                cfg.assumptions.treasury_stake_tnzo = 0.0;
                cfg.assumptions.pol_usd = 0.0;
                for k in ["mint.min_mult_bps", "mint.max_mult_bps"] {
                    cfg.network_params.insert(k.into(), 10_000);
                }
            }
            Ablation::MedianOnly => cfg.rate_reports = true,
            Ablation::FeedAsSource => {
                cfg.rate_reports = true;
                set(&mut cfg, "fees.usd_rate_max_change_bps", 10_000);
                set(&mut cfg, "fees.usd_rate_quantile_low_bps", 5_000);
                set(&mut cfg, "fees.usd_rate_quantile_high_bps", 5_000);
            }
        }
        if cfg.ablation == Ablation::NoExposureBonds {
            set(&mut cfg, "compute_bond.var_ratio_bps", 0);
        }
        // Before a listing nothing sells TNZO: the reserve takes no revenue
        // to sell for running costs, governance grants nothing to sell, and
        // payments, escrows and the treasury leg settle in the stable token.
        if cfg.assumptions.closed_phase {
            cfg.assumptions.stable_settlement = true;
            cfg.assumptions.stable_asset = true;
            cfg.assumptions.stable_leg = true;
            cfg.assumptions.grants_tnzo_month = 0.0;
            set(&mut cfg, n::treasury_reserve::FILL_SHARE_PARAM, 0);
        }
        if cfg.assumptions.stable_leg {
            cfg.assumptions.stable_asset = true;
        }
        if cfg.assumptions.stable_asset {
            cfg.assumptions.stable_settlement = true;
        }
        let a = &cfg.assumptions;
        let mut params = cfg.network_params.clone();
        // A leg taken in the stable token is not charged on chain: the
        // provider pays it to the treasury in the token at the governed rate.
        let leg_of = |key: &str| params.get(key).copied().unwrap_or(0);
        let stable_legs = (
            leg_of(n::economy::TREASURY_LEG_INFERENCE_PARAM),
            leg_of(n::economy::TREASURY_LEG_COMPUTE_PARAM),
        );
        if a.stable_leg {
            for key in [
                n::economy::TREASURY_LEG_INFERENCE_PARAM,
                n::economy::TREASURY_LEG_TEE_PARAM,
                n::economy::TREASURY_LEG_RPC_PARAM,
                n::economy::TREASURY_LEG_COMPUTE_PARAM,
                n::economy::TREASURY_LEG_STORAGE_PARAM,
            ] {
                params.insert(key.into(), 0);
            }
        }
        // One block stands for an hour of blocks, so its compute target is
        // the most the registry allows: the hour's load must not move the
        // base fee as if it were one block's. The fee market is measured at
        // real block time by the spam study instead.
        params
            .entry(tenzro_vm::ledger::COMPUTE_TARGET_PARAM.into())
            .or_insert(1_000_000_000);
        if cfg.rate_reports {
            params.insert("fees.usd_rate_mode".into(), 1);
        }
        params
            .entry("fees.tnzo_usd_nano".into())
            .or_insert((a.price0_usd * 1e9) as u64);
        // The reserve's month and payment lifetime count consensus epochs;
        // on this clock an epoch is a calendar day, not an hour.
        let clock = Clock::HOURLY;
        let epoch_cal_ms = clock.block_ms * clock.blocks_per_epoch * clock.calendar_scale;
        let month_epochs = (30 * DAY_MS as u64 / epoch_cal_ms.max(1)).max(1);
        for key in [
            n::treasury_reserve::MONTH_EPOCHS_PARAM,
            n::treasury_reserve::PAYMENT_TTL_PARAM,
        ] {
            params.entry(key.into()).or_insert(month_epochs);
        }
        // The reserve's sale ceiling is per epoch too: on the chain an
        // epoch is an hour, here a day, so a day here may sell what a day of
        // hourly epochs may.
        if a.reserve_cap_per_hour {
            let hours = (epoch_cal_ms / n::MARKET_EPOCH_MS as u64).max(1);
            params
                .entry(n::treasury_reserve::MAX_SALE_PARAM.into())
                .or_insert(n::treasury_reserve::DEFAULT_MAX_SALE_TNZO_EPOCH * hours);
        }
        // Owned liquidity takes half its depth in treasury TNZO; the
        // treasury's stake is spread over the genesis validators and locked.
        let pol_tnzo = a.pol_usd / 2.0 / a.price0_usd;
        let stake_each = a.treasury_stake_tnzo / a.validators.max(1) as f64;
        let treasury = (a.treasury_genesis_tnzo - pol_tnzo - a.treasury_stake_tnzo).max(0.0);
        // The first sponsorship tranche is approved before launch: the
        // buffer and a month of the sponsored seats' governed cost, taken
        // from the treasury's TNZO into the sponsor account.
        let sponsor_open = if a.sponsor_seats > 0 && !a.sponsor_gated {
            (a.sponsor_seats as f64 * a.validator_cost_usd_month / 30.44
                * (a.sponsor_buffer_days + 30.0)
                * SPONSOR_MARGIN
                / a.price0_usd)
                .ceil()
                .min(treasury)
        } else {
            0.0
        };
        let treasury = treasury - sponsor_open;
        let pool = crate::dex::Pool::new(a.pool_depth_usd + a.pol_usd, a.price0_usd);
        let own_bond_u =
            tenzro_vm::governance::genesis_param("stake.validator_tnzo") + stake_each as u64;
        let own_bond = own_bond_u as f64;
        // Stake delegated from outside holders, so the bonded share of the
        // circulating supply reaches the target.
        let circulating0 = MAX_SUPPLY_TNZO
            - tnzo(tenzro_token::NETWORK_REWARDS_POOL)
            - treasury.floor()
            - sponsor_open.floor()
            - a.insurance_genesis_tnzo.floor()
            - a.reserve_seed_tnzo.floor();
        let delegated_each = if a.staking_ratio > 0.0 {
            (a.staking_ratio * circulating0 / a.validators.max(1) as f64 - own_bond)
                .max(0.0)
                .floor()
        } else {
            0.0
        };
        let plan = GenesisPlan {
            validators: a.validators,
            standby: a.standby,
            bond_tnzo: (own_bond_u + delegated_each as u64).max(1),
            balance_tnzo: 50_000,
            users: ids::TOTAL,
            treasury_tnzo: treasury as u64,
            insurance_tnzo: a.insurance_genesis_tnzo as u64,
            reserve_tnzo: a.reserve_seed_tnzo as u64,
            opening_accounts: if sponsor_open > 0.0 {
                vec![(ledger::account(ids::SPONSOR), sponsor_open as u64)]
            } else {
                Vec::new()
            },
            network_params: params,
        };
        let mut chain = Chain::new(&plan, Clock::HOURLY);
        let genesis_supply = chain.ledger.total_supply();
        if a.sponsor_gated {
            for v in 0..a.sponsor_seats {
                chain.ledger.approve_operator(v);
            }
        }
        // The stable token is created in the first block, before anyone pays.
        let stable = a.stable_asset.then(|| {
            let floor = chain.param(n::token::POLICY_TIMELOCK_FLOOR_PARAM);
            let call = crate::stable::create_call(floor);
            assert!(chain.call(
                ids::STABLE_OUTSIDE,
                None,
                0,
                call[..4].try_into().expect("selector"),
                &call[4..],
                NATIVE_GAS,
                None,
            ));
            let created = chain
                .produce()
                .into_iter()
                .find(|r| r.applied && r.tx.sender() == ids::STABLE_OUTSIDE)
                .expect("the stable token is created");
            let token = serde_json::from_slice::<serde_json::Value>(&created.output)
                .ok()
                .and_then(|v| hex::decode(v["token_id"].as_str()?).ok())
                .and_then(|b| <[u8; 32]>::try_from(b).ok())
                .expect("the creation names the token");
            crate::stable::Stable::new(token, a.stable_leg, stable_legs.0, stable_legs.1)
        });
        let asset_entry = stable
            .as_ref()
            .map(|s| crate::stable::install_action(s.token));
        let launch_fdv = a.price0_usd * tnzo(genesis_supply);
        let mut rng = StdRng::seed_from_u64(cfg.seed);
        let providers = (0..ids::PROVIDER_COUNT)
            .map(|i| {
                let id = ids::PROVIDERS + i;
                let spread: f64 = rng.gen_range(-1.0..1.0);
                let miss = (1.0 - a.provider_availability) * (1.0 + spread);
                Provider {
                    id,
                    // The identity the account is registered under, so its
                    // bond is the one escrows to it are checked against.
                    did: n::identity_did_of(chain.state(), &ledger::account(id))
                        .unwrap_or_else(|| did(id)),
                    last_bal: 50_000.0,
                    bonded: false,
                    availability: (1.0 - miss).clamp(0.5, 1.0),
                    hours: BTreeMap::new(),
                    earned_tnzo: 0.0,
                    sold_usd: 0.0,
                    cost_usd: 0.0,
                    gone: false,
                    back_day: 0,
                    stream_usd: 0.0,
                    session_usd: 0.0,
                    coupons_usd: 0.0,
                    window_start: (0.0, 0.0, 0.0),
                    income_ema: 0.0,
                    stable_in_usd: 0.0,
                    stable_in_seen: 0.0,
                    stable_ema_usd: 0.0,
                    leg_owed: 0,
                    leg_sent_usd: 0.0,
                    fee_tnzo_cost_usd: 0.0,
                }
            })
            .collect();
        let validators = (0..a.validators + a.standby)
            .map(|v| Validator {
                joined_day: if v < a.validators { 0.0 } else { f64::NAN },
                ..Validator::default()
            })
            .collect();
        let price = a.price0_usd;
        let sponsor_seats = a.sponsor_seats as usize;
        let credit_len = (a.validators + a.standby) as usize;
        let agents_per_role = cfg.decision_agents.max(1) as usize;
        let adv = cfg
            .adversary
            .clone()
            .map(crate::attack::AdversaryState::new);
        let out = RunOutcome {
            market: cfg.market.name().into(),
            seed: cfg.seed,
            ..RunOutcome::default()
        };
        Self {
            chain,
            cfg,
            rng,
            price,
            genesis_supply,
            providers,
            streams: Vec::new(),
            validators,
            proposal: None,
            sponsor_props: Vec::new(),
            sponsor_hours: vec![Default::default(); sponsor_seats],
            next_claim_ms: vec![0; sponsor_seats],
            sponsor_credit_usd: vec![0.0; credit_len],
            stable_seeded: false,
            legs_filed: 0,
            stable_given_usd: 0.0,
            cover_paid_usd_total: 0.0,
            legs_at_topup: 0,
            next_topup_day: 30.0,
            verified_days: 0,
            sponsored_usd_total: 0.0,
            next_grant_ms: 30 * DAY_MS,
            next_rate_ms: 7 * DAY_MS,
            next_cost_ms: DAY_MS,
            out,
            day_refused: 0,
            fee_probe_before: 0,
            fee_probe_sum: 0.0,
            fee_probe_n: 0,
            settle_paid: 0.0,
            settle_fee: 0.0,
            adv,
            enacted: 0,
            failed: 0,
            pool,
            fair: pool,
            flow_buy: 0.0,
            flow_sell: 0.0,
            grants_usd_day: 0.0,
            last_grant_tnzo: 0.0,
            sponsored_usd_day: 0.0,
            sponsored_tnzo_total: 0.0,
            outflow_log: if sponsor_open > 0.0 {
                vec![(0, sponsor_open, true)]
            } else {
                Vec::new()
            },
            sponsor_open_tnzo: sponsor_open,
            sponsor_ema_usd: 0.0,
            treasury_open: None,
            next_sponsor_ms: 0,
            off_band_days: 0,
            in_band_days: 0,
            volume_day_tnzo: 0.0,
            desk_inventory: 0,
            desk_proceeds_usd: 0.0,
            desk_sold_tnzo: 0.0,
            reserve_paid_seen: 0,
            reserve_paid_checked: 0,
            cost_trail: std::collections::VecDeque::new(),
            cost_total: (0.0, 0.0),
            standing: crate::decision::Role::ALL.map(|r| vec![r.default_action(); agents_per_role]),
            decided_price: [price; 4],
            delegated_each,
            own_bond,
            circulating0,
            launch_fdv,
            revenue_trail: std::collections::VecDeque::new(),
            tx_seen: 0.0,
            unexec_seen: 0.0,
            agent_bought: 0.0,
            agent_held: 0.0,
            price_ceiling: f64::INFINITY,
            buy_ema: 0.0,
            settled_seen: 0.0,
            burned_seen: 0.0,
            validator_fee_trail: std::collections::VecDeque::new(),
            asset_entry,
            stable,
            stable_breaks: Vec::new(),
            next_sellback_ms: 30 * DAY_MS,
            sellback_sold: 0.0,
        }
    }

    /// Runs to the end.
    pub fn run(self) -> RunOutcome {
        self.run_with(|_| {})
    }

    /// Runs to the end, calling `inspect` before the books close.
    pub fn run_with(mut self, inspect: impl FnOnce(&Economy)) -> RunOutcome {
        let t = std::time::Instant::now();
        let hours = self.cfg.days as u64 * 24;
        for _ in 0..hours {
            if let Err(e) = self.decide() {
                self.out.decision_error = Some(e);
                break;
            }
            self.hour();
        }
        inspect(&self);
        self.out.launch = Some(self.launch_economics());
        if self.cfg.assumptions.closed_phase {
            self.out.listing_gate = Some(crate::listing::ListingGate::of(&self.out.days));
        }
        crate::attack::finish(&mut self);
        let now = self.chain.now_ms();
        let state = self.chain.state();
        self.out.streams_left_open = self
            .providers
            .iter()
            .flat_map(|p| n::economy::provider_exposure(state, &p.did, now).1)
            .filter_map(|id| hex::decode(id).ok()?.try_into().ok())
            .filter_map(|id: [u8; 32]| n::read_escrow(state, &id))
            .filter(|e| e.expires_at.0 + HOUR_MS < now)
            .count() as u64;
        self.out.applied = self.chain.ledger.stats.applied;
        self.out.ledger_failures = self
            .chain
            .ledger
            .conservation_failures
            .iter()
            .take(50)
            .map(|(h, e)| format!("height {h}: {e}"))
            .chain(self.stable_breaks.iter().take(50).cloned())
            .collect();
        self.out.wall_s = t.elapsed().as_secs_f64();
        self.out
    }

    fn day(&self) -> f64 {
        self.chain.now_ms() as f64 / DAY_MS as f64
    }

    fn market_epoch(&self) -> u64 {
        (self.chain.now_ms().max(0) / n::MARKET_EPOCH_MS) as u64
    }

    fn bonded(&self) -> Vec<u32> {
        self.chain
            .ledger
            .bonds_now()
            .iter()
            .enumerate()
            .filter(|(_, b)| **b > 0)
            .map(|(i, _)| i as u32)
            .collect()
    }

    /// Fee the next block's transfer pays at most per unit of gas, TNZO units.
    fn max_fee(&self) -> Option<u128> {
        None
    }

    /// One calendar hour: one block.
    fn hour(&mut self) {
        let day = self.day();
        let hour_of_day = (self.chain.now_ms() / HOUR_MS) % 24;
        let a = self.cfg.assumptions.clone();
        let demand = self.demand_at(day);
        let agents_gone = self.cfg.agents_leave_day.is_some_and(|d| day >= d as f64);
        if hour_of_day == 0 {
            self.step_price();
            self.chaos_day();
        }
        // Probe transfer: one known transfer measures what a human pays.
        self.fee_probe_before = self.chain.balance_of(&ledger::account(ids::FEE_PROBE));
        self.chain
            .transfer(ids::FEE_PROBE, ids::GRANTEE, 1, self.max_fee());
        // Humans.
        let per_hour = a.human_tx_per_day * demand / 24.0;
        let sample = (self.cfg.human_sample_per_block as f64).min(per_hour.ceil());
        let k = sample as u32;
        for _ in 0..k {
            let from = ids::HUMANS + self.rng.gen_range(0..ids::HUMAN_COUNT);
            let to = ids::HUMANS + self.rng.gen_range(0..ids::HUMAN_COUNT);
            let usd = a.human_tx_usd * (-(self.rng.gen_range(1e-6..1.0f64)).ln());
            let amount = ((usd / self.price) * TNZO as f64) as u128;
            self.chain.transfer(from, to, amount.max(1), self.max_fee());
        }
        let unexecuted = (per_hour - k as f64).max(0.0);
        // Paying in the stable token, agents are funded in the first block
        // after the token's, before they first pay.
        if self.stable.is_some() && self.chain.height() == 1 {
            self.top_up(demand);
        }
        // Agent swarms: each task fans out to sub-agents, each paying a
        // provider through one session settled once. A sample settles on
        // chain, each carrying its share of the hour's value.
        if !agents_gone {
            self.agent_sessions(demand);
        }
        // Providers enter, attest and are paid; agents rent.
        self.providers_and_rentals(if agents_gone { 0.0 } else { demand });
        self.validators_attest();
        self.validators_report_rate();
        if hour_of_day == 1 {
            self.validators_claim();
        }
        if hour_of_day == 2 {
            self.top_up(if agents_gone { 0.0 } else { demand });
        }
        self.governance();
        crate::attack::hour(self);
        let probe_fee_before = self.fee_probe_before;
        let results = self.chain.produce();
        self.after_block(&results);
        self.stable_after_block();
        self.check_reserve();
        let after = self.chain.balance_of(&ledger::account(ids::FEE_PROBE));
        let fee = probe_fee_before.saturating_sub(after).saturating_sub(1);
        self.fee_probe_sum += tnzo(fee);
        self.fee_probe_n += 1;
        self.out.unexecuted_gas_fees_tnzo += unexecuted * tnzo(fee);
        if (self.chain.now_ms() / HOUR_MS) % 24 == 23 {
            self.close_day(demand);
        }
    }

    /// The stable-token escrows after a block: what each paid its provider
    /// and the treasury leg the provider owes on it, and the expired ones
    /// their payers close.
    fn stable_after_block(&mut self) {
        let day = self.day();
        let now = self.chain.now_ms();
        let peg = self.peg_at(day);
        let Some(s) = self.stable.as_mut() else {
            return;
        };
        let fee_bps = self.chain.param("fees.settlement_fee_bps");
        let (paid, breaks) = s.after_block(self.chain.state());
        for b in breaks {
            self.stable_breaks.push(format!("day {day:.2}: {b}"));
        }
        for p in paid {
            let prov = &mut self.providers[p.provider];
            prov.stable_in_usd += crate::stable::usd(p.amount) * peg;
            // The leg of provider work: a payee with an eligible compute
            // bond, as the VM classes it.
            let provider_work = n::economy::compute_bond(self.chain.state(), &prov.did)
                .is_some_and(|b| b.is_eligible());
            if provider_work {
                prov.leg_owed += s.leg_of(p.work, p.amount, fee_bps);
            }
        }
        for (payer, id) in s.to_close(now) {
            let payload = serde_json::json!({ "escrow_id": id });
            let _ = self.chain.call(
                payer,
                None,
                0,
                n::SELECTOR_ESCROW_REFUND,
                payload.to_string().as_bytes(),
                NATIVE_GAS,
                None,
            );
        }
    }

    /// The stable token at a day's close: its conservation rule over every
    /// account of the run and the open escrows, and (the treasury's
    /// balance, the legs sent, what outside holders hold), USD. Zeros
    /// without the token.
    fn check_stable(&mut self, day: f64) -> (f64, f64, f64) {
        let Some(s) = self.stable.as_ref() else {
            return (0.0, 0.0, 0.0);
        };
        let a = &self.cfg.assumptions;
        let state = self.chain.state();
        let treasury = n::derive_treasury_address().0;
        let mut holders: Vec<[u8; 32]> = (0..a.validators + a.standby)
            .chain(ledger::USER_BASE..ledger::USER_BASE + ids::TOTAL)
            .chain([crate::chain::RESERVE])
            .map(ledger::account)
            .collect();
        holders.extend([
            treasury,
            n::reserve_address().0,
            n::insurance::pool_address().0,
            tenzro_token::rewards_pool_address().0,
            n::validator_cover::reserve_address().0,
        ]);
        if let Some(e) = s.check(state, &holders) {
            self.stable_breaks.push(format!("day {day:.2}: {e}"));
        }
        (
            crate::stable::usd(s.balance(state, &treasury)),
            crate::stable::usd(s.legs_sent),
            crate::stable::usd(s.balance(state, &ledger::account(ids::STABLE_OUTSIDE))),
        )
    }

    /// The reserve's rules as each block left them: one epoch never pays
    /// more than its sale cap, and payouts only ever add up.
    fn check_reserve(&mut self) {
        let book = n::treasury_reserve::read_book(self.chain.state());
        if book.total_paid < self.reserve_paid_checked {
            self.out.reserve_breaks.push(format!(
                "day {:.2}: reserve payouts went down from {} to {}",
                self.day(),
                self.reserve_paid_checked,
                book.total_paid
            ));
        }
        let paid = book.total_paid.saturating_sub(self.reserve_paid_checked);
        if paid > book.sale_cap {
            self.out.reserve_breaks.push(format!(
                "day {:.2}: paid {paid} over the epoch's sale cap {}",
                self.day(),
                book.sale_cap
            ));
        }
        self.reserve_paid_checked = book.total_paid;
    }

    /// The day's trades on the pool: what agents and providers bought and
    /// sold since the last trade, zero-mean outside trading, any shock, and
    /// a manipulator holding the pool up in the feed-as-source ablation.
    fn step_price(&mut self) {
        // No public market: nothing trades and the price stays at launch.
        if self.cfg.assumptions.closed_phase {
            self.flow_buy = 0.0;
            self.flow_sell = 0.0;
            self.volume_day_tnzo = 0.0;
            self.desk_sold_tnzo = 0.0;
            return;
        }
        self.arbitrage();
        let a = self.cfg.assumptions.clone();
        let z: f64 = {
            let u1: f64 = self.rng.gen_range(1e-12..1.0);
            let u2: f64 = self.rng.gen_range(0.0..1.0);
            (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos()
        };
        let depth = 2.0 * self.fair.usd;
        let outside_usd = a.outside_flow_vol * depth * z;
        let outside = outside_usd / self.fair.price().max(1e-12);
        // The desk sells running-cost payouts as a participant of at most
        // the governed share of the day's volume, its own sale included,
        // and carries the rest to the next day.
        let share = (self
            .chain
            .param(n::treasury_reserve::SALE_VOLUME_SHARE_PARAM) as f64
            / 10_000.0)
            .min(0.5);
        let others = self.flow_sell + self.flow_buy + outside.abs();
        let room = (share / (1.0 - share) * others * TNZO as f64) as u128;
        let q = self
            .desk_inventory
            .min(room)
            .min(self.chain.ledger.balance(ids::DESK));
        let before = self.flow_sell;
        self.sell(ids::DESK, q);
        let sold = self.flow_sell - before;
        if sold > 0.0 {
            self.desk_inventory = self.desk_inventory.saturating_sub(q);
        }
        self.desk_sold_tnzo = sold;
        self.desk_proceeds_usd += sold * self.price;
        let holders = a.holder_buy_usd_day / self.fair.price().max(1e-12);
        let net = self.flow_sell - self.flow_buy - outside - holders;
        // What the market takes out of outside holders' hands, net of what
        // comes back to them.
        self.buy_ema = 0.9 * self.buy_ema + 0.1 * (-net).max(0.0);
        // What a market data source reports: both sides of the day's trades.
        self.volume_day_tnzo = self.flow_sell + self.flow_buy + outside.abs() + holders;
        self.flow_buy = 0.0;
        self.flow_sell = 0.0;
        self.fair.trade(net);
        self.pool.trade(net);
        if let Some((day, factor)) = self.cfg.shock
            && (self.day() - day as f64).abs() < 0.5
        {
            self.fair.move_price(factor);
            self.pool.move_price(factor);
        }
        if let Some(plan) = &self.cfg.chaos {
            let f = plan.price_factor(self.day().round() as u32);
            if f != 1.0 {
                self.fair.move_price(f);
                self.pool.move_price(f);
            }
        }
        // Holders sell into a price above what usage supports: each day
        // they close `holder_sell_elasticity` of the log gap over the
        // ceiling, along the pool's curve.
        let ceiling = a.price0_usd * self.cfg.market.demand(self.day()) * a.valuation_headroom;
        let p = self.fair.price();
        if a.holder_sell_elasticity > 0.0 && p > ceiling {
            self.fair
                .move_price((ceiling / p).powf(a.holder_sell_elasticity.min(1.0)));
        }
        // The valuation bound, when one is set: above it holders sell until
        // the price is back at it.
        self.price_ceiling = self.valuation_ceiling();
        // Holders can only sell into a price above the bound with TNZO they
        // hold. When what outside holders hold falls under a month of the
        // market's net buying, the bound gives way in proportion, and the
        // price rises until a USD of demand needs fewer TNZO.
        if self.price_ceiling.is_finite() {
            let float = tnzo(self.chain.ledger.balance(crate::chain::RESERVE));
            let buffer = FLOAT_BUFFER_DAYS * self.buy_ema;
            if buffer > 0.0 && float < buffer {
                self.price_ceiling *= buffer / float.max(1.0);
            }
        }
        let p = self.fair.price();
        if p > self.price_ceiling {
            self.fair.move_price(self.price_ceiling / p);
        }
        self.pool = match self.cfg.rate_cartel {
            Some((_, f, from))
                if self.cfg.ablation == Ablation::FeedAsSource && self.day() >= from as f64 =>
            {
                let mut p = self.fair;
                p.move_price(f);
                p
            }
            _ => self.fair,
        };
        self.price = self.pool.price().max(1e-7);
    }

    /// The demand multiple on `day`, cut by a chaos plan's demand shocks.
    fn demand_at(&self, day: f64) -> f64 {
        let d = self.cfg.assumptions.demand(self.cfg.market, day);
        match &self.cfg.chaos {
            Some(p) => d * p.demand_factor(day),
            None => d,
        }
    }

    /// The stable unit's market value on `day`, USD.
    fn peg_at(&self, day: f64) -> f64 {
        self.cfg.chaos.as_ref().map_or(1.0, |p| p.peg(day))
    }

    /// A chaos plan's exits at a day's open: a share of bonded stake asks
    /// to leave at once (the chain keeps four validators bonded at least,
    /// as voluntary exits do), and a share of serving operators stops
    /// serving for a span, then comes back.
    fn chaos_day(&mut self) {
        let Some(plan) = self.cfg.chaos.clone() else {
            return;
        };
        let day = self.day().round() as u32;
        for p in self.providers.iter_mut() {
            if p.gone && p.back_day > 0 && p.back_day <= day {
                p.gone = false;
                p.back_day = 0;
            }
        }
        if let Some(share) = plan.validator_exit(day) {
            let bonds: Vec<u128> = self.chain.ledger.bonds_now().to_vec();
            let total: u128 = bonds.iter().sum();
            let target = (total as f64 * share) as u128;
            let now = self.chain.now_ms();
            let mut staying: Vec<u32> = self
                .bonded()
                .into_iter()
                .filter(|v| !self.validators[*v as usize].exiting)
                .collect();
            let mut left = 0u128;
            while left < target && staying.len() > 4 {
                let v = staying.pop().expect("more than four");
                let _ = self
                    .chain
                    .submit(v, NATIVE_GAS, |nonce| SimTx::Exit { from: v, nonce });
                let st = &mut self.validators[v as usize];
                st.exiting = true;
                st.exit_requested_ms = now;
                left += bonds[v as usize];
            }
        }
        if let Some((share, away)) = plan.operator_exit(day) {
            let serving: Vec<usize> = (0..self.providers.len())
                .filter(|i| self.providers[*i].bonded && !self.providers[*i].gone)
                .collect();
            let n = (serving.len() as f64 * share).round() as usize;
            for &i in serving.iter().rev().take(n) {
                self.providers[i].gone = true;
                self.providers[i].back_day = day + away.max(1);
            }
        }
    }

    /// Most the price may be under the valuation bound, USD: the larger of
    /// the launch value (lowered over year one by the stress) and the
    /// revenue multiple, at most the value cap, over today's supply.
    /// Infinite when no bound is set.
    pub fn valuation_ceiling(&self) -> f64 {
        let a = &self.cfg.assumptions;
        if a.max_price_to_revenue <= 0.0 && a.max_fdv_usd <= 0.0 && a.fdv_stress_year1 <= 0.0 {
            return f64::INFINITY;
        }
        let years = (self.day() / YEAR_DAYS).min(1.0);
        let launch = self.launch_fdv * (1.0 - a.fdv_stress_year1.clamp(0.0, 1.0) * years);
        let mut fdv = if a.max_price_to_revenue > 0.0 {
            launch.max(a.max_price_to_revenue * self.revenue_usd_year())
        } else if a.fdv_stress_year1 > 0.0 {
            launch
        } else {
            f64::INFINITY
        };
        if a.max_fdv_usd > 0.0 {
            fdv = fdv.min(a.max_fdv_usd);
        }
        fdv / tnzo(self.chain.ledger.total_supply()).max(1.0)
    }

    /// Fee revenue over the trailing 30 days, annualised, USD.
    pub fn revenue_usd_year(&self) -> f64 {
        if self.revenue_trail.is_empty() {
            return 0.0;
        }
        self.revenue_trail.iter().sum::<f64>() / self.revenue_trail.len() as f64 * YEAR_DAYS
    }

    /// Every role whose decision is due takes it: each week, and at the
    /// day boundary after the price moved enough since its last decision.
    fn decide(&mut self) -> Result<(), String> {
        use crate::decision::{
            DECISION_EVERY_H, EVENT_LOG2_MOVE, Observation, Role, bucket, log_q,
        };
        let hour = (self.chain.now_ms().max(0) / HOUR_MS) as u64;
        let weekly = hour.is_multiple_of(DECISION_EVERY_H);
        if !weekly && !hour.is_multiple_of(24) {
            return Ok(());
        }
        let a = &self.cfg.assumptions;
        let last = self.out.days.last();
        let fee_usd = last.map(|d| d.human_fee_tnzo * d.price_usd).unwrap_or(0.0);
        let rate_gap = last
            .map(|d| d.chain_rate_usd / d.price_usd.max(1e-12) - 1.0)
            .unwrap_or(0.0);
        let serving = self
            .providers
            .iter()
            .filter(|p| p.bonded && !p.gone)
            .count();
        let mut state = std::collections::BTreeMap::new();
        state.insert("week", (hour / DECISION_EVERY_H) as i64);
        state.insert("price_q", log_q(self.price));
        state.insert(
            "demand_pct",
            bucket(self.demand_at(self.day()) * 100.0, 10.0),
        );
        state.insert("fee_q", log_q(fee_usd));
        state.insert("rate_gap_pct", bucket(rate_gap * 100.0, 5.0));
        state.insert(
            "providers_pct",
            bucket(
                serving as f64 * 100.0 / self.providers.len().max(1) as f64,
                10.0,
            ),
        );
        state.insert(
            "streams_pct",
            bucket(
                self.streams.len() as f64 * 100.0 / self.cfg.stream_sample.max(1) as f64,
                10.0,
            ),
        );
        state.insert(
            "margin_pct",
            bucket(
                (a.compute_hour_usd - a.provider_hour_cost_usd) * 100.0 / a.compute_hour_usd,
                10.0,
            ),
        );
        state.insert("validators", self.bonded().len() as i64);
        let policy = self.cfg.policy.0.clone();
        for (r, role) in Role::ALL.into_iter().enumerate() {
            let moved = (self.price / self.decided_price[r]).log2().abs() >= EVENT_LOG2_MOVE;
            if !weekly && !moved {
                continue;
            }
            let mut st = state.clone();
            st.insert("price_move_q", log_q(self.price / self.decided_price[r]));
            for k in 0..self.standing[r].len() {
                let obs = Observation {
                    role,
                    agent: k as u32,
                    hour,
                    current: self.standing[r][k],
                    state: st.clone(),
                };
                self.standing[r][k] = policy.decide(self.cfg.seed, &obs)?.index;
            }
            self.decided_price[r] = self.price;
        }
        Ok(())
    }

    /// Compute the buyers rent against what their workload calls for.
    fn rent_share(&self) -> f64 {
        let s = &self.standing[0];
        let total: f64 = s
            .iter()
            .map(|i| match i {
                0 => 0.5,
                2 => 1.5,
                _ => 1.0,
            })
            .sum();
        total / s.len() as f64
    }

    /// Provider `i`'s price against the market rate.
    fn price_factor(&self, i: usize) -> f64 {
        let s = &self.standing[1];
        match s[i % s.len()] {
            0 => 0.9,
            2 => 1.1,
            _ => 1.0,
        }
    }

    /// Whether validator `v`'s agent chose to skip attestations.
    fn abstains(&self, v: u32) -> bool {
        let s = &self.standing[2];
        s[v as usize % s.len()] == 1
    }

    /// The arbitrageurs' daily trades on the pool.
    fn arbitrage(&mut self) {
        let s = &self.standing[3];
        let each = crate::decision::ARB_DAILY_DEPTH_SHARE * self.fair.usd
            / self.fair.price().max(1e-12)
            / s.len() as f64;
        for i in s.clone() {
            match i {
                0 => self.flow_sell += each,
                2 => self.flow_buy += each,
                _ => {}
            }
        }
    }

    /// Buys `q` whole TNZO from the market for `to`.
    fn buy(&mut self, to: u32, q: u128) {
        if q > 0 && self.chain.transfer(crate::chain::RESERVE, to, q, None) {
            self.flow_buy += tnzo(q);
        }
    }

    /// Moves `q` TNZO units from outside holders to `to` without a trade:
    /// the stable unit an agent pays with, carried as TNZO on the ledger.
    fn take_off_market(&mut self, to: u32, q: u128) -> bool {
        q > 0 && self.chain.transfer(crate::chain::RESERVE, to, q, None)
    }

    /// Sells `q` TNZO units of `from`'s balance to the market.
    fn sell(&mut self, from: u32, q: u128) {
        if q > 0 && self.chain.transfer(from, crate::chain::RESERVE, q, None) {
            self.flow_sell += tnzo(q);
        }
    }

    /// Before an escrow of `amount` to provider `i`, the provider buys and
    /// bonds what its live exposure then needs at the governed ratio.
    fn size_bond(&mut self, i: usize, amount: u128) {
        let ratio = u128::from(self.chain.param("compute_bond.var_ratio_bps"));
        if ratio == 0 {
            return;
        }
        let (id, did) = (self.providers[i].id, self.providers[i].did.clone());
        let have =
            n::economy::compute_bond(self.chain.state(), &did).map_or(0, |b| b.effective_amount());
        let (live, _) =
            n::economy::provider_exposure(self.chain.state(), &did, self.chain.now_ms());
        let need = live.saturating_add(amount).saturating_mul(ratio) / 10_000;
        if have >= need {
            return;
        }
        // A quarter of headroom, so it tops up a few times a day at most.
        let top = (need - have).saturating_mul(5) / 4;
        self.buy(id, top + TNZO);
        let payload = crate::chain::compute_bond_payload(&did, top);
        let _ = self.chain.call(
            id,
            None,
            0,
            n::SELECTOR_INCREASE_COMPUTE_BOND,
            &payload,
            NATIVE_GAS,
            None,
        );
    }

    fn providers_and_rentals(&mut self, demand: f64) {
        let a = self.cfg.assumptions.clone();
        let now = self.chain.now_ms();
        let epoch = self.market_epoch();
        let hours_wanted = a.compute_usd_per_day * demand / a.compute_hour_usd / 24.0;
        let needed = ((hours_wanted * 24.0 / (a.provider_hours_per_day * MACHINES_PER_PROVIDER))
            .ceil() as usize)
            .clamp(1, self.providers.len());
        // Enough providers bond to serve the demand, while it pays.
        let margin = a.compute_hour_usd - a.provider_hour_cost_usd;
        let active = self
            .providers
            .iter()
            .filter(|p| p.bonded && !p.gone)
            .count();
        if active < needed && margin > 0.0 {
            let bond = (a
                .provider_bond_tnzo
                .max(self.chain.param("compute_bond.min_tnzo") as f64)
                * TNZO as f64) as u128;
            for p in self
                .providers
                .iter_mut()
                .filter(|p| !p.bonded && !p.gone)
                .take(needed - active)
            {
                let payload = crate::chain::compute_bond_payload(&p.did, bond);
                let _ = self.chain.call(
                    p.id,
                    None,
                    0,
                    n::SELECTOR_POST_COMPUTE_BOND,
                    &payload,
                    NATIVE_GAS,
                    None,
                );
                p.bonded = true;
            }
        }
        // Availability this hour.
        for p in self.providers.iter_mut().filter(|p| p.bonded && !p.gone) {
            let up = self.rng.gen_range(0.0..1.0) < p.availability;
            p.hours.insert(epoch, up);
            if p.hours.len() > 30 {
                let first = *p.hours.keys().next().expect("non-empty");
                p.hours.remove(&first);
            }
            p.cost_usd +=
                a.provider_hour_cost_usd * a.provider_hours_per_day * MACHINES_PER_PROVIDER / 24.0;
        }
        // Agents keep the sampled streams open, one sampled stream standing
        // for an equal share of the hour's compute.
        let live: Vec<usize> = (0..self.providers.len())
            .filter(|i| self.providers[*i].bonded && !self.providers[*i].gone)
            .collect();
        // A stream that ran its course is closed: its provider takes the
        // hours it accrued and the rest goes back to the agent. Left open,
        // what it holds would count against the provider's bond for good.
        let ended: Vec<(u32, [u8; 32])> = self
            .streams
            .iter()
            .filter(|s| s.expires_ms <= now)
            .map(|s| {
                let p = &self.providers[s.provider];
                (if p.gone { s.agent } else { p.id }, s.escrow)
            })
            .collect();
        for (closer, escrow) in ended {
            let payload = serde_json::json!({ "escrow_id": escrow });
            let _ = self.chain.call(
                closer,
                None,
                0,
                n::SELECTOR_ESCROW_REFUND,
                payload.to_string().as_bytes(),
                NATIVE_GAS,
                None,
            );
        }
        self.streams.retain(|s| s.expires_ms > now);
        if !live.is_empty() && demand > 0.0 {
            let base = self.cfg.stream_sample as usize;
            let target = (base as f64 * self.rent_share()).round() as usize;
            let usd_per_stream_hour = a.compute_usd_per_day * demand / 24.0 / base as f64;
            while self.streams.len() < target {
                let agent = ids::AGENTS + self.rng.gen_range(0..ids::AGENT_COUNT);
                let provider = self.pick_provider(&live);
                let factor =
                    self.price_factor(provider) * crate::attack::collusion_markup(self, provider);
                let rate = if self.stable.is_some() {
                    crate::stable::units(usd_per_stream_hour * factor)
                } else {
                    ((usd_per_stream_hour * factor / self.price) * TNZO as f64) as u128
                };
                let hours = 24i64;
                if !self.open_stream(agent, provider, rate.max(1), hours) {
                    break;
                }
                self.providers[provider].stream_usd += usd_per_stream_hour * factor * hours as f64;
            }
        }
        // Providers claim what their streams accrued; an hour judged
        // unavailable is not paid, and stays with the renter.
        let claims: Vec<(u32, [u8; 32])> = self
            .streams
            .iter()
            .filter(|s| now - s.created_ms >= HOUR_MS && now + HOUR_MS <= s.expires_ms)
            .map(|s| (self.providers[s.provider].id, s.escrow))
            .collect();
        for (pid, escrow) in claims {
            let payload = serde_json::json!({ "escrow_id": escrow });
            let _ = self.chain.call(
                pid,
                None,
                0,
                n::SELECTOR_ESCROW_STREAM_CLAIM,
                payload.to_string().as_bytes(),
                NATIVE_GAS,
                None,
            );
        }
    }

    /// Opens a streaming escrow from `agent` to provider `provider` paying
    /// `rate` per market epoch for `hours`, in TNZO or the stable token.
    fn open_stream(&mut self, agent: u32, provider: usize, rate: u128, hours: i64) -> bool {
        self.out.streams_sent += 1;
        let now = self.chain.now_ms();
        let expires = crate::chain::stream_expiry(now, hours);
        let payee = self.providers[provider].id;
        // A token escrow is not held against the provider's bond.
        let payload = match &self.stable {
            Some(s) => crate::stable::escrow_payload(
                ledger::account(payee),
                rate * hours as u128,
                &s.asset,
                expires,
                tenzro_types::settlement::ReleaseConditions::Stream {
                    rate_per_epoch: rate,
                    epoch_ms: n::MARKET_EPOCH_MS as u64,
                },
            ),
            None => {
                self.size_bond(provider, rate.saturating_mul(hours.max(1) as u128));
                crate::chain::stream_escrow_payload(payee, rate, hours, now)
            }
        };
        let ok = self.chain.call(
            agent,
            None,
            0,
            n::SELECTOR_ESCROW_CREATE,
            &payload,
            NATIVE_GAS,
            None,
        );
        if !ok {
            return false;
        }
        // The escrow id follows from the payer and the nonce it was sent with.
        let nonce = self.chain.last_nonce(agent);
        let escrow = n::derive_escrow_id(&Address::new(ledger::account(agent)), nonce);
        self.follow_stable_escrow(
            escrow,
            agent,
            provider,
            crate::stable::Work::Compute,
            expires,
        );
        self.streams.push(Stream {
            escrow,
            agent,
            provider,
            created_ms: now + self.chain.clock.block_calendar_ms(),
            expires_ms: expires,
        });
        true
    }

    /// Follows a stable-token escrow until it closes, when payments settle
    /// in the token.
    fn follow_stable_escrow(
        &mut self,
        escrow: [u8; 32],
        payer: u32,
        provider: usize,
        work: crate::stable::Work,
        expires_ms: i64,
    ) {
        if let Some(s) = self.stable.as_mut() {
            s.escrows.insert(
                escrow,
                crate::stable::Escrow {
                    provider,
                    payer,
                    work,
                    claimed: 0,
                    expires_ms,
                    close_sent_ms: i64::MIN / 2,
                },
            );
        }
    }

    /// This hour's agent sessions: a sample settles on chain as an escrow
    /// the sub-agent's wallet funds toward a provider and releases when its
    /// work is done, each carrying the value of the sessions it stands for.
    fn agent_sessions(&mut self, demand: f64) {
        let a = self.cfg.assumptions.clone();
        let sessions = a.agent_tasks_per_day * a.agent_fanout.max(1.0) * demand / 24.0;
        if sessions <= 0.0 || self.providers.is_empty() {
            return;
        }
        self.out.agent_sessions += sessions;
        let k = (self.cfg.human_sample_per_block as f64)
            .min(sessions.ceil())
            .max(1.0) as u32;
        let usd = a.agent_task_usd * a.agent_tasks_per_day * demand / 24.0 / k as f64;
        let amount = if self.stable.is_some() {
            crate::stable::units(usd)
        } else {
            ((usd / self.price) * TNZO as f64) as u128
        };
        if amount == 0 {
            return;
        }
        let live: Vec<usize> = (0..self.providers.len())
            .filter(|i| self.providers[*i].bonded && !self.providers[*i].gone)
            .collect();
        if live.is_empty() {
            return;
        }
        for _ in 0..k {
            let agent = ids::AGENTS + self.rng.gen_range(0..ids::AGENT_COUNT);
            let p = self.pick_provider(&live);
            let markup = crate::attack::collusion_markup(self, p);
            let amount = if markup == 1.0 {
                amount
            } else {
                (amount as f64 * markup) as u128
            };
            let now = self.chain.now_ms();
            let expires = now + 2 * HOUR_MS;
            let payee = ledger::account(self.providers[p].id);
            let payload = match &self.stable {
                Some(s) => crate::stable::escrow_payload(
                    payee,
                    amount,
                    &s.asset,
                    expires,
                    tenzro_types::settlement::ReleaseConditions::ConsumerSignature,
                ),
                None => {
                    self.size_bond(p, amount);
                    #[derive(serde::Serialize)]
                    struct Session {
                        payee: Address,
                        amount: u128,
                        asset_id: tenzro_types::AssetId,
                        expires_at: u64,
                        release_conditions: tenzro_types::settlement::ReleaseConditions,
                    }
                    serde_json::to_vec(&Session {
                        payee: Address::new(payee),
                        amount,
                        asset_id: tenzro_types::AssetId::tnzo(),
                        expires_at: expires as u64,
                        release_conditions:
                            tenzro_types::settlement::ReleaseConditions::ConsumerSignature,
                    })
                    .expect("session escrow payload")
                }
            };
            self.out.agent_sessions_sent += 1;
            if !self.chain.call(
                agent,
                None,
                0,
                n::SELECTOR_ESCROW_CREATE,
                &payload,
                NATIVE_GAS,
                None,
            ) {
                continue;
            }
            let nonce = self.chain.last_nonce(agent);
            let escrow = n::derive_escrow_id(&Address::new(ledger::account(agent)), nonce);
            self.follow_stable_escrow(escrow, agent, p, crate::stable::Work::Inference, expires);
            let proof = tenzro_types::settlement::ServiceProof::new(
                tenzro_types::settlement::ProofType::Cryptographic,
                Vec::new(),
            );
            let release =
                serde_json::to_vec(&serde_json::json!({ "escrow_id": escrow, "proof": proof }))
                    .expect("session release payload");
            if self.chain.call(
                agent,
                None,
                0,
                n::SELECTOR_ESCROW_RELEASE,
                &release,
                NATIVE_GAS,
                None,
            ) {
                self.out.agent_sessions_settled += 1;
                self.out.agent_spend_usd += usd * markup;
                self.providers[p].session_usd += usd * markup;
            }
        }
    }

    /// People and agents buy TNZO from outside holders (the reserve) when
    /// they run low: three days of their spending at the current price.
    fn top_up(&mut self, demand: f64) {
        let a = &self.cfg.assumptions;
        // An agent opens one sampled stream at a time; it holds at least two
        // of them, or three days of its share of the demand.
        let stream_day =
            a.compute_usd_per_day * demand / self.cfg.stream_sample.max(1) as f64 / self.price;
        let swarm_usd = a.agent_tasks_per_day * a.agent_task_usd;
        let agent_day =
            ((a.compute_usd_per_day + swarm_usd) * demand / ids::AGENT_COUNT as f64 / self.price)
                .max(2.0 * stream_day / 3.0);
        let human_day =
            a.human_tx_per_day * demand * a.human_tx_usd / ids::HUMAN_COUNT as f64 / self.price;
        let mut groups = vec![
            (ids::AGENTS, ids::AGENT_COUNT, agent_day),
            (ids::HUMANS, ids::HUMAN_COUNT, human_day),
        ];
        if self.stable.is_some() {
            groups.remove(0);
            self.top_up_stable(agent_day * self.price);
        }
        let stable = self.cfg.assumptions.stable_settlement;
        for (first, count, daily) in groups {
            let want = (3.0 * daily * TNZO as f64) as u128;
            for id in first..first + count {
                let have = self.chain.ledger.balance(id);
                if have < want / 2 {
                    // Paying in a stable unit, an agent buys no TNZO to pay
                    // with; what it spends on fees is bought at the close.
                    if stable && first == ids::AGENTS {
                        if self.take_off_market(id, want - have) {
                            self.agent_bought += tnzo(want - have);
                        }
                    } else {
                        self.buy(id, want - have);
                    }
                }
            }
        }
    }

    /// Paying in the stable token: agents hold three days of their spending
    /// in it, funded by outside holders, and some TNZO for gas; providers
    /// hold the TNZO three days of their settlement fees need (and the leg,
    /// when the chain charges it in TNZO), bought at the market, or taken
    /// from outside holders before a listing.
    /// Outside holders of the stable unit give the treasury stable asset:
    /// once at the start, and at each month close a share of the sponsored
    /// seats cost the month legs left uncovered. A transfer from the
    /// holders, never an issue.
    fn give_stable(&mut self, token: [u8; 32]) {
        let a = self.cfg.assumptions.clone();
        let day = self.day();
        let treasury = n::derive_treasury_address();
        let mut give = 0.0;
        if !self.stable_seeded {
            self.stable_seeded = true;
            give += a.stable_seed_usd;
        }
        if a.stable_topup_share > 0.0 && day >= self.next_topup_day {
            self.next_topup_day += 30.0;
            let legs = self.stable.as_ref().map_or(0, |s| s.legs_sent);
            let got = crate::stable::usd(legs.saturating_sub(self.legs_at_topup));
            self.legs_at_topup = legs;
            let need = f64::from(a.sponsor_seats) * a.validator_cost_usd_month;
            give += (need - got).max(0.0) * a.stable_topup_share;
        }
        if give > 0.0 {
            let call = crate::stable::transfer_call(token, treasury.0, crate::stable::units(give));
            let _ = self.chain.call(
                ids::STABLE_OUTSIDE,
                None,
                0,
                n::SELECTOR_TOKEN,
                &call[4..],
                NATIVE_GAS,
                None,
            );
            self.stable_given_usd += give;
        }
    }

    fn top_up_stable(&mut self, agent_day_usd: f64) {
        let Some((token, leg_in_token)) = self.stable.as_ref().map(|s| (s.token, s.leg_in_token))
        else {
            return;
        };
        self.give_stable(token);
        let want = crate::stable::units(3.0 * agent_day_usd);
        for id in ids::AGENTS..ids::AGENTS + ids::AGENT_COUNT {
            let have =
                tenzro_vm::token_ledger::balance(self.chain.state(), &token, &ledger::account(id));
            if have < want / 2 {
                let call = crate::stable::transfer_call(token, ledger::account(id), want - have);
                let _ = self.chain.call(
                    ids::STABLE_OUTSIDE,
                    None,
                    0,
                    n::SELECTOR_TOKEN,
                    &call[4..],
                    NATIVE_GAS,
                    None,
                );
            }
            let gas = self.chain.ledger.balance(id);
            if gas < 1_000 * TNZO {
                self.acquire_tnzo(id, 10_000 * TNZO - gas);
            }
        }
        // Outside holders pay the gas of what they send.
        let gas = self.chain.ledger.balance(ids::STABLE_OUTSIDE);
        if gas < 10_000 * TNZO {
            let _ = self.take_off_market(ids::STABLE_OUTSIDE, 50_000 * TNZO - gas);
        }
        let fee_share = self.chain.param("fees.settlement_fee_bps") as f64 / 10_000.0;
        let leg_share = if leg_in_token {
            0.0
        } else {
            self.chain
                .param(n::economy::TREASURY_LEG_INFERENCE_PARAM)
                .max(self.chain.param(n::economy::TREASURY_LEG_COMPUTE_PARAM))
                .min(n::economy::MAX_TREASURY_LEG_BPS) as f64
                / 10_000.0
        };
        let rate = (n::read_fee_rate(self.chain.state()).rate_nano_usd as f64 / 1e9).max(1e-9);
        for i in 0..self.providers.len() {
            let p = &self.providers[i];
            if !p.bonded || p.gone {
                continue;
            }
            let day_tnzo = p.stable_ema_usd * (fee_share + leg_share) / rate;
            let want = ((1_000.0 + 3.0 * day_tnzo) * TNZO as f64) as u128;
            let have = self.chain.ledger.balance(p.id);
            if have < want {
                let q = want - have + (day_tnzo * TNZO as f64) as u128;
                let id = p.id;
                if self.acquire_tnzo(id, q) {
                    self.providers[i].fee_tnzo_cost_usd += tnzo(q) * self.price;
                }
            }
        }
    }

    /// `to` gets `q` TNZO units: bought at the market, or taken from
    /// outside holders without a trade before a listing.
    fn acquire_tnzo(&mut self, to: u32, q: u128) -> bool {
        if self.cfg.assumptions.closed_phase {
            self.take_off_market(to, q)
        } else {
            let before = self.flow_buy;
            self.buy(to, q);
            self.flow_buy > before
        }
    }

    fn validators_attest(&mut self) {
        if !self.cfg.sla_attest {
            return;
        }
        let epoch = self.market_epoch();
        if epoch < 2 {
            return;
        }
        let closed = epoch - 1;
        let mut truth: Vec<(String, bool)> = self
            .providers
            .iter()
            .filter(|p| p.bonded && !p.gone)
            .filter_map(|p| Some((p.did.clone(), *p.hours.get(&closed)?)))
            .filter(|(did, _)| n::read_sla_verdict(self.chain.state(), did, closed).is_none())
            .collect();
        truth.extend(crate::attack::adversary_outcomes(self));
        if truth.is_empty() {
            return;
        }
        for v in self.bonded() {
            if crate::attack::validator_withholds_attestation(self, v) || self.abstains(v) {
                continue;
            }
            let outcomes: Vec<serde_json::Value> = truth
                .iter()
                .map(|(did, up)| {
                    let seen = crate::attack::attest_for(self, v, did, *up);
                    serde_json::json!({ "provider_did": did, "available": seen, "capacity": null })
                })
                .collect();
            for chunk in outcomes.chunks(n::MAX_SLA_OUTCOMES) {
                let payload = serde_json::json!({ "epoch": closed, "outcomes": chunk });
                let _ = self.chain.call(
                    v,
                    None,
                    0,
                    n::SELECTOR_SLA_ATTEST,
                    payload.to_string().as_bytes(),
                    NATIVE_GAS,
                    None,
                );
            }
        }
    }

    /// Every bonded validator reports the closed market epoch's TNZO/USD
    /// rate from two sources; a cartel reports a multiple of it.
    /// Each bonded validator seals the closed epoch's rate and opens the
    /// rate it sealed the epoch before.
    fn validators_report_rate(&mut self) {
        // Volume is always reported: the reserve's sale cap reads it.
        let volume = (self.volume_day_tnzo * 1e9) as u128;
        if !self.cfg.rate_reports && volume == 0 && self.stable.is_none() {
            return;
        }
        let epoch = self.market_epoch();
        if epoch < 2 {
            return;
        }
        let day = self.day();
        // One simulated block stands for the hour, and the reports queued
        // now execute in it, an epoch later: the epoch closed by then is
        // the current one.
        let closed = epoch;
        let walk = crate::attack::rate_walk(self);
        let skew = crate::attack::rate_skew(self);
        // A chaos rate shock: the lowest-id share of bonded validators
        // skews both venues, or one venue's quote is manipulated for all.
        let bonded = self.bonded();
        let chaos_rate = self.cfg.chaos.as_ref().and_then(|p| p.rate_shock(day));
        let cartel: Vec<u32> = match chaos_rate {
            Some(s) if !s.venue => {
                let n = (bonded.len() as f64 * s.share).ceil() as usize;
                bonded.iter().copied().take(n).collect()
            }
            _ => Vec::new(),
        };
        for v in bonded {
            let walked = match walk {
                Some((cartel, _, true)) if v < cartel => continue,
                Some((cartel, rate, false)) if v < cartel => Some(rate),
                _ => None,
            };
            let factor = match self.cfg.rate_cartel {
                Some((n, f, from))
                    if v < n
                        && day >= from as f64
                        && self.cfg.ablation != Ablation::FeedAsSource =>
                {
                    f
                }
                _ => 1.0,
            };
            let factor = match skew {
                Some((n, f)) if v < n => f,
                _ => factor,
            };
            let (factor, venue_a) = match chaos_rate {
                Some(s) if s.venue => (factor, s.factor),
                Some(s) if cartel.contains(&v) => (s.factor, 1.0),
                _ => (factor, 1.0),
            };
            let rate = walked.unwrap_or((self.price * factor * 1e9).max(1.0) as u128);
            let rate_a = walked.unwrap_or((self.price * factor * venue_a * 1e9).max(1.0) as u128);
            let mut quotes = Vec::new();
            if self.cfg.rate_reports {
                quotes.push(("TNZO".to_string(), "venue-a".to_string(), rate_a));
                quotes.push(("TNZO".to_string(), "venue-b".to_string(), rate));
            }
            if self.stable.is_some() {
                // The stable token's market value, which the registry
                // checks against its peg.
                let peg = ((self.peg_at(day) * 1e9).max(1.0)) as u128;
                for venue in ["venue-a", "venue-b"] {
                    quotes.push((crate::stable::SYMBOL.to_string(), venue.to_string(), peg));
                }
            }
            if volume > 0 {
                let sym = n::economy::VOLUME_SYMBOL.to_string();
                quotes.push((sym.clone(), "venue-a".to_string(), volume));
                quotes.push((sym, "venue-b".to_string(), volume));
            }
            let mut salt = [0u8; 32];
            self.rng.fill(&mut salt);
            let addr = ledger::account(v);
            let commitment = tenzro_types::fee_rate_commitment(
                &addr,
                closed,
                &salt,
                quotes.iter().map(|(a, b, r)| (a.as_str(), b.as_str(), *r)),
            );
            let reveal = self.validators[v as usize]
                .sealed
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
            self.validators[v as usize].sealed = Some((closed, quotes, salt));
            let payload = serde_json::json!({
                "epoch": closed,
                "commitment": hex::encode(commitment),
                "reveal": reveal,
            });
            let _ = self.chain.call(
                v,
                None,
                0,
                n::SELECTOR_FEE_RATE_SUBMIT,
                payload.to_string().as_bytes(),
                NATIVE_GAS,
                None,
            );
        }
    }

    /// Each provider's account, identity, whether it is bonded and in
    /// business, and its income so far in USD (what it sold plus what it
    /// holds above its start at today's price), in provider order.
    pub fn provider_books(&self) -> Vec<(u32, String, bool, f64)> {
        let a = &self.cfg.assumptions;
        self.providers
            .iter()
            .map(|p| {
                let bal = tnzo(self.chain.ledger.balance(p.id));
                let income = if p.bonded {
                    p.sold_usd + (bal - 50_000.0 + a.provider_bond_tnzo) * self.price
                } else {
                    0.0
                };
                (p.id, p.did.clone(), p.bonded && !p.gone, income)
            })
            .collect()
    }

    /// Per-class provider accounts over the last year (or the whole run if
    /// shorter) and what a user pays.
    pub fn launch_economics(&self) -> crate::classes::LaunchEconomics {
        let a = &self.cfg.assumptions;
        let inputs = a.classes.clone();
        let fee = self.chain.param("fees.settlement_fee_bps") as f64 / 10_000.0;
        let window_days = (self.out.days.len() as f64).min(365.0);
        let fleets: Vec<crate::classes::FleetBooks> = self
            .providers
            .iter()
            .filter(|p| p.bonded)
            .map(|p| crate::classes::FleetBooks {
                // The GPUs the stream hours needed at the assumed hours a
                // GPU sells a day: supply sized to demand, not the fleet
                // account's nominal size.
                gpus: (p.stream_usd - p.window_start.0)
                    / (a.compute_hour_usd * a.provider_hours_per_day * window_days.max(1.0)),
                stream_usd: p.stream_usd - p.window_start.0,
                session_usd: p.session_usd - p.window_start.1,
                coupons_usd: p.coupons_usd - p.window_start.2,
            })
            .collect();
        let (gpu_rental, inference_hosting, agent_operators, app_owners) =
            crate::classes::accounts(&inputs, &fleets, window_days, fee);
        let last = self.out.days.last();
        let gas = last.map_or(0.0, |d| d.human_fee_tnzo * d.price_usd);
        let session_usd = a.agent_task_usd / a.agent_fanout.max(1.0);
        let mut users =
            crate::classes::user_side(&inputs, a.compute_hour_usd, gas, fee, session_usd);
        // Payments the ledger refused: escrows not created, over the
        // escrows the populations sent.
        let refused: u64 = self
            .out
            .refusals
            .iter()
            .filter(|(k, _)| k.starts_with("escrow create"))
            .map(|(_, v)| *v)
            .sum();
        users.refused_share =
            refused as f64 / (self.out.agent_sessions_sent + self.out.streams_sent).max(1) as f64;
        users.session_failed_share = if self.out.agent_sessions_sent > 0 {
            1.0 - self.out.agent_sessions_settled as f64 / self.out.agent_sessions_sent as f64
        } else {
            0.0
        };
        users.trace_undelivered_share = a.trace.as_ref().map(|t| 1.0 - t.delivered_share);
        crate::classes::LaunchEconomics {
            window_days,
            gpu_rental,
            inference_hosting,
            agent_operators,
            app_owners,
            users,
            inputs,
        }
    }

    /// Liquid TNZO by holder group.
    fn held_by(&self) -> HeldBy {
        let sum = |ids: std::ops::Range<u32>| -> f64 {
            ids.map(|id| tnzo(self.chain.ledger.balance(id))).sum()
        };
        let validators = self.cfg.assumptions.validators + self.cfg.assumptions.standby;
        let vesting: f64 = (0..validators)
            .map(|v| tnzo(vesting_total(self.chain.state(), &ledger::account(v))))
            .sum();
        HeldBy {
            providers: sum(ids::PROVIDERS..ids::PROVIDERS + ids::PROVIDER_COUNT),
            agents: sum(ids::AGENTS..ids::AGENTS + ids::AGENT_COUNT),
            humans: sum(ids::HUMANS..ids::HUMANS + ids::HUMAN_COUNT),
            validators_liquid: sum(0..validators),
            validators_vesting: vesting,
            other: sum(ids::FEE_PROBE..ids::HUMANS)
                + sum(ids::ADVERSARY..ids::ADVERSARY + ids::ADVERSARY_COUNT),
        }
    }

    /// Picks the provider a buyer pays among `live` (provider indices):
    /// uniformly, or, when the running strategy routes by price, weighted by
    /// price and away from providers judged unavailable in the last closed
    /// market epoch.
    fn pick_provider(&mut self, live: &[usize]) -> usize {
        let Some(e) = crate::attack::routing_elasticity(self) else {
            return live[self.rng.gen_range(0..live.len())];
        };
        let closed = self.market_epoch().saturating_sub(1);
        let w: Vec<f64> = live
            .iter()
            .map(|i| {
                let down = n::read_sla_verdict(self.chain.state(), &self.providers[*i].did, closed)
                    .is_some_and(|v| !v.available);
                let price = self.price_factor(*i) * crate::attack::collusion_markup(self, *i);
                if down { 0.0 } else { price.max(1e-9).powf(-e) }
            })
            .collect();
        let total: f64 = w.iter().sum();
        if total <= 0.0 {
            return live[self.rng.gen_range(0..live.len())];
        }
        let mut u = self.rng.gen_range(0.0..total);
        for (i, x) in live.iter().zip(&w) {
            if u < *x {
                return *i;
            }
            u -= x;
        }
        live[live.len() - 1]
    }

    /// Whether provider account `id` has posted its compute bond.
    pub fn provider_bonded(&self, id: u32) -> bool {
        self.providers
            .iter()
            .any(|p| p.id == id && p.bonded && !p.gone)
    }

    fn validators_claim(&mut self) {
        let claim = serde_json::json!({ "op": "claim_rewards" }).to_string();
        let release = serde_json::json!({ "op": "release_vesting" }).to_string();
        if self.cfg.assumptions.providers_claim_rewards {
            let rate = n::read_fee_rate(self.chain.state()).rate_nano_usd as f64 / 1e9;
            let weekly = (self.chain.now_ms() / DAY_MS) % 7 == 0;
            for i in 0..self.providers.len() {
                let p = &self.providers[i];
                if !p.bonded || p.gone {
                    continue;
                }
                let id = p.id;
                let addr = Address::new(ledger::account(id));
                let issued: u128 = n::rewards::read_coupons(self.chain.state(), &addr)
                    .unwrap_or_default()
                    .iter()
                    .filter(|c| matches!(c.status, tenzro_token::rewards::CouponStatus::Issued))
                    .map(|c| c.amount)
                    .sum();
                if issued == 0 && !weekly {
                    continue;
                }
                if issued > 0
                    && self.chain.call(
                        id,
                        None,
                        0,
                        n::SELECTOR_FUNDING,
                        claim.as_bytes(),
                        NATIVE_GAS,
                        None,
                    )
                {
                    self.providers[i].coupons_usd += tnzo(issued) * rate;
                }
                if weekly {
                    let _ = self.chain.call(
                        id,
                        None,
                        0,
                        n::SELECTOR_FUNDING,
                        release.as_bytes(),
                        NATIVE_GAS,
                        None,
                    );
                }
            }
        }
        for v in self.bonded() {
            let _ = self.chain.call(
                v,
                None,
                0,
                n::SELECTOR_FUNDING,
                claim.as_bytes(),
                NATIVE_GAS,
                None,
            );
            if (self.chain.now_ms() / DAY_MS) % 7 == 0 {
                let _ = self.chain.call(
                    v,
                    None,
                    0,
                    n::SELECTOR_FUNDING,
                    release.as_bytes(),
                    NATIVE_GAS,
                    None,
                );
            }
        }
    }

    fn treasury_tnzo(&self) -> f64 {
        tnzo(
            self.chain
                .balance_of(n::derive_treasury_address().as_bytes()),
        )
    }

    /// The tranche governance files next, TNZO, when the sponsor account
    /// holds less than the buffer: the buffer and 30 days of the recent daily
    /// sponsorship (of the full sponsored need before any was paid) at
    /// today's price with [`SPONSOR_MARGIN`] over,
    /// within the combined yearly cap, one proposal's and one period's
    /// outflow limit. The treasury pays from what it holds; nothing is
    /// issued.
    fn sponsor_tranche(&self) -> Option<f64> {
        let a = &self.cfg.assumptions;
        let now = self.chain.now_ms();
        if a.sponsor_seats == 0 || now < self.next_sponsor_ms {
            return None;
        }
        let need_usd_day = a.sponsor_seats as f64 * a.validator_cost_usd_month / 30.44;
        let usd_day = if self.sponsored_tnzo_total > 0.0 {
            self.sponsor_ema_usd.max(need_usd_day * 0.1)
        } else {
            need_usd_day
        };
        let day_rate = usd_day * SPONSOR_MARGIN / self.price;
        let held = tnzo(
            self.chain
                .ledger
                .balance(ids::SPONSOR)
                .saturating_sub(OPENING_BALANCE),
        );
        if held >= a.sponsor_buffer_days * day_rate {
            return None;
        }
        let treasury = self.treasury_tnzo();
        let bps = |k: &str| self.chain.param(k) as f64 / 10_000.0;
        let period_from = now - 30 * DAY_MS;
        let period_out: f64 = self
            .outflow_log
            .iter()
            .filter(|(t, _, _)| *t > period_from)
            .map(|(_, q, _)| q)
            .sum();
        let room = (treasury * bps(tenzro_vm::governance::MAX_PROPOSAL_OUTFLOW_PARAM))
            .min(treasury * bps(tenzro_vm::governance::MAX_PERIOD_OUTFLOW_PARAM) - period_out)
            * 0.95;
        let q = ((a.sponsor_buffer_days + 30.0) * day_rate - held)
            .min(room)
            .min(self.outflow_room())
            .min(treasury);
        (q >= 1.0).then_some(q)
    }

    /// TNZO paid out in sponsorship tranches and grants over the trailing
    /// year.
    fn outflow_year(&self) -> f64 {
        let from = self.chain.now_ms() - 365 * DAY_MS;
        self.outflow_log
            .iter()
            .filter(|(t, _, capped)| *t > from && *capped)
            .map(|(_, q, _)| q)
            .sum()
    }

    /// The combined yearly cap on sponsorship and grants, TNZO; zero when
    /// none is set.
    fn outflow_cap(&self) -> f64 {
        let a = &self.cfg.assumptions;
        match self.treasury_open {
            Some(open) if a.sponsor_cap_bps_year > 0.0 => open * a.sponsor_cap_bps_year / 10_000.0,
            _ => 0.0,
        }
    }

    /// What the combined cap leaves this year, TNZO (unbounded without one).
    fn outflow_room(&self) -> f64 {
        let cap = self.outflow_cap();
        if cap > 0.0 {
            (cap - self.outflow_year()).max(0.0)
        } else {
            f64::MAX
        }
    }

    /// Running costs enacted and not yet paid, wei.
    fn running_cost_owed(&self) -> u128 {
        n::treasury_reserve::read_queue(self.chain.state())
            .iter()
            .fold(0u128, |a, q| a.saturating_add(q.remaining))
    }

    /// A rate hold to propose from outside price evidence, in the full
    /// design only: hold once the chain rate sat off the market by more
    /// than the band for a day, release once the reported median is back
    /// inside it for two.
    fn challenge_action(&self) -> Option<u64> {
        if !self.cfg.rate_reports || self.cfg.ablation != Ablation::Full {
            return None;
        }
        let held = self.chain.param("fees.usd_rate_frozen") == 1;
        match (held, self.off_band_days >= 1, self.in_band_days >= 2) {
            (false, true, _) => Some(1),
            (true, _, true) => Some(0),
            _ => None,
        }
    }

    /// Whether the dispersion breaker has put the governance rate in force.
    fn rate_breaker_tripped(&self) -> bool {
        n::economy::rate_breaker(self.chain.state(), n::economy::FEE_SYMBOL)
            .tripped_epoch
            .is_some()
    }

    /// Monthly treasury grants and weekly fee-rate updates, through the
    /// governance path: propose, every honest validator votes, close,
    /// timelock, enact.
    fn governance(&mut self) {
        let now = self.chain.now_ms();
        let rules = tenzro_vm::governance::GovernanceRules::GENESIS;
        let bonded = self.bonded();
        let Some(&first) = bonded.first() else { return };
        if self.treasury_open.is_none() {
            self.treasury_open = Some(self.treasury_tnzo() + self.sponsor_open_tnzo);
        }
        self.record_verified_hours();
        self.sponsor_governance(first, &rules);
        match self.proposal.clone() {
            None => {
                let a = &self.cfg.assumptions;
                let challenge = self.challenge_action();
                let action = if let Some(entry) = self.asset_entry.clone() {
                    Some(("settlement asset", entry))
                } else if self.rate_breaker_tripped() {
                    // The dispersion breaker put the governance rate in
                    // force: governance brings that rate to the market it
                    // fell behind, then sets validator mode again.
                    let gov = self.chain.param("fees.tnzo_usd_nano") as f64 / 1e9;
                    if (gov / self.price - 1.0).abs() > 0.05 {
                        let v = ((self.price * 1e9) as u64).max(1);
                        Some((
                            "fee rate",
                            ledger::parameter_change("fees.tnzo_usd_nano", v),
                        ))
                    } else {
                        Some((
                            "rate re-arm",
                            ledger::parameter_change("fees.usd_rate_mode", 1),
                        ))
                    }
                } else if let Some(v) = challenge {
                    Some((
                        "rate hold",
                        ledger::parameter_change("fees.usd_rate_frozen", v),
                    ))
                } else if a.leg_proposal_bps > 0.0
                    && self.legs_filed < 2
                    && self.day() >= a.leg_proposal_day
                {
                    let key = if self.legs_filed == 0 {
                        n::economy::TREASURY_LEG_INFERENCE_PARAM
                    } else {
                        n::economy::TREASURY_LEG_COMPUTE_PARAM
                    };
                    self.legs_filed += 1;
                    Some((
                        "treasury leg",
                        ledger::parameter_change(key, a.leg_proposal_bps as u64),
                    ))
                } else if now >= self.next_grant_ms && a.grants_tnzo_month > 0.0 {
                    self.next_grant_ms = now + 30 * DAY_MS;
                    let treasury = self.treasury_tnzo();
                    // Without a reserve, running costs are paid with the grants.
                    let usd = if self.cfg.ablation == Ablation::NoReserve {
                        a.grants_usd_month + a.running_cost_ask_usd_month
                    } else {
                        a.grants_usd_month
                    };
                    let grant = (usd / self.price)
                        .min(a.grants_tnzo_month)
                        .min(treasury * a.grant_cap_bps_month / 10_000.0)
                        .min(self.outflow_room());
                    self.last_grant_tnzo = grant;
                    self.outflow_log.push((now, grant, true));
                    let amount = (grant * TNZO as f64) as u128;
                    // An empty treasury grants nothing.
                    (amount > 0).then(|| ("grant", ledger::treasury_grant(ids::GRANTEE, amount)))
                } else if now >= self.next_cost_ms
                    && a.running_cost_ask_usd_month > 0.0
                    && self.cfg.ablation != Ablation::NoReserve
                    && !a.closed_phase
                    && self.running_cost_owed()
                        < (a.running_cost_ask_usd_month / 2.0 / self.price * TNZO as f64) as u128
                {
                    // One month's asked running costs at today's price; a
                    // month still largely unpaid is not asked again.
                    self.next_cost_ms = now + 30 * DAY_MS;
                    let amount = (a.running_cost_ask_usd_month / self.price * TNZO as f64) as u128;
                    Some((
                        "running costs",
                        ledger::running_cost_payment(ids::DESK, amount),
                    ))
                } else if a.treasury_sellback
                    && !a.closed_phase
                    && now >= self.next_sellback_ms
                    && self.treasury_tnzo() > a.sellback_target_tnzo
                {
                    // The treasury's TNZO above its target, at most a month of
                    // the desk's daily cap, within what one proposal and the
                    // outflow period (less the last grant) may pay out.
                    self.next_sellback_ms = now + 30 * DAY_MS;
                    let treasury = self.treasury_tnzo();
                    let bps = |k: &str| self.chain.param(k) as f64 / 10_000.0;
                    let room = (treasury * bps(tenzro_vm::governance::MAX_PROPOSAL_OUTFLOW_PARAM))
                        .min(
                            treasury * bps(tenzro_vm::governance::MAX_PERIOD_OUTFLOW_PARAM)
                                - self.last_grant_tnzo,
                        );
                    let q = (treasury - a.sellback_target_tnzo)
                        .min(a.sellback_max_tnzo_day * 30.0)
                        .min(room * 0.95);
                    let amount = (q.max(0.0) * TNZO as f64) as u128;
                    self.outflow_log.push((now, q.max(0.0), false));
                    (amount > 0)
                        .then(|| ("sell-back", ledger::treasury_grant(ids::SELLBACK, amount)))
                } else if now >= self.next_rate_ms && a.governance_tracks_price {
                    self.next_rate_ms = now + 7 * DAY_MS;
                    let v = ((self.price * 1e9) as u64).max(1);
                    Some((
                        "fee rate",
                        ledger::parameter_change("fees.tnzo_usd_nano", v),
                    ))
                } else {
                    None
                };
                if let Some((_, action)) = action {
                    let sent = action.clone();
                    let ok = self
                        .chain
                        .submit(first, NATIVE_GAS, |nonce| SimTx::Propose {
                            from: first,
                            action,
                            nonce,
                        });
                    if ok {
                        self.proposal = Some(Proposal {
                            claim: None,
                            id: None,
                            proposed_ms: now,
                            stage: 0,
                            enact_after: 0,
                            action: sent,
                        });
                    }
                }
            }
            Some(p) => {
                let Some(id) = p.id.clone() else {
                    if now > p.proposed_ms + DAY_MS {
                        self.proposal = None;
                    }
                    return;
                };
                match p.stage {
                    1 => {
                        let close =
                            p.proposed_ms + rules.voting_period_ms + rules.voting_period_ms / 10;
                        if now >= close {
                            let _ = self
                                .chain
                                .submit(first, NATIVE_GAS, |nonce| SimTx::Execute {
                                    from: first,
                                    proposal: id,
                                    nonce,
                                });
                            if let Some(p) = self.proposal.as_mut() {
                                p.stage = 2;
                            }
                        }
                    }
                    3 if now >= p.enact_after => {
                        let _ = self
                            .chain
                            .submit(first, NATIVE_GAS, |nonce| SimTx::Execute {
                                from: first,
                                proposal: id,
                                nonce,
                            });
                        if let Some(p) = self.proposal.as_mut() {
                            p.stage = 4;
                        }
                    }
                    _ => {}
                }
                if now > p.proposed_ms + 60 * DAY_MS {
                    self.proposal = None;
                }
            }
        }
    }

    /// The sponsorship tranche runs in its own proposal, beside the one the
    /// rate and parameter proposals share: the chain takes proposals in
    /// parallel, and a tranche's vote and timelock last weeks, long enough
    /// for the rate to need several changes meanwhile.
    fn sponsor_governance(&mut self, first: u32, rules: &tenzro_vm::governance::GovernanceRules) {
        let now = self.chain.now_ms();
        // Move every claim in flight one stage on.
        for i in 0..self.sponsor_props.len() {
            let p = self.sponsor_props[i].clone();
            let Some(id) = p.id.clone() else {
                continue;
            };
            let close = p.proposed_ms + rules.voting_period_ms + rules.voting_period_ms / 10;
            if (p.stage == 1 && now >= close) || (p.stage == 3 && now >= p.enact_after) {
                let _ = self
                    .chain
                    .submit(first, NATIVE_GAS, |nonce| SimTx::Execute {
                        from: first,
                        proposal: id,
                        nonce,
                    });
                self.sponsor_props[i].stage += 1;
            }
        }
        self.sponsor_props.retain(|p| match p.id {
            None => now <= p.proposed_ms + DAY_MS,
            Some(_) => now <= p.proposed_ms + 90 * DAY_MS,
        });
        if self.cfg.assumptions.sponsor_gated {
            self.file_claims(first, now);
            return;
        }
        if !self.sponsor_props.is_empty() {
            return;
        }
        let Some(q) = self.sponsor_tranche() else {
            return;
        };
        let action = ledger::treasury_grant(ids::SPONSOR, (q * TNZO as f64) as u128);
        let sent = action.clone();
        if self
            .chain
            .submit(first, NATIVE_GAS, |nonce| SimTx::Propose {
                from: first,
                action,
                nonce,
            })
        {
            self.next_sponsor_ms = now + 7 * DAY_MS;
            self.outflow_log.push((now, q, true));
            self.sponsor_props.push(Proposal {
                claim: None,
                id: None,
                proposed_ms: now,
                stage: 0,
                enact_after: 0,
                action: sent,
            });
        }
    }

    /// The hours each sponsored seat served in the days just ended become
    /// frozen availability verdicts, one per hour, as the chain's
    /// availability verdicts record them.
    fn record_verified_hours(&mut self) {
        let a = &self.cfg.assumptions;
        if !a.sponsor_gated {
            return;
        }
        let seats = a.sponsor_seats;
        let today = self.day().floor() as u64;
        while self.verified_days < today {
            self.verified_days += 1;
            let d = self.verified_days;
            let bonded = self.bonded();
            for v in 0..seats {
                if bonded.contains(&v) && !self.validators[v as usize].exiting {
                    let (from, to) = ((d - 1) * 24 + 1, d * 24);
                    self.chain.ledger.record_available(v, from, to);
                    self.sponsor_hours[v as usize].extend(from..=to);
                }
            }
        }
    }

    /// Weekly in arrears, each sponsored seat claims the running cost of its
    /// unpaid verified hours in the stable asset: the governed per-hour
    /// value, never more than the treasury holds of the asset.
    fn file_claims(&mut self, first: u32, now: i64) {
        let Some(stable) = self.stable.as_ref() else {
            return;
        };
        let rate = u128::from(
            self.chain
                .param(n::payout_gates::PER_VERIFIED_EPOCH_USD_PARAM),
        );
        if rate == 0 {
            return;
        }
        let token = stable.asset.clone();
        let treasury = n::derive_treasury_address();
        let mut budget = stable.balance(self.chain.state(), treasury.as_bytes());
        for p in &self.sponsor_props {
            if p.claim.is_some()
                && let Ok(a) =
                    serde_json::from_slice::<tenzro_vm::governance::ProposalAction>(&p.action)
                && let tenzro_vm::governance::ProposalAction::SponsorOperatorStable {
                    amount, ..
                } = a
            {
                budget = budget.saturating_sub(amount);
            }
        }
        for v in 0..self.cfg.assumptions.sponsor_seats {
            let i = v as usize;
            if self
                .sponsor_props
                .iter()
                .any(|p| p.claim.is_some_and(|(s, _)| s == v))
                || now < self.next_claim_ms[i]
                || self.sponsor_hours[i].len()
                    < (self.cfg.assumptions.sponsor_claim_days * 24.0) as usize
            {
                continue;
            }
            let hours = &self.sponsor_hours[i];
            let first_epoch = hours[0];
            let span = hours
                .iter()
                .take_while(|e| **e - first_epoch < tenzro_vm::governance::MAX_RUNNING_COST_EPOCHS)
                .count();
            let n_hours = span.min((budget / rate) as usize);
            if n_hours == 0 {
                continue;
            }
            let last_epoch = hours[n_hours - 1];
            let amount = n_hours as u128 * rate;
            let action = ledger::sponsor_stable(v, first_epoch, last_epoch, &token, amount, true);
            let sent = action.clone();
            if self
                .chain
                .submit(first, NATIVE_GAS, |nonce| SimTx::Propose {
                    from: first,
                    action,
                    nonce,
                })
            {
                budget -= amount;
                self.next_claim_ms[i] =
                    now + (self.cfg.assumptions.sponsor_claim_days * DAY_MS as f64) as i64;
                self.sponsor_props.push(Proposal {
                    claim: Some((v, n_hours as u32)),
                    id: None,
                    proposed_ms: now,
                    stage: 0,
                    enact_after: 0,
                    action: sent,
                });
            }
        }
    }

    fn after_block(&mut self, results: &[TxResult]) {
        let now = self.chain.now_ms();
        let rules = tenzro_vm::governance::GovernanceRules::GENESIS;
        for r in results {
            crate::attack::on_result(self, r);
            if !r.applied {
                self.day_refused += 1;
                let key: String = strip_ids(&format!("{}: {}", tx_kind(&r.tx), r.error))
                    .chars()
                    .take(200)
                    .collect();
                *self.out.refusals.entry(key).or_default() += 1;
            }
            match &r.tx {
                SimTx::Propose { action, .. }
                    if self
                        .sponsor_props
                        .iter()
                        .any(|p| p.id.is_none() && &p.action == action) =>
                {
                    let i = self
                        .sponsor_props
                        .iter()
                        .position(|p| p.id.is_none() && &p.action == action)
                        .expect("matched above");
                    if r.applied {
                        let id = r.output.clone();
                        self.sponsor_props[i].id = Some(id.clone());
                        self.sponsor_props[i].stage = 1;
                        for v in self.bonded() {
                            let id = id.clone();
                            let _ = self.chain.submit(v, NATIVE_GAS, |nonce| SimTx::Vote {
                                from: v,
                                proposal: id,
                                nonce,
                            });
                        }
                    } else {
                        self.sponsor_props.remove(i);
                    }
                }
                SimTx::Execute { proposal, .. }
                    if self
                        .sponsor_props
                        .iter()
                        .any(|p| p.id.as_ref() == Some(proposal)) =>
                {
                    let i = self
                        .sponsor_props
                        .iter()
                        .position(|p| p.id.as_ref() == Some(proposal))
                        .expect("matched above");
                    let p = self.sponsor_props[i].clone();
                    match (p.stage, r.applied) {
                        (2, true) => {
                            let tl = if is_large_spend(&p.action, &rules) {
                                rules.timelock_ms.max(rules.large_spend_timelock_ms)
                            } else {
                                rules.timelock_ms
                            };
                            self.sponsor_props[i].stage = 3;
                            self.sponsor_props[i].enact_after = now + tl + tl / 10;
                        }
                        (4, ok) => {
                            if ok {
                                self.enacted += 1;
                                if let Some((seat, hours)) = p.claim {
                                    let rate = self
                                        .chain
                                        .param(n::payout_gates::PER_VERIFIED_EPOCH_USD_PARAM)
                                        as f64
                                        / 1e6;
                                    self.sponsor_hours[seat as usize].drain(..hours as usize);
                                    self.sponsored_usd_total += hours as f64 * rate;
                                    self.sponsored_usd_day += hours as f64 * rate;
                                    self.sponsor_credit_usd[seat as usize] += hours as f64 * rate;
                                }
                            } else {
                                self.failed += 1;
                            }
                            self.sponsor_props.remove(i);
                        }
                        (_, false) => {
                            self.failed += 1;
                            self.sponsor_props.remove(i);
                        }
                        _ => {}
                    }
                }
                SimTx::Propose { action, .. }
                    if self
                        .proposal
                        .as_ref()
                        .is_some_and(|p| p.id.is_none() && &p.action == action) =>
                {
                    if r.applied {
                        let id = r.output.clone();
                        if let Some(p) = self.proposal.as_mut() {
                            p.id = Some(id.clone());
                            p.stage = 1;
                        }
                        for v in self.bonded() {
                            if crate::attack::validator_votes(self, v) {
                                let id = id.clone();
                                let _ = self.chain.submit(v, NATIVE_GAS, |nonce| SimTx::Vote {
                                    from: v,
                                    proposal: id,
                                    nonce,
                                });
                            }
                        }
                    } else {
                        self.proposal = None;
                    }
                }
                SimTx::Execute { proposal, .. }
                    if self
                        .proposal
                        .as_ref()
                        .is_some_and(|p| p.id.as_ref() == Some(proposal)) =>
                {
                    if let Some(p) = self.proposal.as_mut() {
                        match (p.stage, r.applied) {
                            (2, true) => {
                                p.stage = 3;
                                // A large spend waits out the longer timelock.
                                let tl = if is_large_spend(&p.action, &rules) {
                                    rules.timelock_ms.max(rules.large_spend_timelock_ms)
                                } else {
                                    rules.timelock_ms
                                };
                                p.enact_after = now + tl + tl / 10;
                            }
                            (4, ok) => {
                                if ok {
                                    self.enacted += 1;
                                    if self.asset_entry.as_ref() == Some(&p.action) {
                                        self.asset_entry = None;
                                    }
                                } else {
                                    self.failed += 1;
                                }
                                self.proposal = None;
                            }
                            (_, false) => {
                                self.failed += 1;
                                self.proposal = None;
                            }
                            _ => {}
                        }
                    }
                }
                SimTx::Call {
                    from, data, nonce, ..
                } if !r.applied && data.starts_with(&n::SELECTOR_ESCROW_CREATE) => {
                    // A stream whose escrow was never created is no stream.
                    let id = n::derive_escrow_id(&Address::new(ledger::account(*from)), *nonce);
                    self.streams.retain(|s| s.escrow != id);
                }
                _ => {}
            }
        }
        // Votes queued above go into the next block.
        let _ = &self.settle_paid;
        let _ = &self.settle_fee;
    }

    fn close_day(&mut self, demand: f64) {
        let a = self.cfg.assumptions.clone();
        // The class accounts cover the last year of the run.
        if self.out.days.len() as u32 == self.cfg.days.saturating_sub(365) {
            for p in &mut self.providers {
                p.window_start = (p.stream_usd, p.session_usd, p.coupons_usd);
            }
        }
        let snap = self.chain.snapshot(self.genesis_supply);
        let day = snap.day;
        // Validator income: balances move by claims and fees; read the
        // liquid balance and vesting schedules through the claim results.
        let bonded = self.bonded();
        let daily_cost = a.validator_cost_usd_month / 30.44;
        let mut profitable = 0;
        let mut yields = Vec::new();
        let bond = tnzo(
            self.chain
                .ledger
                .bonds_now()
                .iter()
                .copied()
                .max()
                .unwrap_or(0),
        )
        .max(1.0);
        // The floor seats' base reward each bonded validator earns in a day,
        // which no burn is needed for: it pays the operator's running cost,
        // so the operator keeps it rather than passing it to delegators.
        let base_each = if bonded.is_empty() {
            0.0
        } else {
            let st = self.chain.state();
            let per_year = n::rewards::read_reward_schedule(st)
                .map(|s| s.epochs_per_year)
                .unwrap_or(365);
            let epochs_a_day = (per_year as f64 / YEAR_DAYS).max(1.0);
            tnzo(n::rewards::validator_base_rights(
                st,
                u64::MAX,
                bonded.len() as u64,
                per_year,
            )) / bonded.len() as f64
                * epochs_a_day
        };
        // With delegated stake, an operator's yield is on its own stake.
        let yield_base = if self.delegated_each > 0.0 {
            self.own_bond.max(1.0)
        } else {
            bond
        };
        self.sponsored_usd_day = 0.0;
        // The account's opening balance is not sponsorship; one TNZO more
        // stays to pay the transfers' gas.
        let mut sponsor_left = self
            .chain
            .ledger
            .balance(ids::SPONSOR)
            .saturating_sub(OPENING_BALANCE + TNZO);
        let mut sponsor_paid_day_usd = 0.0;
        for v in &bonded {
            let addr = ledger::account(*v);
            let now_bal =
                tnzo(self.chain.balance_of(&addr)) + tnzo(vesting_total(self.chain.state(), &addr));
            // The running cost the cover reserve pays in the stable token
            // is income at the token's market value.
            let stable_now = self
                .stable
                .as_ref()
                .map_or(0, |s| s.balance(self.chain.state(), &addr));
            let peg = self.peg_at(day);
            let st = &mut self.validators[*v as usize];
            let cover_usd = crate::stable::usd(stable_now.saturating_sub(st.stable_seen)) * peg;
            st.stable_seen = stable_now;
            if st.trail.is_empty() && st.income_tnzo == 0.0 {
                st.income_tnzo = now_bal;
            }
            let mut income = (now_bal - st.income_tnzo).max(0.0);
            // Sponsorship sent yesterday is in this change; the operator's
            // own income, and what it shares with delegators, leaves it out.
            let sponsor_in = std::mem::take(&mut st.sponsor_sent).min(income);
            income -= sponsor_in;
            // It sells what pays the day's running cost, from what is liquid;
            // a contracted validator is paid that cost in USD instead.
            let liquid = tnzo(self.chain.balance_of(&addr));
            let sold = if a.closed_phase {
                0.0
            } else {
                (daily_cost / self.price).min((liquid - 1.0).max(0.0))
            };
            // Rewards on delegated stake go to the delegators, less the
            // validator's commission, paid from what is liquid.
            let mut paid_out = 0.0;
            if self.delegated_each > 0.0 {
                let mine = tnzo(self.chain.ledger.bonds_now()[*v as usize]);
                let delegated = (mine - self.own_bond).max(0.0) / mine.max(1.0);
                let own_cost = income.min(base_each);
                let pass = (income - own_cost)
                    * delegated
                    * (1.0 - a.validator_commission.clamp(0.0, 1.0));
                income -= pass;
                let st = &mut self.validators[*v as usize];
                st.owed_delegators += pass;
                paid_out = st.owed_delegators.min((liquid - 1.0 - sold).max(0.0));
                st.owed_delegators -= paid_out;
            }
            // The top-up, on the days the operator's own income falls short
            // of the governed cost: approved seats only, bonded and serving,
            // paid from what governance has put in the sponsor account.
            self.cover_paid_usd_total += cover_usd;
            let own_usd = income * self.price + cover_usd;
            let mut sponsor_today_usd = 0.0;
            if a.sponsor_gated {
                sponsor_today_usd = std::mem::take(&mut self.sponsor_credit_usd[*v as usize]);
            }
            let serving = !self.validators[*v as usize].exiting;
            if *v < a.sponsor_seats && serving && day > 1.0 && !a.sponsor_gated {
                let short_usd = (daily_cost - own_usd).max(0.0);
                // Rounded up, so the top-up never leaves the operator a
                // fraction under its cost.
                let want = (short_usd / self.price * (1.0 + 1e-9) * TNZO as f64).ceil() as u128;
                let pay = want.min(sponsor_left);
                if pay > 0 && self.chain.transfer(ids::SPONSOR, *v, pay, None) {
                    sponsor_left -= pay;
                    self.validators[*v as usize].sponsor_sent = tnzo(pay);
                    sponsor_today_usd = tnzo(pay) * self.price;
                    self.sponsored_tnzo_total += tnzo(pay);
                    self.sponsored_usd_day += tnzo(pay) * self.price;
                    sponsor_paid_day_usd += tnzo(pay) * self.price;
                }
            }
            let st = &mut self.validators[*v as usize];
            st.income_tnzo = now_bal - sold - paid_out;
            st.income_usd += income * self.price + cover_usd + sponsor_today_usd;
            if paid_out > 0.0 {
                let q = (paid_out * TNZO as f64) as u128;
                let _ = self.chain.transfer(*v, crate::chain::RESERVE, q, None);
            }
            if sold > 0.0 {
                self.sell(*v, (sold * TNZO as f64) as u128);
            }
            let st = &mut self.validators[*v as usize];
            st.cost_usd += daily_cost;
            st.trail.push((
                income * self.price + cover_usd + sponsor_today_usd,
                daily_cost,
            ));
            if st.trail.len() > 30 {
                st.trail.remove(0);
            }
            let (i, c): (f64, f64) = st
                .trail
                .iter()
                .fold((0.0, 0.0), |(a, b), (x, y)| (a + x, b + y));
            if i >= c {
                profitable += 1;
            }
            let y =
                (i - c) / (yield_base * self.price) * (YEAR_DAYS / st.trail.len().max(1) as f64);
            yields.push(y);
        }
        self.sponsor_ema_usd = 0.9 * self.sponsor_ema_usd + 0.1 * sponsor_paid_day_usd;
        let mean_yield = if yields.is_empty() {
            0.0
        } else {
            yields.iter().sum::<f64>() / yields.len() as f64
        };
        // Entry and exit, once a validator has a month of history; contracted
        // validators stay whatever their yield.
        if day > 30.0 && !a.closed_phase {
            for v in bonded.clone() {
                let st = &self.validators[v as usize];
                if st.exiting || st.trail.len() < 30 {
                    continue;
                }
                let (i, c): (f64, f64) = st
                    .trail
                    .iter()
                    .fold((0.0, 0.0), |(a, b), (x, y)| (a + x, b + y));
                let y = (i - c) / (yield_base * self.price) * 12.17;
                if y < a.validator_exit_yield && bonded.len() > 4 {
                    let _ = self
                        .chain
                        .submit(v, NATIVE_GAS, |nonce| SimTx::Exit { from: v, nonce });
                    let st = &mut self.validators[v as usize];
                    st.exiting = true;
                    st.exit_requested_ms = self.chain.now_ms();
                    break;
                }
            }
            if mean_yield > a.validator_join_yield {
                let total = (a.validators + a.standby) as usize;
                if let Some(v) = (0..total)
                    .find(|v| !bonded.contains(&(*v as u32)) && !self.validators[*v].exiting)
                {
                    let v = v as u32;
                    let amount = (bond as u128) * TNZO;
                    let mut continue_join = true;
                    // Delegators bring the stake a joining validator lacks,
                    // but only up to the staking share they hold: past it
                    // they would move stake, not add it.
                    if self.delegated_each > 0.0 {
                        let bonded_now = tnzo(self.chain.ledger.bonds_now().iter().sum());
                        let target = self.cfg.assumptions.staking_ratio * self.circulating0;
                        if bonded_now + bond > target {
                            continue_join = false;
                        } else {
                            let have = self.chain.ledger.balance(v);
                            let _ = self.take_off_market(v, amount.saturating_sub(have) + TNZO);
                        }
                    }
                    if continue_join {
                        let _ = self
                            .chain
                            .submit(v, NATIVE_GAS, |nonce| SimTx::IncreaseStake {
                                from: v,
                                amount,
                                nonce,
                            });
                        self.validators[v as usize].joined_day = day;
                    }
                }
            }
        }
        // Withdraw finished unbondings.
        let unbond_ms = self.chain.param("staking.validator_unbonding_ms") as i64;
        for v in 0..self.validators.len() {
            let st = &self.validators[v];
            if st.exiting
                && self.chain.now_ms() > st.exit_requested_ms + unbond_ms.max(DAY_MS) + DAY_MS
            {
                let v = v as u32;
                let _ = self
                    .chain
                    .submit(v, NATIVE_GAS, |nonce| SimTx::Exit { from: v, nonce });
                self.validators[v as usize].exiting = false;
            }
        }
        // Delegated stake a departed validator got back goes back to its
        // delegators, outside holders, rather than staying with the operator.
        if self.delegated_each > 0.0 {
            let bonded_set = self.bonded();
            let keep = 50_000.0 + self.own_bond;
            for v in 0..self.validators.len() as u32 {
                if bonded_set.contains(&v) || self.validators[v as usize].exiting {
                    continue;
                }
                let liquid = tnzo(self.chain.ledger.balance(v));
                if liquid > keep + 1.0 {
                    let q = ((liquid - keep) * TNZO as f64) as u128;
                    let _ = self.chain.transfer(v, crate::chain::RESERVE, q, None);
                }
            }
        }
        // Providers.
        let mut prov_ok = 0;
        let mut prov_n = 0;
        let mut sales = Vec::new();
        let stable = a.stable_settlement;
        let mut provider_income = 0.0;
        let stable_token = self.stable.as_ref().map(|s| s.token);
        if let Some(token) = stable_token {
            // Paid in the stable token: each provider sends the treasury the
            // leg it owes and redeems the rest with outside holders. What it
            // made is what it was paid less the leg, the TNZO it holds above
            // its start at today's price, less what its fee TNZO cost.
            let treasury = n::derive_treasury_address().0;
            for p in self.providers.iter_mut().filter(|p| p.bonded && !p.gone) {
                let bal = tnzo(self.chain.ledger.balance(p.id));
                p.earned_tnzo = bal;
                let today = p.stable_in_usd - p.stable_in_seen;
                p.stable_in_seen = p.stable_in_usd;
                p.stable_ema_usd = (0.7 * p.stable_ema_usd + 0.3 * today).max(today);
                let held = tenzro_vm::token_ledger::balance(
                    self.chain.state(),
                    &token,
                    &ledger::account(p.id),
                );
                let leg = p.leg_owed.min(held);
                if leg > 0 {
                    let call = crate::stable::transfer_call(token, treasury, leg);
                    if self.chain.call(
                        p.id,
                        None,
                        0,
                        n::SELECTOR_TOKEN,
                        &call[4..],
                        NATIVE_GAS,
                        None,
                    ) {
                        p.leg_owed -= leg;
                        p.leg_sent_usd += crate::stable::usd(leg);
                        if let Some(s) = self.stable.as_mut() {
                            s.legs_sent += leg;
                        }
                    }
                }
                let redeem = held - leg;
                if redeem > 0 {
                    let call = crate::stable::transfer_call(
                        token,
                        ledger::account(ids::STABLE_OUTSIDE),
                        redeem,
                    );
                    let _ = self.chain.call(
                        p.id,
                        None,
                        0,
                        n::SELECTOR_TOKEN,
                        &call[4..],
                        NATIVE_GAS,
                        None,
                    );
                }
                prov_n += 1;
                let income_usd = p.stable_in_usd - p.leg_sent_usd - crate::stable::usd(p.leg_owed)
                    + p.sold_usd
                    + (bal - 50_000.0 + a.provider_bond_tnzo) * self.price
                    - p.fee_tnzo_cost_usd;
                if income_usd >= p.cost_usd {
                    prov_ok += 1;
                }
            }
        }
        for p in self
            .providers
            .iter_mut()
            .filter(|p| p.bonded && !p.gone && stable_token.is_none())
        {
            let bal = tnzo(self.chain.ledger.balance(p.id));
            p.earned_tnzo = bal;
            provider_income += (bal - p.last_bal).max(0.0);
            // Paid in a stable unit, a provider keeps none of it as TNZO.
            let share = if stable { 1.0 } else { a.provider_sell_share };
            let income = (bal - p.last_bal).max(0.0);
            let mut sold = income * share;
            // A provider keeps at most its set days of income; above that it
            // sells, so what it holds does not grow without end.
            if a.provider_hold_days > 0.0 && !stable {
                p.income_ema = 0.9 * p.income_ema + 0.1 * income;
                let held = bal - sold - 50_000.0;
                let cap = a.provider_hold_days * p.income_ema;
                if held > cap {
                    sold += held - cap;
                }
            }
            p.last_bal = bal - sold;
            p.sold_usd += sold * self.price;
            if sold > 0.0 {
                sales.push((p.id, (sold * TNZO as f64) as u128));
            }
            prov_n += 1;
            // What it sold, in the USD it realised, and what it still holds
            // above its start, at today's price.
            let income_usd = p.sold_usd + (bal - 50_000.0 + a.provider_bond_tnzo) * self.price;
            if income_usd >= p.cost_usd {
                prov_ok += 1;
            }
        }
        // Paid in the stable token, providers sell nothing, and the TNZO
        // agents and providers took for gas and fees was counted when taken.
        if stable && stable_token.is_none() {
            for (id, q) in sales {
                let _ = self.chain.transfer(id, crate::chain::RESERVE, q, None);
            }
            // TNZO agents spent on fees and gas leaves the payment loop: it
            // is what they had to buy on the market.
            let held: f64 = (ids::AGENTS..ids::AGENTS + ids::AGENT_COUNT)
                .map(|id| tnzo(self.chain.ledger.balance(id)))
                .sum();
            let fees =
                std::mem::take(&mut self.agent_bought) - provider_income - (held - self.agent_held);
            self.agent_held = held;
            self.flow_buy += fees.max(0.0);
        } else {
            for (id, q) in sales {
                self.sell(id, q);
            }
        }
        // Grantees sell their share of a grant over the month it covers.
        let g = if a.closed_phase {
            0
        } else {
            self.chain.ledger.balance(ids::GRANTEE)
        };
        let g_sold = (g as f64 * a.grant_sell_share / 30.0) as u128;
        self.sell(ids::GRANTEE, g_sold);
        self.grants_usd_day = tnzo(g_sold) * self.price;
        // The sell-back desk sells what the treasury granted it, at most its
        // daily cap, keeping its starting balance.
        if a.treasury_sellback && !a.closed_phase {
            let held = self
                .chain
                .ledger
                .balance(ids::SELLBACK)
                .saturating_sub(50_000 * TNZO);
            let q = held.min((a.sellback_max_tnzo_day * TNZO as f64) as u128);
            let before = self.flow_sell;
            self.sell(ids::SELLBACK, q);
            self.sellback_sold += self.flow_sell - before;
        }
        // The desk takes in the running-cost payouts the reserve made today
        // and sells them at the next trade, within its participation share.
        let book = n::treasury_reserve::read_book(self.chain.state());
        let paid_today = book.total_paid.saturating_sub(self.reserve_paid_seen);
        self.reserve_paid_seen = book.total_paid;
        self.desk_inventory = self.desk_inventory.saturating_add(paid_today);
        let proceeds = std::mem::take(&mut self.desk_proceeds_usd);
        let asked_day = if self.cfg.ablation == Ablation::NoReserve {
            0.0
        } else {
            a.running_cost_ask_usd_month / 30.44
        };
        // Before a listing the bootstrap funder pays the running costs in full.
        let proceeds = if a.closed_phase { asked_day } else { proceeds };
        self.cost_trail.push_back((proceeds, asked_day));
        self.cost_total.0 += proceeds;
        self.cost_total.1 += asked_day;
        if self.cost_trail.len() > 30 {
            self.cost_trail.pop_front();
        }
        let (paid_30d, asked_30d) = self
            .cost_trail
            .iter()
            .fold((0.0, 0.0), |(p, q), (x, y)| (p + x, q + y));
        let fee = if self.fee_probe_n > 0 {
            self.fee_probe_sum / self.fee_probe_n as f64
        } else {
            0.0
        };
        self.fee_probe_sum = 0.0;
        self.fee_probe_n = 0;
        // Fee revenue: the settlement fee on the day's spend, and the gas
        // the day's transactions paid, those the run stood for included.
        let agents_gone = self
            .cfg
            .agents_leave_day
            .is_some_and(|d| snap.day >= d as f64);
        let spend_usd = if agents_gone {
            0.0
        } else {
            (a.compute_usd_per_day * self.rent_share() + a.agent_tasks_per_day * a.agent_task_usd)
                * demand
        };
        let applied = self.chain.ledger.stats.applied as f64;
        let gas_tnzo =
            (applied - self.tx_seen) * fee + (self.out.unexecuted_gas_fees_tnzo - self.unexec_seen);
        self.tx_seen = applied;
        self.unexec_seen = self.out.unexecuted_gas_fees_tnzo;
        let fee_share = self.chain.param("fees.settlement_fee_bps") as f64 / 10_000.0;
        // The treasury leg of provider work, on what the provider is
        // credited after the fee: compute streams are compute leases, agent
        // sessions inference.
        // A leg taken in the stable token is at the rate the run took it at.
        let leg = |k: &str| {
            let bps = match self.stable.as_ref().filter(|s| s.leg_in_token) {
                Some(s) if k == n::economy::TREASURY_LEG_COMPUTE_PARAM => s.leg_compute_bps,
                Some(s) => s.leg_inference_bps,
                None => self.chain.param(k),
            };
            bps.min(5_000) as f64 / 10_000.0
        };
        let legs = if agents_gone {
            0.0
        } else {
            (a.compute_usd_per_day
                * self.rent_share()
                * leg(n::economy::TREASURY_LEG_COMPUTE_PARAM)
                + a.agent_tasks_per_day
                    * a.agent_task_usd
                    * leg(n::economy::TREASURY_LEG_INFERENCE_PARAM))
                * demand
                * (1.0 - fee_share)
        };
        self.revenue_trail
            .push_back(spend_usd * fee_share + legs + gas_tnzo.max(0.0) * self.price);
        if self.revenue_trail.len() > 30 {
            self.revenue_trail.pop_front();
        }
        // What providers were paid today, the anchor share taken out.
        let settled: f64 = self
            .providers
            .iter()
            .map(|p| p.stream_usd + p.session_usd)
            .sum();
        let unrelated_demand_usd_day =
            (settled - self.settled_seen).max(0.0) * (1.0 - a.anchor_share.clamp(0.0, 1.0));
        self.settled_seen = settled;
        // Validators' income without issuance: their governed share of the
        // day's burn, against what the bonded set costs.
        let burn_share = self
            .chain
            .param(n::rewards::VALIDATOR_BURN_SHARE_PARAM)
            .min(10_000) as f64
            / 10_000.0;
        let burned_today = (snap.burned - self.burned_seen).max(0.0);
        self.burned_seen = snap.burned;
        self.validator_fee_trail.push_back((
            burned_today * burn_share * self.price,
            bonded.len() as f64 * daily_cost,
        ));
        if self.validator_fee_trail.len() > 30 {
            self.validator_fee_trail.pop_front();
        }
        let (validator_fee_income_usd_30d, validator_cost_usd_30d) = self
            .validator_fee_trail
            .iter()
            .fold((0.0, 0.0), |(p, q), (x, y)| (p + x, q + y));
        let third = snap.bonded / 3.0;
        let attack_cost_pool_usd = self.pool.buy_cost(third).unwrap_or(f64::INFINITY);
        let supply_liquid = snap.supply.max(1.0);
        // Months the treasury keeps granting at the rate in force, and
        // months of the asked running costs the reserve holds.
        let reserve_runway = if a.running_cost_ask_usd_month > 0.0 {
            snap.reserve * self.price / a.running_cost_ask_usd_month
        } else {
            f64::INFINITY
        };
        let grant_months = if self.last_grant_tnzo > 0.0 {
            snap.treasury / self.last_grant_tnzo
        } else {
            f64::INFINITY
        };
        let runway = grant_months;
        // Outside prices as challenge evidence: days the chain rate sat off
        // the market by more than the band, and days the reported median
        // was back inside it.
        let chain_rate = n::read_fee_rate(self.chain.state()).rate_nano_usd as f64 / 1e9;
        if (chain_rate / self.price - 1.0).abs() > a.challenge_band {
            self.off_band_days += 1;
        } else {
            self.off_band_days = 0;
        }
        let e = self.market_epoch().saturating_sub(3);
        let median_ok = n::economy::read_committed_rate(self.chain.state(), "TNZO", e)
            .and_then(|r| r.median_nano_usd.parse::<f64>().ok())
            .is_some_and(|m| (m / 1e9 / self.price - 1.0).abs() <= a.challenge_band);
        self.in_band_days = if median_ok { self.in_band_days + 1 } else { 0 };
        let (treasury_stable_usd, stable_legs_usd_total, stable_outside_usd) =
            self.check_stable(day);
        let peg = self.peg_at(day);
        let treasury_stable_usd = treasury_stable_usd * peg;
        let (security_ratio_bps, extractable_tnzo) = {
            let st = self.chain.state();
            let limits = n::bridge_circuit::read_bridge_outflow_limits(st)
                .unwrap_or_else(n::bridge_circuit::default_bridge_outflow);
            (
                n::security::ratio_bps_under(st, &limits),
                n::security::extractable_tnzo(st, &limits)
                    .map(tnzo)
                    .unwrap_or(0.0),
            )
        };
        let min_ratio_bps = match self.chain.param(n::security::MIN_RATIO_PARAM) {
            0 => n::security::DEFAULT_MIN_RATIO_BPS,
            k => k,
        };
        self.out.days.push(Day {
            staking_ratio: snap.bonded / supply_liquid,
            revenue_usd_year: self.revenue_usd_year(),
            fdv_usd: self.price * snap.supply,
            price_ceiling_usd: self.price_ceiling,
            staking_ratio_circulating: snap.bonded / self.circulating0.max(1.0),
            attack_cost_usd: third * self.price,
            attack_cost_pool_usd,
            outside_float_tnzo: tnzo(self.chain.ledger.balance(crate::chain::RESERVE)),
            held_by: self.held_by(),
            unrelated_demand_usd_day,
            validator_fee_income_usd_30d,
            validator_cost_usd_30d,
            treasury_stable_usd,
            stable_legs_usd_total,
            stable_outside_usd,
            sellback_sold_tnzo_total: self.sellback_sold,
            security_ratio_bps,
            extractable_tnzo,
            min_ratio_bps,
            stable_peg_usd: peg,
            snap,
            price_usd: self.price,
            demand,
            human_fee_tnzo: fee,
            agent_fee_share: self.chain.param("fees.settlement_fee_bps") as f64 / 10_000.0,
            validator_yield: mean_yield,
            validators_profitable: if bonded.is_empty() {
                0.0
            } else {
                profitable as f64 / bonded.len() as f64
            },
            providers_profitable: if prov_n == 0 {
                0.0
            } else {
                prov_ok as f64 / prov_n as f64
            },
            providers: prov_n,
            treasury_runway_months: runway,
            refused: self.day_refused,
            chain_rate_usd: chain_rate,
            fair_price_usd: self.fair.price(),
            grants_usd: self.grants_usd_day,
            sponsored_usd: self.sponsored_usd_day,
            sponsored_tnzo_total: self.sponsored_tnzo_total,
            sponsored_usd_total: self.sponsored_usd_total,
            stable_given_usd: self.stable_given_usd,
            cover_reserve_usd: self.stable.as_ref().map_or(0.0, |s| {
                crate::stable::usd(
                    s.balance(self.chain.state(), &n::validator_cover::reserve_address().0),
                )
            }),
            cover_paid_usd_total: self.cover_paid_usd_total,
            sponsor_grant_outflow_year_tnzo: self.outflow_year(),
            sponsor_grant_cap_tnzo: self.outflow_cap(),
            running_costs_paid_usd_30d: paid_30d,
            running_costs_asked_usd_30d: asked_30d,
            running_costs_paid_usd_total: self.cost_total.0,
            running_costs_asked_usd_total: self.cost_total.1,
            reserve_target_tnzo: tnzo(book.target),
            reserve_runway_months: reserve_runway,
            volume_tnzo: self.volume_day_tnzo,
            reserve_sold_tnzo: self.desk_sold_tnzo,
            reserve_paid_tnzo: tnzo(paid_today),
            sale_cap_epoch_tnzo: tnzo(book.sale_cap),
            running_costs_owed_tnzo: tnzo(self.running_cost_owed()),
            mint_mult: n::read_reward_state(self.chain.state())
                .map(|r| r.mint_mult_ppm as f64 / 1e6)
                .unwrap_or(1.0),
            rate_frozen: self.chain.param("fees.usd_rate_frozen") == 1,
        });
        self.day_refused = 0;
        let _ = demand;
    }
}

/// Whether a proposal action pays at least the large-spend size.
fn is_large_spend(action: &[u8], rules: &tenzro_vm::governance::GovernanceRules) -> bool {
    use tenzro_vm::governance::ProposalAction as A;
    let large = u128::from(rules.large_spend_tnzo).saturating_mul(TNZO);
    match serde_json::from_slice::<A>(action) {
        // A stable payout is sized in USD and valued only against state, so
        // the chain treats it as the largest kind of spend: the supermajority
        // and the long timelock apply to every one.
        Ok(A::SponsorOperatorStable { .. } | A::TreasuryGrant { asset: Some(_), .. }) => true,
        Ok(A::TreasuryGrant { amount, .. } | A::RunningCostPayment { amount, .. }) => {
            amount >= large
        }
        _ => false,
    }
}

/// Sum of an address's unreleased vesting, TNZO base units.
pub(crate) fn vesting_total(state: &dyn tenzro_vm::traits::VmState, addr: &[u8; 32]) -> u128 {
    let key = format!("vesting:{}", hex::encode(addr));
    let Some(blob) = state.get_storage(&n::SYSTEM_ADDRESS, key.as_bytes()) else {
        return 0;
    };
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(&blob) else {
        return 0;
    };
    let mut total = 0u128;
    let items = v.as_array().cloned().unwrap_or_default();
    for s in items {
        let amount = s.get("total").or_else(|| s.get("amount")).and_then(num);
        let released = s.get("released").and_then(num).unwrap_or(0);
        if let Some(a) = amount {
            total += a.saturating_sub(released);
        }
    }
    total
}

fn num(v: &serde_json::Value) -> Option<u128> {
    match v {
        serde_json::Value::String(s) => s.parse().ok(),
        serde_json::Value::Number(n) => n.as_u64().map(u128::from),
        _ => None,
    }
}

/// Replaces ids and long numbers in a message so equal refusals group.
pub fn strip_ids(s: &str) -> String {
    let mut out = String::new();
    let mut run = String::new();
    for c in s.chars() {
        if c.is_ascii_hexdigit() {
            run.push(c);
        } else {
            out.push_str(if run.len() >= 8 { "<n>" } else { &run });
            run.clear();
            out.push(c);
        }
    }
    out.push_str(if run.len() >= 8 { "<n>" } else { &run });
    out
}

/// A short name of a transaction's kind.
pub fn tx_kind(tx: &SimTx) -> String {
    match tx {
        SimTx::Call { data, to, .. } => {
            if data.len() < 4 {
                return if to.is_some() {
                    "transfer".into()
                } else {
                    "call".into()
                };
            }
            let sel: [u8; 4] = data[..4].try_into().expect("selector");
            selector_name(sel).into()
        }
        other => format!("{other:?}")
            .split([' ', '{'])
            .next()
            .unwrap_or("tx")
            .to_string(),
    }
}

/// Name of a native selector the populations use.
pub fn selector_name(sel: [u8; 4]) -> &'static str {
    match sel {
        s if s == n::SELECTOR_POST_COMPUTE_BOND => "post compute bond",
        s if s == n::SELECTOR_SLA_ATTEST => "SLA attest",
        s if s == n::SELECTOR_ESCROW_CREATE => "escrow create",
        s if s == n::SELECTOR_ESCROW_STREAM_CLAIM => "stream claim",
        s if s == n::SELECTOR_PAY_INSURANCE_CLAIM => "insurance claim",
        s if s == n::SELECTOR_FUNDING => "funding",
        s if s == n::SELECTOR_GOVERNANCE_VOTE => "vote",
        s if s == n::SELECTOR_FEE_RATE_SUBMIT => "rate report",
        s if s == n::SELECTOR_SETTLEMENT_PLAN => "settlement plan",
        _ => "native call",
    }
}

/// Sends a value-transfer ladder at one block to measure fee response: the
/// harness's fee-market check at real block time.
pub fn fee_market_probe(
    load_gas_per_block: &[u64],
    blocks: u32,
    tip: Option<u128>,
) -> Vec<(u64, f64, f64)> {
    let plan = GenesisPlan {
        validators: 4,
        standby: 0,
        bond_tnzo: tenzro_vm::governance::genesis_param("stake.validator_tnzo").max(1),
        balance_tnzo: 1_000_000,
        users: 400,
        treasury_tnzo: 0,
        insurance_tnzo: 0,
        reserve_tnzo: 0,
        opening_accounts: Vec::new(),
        network_params: BTreeMap::new(),
    };
    let mut out = Vec::new();
    for &load in load_gas_per_block {
        let mut chain = Chain::new(&plan, Clock::REAL);
        let per_block = (load / 21_000).max(1);
        for b in 0..blocks {
            for i in 0..per_block {
                let from = USER_BASE + ((b as u64 * per_block + i) % 400) as u32;
                let to = USER_BASE + ((from - USER_BASE + 1) % 400);
                chain.transfer(from, to, 1, tip);
            }
            chain.produce();
        }
        let fee = tnzo(chain.base_fee()) * 21_000.0;
        out.push((load, fee, tnzo(chain.base_fee())));
    }
    out
}
