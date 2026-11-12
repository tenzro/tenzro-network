//! Whether the machine economy grows itself: an aggregate daily model of
//! app-mediated demand, endogenous provider supply and a funded bootstrap.
//!
//! This model does not execute transactions. It takes the protocol's fee
//! rules as inputs (network take per class, settlement fee, gas, the reward
//! cap of a settlement at a share of its fee) and runs the loop between them
//! day by day, so that thresholds, tariff sweeps and failure modes can be
//! searched in seconds. The ledger economy ([`crate::economy`]) is where the
//! fee and reward rules themselves are executed.
//!
//! - **Demand** is app-mediated and arrives through four channels:
//!   resellers, third-party platforms, partners' deployments and direct
//!   developers. Each channel holds a share of the potential demand, adds its
//!   own commission on top of the network's end price, and moves demand to
//!   or away from the network by its own price and quality elasticity
//!   against centralised API prices. Every channel is treated alike: same
//!   fees, same rules, its own elasticity.
//! - **Supply** per class (GPU rental, inference hosting, storage) enters
//!   after a lag while the expected margin is positive, and leaves while it
//!   is negative. The bootstrap funder runs a bootstrap supply and funds an
//!   agent swarm until a set day. Consumer platforms buy inference for their
//!   own products; a set share of their demand is related to the bootstrap
//!   funder, served by its providers, pays fees, earns no rewards and is kept
//!   out of the organic figures.
//! - **Outcome**: growth, stall or collapse; the day organic fees cover
//!   provider costs and running costs; what the bootstrap funder carried until then.

use serde::Serialize;

/// Days in a year.
const YEAR: f64 = 365.25;

/// A priced service class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Class {
    /// Model inference, priced per million tokens.
    Inference,
    /// GPU rental, priced per GPU-hour.
    Gpu,
    /// Storage, priced per TB-month.
    Storage,
    /// The edge tier's CPU profile (small, embedded and edge devices; a
    /// Raspberry Pi 5 is the reference): hosting agents, swarms and
    /// harnesses for others, with small models and edge relay, priced per
    /// agent slot-day.
    Edge,
    /// The edge tier's small-GPU profile (a Jetson Orin Nano Super):
    /// hosting agents with a local 8B model, priced per agent slot-day.
    EdgeGpu,
    /// The edge tier's large profile (a Jetson AGX Orin 64 GB): many agent
    /// slots and larger local models, priced per agent slot-day.
    EdgeAgx,
    /// Consumer GPUs (an RTX 4090 as the reference) serving 7-8B models
    /// with batching, priced per million tokens.
    ConsumerGpu,
}

impl Class {
    /// Every class.
    pub const ALL: [Class; 7] = [
        Class::Inference,
        Class::Gpu,
        Class::Storage,
        Class::Edge,
        Class::EdgeGpu,
        Class::EdgeAgx,
        Class::ConsumerGpu,
    ];
}

/// One class's prices, costs and supply rules.
#[derive(Debug, Clone, Serialize)]
pub struct ClassSpec {
    /// The class.
    pub class: Class,
    /// Share of potential demand (USD at reference prices).
    pub demand_mix: f64,
    /// Centralised reference price per unit at launch, USD.
    pub reference_usd: f64,
    /// Yearly fall of the reference price, share.
    pub reference_decline: f64,
    /// Network take on this class, share of the provider price.
    pub take: f64,
    /// Units one provider can serve a day.
    pub units_per_provider_day: f64,
    /// One provider's cost a day, USD, used or idle.
    pub cost_usd_day: f64,
    /// Providers the bootstrap funder runs at launch.
    pub bootstrap: f64,
    /// Settlement payments one unit takes at launch prices (streams claim
    /// hourly; sessions settle once); a payment carries a value, so it covers
    /// more units as prices fall.
    pub payments_per_unit: f64,
    /// Range of one provider's cost a day across operators, USD (low, high);
    /// the share profitable is the share of a uniform spread below revenue.
    pub cost_range_usd_day: (f64, f64),
    /// Yearly fall of the cost of one unit of service (newer hardware,
    /// better serving). Equal to the price's fall by default: an assumption.
    pub cost_decline: f64,
    /// Share of `cost_usd_day` (and its range) that is the hardware's
    /// amortisation; an operator whose hardware is already paid for carries
    /// only the rest ([`GrowthInputs::sunk_hardware`]).
    pub hardware_share: f64,
}

impl ClassSpec {
    /// One provider's cost a day in year `y`.
    pub fn cost_at(&self, y: f64) -> f64 {
        self.cost_usd_day * (1.0 - self.cost_decline).powf(y)
    }

    /// This class with the hardware's amortisation taken out of its cost.
    pub fn sunk(&self) -> Self {
        self.charging_hardware(0.0)
    }

    /// This class charging `charge` (0 to 1) of the hardware's amortisation:
    /// what owned hardware could earn elsewhere, as a share of buying it.
    pub fn charging_hardware(&self, charge: f64) -> Self {
        let keep = 1.0 - self.hardware_share * (1.0 - charge.clamp(0.0, 1.0));
        Self {
            cost_usd_day: self.cost_usd_day * keep,
            cost_range_usd_day: (
                self.cost_range_usd_day.0 * keep,
                self.cost_range_usd_day.1 * keep,
            ),
            hardware_share: 0.0,
            ..self.clone()
        }
    }
}

/// One demand channel.
#[derive(Debug, Clone, Serialize)]
pub struct Channel {
    /// Name.
    pub name: String,
    /// Share of potential demand.
    pub share: f64,
    /// Commission the channel adds on top of the network's end price.
    pub commission: f64,
    /// Share of the channel's demand the network wins at price parity and
    /// full quality.
    pub parity_share: f64,
    /// Price elasticity against centralised prices.
    pub price_elasticity: f64,
    /// Quality (availability) elasticity.
    pub quality_elasticity: f64,
    /// Accounts the channel pays providers from (one root each).
    pub accounts: f64,
    /// Settlement batches a day per provider it pays (0: every payment
    /// settles on its own).
    pub batches_per_day: f64,
    /// The channel's own cost a month, USD (platform operations).
    pub cost_usd_month: f64,
    /// Share of the channel's demand that is related to the bootstrap funder
    /// and served by its providers: it pays providers and fees but earns
    /// no rewards and is not counted as organic demand.
    pub related_share: f64,
}

/// Every input of one run.
#[derive(Debug, Clone, Serialize)]
pub struct GrowthInputs {
    /// Days simulated.
    pub days: u32,
    /// Potential app demand at launch, USD a day at reference prices.
    pub potential_usd_day: f64,
    /// Yearly growth of potential demand.
    pub potential_growth: f64,
    /// Provider price over the reference price (the tariff).
    pub tariff: f64,
    /// Settlement fee, share of value.
    pub settlement_fee: f64,
    /// Gas of one settlement, USD.
    pub gas_usd: f64,
    /// Rewards one settlement earns, share of its settlement fee (the
    /// protocol caps provider and activity rewards together at 90%).
    pub reward_share_of_fee: f64,
    /// Agent swarm paid for by the bootstrap funder, USD a day, until `bootstrap_days`.
    pub owner_swarm_usd_day: f64,
    /// Day the bootstrap funder stops funding the swarm and the bootstrap supply.
    pub bootstrap_days: f64,
    /// Network running costs, USD a month.
    pub running_cost_usd_month: f64,
    /// Days from a positive margin to a provider serving.
    pub entry_lag_days: f64,
    /// Most a class's supply grows a day while margins are positive, share.
    pub entry_rate: f64,
    /// Most it shrinks a day while margins are negative, share.
    pub exit_rate: f64,
    /// Provider availability.
    pub availability: f64,
    /// Volume of settlement wash (reward farming) a day, USD, with no
    /// demand behind it.
    pub farming_usd_day: f64,
    /// Classes.
    pub classes: Vec<ClassSpec>,
    /// Channels.
    pub channels: Vec<Channel>,
    /// Harnesses that cut the inference a task needs, when they run.
    pub harness: Option<Harness>,
    /// Providers run hardware they already own: their cost is power,
    /// connectivity and operations, not the hardware's amortisation.
    pub sunk_hardware: bool,
    /// Share of the hardware's amortisation owned hardware still carries:
    /// what it could earn on another market. Applies with `sunk_hardware`.
    pub hardware_charge: f64,
    /// The chain's running-cost reserve rules. Running costs are paid only
    /// within the month's allowance: `revenue_share` of the trailing month's
    /// fee revenue plus `drawdown` of the reserve; the reserve fills with
    /// `fill_share` of new revenue up to `target_months` of observed cost.
    /// What the allowance does not cover, the bootstrap funder carries.
    pub reserve: ReserveRules,
    /// Buyers' routing fills the busiest providers first: a provider is
    /// either loaded to capacity or idle, a newcomer expects load only while
    /// demand goes unserved, and idle providers leave. Entry stays open to
    /// anyone. Off: demand spreads evenly over every provider.
    pub fill_busy_first: bool,
    /// Fee per root task, USD: one per request a person or app makes, however
    /// many sub-sessions it fans out to. Charged on the token classes.
    pub root_task_fee_usd: f64,
    /// Million tokens one root task spends across its sub-sessions.
    pub mtok_per_root_task: f64,
}

/// The chain's running-cost reserve rules (genesis values from
/// `treasury_reserve`: fill 50%, target 12 months, revenue share 30%,
/// drawdown 3% a month).
#[derive(Debug, Clone, Serialize)]
pub struct ReserveRules {
    /// Share of new fee revenue moved into the reserve while under target.
    pub fill_share: f64,
    /// Target, months of observed running cost.
    pub target_months: f64,
    /// Share of the trailing month's revenue running costs may use.
    pub revenue_share: f64,
    /// Share of the reserve running costs may draw in a month beyond that.
    pub drawdown: f64,
}

impl Default for ReserveRules {
    fn default() -> Self {
        Self {
            fill_share: 0.5,
            target_months: 12.0,
            revenue_share: 0.30,
            drawdown: 0.03,
        }
    }
}

/// One workload type a harness serves.
#[derive(Debug, Clone, Serialize)]
pub struct Workload {
    /// Name.
    pub name: String,
    /// Share of inference tasks.
    pub mix: f64,
    /// Share of a well-built direct path's cost the harness saves.
    pub saving: f64,
}

/// Harnesses priced on the saving: a task pays
/// `min(C_direct, C_actual + saving_share * (C_direct - C_actual))`.
#[derive(Debug, Clone, Serialize)]
pub struct Harness {
    /// Workloads.
    pub workloads: Vec<Workload>,
    /// Share of the saving the harness author keeps (at most 0.5).
    pub saving_share: f64,
}

impl Default for Harness {
    /// Savings against a well-built direct path: coding 10-20%, research
    /// 30-50% of input, extraction about 50% through batching, long agents
    /// 25-40%; the middle of each range, author keeping half the saving.
    fn default() -> Self {
        let w = |name: &str, mix, saving| Workload {
            name: name.into(),
            mix,
            saving,
        };
        Self {
            workloads: vec![
                w("coding", 0.35, 0.15),
                w("research", 0.25, 0.40),
                w("extraction", 0.20, 0.50),
                w("long_agents", 0.20, 0.325),
            ],
            saving_share: 0.5,
        }
    }
}

impl Default for GrowthInputs {
    fn default() -> Self {
        Self {
            days: 3652,
            potential_usd_day: 50_000.0,
            potential_growth: 2.0,
            tariff: 1.0,
            settlement_fee: 0.001,
            gas_usd: 0.0005,
            reward_share_of_fee: 0.9,
            owner_swarm_usd_day: 5_000.0,
            bootstrap_days: 730.0,
            running_cost_usd_month: 200_000.0,
            entry_lag_days: 30.0,
            entry_rate: 0.02,
            exit_rate: 0.01,
            availability: 0.985,
            farming_usd_day: 0.0,
            classes: default_classes(),
            channels: default_channels(),
            harness: None,
            sunk_hardware: false,
            hardware_charge: 0.0,
            reserve: ReserveRules::default(),
            fill_busy_first: false,
            root_task_fee_usd: 0.0,
            mtok_per_root_task: 0.02,
        }
    }
}

/// The classes at their default prices and costs.
///
/// - Inference: $0.12 per million tokens, DeepSeek V4 Flash on OpenRouter
///   blended 3:1 input to output ($0.098 and $0.196); Qwen3.8-Flash-Next
///   lists at $0.15 and $0.47, gpt-oss-120b at $0.039 and $0.18. Prices fall
///   40% a year (an assumption). A host is one H100 at $1.20 an hour used or
///   idle serving 12 million tokens an hour at full load with batching (a
///   mid-size model; 5 is a conservative case, a sparse model with a few
///   billion active parameters serves more).
/// - GPU rental: $2.20 a GPU-hour, between Vast.ai ($1.5-1.8), RunPod
///   ($2.0-2.7) and Akash ($2.7) for an H100; falls 20% a year; the provider
///   is one H100 at $1.20 an hour, selling at most 20 hours a day.
/// - Storage: $20 a TB-month (object storage list prices run $6-23); a
///   provider is 100 TB at $600 a month.
pub fn default_classes() -> Vec<ClassSpec> {
    const DECLINE: f64 = f64::NAN;
    let mut v = vec![
        ClassSpec {
            class: Class::Inference,
            demand_mix: 0.60,
            reference_usd: 0.12,
            reference_decline: 0.40,
            take: 0.10,
            units_per_provider_day: 12.0 * 24.0,
            cost_usd_day: 1.20 * 24.0,
            bootstrap: 4.0,
            payments_per_unit: 1.0,
            cost_range_usd_day: (1.0 * 24.0, 1.5 * 24.0),
            cost_decline: DECLINE,
            hardware_share: f64::NAN,
        },
        ClassSpec {
            class: Class::Gpu,
            demand_mix: 0.20,
            reference_usd: 2.20,
            reference_decline: 0.20,
            take: 0.10,
            units_per_provider_day: 20.0,
            cost_usd_day: 1.20 * 24.0,
            bootstrap: 8.0,
            payments_per_unit: 1.0,
            cost_range_usd_day: (1.0 * 24.0, 1.5 * 24.0),
            cost_decline: DECLINE,
            hardware_share: f64::NAN,
        },
        ClassSpec {
            class: Class::Storage,
            demand_mix: 0.05,
            reference_usd: 20.0 / 30.44,
            reference_decline: 0.10,
            take: 0.10,
            units_per_provider_day: 100.0,
            cost_usd_day: 600.0 / 30.44,
            bootstrap: 2.0,
            payments_per_unit: 1.0 / 30.0,
            cost_range_usd_day: (400.0 / 30.44, 800.0 / 30.44),
            cost_decline: DECLINE,
            hardware_share: f64::NAN,
        },
        ClassSpec {
            class: Class::Edge,
            demand_mix: 0.03,
            reference_usd: PI_SLOT_REFERENCE_USD_DAY,
            reference_decline: 0.10,
            take: 0.10,
            units_per_provider_day: PI_SLOTS,
            cost_usd_day: PI_COST_USD_DAY.0 / 2.0 + PI_COST_USD_DAY.1 / 2.0,
            bootstrap: 10.0,
            payments_per_unit: 1.0,
            cost_range_usd_day: PI_COST_USD_DAY,
            cost_decline: DECLINE,
            hardware_share: f64::NAN,
        },
        ClassSpec {
            class: Class::EdgeGpu,
            demand_mix: 0.015,
            reference_usd: slot_reference(JETSON_MTOK_DAY / JETSON_SLOTS),
            reference_decline: 0.10,
            take: 0.10,
            units_per_provider_day: JETSON_SLOTS,
            cost_usd_day: JETSON_COST_USD_DAY.0 / 2.0 + JETSON_COST_USD_DAY.1 / 2.0,
            bootstrap: 4.0,
            payments_per_unit: 1.0,
            cost_range_usd_day: JETSON_COST_USD_DAY,
            cost_decline: DECLINE,
            hardware_share: f64::NAN,
        },
        ClassSpec {
            class: Class::ConsumerGpu,
            demand_mix: 0.10,
            reference_usd: SMALL_MODEL_REFERENCE_USD_MTOK,
            reference_decline: 0.30,
            take: 0.10,
            units_per_provider_day: RTX_MTOK_DAY,
            cost_usd_day: RTX_COST_USD_DAY.0 / 2.0 + RTX_COST_USD_DAY.1 / 2.0,
            bootstrap: 2.0,
            payments_per_unit: 1.0,
            cost_range_usd_day: RTX_COST_USD_DAY,
            cost_decline: DECLINE,
            hardware_share: f64::NAN,
        },
        ClassSpec {
            class: Class::EdgeAgx,
            demand_mix: 0.005,
            reference_usd: slot_reference(AGX_MTOK_DAY / AGX_SLOTS),
            reference_decline: 0.10,
            take: 0.10,
            units_per_provider_day: AGX_SLOTS,
            cost_usd_day: AGX_COST_USD_DAY.0 / 2.0 + AGX_COST_USD_DAY.1 / 2.0,
            bootstrap: 1.0,
            payments_per_unit: 1.0,
            cost_range_usd_day: AGX_COST_USD_DAY,
            cost_decline: DECLINE,
            hardware_share: f64::NAN,
        },
    ];
    for c in &mut v {
        c.cost_decline = c.reference_decline;
        c.hardware_share = match c.class {
            // H100 at $1.20 an hour: $0.86 of it the hardware.
            Class::Inference | Class::Gpu => 0.86 / 1.20,
            // 100 TB of disks over five years, about half the cost.
            Class::Storage => 0.5,
            Class::Edge => hardware_share(PI_HARDWARE_USD_DAY, PI_COST_USD_DAY),
            Class::EdgeGpu => hardware_share(JETSON_HARDWARE_USD_DAY, JETSON_COST_USD_DAY),
            Class::EdgeAgx => hardware_share(AGX_HARDWARE_USD_DAY, AGX_COST_USD_DAY),
            Class::ConsumerGpu => hardware_share(RTX_HARDWARE_USD_DAY, RTX_COST_USD_DAY),
        };
    }
    v
}

fn hardware_share(hw: f64, range: (f64, f64)) -> f64 {
    hw / ((range.0 + range.1) / 2.0)
}

/// One agent slot-day at the centralised alternative, USD, for a device
/// whose local model serves `mtok_day_per_slot` million tokens a day per
/// slot: the VPS slot, plus the small-model API calls the local model
/// replaces at [`SMALL_MODEL_REFERENCE_USD_MTOK`].
pub fn slot_reference(mtok_day_per_slot: f64) -> f64 {
    PI_SLOT_REFERENCE_USD_DAY + mtok_day_per_slot * SMALL_MODEL_REFERENCE_USD_MTOK
}

/// Million tokens an RTX 4090 serves a day with a 7-8B model under vLLM
/// with batching: about 2,550 tokens a second (vendor figures; an RTX 5090
/// is quoted at about 3,500).
pub const RTX_MTOK_DAY: f64 = 2_550.0 * 86_400.0 / 1e6;

/// Hardware of an RTX 4090 host a day: $1,700 for the card and $1,000 for
/// the rest of the machine over three years.
pub const RTX_HARDWARE_USD_DAY: f64 = 2_700.0 / 1_095.0;

/// An RTX 4090 host's cost a day, USD, low and high: the hardware
/// ($2.47), 450-600 W at $0.10-0.15/kWh ($1.08-2.16) and connectivity and
/// operations of $5-30 a month ($0.16-0.99).
pub const RTX_COST_USD_DAY: (f64, f64) = (2.466 + 1.08 + 0.16, 2.466 + 2.16 + 0.99);

/// Hardware of a Pi 5 a day: $100 over three years.
pub const PI_HARDWARE_USD_DAY: f64 = 100.0 / 1_095.0;

/// Million tokens a Jetson Orin Nano Super serves a day with an 8B model in
/// INT4: 19.1 tokens a second single-stream (NVIDIA's JetPack 6.2 tables);
/// 43 a second on a 3B model.
pub const JETSON_MTOK_DAY: f64 = 19.1 * 86_400.0 / 1e6;

/// Agent slots a Jetson Orin Nano Super (8 GB) hosts beside a resident 8B
/// model in INT4 (about 5 GB). An assumption.
pub const JETSON_SLOTS: f64 = 3.0;

/// Hardware of a Jetson Orin Nano Super a day: the $399 developer kit over
/// three years.
pub const JETSON_HARDWARE_USD_DAY: f64 = 399.0 / 1_095.0;

/// A Jetson Orin Nano Super operator's cost a day, USD, low and high: the
/// kit ($0.364), 7-25 W at $0.15/kWh ($0.025-0.090) and connectivity of
/// $0-5 a month ($0-0.164).
pub const JETSON_COST_USD_DAY: (f64, f64) = (0.364 + 0.025, 0.364 + 0.090 + 0.164);

/// Million tokens a Jetson AGX Orin 64 GB serves a day with an 8B model:
/// about three times the Orin Nano Super. An assumption; no published
/// figure was found.
pub const AGX_MTOK_DAY: f64 = 3.0 * JETSON_MTOK_DAY;

/// Agent slots a Jetson AGX Orin 64 GB hosts beside its local model. An
/// assumption.
pub const AGX_SLOTS: f64 = 32.0;

/// Hardware of a Jetson AGX Orin 64 GB a day: the $3,499 developer kit
/// over three years.
pub const AGX_HARDWARE_USD_DAY: f64 = 3_499.0 / 1_095.0;

/// A Jetson AGX Orin operator's cost a day, USD, low and high: the kit
/// ($3.195), 15-60 W at $0.15/kWh ($0.054-0.216) and connectivity of $0-5 a
/// month ($0-0.164).
pub const AGX_COST_USD_DAY: (f64, f64) = (3.195 + 0.054, 3.195 + 0.216 + 0.164);

/// A small open model on an aggregator, USD per million tokens: gpt-oss-20b
/// lists at $0.03 in and $0.13 out on OpenRouter, $0.055 blended 3:1.
pub const SMALL_MODEL_REFERENCE_USD_MTOK: f64 = 0.055;

/// Agent slots one edge-tier reference device, a Raspberry Pi 5 (8 GB), hosts: harness processes with
/// about 1 GB each beside the system. An assumption.
pub const PI_SLOTS: f64 = 6.0;

/// One agent slot-day at the centralised alternative, USD: a small VPS
/// (2 vCPU, 4 GB) at about $4.50 a month hosts four such agents.
pub const PI_SLOT_REFERENCE_USD_DAY: f64 = 4.5 / 4.0 / 30.44;

/// A Pi operator's cost a day, USD, low and high: a Pi 5 at $80-120 over
/// three years ($0.073-0.110), 5-10 W at $0.15/kWh ($0.018-0.036), and
/// connectivity of $0-5 a month ($0-0.164).
pub const PI_COST_USD_DAY: (f64, f64) = (0.073 + 0.018, 0.110 + 0.036 + 0.164);

/// The channels at a stated split: resellers and third-party platforms hold the
/// majority; consumer platforms (buying for their own products, half of it
/// related to the bootstrap funder) hold 15%. Elasticities are assumptions with these ranges: aggregators
/// that route by price (third-party platforms) 4-8, resellers 2-4, partners'
/// deployments 1-2, direct developers 1.5-3.
pub fn default_channels() -> Vec<Channel> {
    let ch =
        |name: &str, share, commission, parity, eps, accounts, batches, cost, related| Channel {
            name: name.into(),
            share,
            commission,
            parity_share: parity,
            price_elasticity: eps,
            quality_elasticity: 4.0,
            accounts,
            batches_per_day: batches,
            cost_usd_month: cost,
            related_share: related,
        };
    vec![
        ch("resellers", 0.30, 0.15, 0.5, 3.0, 1.0, 24.0, 50_000.0, 0.0),
        ch(
            "third_party",
            0.25,
            0.15,
            0.3,
            6.0,
            5.0,
            24.0,
            30_000.0,
            0.0,
        ),
        ch("partners", 0.15, 0.0, 0.3, 1.5, 10.0, 24.0, 0.0, 0.0),
        ch("direct", 0.15, 0.0, 0.1, 2.0, 2_000.0, 0.0, 0.0, 0.0),
        ch("consumer", 0.15, 0.0, 0.4, 2.0, 20.0, 24.0, 0.0, 0.5),
    ]
}

/// One year-end of a run.
#[derive(Debug, Clone, Default, Serialize)]
pub struct YearPoint {
    /// Year.
    pub year: u32,
    /// Organic demand the network served, USD a day.
    pub organic_usd_day: f64,
    /// Demand paid for by the bootstrap funder, USD a day.
    pub owner_usd_day: f64,
    /// Related-party demand served by the bootstrap funder's providers, USD a day.
    pub related_usd_day: f64,
    /// Harness authors' income, USD a day.
    pub author_usd_day: f64,
    /// Provider income per class, USD a day.
    pub provider_usd_day: Vec<f64>,
    /// Fees over running costs.
    pub running_cost_coverage: f64,
    /// Share of potential demand the network won.
    pub won_share: f64,
    /// Providers per class (inference, GPU, storage, Pi).
    pub providers: Vec<f64>,
    /// Of them, run by the bootstrap funder.
    pub owner_providers: Vec<f64>,
    /// Mean provider margin per class, USD a month.
    pub margin_usd_month: Vec<f64>,
    /// Share of each class's providers whose revenue covers their own cost,
    /// across the class's cost range.
    pub profitable_share: Vec<f64>,
    /// Agent slots the edge tier's reference device (a Pi) must sell a day
    /// to cover the middle of its cost range at the day's price.
    pub edge_break_even_slots: f64,
    /// Agent slots a Jetson Orin Nano Super must sell a day to cover the
    /// middle of its cost range at the day's price.
    pub edge_gpu_break_even_slots: f64,
    /// The same for a Jetson AGX Orin 64 GB.
    pub edge_agx_break_even_slots: f64,
    /// Network fee revenue, USD a month.
    pub fees_usd_month: f64,
    /// Availability of the network's service.
    pub quality: f64,
}

/// One channel's result over the last year.
#[derive(Debug, Clone, Default, Serialize)]
pub struct ChannelResult {
    /// Name.
    pub name: String,
    /// Share of the channel's potential demand the network won.
    pub won_share: f64,
    /// The channel's commission revenue less its cost, USD a month.
    pub margin_usd_month: f64,
    /// Payments a day it makes to providers.
    pub payments_day: f64,
    /// Settlements a day it puts on chain, after batching.
    pub settlements_day: f64,
}

/// One run's result.
#[derive(Debug, Clone, Default, Serialize)]
pub struct GrowthResult {
    /// growth, stall or collapse.
    pub outcome: String,
    /// First day from which, for 90 days, organic fees covered running
    /// costs and the median independent provider covered its cost in every
    /// class with demand; `None` if never.
    pub self_sustaining_day: Option<f64>,
    /// What the bootstrap funder carried: swarm spend, bootstrap providers' losses and
    /// running costs fees did not cover, USD.
    pub owner_carry_usd: f64,
    /// Year-end points.
    pub years: Vec<YearPoint>,
    /// Per channel, last year.
    pub channels: Vec<ChannelResult>,
    /// Payments a day without batching, last year.
    pub payments_day: f64,
    /// Settlements a day on chain with the channels' batching, last year.
    pub settlements_day: f64,
    /// Peak settlements a second on chain (the day's settlements spread
    /// over the day, times three for the busy hour).
    pub settlements_peak_tps: f64,
    /// Reward farming's net, USD a day: rewards less fees and gas.
    pub farming_net_usd_day: f64,
    /// Whether every class's median provider and every platform with a
    /// commission covered cost in the last year.
    pub providers_profitable: bool,
    /// Whether every channel with a commission covered its cost.
    pub platforms_profitable: bool,
}

#[derive(Clone, Default)]
struct Supply {
    organic: f64,
    owner: f64,
    pipeline: std::collections::VecDeque<f64>,
    margin_trail: std::collections::VecDeque<f64>,
}

/// Units a day one provider of `class` must sell to cover the middle of
/// its cost range at year `y`'s price.
fn break_even(i: &GrowthInputs, class: Class, y: f64) -> f64 {
    i.classes
        .iter()
        .find(|c| c.class == class)
        .map_or(0.0, |c| {
            let price = c.reference_usd * (1.0 - c.reference_decline).powf(y) * i.tariff;
            c.cost_at(y) / price.max(1e-12)
        })
}

/// Runs the loop.
pub fn run(i: &GrowthInputs) -> GrowthResult {
    if i.sunk_hardware {
        let mut j = i.clone();
        j.classes = i
            .classes
            .iter()
            .map(|c| c.charging_hardware(i.hardware_charge))
            .collect();
        j.sunk_hardware = false;
        return run(&j);
    }
    let nc = i.classes.len();
    let mut supply: Vec<Supply> = i
        .classes
        .iter()
        .map(|c| Supply {
            owner: c.bootstrap,
            pipeline: std::iter::repeat_n(0.0, i.entry_lag_days.max(1.0) as usize).collect(),
            ..Supply::default()
        })
        .collect();
    let mut out = GrowthResult::default();
    let mut carry = 0.0;
    let mut covered_run = 0u32;
    let mut reserve = 0.0;
    let mut rev_trail: std::collections::VecDeque<f64> = std::collections::VecDeque::new();
    let mut paid_trail: std::collections::VecDeque<f64> = std::collections::VecDeque::new();
    let mut peak_organic: f64 = 0.0;
    let mut organic_y2 = 0.0;
    let mut last_year: Vec<(f64, f64, f64, f64)> = vec![(0.0, 0.0, 0.0, 0.0); i.channels.len()];
    let mut last_pay = 0.0;
    let mut last_settle = 0.0;
    let mut farming_net = 0.0;
    let mut ok_providers = true;
    for day in 0..i.days {
        let t = day as f64;
        let y = t / YEAR;
        let boot = t < i.bootstrap_days;
        let potential = i.potential_usd_day * i.potential_growth.powf(y);
        let mut organic_usd = 0.0;
        let mut owner_usd = 0.0;
        let mut related_usd = 0.0;
        let mut fees = 0.0;
        let mut organic_fees = 0.0;
        let mut author_usd = 0.0;
        let mut won_pot = 0.0;
        let mut quality_w = 0.0;
        let mut margins = vec![0.0; nc];
        let mut provider_day = vec![0.0; nc];
        let mut utilisation = vec![0.0; nc];
        let mut full_rev = vec![0.0; nc];
        let mut unserved = vec![false; nc];
        let mut pay_day = 0.0;
        let mut settle_day = 0.0;
        let mut channel_day: Vec<(f64, f64, f64, f64)> =
            vec![(0.0, 0.0, 0.0, 0.0); i.channels.len()];
        for (k, c) in i.classes.iter().enumerate() {
            let s = &supply[k];
            let n = s.organic + s.owner;
            let reference = c.reference_usd * (1.0 - c.reference_decline).powf(y);
            let price = reference * i.tariff;
            // A payment carries a value, not a count of units: as the unit
            // price falls, one payment covers more units.
            let ppu = c.payments_per_unit * (1.0 - c.reference_decline).powf(y);
            // A root task's fee is one per request, not per sub-session, so a
            // swarm that splits a task pays it once.
            let root_fee_unit = if matches!(c.class, Class::Inference | Class::ConsumerGpu) {
                i.root_task_fee_usd / i.mtok_per_root_task.max(1e-9)
            } else {
                0.0
            };
            let gross = price * (1.0 + c.take + i.settlement_fee) + i.gas_usd * ppu + root_fee_unit;
            let capacity = n * c.units_per_provider_day;
            // Units the bootstrap funder's swarm buys, always on the network.
            let owner_units = if boot {
                i.owner_swarm_usd_day * c.demand_mix / gross
            } else {
                0.0
            };
            // What each channel sends: buyers see the providers'
            // availability; demand above capacity goes unserved.
            let mut wanted = Vec::with_capacity(i.channels.len());
            let q = i.availability;
            {
                let mut total = owner_units;
                for ch in &i.channels {
                    let end = gross * (1.0 + ch.commission);
                    let win = |ratio: f64| {
                        let a = ch.parity_share
                            * ratio.max(1e-9).powf(-ch.price_elasticity)
                            * q.powf(ch.quality_elasticity);
                        a / (a + (1.0 - ch.parity_share)).max(1e-12)
                    };
                    let tasks = potential * ch.share * c.demand_mix / reference;
                    let (share, units) = match (&i.harness, c.class) {
                        // A harness cuts the units a task needs by its
                        // workload's saving and charges the task the cost it
                        // ran plus its share of the saving.
                        (Some(h), Class::Inference) => {
                            let mut share = 0.0;
                            let mut units = 0.0;
                            for w in &h.workloads {
                                let pay = 1.0 - w.saving * (1.0 - h.saving_share);
                                let won = win(end / reference * pay);
                                share += w.mix * won;
                                units += tasks * w.mix * won * (1.0 - w.saving);
                            }
                            (share, units)
                        }
                        _ => {
                            let share = win(end / reference);
                            (share, tasks * share)
                        }
                    };
                    wanted.push((share, units, end, tasks * share));
                    total += units;
                }
                let _ = total;
            }
            let total: f64 = owner_units + wanted.iter().map(|w| w.1).sum::<f64>();
            let served = total.min(capacity);
            utilisation[k] = served / capacity.max(1e-12);
            unserved[k] = total > capacity;
            full_rev[k] =
                c.units_per_provider_day * price * (1.0 + i.settlement_fee * i.reward_share_of_fee);
            let fill = if total > 0.0 { served / total } else { 0.0 };
            let channel_units: f64 = wanted.iter().map(|w| w.1).sum::<f64>() * fill;
            let related_units: f64 = wanted
                .iter()
                .zip(&i.channels)
                .map(|(w, ch)| w.1 * ch.related_share)
                .sum::<f64>()
                * fill;
            let organic_units = channel_units - related_units;
            if let (Some(h), Class::Inference) = (&i.harness, c.class) {
                // Authors take their share of each workload's saving, on
                // what the task would have cost direct.
                let per_unit: f64 = h
                    .workloads
                    .iter()
                    .map(|w| w.mix * w.saving * h.saving_share / (1.0 - w.saving).max(1e-9))
                    .sum::<f64>()
                    / h.workloads.iter().map(|w| w.mix).sum::<f64>().max(1e-12);
                author_usd += wanted.iter().map(|w| w.1 * w.2).sum::<f64>() * fill * per_unit;
            }
            let owner_served = owner_units * fill;
            organic_usd += organic_units * price;
            related_usd += related_units * price;
            owner_usd += owner_served * gross;
            let provider_rev = (channel_units + owner_served) * price;
            // Rewards: at most the reward share of the settlement fee, and
            // none on related-party demand.
            let rewards =
                (organic_units + owner_served) * price * i.settlement_fee * i.reward_share_of_fee;
            fees += provider_rev * (c.take + i.settlement_fee)
                + (channel_units + owner_served) * (ppu * i.gas_usd + root_fee_unit)
                - rewards;
            organic_fees += organic_units
                * (price * (c.take + i.settlement_fee * (1.0 - i.reward_share_of_fee))
                    + ppu * i.gas_usd
                    + root_fee_unit);
            provider_day[k] = provider_rev + rewards;
            // With under one provider, the margin is what one entrant would
            // earn on the demand there is.
            let per = if n >= 1.0 {
                (provider_rev + rewards) / n - c.cost_at(y)
            } else {
                total.min(c.units_per_provider_day)
                    * price
                    * (1.0 + i.settlement_fee * i.reward_share_of_fee)
                    - c.cost_at(y)
            };
            margins[k] = per;
            for (j, w) in wanted.iter().enumerate() {
                let units = w.1 * fill;
                let ch = &i.channels[j];
                let pays = units * ppu;
                let settles = if ch.batches_per_day > 0.0 {
                    (ch.accounts * n.max(1.0) * ch.batches_per_day).min(pays)
                } else {
                    pays
                };
                pay_day += pays;
                settle_day += settles;
                channel_day[j].0 += units * reference / w.0.max(1e-12) * w.0; // won potential, USD
                channel_day[j].1 += potential * ch.share * c.demand_mix; // potential, USD
                channel_day[j].2 += units * w.2 * ch.commission / (1.0 + ch.commission);
                channel_day[j].3 += pays;
                let _ = settles;
            }
            // Demand won counts tasks, whatever units a harness saved them.
            let tasks_won: f64 = wanted.iter().map(|w| w.3).sum::<f64>() * fill;
            won_pot += tasks_won * reference * organic_units / channel_units.max(1e-12);
            quality_w += q * c.demand_mix;
        }
        // Reward farming: wash volume pays the fee and gas and earns at
        // most the reward share of the fee.
        let farm_fee = i.farming_usd_day * i.settlement_fee;
        farming_net =
            farm_fee * i.reward_share_of_fee - farm_fee - i.gas_usd * i.farming_usd_day / 10.0;
        fees += farm_fee * (1.0 - i.reward_share_of_fee);
        // Supply moves on margins: entrants arrive after the lag.
        for (k, c) in i.classes.iter().enumerate() {
            let s = &mut supply[k];
            s.margin_trail.push_back(margins[k]);
            if s.margin_trail.len() > 30 {
                s.margin_trail.pop_front();
            }
            let m = s.margin_trail.iter().sum::<f64>() / s.margin_trail.len() as f64;
            let arrived = s.pipeline.pop_front().unwrap_or(0.0);
            s.organic += arrived;
            let n = s.organic + s.owner;
            let cost = c.cost_at(y);
            if i.fill_busy_first {
                // A newcomer is routed load only while demand goes unserved;
                // idle providers earn nothing and leave.
                let m_new = if unserved[k] {
                    full_rev[k] - cost
                } else {
                    -cost
                };
                let entering = if m_new > 0.0 {
                    i.entry_rate * n.max(1.0) * (m_new / cost).min(1.0)
                } else {
                    0.0
                };
                s.pipeline.push_back(entering);
                let idle = (n * (1.0 - utilisation[k])).max(0.0);
                let leave = (i.exit_rate * idle).min(s.organic);
                s.organic -= leave;
                if full_rev[k] < cost {
                    let out = i.exit_rate * ((cost - full_rev[k]) / cost).min(1.0);
                    s.organic = (s.organic * (1.0 - out)).max(0.0);
                }
                if !boot {
                    let owner_idle = (s.owner * (1.0 - utilisation[k])).max(0.0);
                    s.owner -= (i.exit_rate * owner_idle).min(s.owner);
                }
                if boot && margins[k] < 0.0 {
                    carry += -margins[k] * s.owner;
                }
                continue;
            }
            let entering = if m > 0.0 {
                i.entry_rate * n.max(1.0) * (m / cost).min(1.0)
            } else {
                0.0
            };
            s.pipeline.push_back(entering);
            if m < 0.0 {
                let out = i.exit_rate * (-m / c.cost_at(y)).min(1.0);
                s.organic = (s.organic * (1.0 - out)).max(0.0);
                // After the bootstrap the funder's providers face the same
                // rule as anyone's.
                if !boot {
                    s.owner = (s.owner * (1.0 - out)).max(0.0);
                }
            }
            if boot && margins[k] < 0.0 {
                carry += -margins[k] * s.owner;
            }
        }
        // Running costs, paid by the chain's reserve rules: the reserve
        // fills with a share of new revenue up to its target, and pays at
        // most the month's allowance; the bootstrap funder carries the rest.
        let run_day = i.running_cost_usd_month / 30.44;
        let r = &i.reserve;
        rev_trail.push_back(fees.max(0.0));
        if rev_trail.len() > 30 {
            rev_trail.pop_front();
        }
        let month_revenue: f64 = rev_trail.iter().sum();
        let month_paid: f64 = paid_trail.iter().sum();
        let monthly_cost = month_paid.max(r.revenue_share * month_revenue);
        let target = monthly_cost * r.target_months;
        reserve += (r.fill_share * fees.max(0.0)).min((target - reserve).max(0.0));
        let allowance = r.revenue_share * month_revenue + r.drawdown * reserve;
        let paid = run_day.min((allowance - month_paid).max(0.0)).min(reserve);
        reserve -= paid;
        paid_trail.push_back(paid);
        if paid_trail.len() > 30 {
            paid_trail.pop_front();
        }
        carry += run_day - paid;
        if boot {
            carry += owner_usd;
        }
        // Providers cover cost when the classes carrying at least 90% of
        // demand do, on their trailing 30-day margin.
        let mix: f64 = i.classes.iter().map(|c| c.demand_mix).sum();
        let ok_mix: f64 = i
            .classes
            .iter()
            .enumerate()
            .filter(|(k, _)| supply[*k].margin_trail.iter().sum::<f64>() >= 0.0)
            .map(|(_, c)| c.demand_mix)
            .sum();
        let providers_ok = ok_mix >= 0.9 * mix;
        // Organic fees cover running costs when the reserve rules pay them
        // in full, and organic fees alone would fund that.
        let organic_fees_cover = paid >= 0.999 * run_day && organic_fees >= 0.0;
        if providers_ok && organic_fees_cover && organic_usd > 0.0 {
            covered_run += 1;
            if covered_run == 90 && out.self_sustaining_day.is_none() {
                out.self_sustaining_day = Some(t - 89.0);
            }
        } else {
            covered_run = 0;
        }
        peak_organic = peak_organic.max(organic_usd);
        if (t - 2.0 * YEAR).abs() < 0.5 {
            organic_y2 = organic_usd;
        }
        if t + YEAR >= i.days as f64 {
            for (j, d) in channel_day.iter().enumerate() {
                last_year[j].0 += d.0;
                last_year[j].1 += d.1;
                last_year[j].2 += d.2;
                last_year[j].3 += d.3;
            }
            last_pay += pay_day;
            last_settle += settle_day;
        }
        if (day + 1) % 365 == 0 || day + 1 == i.days {
            out.years.push(YearPoint {
                year: ((day + 1) as f64 / YEAR).round() as u32,
                organic_usd_day: organic_usd,
                owner_usd_day: owner_usd,
                related_usd_day: related_usd,
                author_usd_day: author_usd,
                provider_usd_day: provider_day.clone(),
                running_cost_coverage: paid / run_day.max(1e-12),
                won_share: won_pot / potential.max(1e-12),
                providers: supply.iter().map(|s| s.organic + s.owner).collect(),
                owner_providers: supply.iter().map(|s| s.owner).collect(),
                margin_usd_month: margins.iter().map(|m| m * 30.44).collect(),
                profitable_share: i
                    .classes
                    .iter()
                    .enumerate()
                    .map(|(k, c)| {
                        let f = (1.0 - c.cost_decline).powf(y);
                        let (lo, hi) = (c.cost_range_usd_day.0 * f, c.cost_range_usd_day.1 * f);
                        let covered =
                            |rev: f64| ((rev - lo) / (hi - lo).max(1e-12)).clamp(0.0, 1.0);
                        if i.fill_busy_first {
                            // Loaded providers earn full capacity; idle ones
                            // earn nothing.
                            utilisation[k].min(1.0) * covered(full_rev[k])
                        } else {
                            covered(margins[k] + c.cost_at(y))
                        }
                    })
                    .collect(),
                edge_break_even_slots: break_even(i, Class::Edge, y),
                edge_gpu_break_even_slots: break_even(i, Class::EdgeGpu, y),
                edge_agx_break_even_slots: break_even(i, Class::EdgeAgx, y),
                fees_usd_month: fees * 30.44,
                quality: quality_w,
            });
        }
        if day + 1 == i.days {
            ok_providers = providers_ok;
        }
    }
    let days_last = (i.days as f64).min(YEAR);
    out.channels = i
        .channels
        .iter()
        .zip(&last_year)
        .map(|(ch, d)| ChannelResult {
            name: ch.name.clone(),
            won_share: d.0 / d.1.max(1e-12),
            margin_usd_month: (d.2 / days_last - ch.cost_usd_month / 30.44) * 30.44,
            payments_day: d.3 / days_last,
            settlements_day: if ch.batches_per_day > 0.0 {
                (d.3 / days_last).min(ch.accounts * 1e9)
            } else {
                d.3 / days_last
            },
        })
        .collect();
    out.payments_day = last_pay / days_last;
    out.settlements_day = last_settle / days_last;
    out.settlements_peak_tps = out.settlements_day / 86_400.0 * 3.0;
    out.farming_net_usd_day = farming_net;
    out.owner_carry_usd = carry;
    out.providers_profitable = ok_providers;
    out.platforms_profitable = out
        .channels
        .iter()
        .zip(&i.channels)
        .all(|(r, ch)| ch.commission == 0.0 || r.margin_usd_month >= 0.0);
    let end = out.years.last().map_or(0.0, |p| p.organic_usd_day);
    // The loop collapses when no provider is left in the classes that
    // carry most demand (inference and GPU rental).
    let core: f64 = i
        .classes
        .iter()
        .zip(&supply)
        .filter(|(c, _)| matches!(c.class, Class::Inference | Class::Gpu))
        .map(|(_, s)| s.organic + s.owner)
        .sum();
    // Growth: fees came to cover provider and running costs and the
    // network kept most of the share it had won; collapse: no provider left
    // in the core classes or organic demand gone; stall: otherwise.
    let won_end = out.years.last().map_or(0.0, |p| p.won_share);
    let won_peak = out.years.iter().map(|p| p.won_share).fold(0.0, f64::max);
    out.outcome = if end <= 0.05 * peak_organic.max(1e-9) || core < 1.0 {
        "collapse"
    } else if out.self_sustaining_day.is_some() && won_end >= 0.5 * won_peak {
        "growth"
    } else {
        "stall"
    }
    .into();
    let _ = organic_y2;
    out
}

/// The least potential demand at launch, USD a day, whose run grows and
/// sustains itself within a year of the bootstrap funder stopping, searched between
/// `lo` and `hi`; `None` when even `hi` does not.
pub fn threshold(base: &GrowthInputs, lo: f64, hi: f64) -> Option<f64> {
    // Turned on: it grows, and sustains itself within a year of the bootstrap
    // funder stopping.
    let grows = |d: f64| {
        let mut i = base.clone();
        i.potential_usd_day = d;
        let r = run(&i);
        r.outcome == "growth"
            && r.self_sustaining_day
                .is_some_and(|t| t <= base.bootstrap_days + 365.25)
    };
    if !grows(hi) {
        return None;
    }
    if grows(lo) {
        return Some(lo);
    }
    let (mut a, mut b) = (lo.max(1.0), hi);
    for _ in 0..40 {
        let m = (a * b).sqrt();
        if grows(m) {
            b = m;
        } else {
            a = m;
        }
        if b / a < 1.02 {
            break;
        }
    }
    Some(b)
}

/// One point of the price search.
#[derive(Debug, Clone, Serialize)]
pub struct FrontierPoint {
    /// Provider price over the reference price.
    pub tariff: f64,
    /// Network take on inference.
    pub take_inference: f64,
    /// Network take on GPU rental and storage.
    pub take_compute: f64,
    /// Commission of the platforms (resellers and third parties).
    pub commission: f64,
    /// Share of potential demand won in the last year.
    pub won_share: f64,
    /// Of the platforms' demand.
    pub platform_won_share: f64,
    /// Every class's median provider covers cost.
    pub providers_profitable: bool,
    /// Every platform covers its cost.
    pub platforms_profitable: bool,
    /// Outcome.
    pub outcome: String,
    /// Network fee revenue in the last year, USD a month.
    pub fees_usd_month: f64,
}

/// Searches tariff, per-class take and platform commission; returns every
/// point, best won share first among those where providers and platforms
/// both cover cost.
pub fn frontier(base: &GrowthInputs) -> Vec<FrontierPoint> {
    let mut pts = Vec::new();
    for tariff in [0.5, 0.6, 0.7, 0.8, 0.9, 1.0, 1.1, 1.2, 1.4] {
        for take_inf in [0.10, 0.08, 0.05] {
            for take_cmp in [0.10, 0.05] {
                for commission in [0.05, 0.10, 0.15, 0.20] {
                    let mut i = base.clone();
                    i.tariff = tariff;
                    for c in &mut i.classes {
                        c.take = if c.class == Class::Inference {
                            take_inf
                        } else {
                            take_cmp
                        };
                    }
                    for ch in &mut i.channels {
                        if ch.commission > 0.0 {
                            ch.commission = commission;
                        }
                    }
                    let r = run(&i);
                    let last = r.years.last().cloned().unwrap_or_default();
                    let plat: Vec<&ChannelResult> = r
                        .channels
                        .iter()
                        .zip(&i.channels)
                        .filter(|(_, ch)| ch.commission > 0.0)
                        .map(|(c, _)| c)
                        .collect();
                    let platform_won_share = if plat.is_empty() {
                        0.0
                    } else {
                        plat.iter().map(|c| c.won_share).sum::<f64>() / plat.len() as f64
                    };
                    pts.push(FrontierPoint {
                        tariff,
                        take_inference: take_inf,
                        take_compute: take_cmp,
                        commission,
                        won_share: last.won_share,
                        platform_won_share,
                        providers_profitable: r.providers_profitable,
                        platforms_profitable: r.platforms_profitable,
                        outcome: r.outcome,
                        fees_usd_month: last.fees_usd_month,
                    });
                }
            }
        }
    }
    pts.sort_by(|a, b| {
        let ok = |p: &FrontierPoint| p.providers_profitable && p.platforms_profitable;
        ok(b).cmp(&ok(a)).then(
            b.won_share
                .partial_cmp(&a.won_share)
                .unwrap_or(std::cmp::Ordering::Equal),
        )
    });
    pts
}

/// Inputs of the model ladder: a edge-hosted harness (a Pi) answers a share of
/// requests with a local small model and sends the rest to a large model on
/// GPUs.
#[derive(Debug, Clone, Serialize)]
pub struct LadderInputs {
    /// Tokens one request carries, millions. 0.002: 2,000 tokens.
    pub mtok_per_request: f64,
    /// Large-model reference price, USD per million tokens. $0.70:
    /// GPT-4.1 mini blended 3:1 ($0.40 in, $1.60 out).
    pub big_reference_usd_mtok: f64,
    /// Small-model reference price on a centralised API, USD per million
    /// tokens: 1-3B models list at about $0.01-0.05. An assumption.
    pub small_reference_usd_mtok: f64,
    /// Requests one Pi 5 answers a day with a 1B model locally: about 15
    /// tokens a second, 2,000 tokens a request. An assumption.
    pub pi_requests_day: f64,
    /// Share of the consumer price the harness author takes.
    pub author_share: f64,
    /// Share of app demand the network wins at parity with the cheapest
    /// centralised option.
    pub parity_share: f64,
    /// Price elasticity of app demand against that option.
    pub price_elasticity: f64,
    /// Requests a day the apps would make at the large-model reference price.
    pub requests_day: f64,
}

impl Default for LadderInputs {
    fn default() -> Self {
        Self {
            mtok_per_request: 0.002,
            big_reference_usd_mtok: 0.70,
            small_reference_usd_mtok: 0.03,
            pi_requests_day: 600.0,
            author_share: 0.10,
            parity_share: 0.3,
            price_elasticity: 4.0,
            requests_day: 1_000_000.0,
        }
    }
}

/// One share of local answers.
#[derive(Debug, Clone, Serialize)]
pub struct LadderPoint {
    /// Share of requests answered on the Pi.
    pub local_share: f64,
    /// Consumer cost of one request through the network ladder, USD.
    pub consumer_cost_usd: f64,
    /// A direct large-model call on the network, USD.
    pub network_direct_usd: f64,
    /// A direct large-model call on a centralised API, USD.
    pub central_direct_usd: f64,
    /// The same ladder on centralised APIs, USD.
    pub central_ladder_usd: f64,
    /// Share of app demand the network wins against the cheaper of the
    /// centralised options.
    pub won_share: f64,
    /// Requests won a day.
    pub requests_won_day: f64,
    /// Pi hosts' income, USD a day, and per Pi.
    pub pi_usd_day: f64,
    /// Per Pi, USD a month.
    pub pi_usd_month_each: f64,
    /// GPU runners' income, USD a day.
    pub gpu_usd_day: f64,
    /// Per GPU, USD a month, at the class's utilisation.
    pub gpu_usd_month_each: f64,
    /// Harness authors' income, USD a day.
    pub author_usd_day: f64,
    /// GPU runners' income against the ladder with no local answers.
    pub gpu_vs_no_ladder: f64,
}

/// The ladder at local shares `shares`, priced at the network's tariff and
/// takes of `base`.
pub fn ladder(base: &GrowthInputs, l: &LadderInputs, shares: &[f64]) -> Vec<LadderPoint> {
    let take = |c: Class| {
        base.classes
            .iter()
            .find(|x| x.class == c)
            .map_or(0.10, |x| x.take)
    };
    let gross = |t: Class| 1.0 + take(t) + base.settlement_fee;
    let edge = base.classes.iter().find(|c| c.class == Class::Edge);
    let pi_day_price =
        edge.map_or(0.0, |c| c.reference_usd * c.units_per_provider_day) * base.tariff;
    let big_provider = l.big_reference_usd_mtok * base.tariff * l.mtok_per_request;
    let big_net = big_provider * gross(Class::Inference) + base.gas_usd;
    // The Pi's local answer costs its day's price over the requests it
    // answers; every request passes its harness.
    let pi_provider = pi_day_price / l.pi_requests_day;
    let central_direct = l.big_reference_usd_mtok * l.mtok_per_request;
    let mtok_gpu_month = base
        .classes
        .iter()
        .find(|c| c.class == Class::Inference)
        .map_or(120.0, |c| c.units_per_provider_day)
        * 30.44;
    let mut out = Vec::new();
    let mut gpu0 = None;
    for &s in shares {
        let pi_part = s * (pi_provider * gross(Class::Edge) + base.gas_usd);
        let cost = (pi_part + (1.0 - s) * big_net) / (1.0 - l.author_share).max(1e-9);
        let central_ladder =
            s * l.small_reference_usd_mtok * l.mtok_per_request + (1.0 - s) * central_direct;
        let alt = central_direct.min(central_ladder);
        let a = l.parity_share * (cost / alt).powf(-l.price_elasticity);
        let won = a / (a + 1.0 - l.parity_share);
        let requests = l.requests_day * won;
        let pi_usd = requests * s * pi_provider;
        let gpu_usd = requests * (1.0 - s) * big_provider;
        let author = requests * cost * l.author_share;
        let pis = (requests * s / l.pi_requests_day).max(1.0);
        let gpus = (requests * (1.0 - s) * l.mtok_per_request * 30.44 / mtok_gpu_month).max(1.0);
        let g0 = *gpu0.get_or_insert(gpu_usd);
        out.push(LadderPoint {
            local_share: s,
            consumer_cost_usd: cost,
            network_direct_usd: big_net,
            central_direct_usd: central_direct,
            central_ladder_usd: central_ladder,
            won_share: won,
            requests_won_day: requests,
            pi_usd_day: pi_usd,
            pi_usd_month_each: pi_usd / pis * 30.44,
            gpu_usd_day: gpu_usd,
            gpu_usd_month_each: gpu_usd / gpus * 30.44,
            author_usd_day: author,
            gpu_vs_no_ladder: if g0 > 0.0 { gpu_usd / g0 } else { 0.0 },
        });
    }
    out
}

/// One row of the tier comparison.
#[derive(Debug, Clone, Serialize)]
pub struct TierRow {
    /// A: no edge tier or harnesses; B: edge tier and harnesses.
    pub tiers: String,
    /// i: settlement fee only; ii-10: a 10% service split on chain;
    /// ii-class: inference 8%, compute, storage and edge 5%.
    pub protocol: String,
    /// Outcome.
    pub outcome: String,
    /// Share of potential demand won, year 5 and year 10.
    pub won_share: (f64, f64),
    /// Least potential demand at launch that grows, USD a day.
    pub break_even_potential_usd_day: Option<f64>,
    /// Fees over running costs, year 5 and year 10.
    pub running_cost_coverage: (f64, f64),
    /// Network fees in year 10, USD a month: what validators' base reward
    /// and the treasury draw on.
    pub fees_usd_month: f64,
    /// Income in year 10, USD a day: edge (CPU and GPU profiles), GPU
    /// (rental and inference hosting), harness authors.
    pub edge_usd_day: f64,
    /// GPU income.
    pub gpu_usd_day: f64,
    /// Author income.
    pub author_usd_day: f64,
    /// Share of edge operators profitable in year 10 (Pi, Jetson Orin Nano
    /// Super, Jetson AGX Orin).
    pub edge_profitable: (f64, f64, f64),
    /// Day fees first covered provider and running costs for 90 days.
    pub self_sustaining_day: Option<f64>,
}

/// Compares the economy without and with the edge tier and harnesses,
/// under the settlement fee alone and under an on-chain service split.
pub fn compare_tiers(base: &GrowthInputs) -> Vec<TierRow> {
    let mut rows = Vec::new();
    for tiers in ["A", "B"] {
        for protocol in ["i", "ii-10", "ii-class"] {
            let mut i = base.clone();
            if tiers == "A" {
                i.classes
                    .retain(|c| !matches!(c.class, Class::Edge | Class::EdgeGpu | Class::EdgeAgx));
                i.harness = None;
            } else {
                i.harness = Some(Harness::default());
            }
            for c in &mut i.classes {
                c.take = match (protocol, c.class) {
                    ("i", _) => 0.0,
                    ("ii-10", _) => 0.10,
                    (_, Class::Inference) => 0.08,
                    _ => 0.05,
                };
            }
            let r = run(&i);
            let at = |y: usize| r.years.get(y).cloned().unwrap_or_default();
            let (y5, y10) = (at(4), r.years.last().cloned().unwrap_or_default());
            let idx = |c: Class| i.classes.iter().position(|x| x.class == c);
            let get = |p: &YearPoint, c: Class| {
                idx(c)
                    .and_then(|k| p.provider_usd_day.get(k).copied())
                    .unwrap_or(0.0)
            };
            let share = |p: &YearPoint, c: Class| {
                idx(c)
                    .and_then(|k| p.profitable_share.get(k).copied())
                    .unwrap_or(0.0)
            };
            rows.push(TierRow {
                tiers: tiers.into(),
                protocol: protocol.into(),
                outcome: r.outcome.clone(),
                won_share: (y5.won_share, y10.won_share),
                break_even_potential_usd_day: threshold(&i, 100.0, 1e8),
                running_cost_coverage: (y5.running_cost_coverage, y10.running_cost_coverage),
                fees_usd_month: y10.fees_usd_month,
                edge_usd_day: get(&y10, Class::Edge)
                    + get(&y10, Class::EdgeGpu)
                    + get(&y10, Class::EdgeAgx),
                gpu_usd_day: get(&y10, Class::Gpu) + get(&y10, Class::Inference),
                author_usd_day: y10.author_usd_day,
                edge_profitable: (
                    share(&y10, Class::Edge),
                    share(&y10, Class::EdgeGpu),
                    share(&y10, Class::EdgeAgx),
                ),
                self_sustaining_day: r.self_sustaining_day,
            });
        }
    }
    rows
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn demand_far_above_the_reference_price_is_not_won() {
        // Capacity far above demand, so the price alone decides.
        let mut i = GrowthInputs {
            days: 30,
            ..GrowthInputs::default()
        };
        for c in &mut i.classes {
            c.bootstrap = 1e6;
        }
        i.tariff = 1.0;
        let fair = run(&i);
        i.tariff = 3.0;
        let dear = run(&i);
        let w = |r: &GrowthResult| r.years.last().map_or(0.0, |p| p.won_share);
        assert!(w(&dear) < w(&fair) * 0.2, "{} vs {}", w(&dear), w(&fair));
    }

    #[test]
    fn no_demand_collapses_once_the_bootstrap_funder_stops() {
        let i = GrowthInputs {
            potential_usd_day: 0.0,
            owner_swarm_usd_day: 1_000.0,
            bootstrap_days: 365.0,
            days: 3 * 365,
            ..GrowthInputs::default()
        };
        let r = run(&i);
        assert_eq!(r.outcome, "collapse");
        assert!(r.self_sustaining_day.is_none());
        assert!(r.owner_carry_usd > 365.0 * 1_000.0);
    }

    #[test]
    fn local_answers_lower_the_consumer_cost() {
        let pts = ladder(
            &GrowthInputs::default(),
            &LadderInputs::default(),
            &[0.0, 0.3, 0.6, 0.8],
        );
        assert!(
            pts.windows(2)
                .all(|w| w[1].consumer_cost_usd < w[0].consumer_cost_usd)
        );
        assert!(pts[0].pi_usd_day == 0.0);
    }

    #[test]
    fn sunk_hardware_carries_only_the_running_cost() {
        let c = default_classes();
        let gpu = c.iter().find(|c| c.class == Class::Gpu).expect("gpu");
        assert!((gpu.sunk().cost_usd_day - 0.34 * 24.0).abs() < 1e-9);
        let nano = c.iter().find(|c| c.class == Class::EdgeGpu).expect("nano");
        assert!(nano.sunk().cost_usd_day < nano.cost_usd_day * 0.3);
    }

    #[test]
    fn a_jetson_slot_is_worth_more_than_a_pi_slot() {
        let c = default_classes();
        let price = |k: Class| {
            c.iter()
                .find(|c| c.class == k)
                .expect("class")
                .reference_usd
        };
        assert!(price(Class::EdgeGpu) > price(Class::Edge));
        assert!((price(Class::Edge) - PI_SLOT_REFERENCE_USD_DAY).abs() < 1e-12);
    }

    #[test]
    fn running_costs_are_paid_only_within_the_reserve_allowance() {
        let i = GrowthInputs {
            days: 2 * 365,
            ..GrowthInputs::default()
        };
        let r = run(&i);
        for y in &r.years {
            assert!(y.running_cost_coverage <= 1.0 + 1e-9);
        }
        // Early on, fees are thin and the allowance pays little.
        assert!(r.years[0].running_cost_coverage < 1.0);
    }

    #[test]
    fn a_root_task_fee_is_paid_once_however_a_task_fans_out() {
        // The fee is per root task, so it adds the same to a unit of
        // inference whatever the fan-out; it rises with requests, not value.
        let base = GrowthInputs {
            days: 30,
            ..GrowthInputs::default()
        };
        let with = GrowthInputs {
            root_task_fee_usd: 0.0005,
            ..base.clone()
        };
        let (a, b) = (run(&base), run(&with));
        assert!(b.years[0].fees_usd_month > a.years[0].fees_usd_month);
    }

    #[test]
    fn filling_busy_providers_first_keeps_entry_open_and_providers_loaded() {
        let i = GrowthInputs {
            days: 3 * 365,
            fill_busy_first: true,
            sunk_hardware: true,
            ..GrowthInputs::default()
        };
        let r = run(&i);
        let last = r.years.last().expect("a year");
        assert!(last.providers.iter().sum::<f64>() > 0.0);
    }

    #[test]
    fn charging_hardware_sits_between_owned_and_bought() {
        let c = default_classes();
        let gpu = c.iter().find(|c| c.class == Class::Gpu).expect("gpu");
        let half = gpu.charging_hardware(0.5).cost_usd_day;
        assert!(gpu.sunk().cost_usd_day < half && half < gpu.cost_usd_day);
        assert!((gpu.charging_hardware(1.0).cost_usd_day - gpu.cost_usd_day).abs() < 1e-9);
    }

    #[test]
    fn reward_farming_never_pays() {
        let i = GrowthInputs {
            farming_usd_day: 1e6,
            days: 30,
            ..GrowthInputs::default()
        };
        assert!(run(&i).farming_net_usd_day < 0.0);
    }

    #[test]
    fn batching_carries_fewer_settlements_than_payments() {
        let r = run(&GrowthInputs {
            days: 800,
            ..GrowthInputs::default()
        });
        assert!(r.settlements_day <= r.payments_day);
    }
}
