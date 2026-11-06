//! What each class of provider earns and what users pay, over the last
//! year of a run.
//!
//! The simulated providers are fleets that take both compute streams (GPU
//! rental) and agent sessions. The agent sessions' spend is split between
//! the model host that serves the tokens, the agent operator and the app or
//! tool, by the shares in [`ClassInputs`]. Revenue is the service payments
//! net of the treasury leg and the settlement fee, plus the reward coupons
//! the run issued, valued at the rate in force when they were claimed.
//!
//! Costs and the split are inputs, not measurements; each default says where
//! it comes from.

use serde::Serialize;

/// Hours in an average month.
pub const MONTH_HOURS: f64 = 730.0;

/// Cost and split inputs of the class accounts.
#[derive(Debug, Clone, Serialize)]
pub struct ClassInputs {
    /// Treasury leg of a service payment, share. 10%: the public validating
    /// node's treasury share (`EconomicPolicy::validating.treasury_bps`, the
    /// rate `HTTP_402_NETWORK_SHARE_BPS` in tenzro-types fees.rs repeats).
    pub treasury_leg: f64,
    /// Cost of one GPU for one hour of the month, used or idle, USD.
    /// $1.20 for an H100: $30,000 over four years is $0.86, 0.7 kW at PUE
    /// 1.15 and $0.11/kWh is $0.09, colocation and operations $0.25. Owner
    /// cost analyses put an H100 at $1.7 (hardware alone) to $5-6 an hour
    /// (with financing at 20%).
    pub gpu_cost_usd_hour: f64,
    /// Share of agent session spend that pays the model host.
    pub inference_share: f64,
    /// Share that pays the agent operator.
    pub agent_share: f64,
    /// Share that pays the app or tool.
    pub app_share: f64,
    /// Tariff of inference, USD per million tokens. $0.40: GPT-4.1 mini
    /// input on the OpenAI API; Llama 3.3 70B lists at $0.10 in and $0.32 out
    /// on OpenRouter.
    pub inference_usd_per_mtok: f64,
    /// Tokens one GPU serves in an hour, millions. 5: a 70B model on an H100
    /// at about 1,400 tokens a second with batching.
    pub mtok_per_gpu_hour: f64,
    /// Share of a model host's GPU hours that carry load.
    pub inference_utilisation: f64,
    /// Agent operators the agent share is spread over.
    pub agent_operators: f64,
    /// An agent operator's cost, USD a month: hosting and part of one
    /// engineer's time. An assumption.
    pub agent_operator_cost_usd_month: f64,
    /// App and tool owners the app share is spread over.
    pub app_owners: f64,
    /// An app owner's cost, USD a month. An assumption.
    pub app_owner_cost_usd_month: f64,
}

impl Default for ClassInputs {
    fn default() -> Self {
        Self {
            treasury_leg: 0.10,
            gpu_cost_usd_hour: 1.20,
            inference_share: 0.70,
            agent_share: 0.20,
            app_share: 0.10,
            inference_usd_per_mtok: 0.40,
            mtok_per_gpu_hour: 5.0,
            inference_utilisation: 0.6,
            agent_operators: 50.0,
            agent_operator_cost_usd_month: 3_000.0,
            app_owners: 200.0,
            app_owner_cost_usd_month: 1_000.0,
        }
    }
}

/// One simulated provider fleet's books over the window.
#[derive(Debug, Clone, Default)]
pub struct FleetBooks {
    /// GPUs its stream hours needed.
    pub gpus: f64,
    /// Compute stream payments, USD.
    pub stream_usd: f64,
    /// Agent session payments, USD.
    pub session_usd: f64,
    /// Reward coupons claimed, USD at the rate in force.
    pub coupons_usd: f64,
}

/// One class's month.
#[derive(Debug, Clone, Default, Serialize)]
pub struct ClassMonth {
    /// Providers in the class.
    pub providers: f64,
    /// Revenue per provider a month, USD (median across providers).
    pub revenue_usd_month: f64,
    /// Of it, reward coupons, USD (median).
    pub rewards_usd_month: f64,
    /// Cost per provider a month, USD (median).
    pub cost_usd_month: f64,
    /// Revenue less cost, USD (median).
    pub margin_usd_month: f64,
    /// Share of the class's providers whose revenue covers cost.
    pub profitable_share: f64,
    /// What the unit is: a GPU, a model host, an operator, an app.
    pub unit: String,
}

/// What a user or agent pays per unit, and how often a payment fails.
#[derive(Debug, Clone, Default, Serialize)]
pub struct UserSide {
    /// GPU-hour at the tariff, the treasury leg, the settlement fee and the
    /// gas of the hour's claim, USD.
    pub gpu_hour_all_in_usd: f64,
    /// GPU-hour tariff, USD.
    pub gpu_hour_tariff_usd: f64,
    /// Million tokens at the tariff, the leg, the fee and the gas of a
    /// session (create and release), USD.
    pub mtok_all_in_usd: f64,
    /// Million tokens tariff, USD.
    pub mtok_tariff_usd: f64,
    /// Gas one transaction paid, USD (last day).
    pub gas_per_tx_usd: f64,
    /// Payment escrows the ledger refused over those sent.
    pub refused_share: f64,
    /// Agent sessions not settled over those sent.
    pub session_failed_share: f64,
    /// Payments the demand trace records as not delivered, when one drives
    /// the run.
    pub trace_undelivered_share: Option<f64>,
}

/// The classes and the user side.
#[derive(Debug, Clone, Default, Serialize)]
pub struct LaunchEconomics {
    /// Days the window covers (the last year, or the whole run if shorter).
    pub window_days: f64,
    /// GPU compute rental.
    pub gpu_rental: ClassMonth,
    /// Model or inference hosting.
    pub inference_hosting: ClassMonth,
    /// Agent operators.
    pub agent_operators: ClassMonth,
    /// App and tool owners.
    pub app_owners: ClassMonth,
    /// The user side.
    pub users: UserSide,
    /// Inputs used.
    pub inputs: ClassInputs,
}

fn median(mut v: Vec<f64>) -> f64 {
    v.retain(|x| x.is_finite());
    if v.is_empty() {
        return 0.0;
    }
    v.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    v[v.len() / 2]
}

fn class(units: &[(f64, f64, f64)], unit: &str, providers: f64) -> ClassMonth {
    // (revenue, rewards, cost) per unit and month.
    if units.is_empty() {
        return ClassMonth {
            unit: unit.into(),
            ..ClassMonth::default()
        };
    }
    let ok = units.iter().filter(|u| u.0 >= u.2).count() as f64;
    ClassMonth {
        providers,
        revenue_usd_month: median(units.iter().map(|u| u.0).collect()),
        rewards_usd_month: median(units.iter().map(|u| u.1).collect()),
        cost_usd_month: median(units.iter().map(|u| u.2).collect()),
        margin_usd_month: median(units.iter().map(|u| u.0 - u.2).collect()),
        profitable_share: ok / units.len() as f64,
        unit: unit.into(),
    }
}

/// The class accounts of `fleets` over `window_days`, with `settlement_fee`
/// the fee share of a settlement.
pub fn accounts(
    inputs: &ClassInputs,
    fleets: &[FleetBooks],
    window_days: f64,
    settlement_fee: f64,
) -> (ClassMonth, ClassMonth, ClassMonth, ClassMonth) {
    let months = (window_days / 30.44).max(1.0 / 30.44);
    let net = (1.0 - inputs.treasury_leg - settlement_fee).max(0.0);
    let gpu_month = inputs.gpu_cost_usd_hour * MONTH_HOURS;
    let mut gpu = Vec::new();
    let mut gpu_n = 0.0;
    let mut hosts = Vec::new();
    let mut sessions_total = 0.0;
    for f in fleets {
        let paid = f.stream_usd + f.session_usd;
        let share = |x: f64| if paid > 0.0 { x / paid } else { 0.0 };
        // Coupons follow the value each kind of payment carried.
        let stream_rewards = f.coupons_usd * share(f.stream_usd);
        let session_rewards = f.coupons_usd * share(f.session_usd);
        if f.stream_usd > 0.0 {
            let per_gpu = |x: f64| x / f.gpus.max(1.0) / months;
            let rewards = per_gpu(stream_rewards);
            gpu.push((per_gpu(f.stream_usd * net) + rewards, rewards, gpu_month));
            gpu_n += f.gpus;
        }
        if f.session_usd > 0.0 {
            let rev = f.session_usd * inputs.inference_share * net / months;
            let rewards = session_rewards / months;
            let mtok =
                f.session_usd * inputs.inference_share / inputs.inference_usd_per_mtok / months;
            let gpus = (mtok
                / (inputs.mtok_per_gpu_hour * MONTH_HOURS * inputs.inference_utilisation)
                    .max(1e-9))
            .ceil()
            .max(1.0);
            hosts.push((rev + rewards, rewards, gpus * gpu_month));
        }
        sessions_total += f.session_usd;
    }
    let spread = |share: f64, n: f64, cost: f64| -> Vec<(f64, f64, f64)> {
        if sessions_total <= 0.0 || n <= 0.0 {
            return Vec::new();
        }
        vec![(sessions_total * share * net / n / months, 0.0, cost)]
    };
    let n_hosts = hosts.len() as f64;
    (
        class(&gpu, "GPU", gpu_n),
        class(&hosts, "model host (fleet account)", n_hosts),
        class(
            &spread(
                inputs.agent_share,
                inputs.agent_operators,
                inputs.agent_operator_cost_usd_month,
            ),
            "agent operator",
            inputs.agent_operators,
        ),
        class(
            &spread(
                inputs.app_share,
                inputs.app_owners,
                inputs.app_owner_cost_usd_month,
            ),
            "app or tool owner",
            inputs.app_owners,
        ),
    )
}

/// The user side at the tariffs, with `gas_usd` one transaction's gas and
/// `session_usd` the mean agent session.
pub fn user_side(
    inputs: &ClassInputs,
    gpu_hour_tariff_usd: f64,
    gas_usd: f64,
    settlement_fee: f64,
    session_usd: f64,
) -> UserSide {
    let gross = 1.0 + inputs.treasury_leg + settlement_fee;
    // A stream pays its provider once an hour: one claim's gas an hour.
    let gpu = gpu_hour_tariff_usd * gross + gas_usd;
    // A session is an escrow create and a release; it carries this many
    // million tokens at the tariff.
    let mtok_per_session = session_usd * inputs.inference_share / inputs.inference_usd_per_mtok;
    let gas_per_mtok = if mtok_per_session > 0.0 {
        2.0 * gas_usd / mtok_per_session
    } else {
        f64::INFINITY
    };
    UserSide {
        gpu_hour_all_in_usd: gpu,
        gpu_hour_tariff_usd,
        mtok_all_in_usd: inputs.inference_usd_per_mtok * gross + gas_per_mtok,
        mtok_tariff_usd: inputs.inference_usd_per_mtok,
        gas_per_tx_usd: gas_usd,
        ..UserSide::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fleet_nets_the_leg_and_fee_and_pays_for_every_gpu_hour() {
        let i = ClassInputs::default();
        let f = FleetBooks {
            gpus: 10.0,
            stream_usd: 10.0 * 30.44 * 24.0 * 2.0,
            session_usd: 0.0,
            coupons_usd: 0.0,
        };
        let (gpu, hosts, _, _) = accounts(&i, &[f], 30.44, 0.001);
        // 24 hours a day at $2: $1,461 a GPU-month gross, 89.9% of it net.
        assert!((gpu.revenue_usd_month - 2.0 * 24.0 * 30.44 * 0.899).abs() < 1e-6);
        assert!((gpu.cost_usd_month - 1.2 * 730.0).abs() < 1e-9);
        assert_eq!(gpu.profitable_share, 1.0);
        assert_eq!(hosts.providers, 0.0);
    }

    #[test]
    fn the_all_in_price_adds_leg_fee_and_gas() {
        let i = ClassInputs::default();
        let u = user_side(&i, 2.0, 0.001, 0.001, 0.4 / 0.7);
        assert!((u.gpu_hour_all_in_usd - (2.0 * 1.101 + 0.001)).abs() < 1e-12);
        // A session carries one million tokens: two transactions of gas.
        assert!((u.mtok_all_in_usd - (0.4 * 1.101 + 0.002)).abs() < 1e-12);
    }
}
