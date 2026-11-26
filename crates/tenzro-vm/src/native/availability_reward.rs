//! Availability reward: a bounded, decaying, treasury-funded payment for a
//! verified-available SLA verdict (see `tenzro_model::sla` for the challenge
//! protocol and [`super::execute_sla_attest`] for where a verdict freezes).
//!
//! Paid once per (subject, epoch), directly out of the treasury within the
//! treasury's outflow period cap, gated
//! entirely by governed parameters -- the same pattern
//! `payment_settlement::recon::begin_block` already uses for the
//! reconciliation duty's own treasury-funded reward. Insufficient treasury
//! balance forfeits that epoch's reward rather than refusing the
//! attestation that records the verdict.
//!
//! Vests the same way every other earned T1/T2 reward does: split via the
//! governed `rewards::CLAIM_LIQUID_PARAM`/`CLAIM_VESTING_PARAM` pair into a
//! liquid share (paid straight to the subject's balance) and a vesting
//! share (opened as a [`tenzro_token::vesting::VestingSchedule`] in the same
//! escrow a reward-coupon claim or a vesting treasury grant uses) -- reusing
//! `native::rewards::open_vesting` rather than inventing a second vesting
//! path for this one reward.
//!
//! Readiness tiers scale the reward by a subject's own declaration
//! ([`declare_readiness_tier`], a `DeclareReadinessTier` transaction a
//! subject's owner signs): Warm (the default for anything that has never
//! declared, so this is purely additive -- no existing payout changes
//! until a subject opts into a lower tier), Cool or Cold, each a governed
//! bps multiplier (genesis 100% for all three, so the tiers are a no-op
//! until governance actually differentiates them). This does not yet
//! change CHALLENGE RATE by tier (only the reward), which queue item 75
//! (the on-chain energy budget) covers separately against the same
//! declaration this module writes.
//!
//! Indexed cap (dormant): from [`AVAILABILITY_INDEX_CAP_KEY`]'s epoch a unit
//! paid per proven GPU is capped at [`AVAILABILITY_INDEX_CAP_BPS_PARAM`] of
//! the datacenter-GPU compute price index in force (the validators' rate
//! symbol from `economy::compute_index_symbol`), converted to wei at the TNZO
//! rate in force, when that is below the absolute cap. A unit with no proven
//! GPU keeps the absolute cap: the chain knows no other hardware class for a
//! bond, and the provider's own announcement would let it pick the dearest
//! index. With no index in force the absolute cap holds.
//!
//! Dormant behind [`UNIT_BUDGET_KEY`]: the reward per verified unit as an
//! equal share of an hourly budget pinned to verified paid demand
//! ([`unit_budget_reward`]) in place of the schedule's demand offset.
//!
//! With hardware binding on, the reward is paid per GPU: once for each GPU
//! the host proved with its NVIDIA device certificate in the current reward
//! epoch or the one before ([`super::hardware_level::current_gpus`]), once
//! for a host that proved none.
//!
//! Decay is a deterministic integer half-life, never floating point: this
//! crate has no floating-point arithmetic anywhere in native VM execution
//! today (checked before writing this module), because `powf`'s rounding is
//! not guaranteed bit-identical across validators' platforms and libm
//! versions -- a real consensus-divergence risk, not a style choice.
//! [`halving_decay`] computes the exact value at every whole half-life (a
//! right shift -- `cap >> n` after `n` half-lives) and linearly interpolates
//! between two consecutive halving points for everything in between. This
//! is exact at every half-life boundary and a close, monotonically
//! decreasing approximation of the true exponential in between (the true
//! curve is itself convex between those points, so the linear interpolation
//! sits slightly above it) -- never clamped to zero at some fixed multiple
//! of the half-life the way a linear ramp would be; it keeps halving for as
//! long as the governed cap has bits left (at most 128 halvings of a
//! u128).

use super::funding::{move_balance, refuse};
use super::*;

/// Governed: TNZO per hour the availability reward pays for one verified-
/// available SLA verdict, before decay. Zero disables the reward entirely.
pub const AVAILABILITY_REWARD_PER_UNIT_HOUR_PARAM: &str = "reward.availability_per_unit_hour_wei";
/// Genesis: disabled.
pub const DEFAULT_AVAILABILITY_REWARD_PER_UNIT_HOUR: u64 = 0;
/// Highest per-unit-hour cap governance may set: 1 TNZO/hour.
pub const MAX_AVAILABILITY_REWARD_PER_UNIT_HOUR: u64 = 1_000_000_000_000_000_000;

/// Governed: the epoch ([`super::MARKET_EPOCH_MS`]-sized, i.e. one hour)
/// the decay clock starts counting from. Zero means decay has not been
/// scheduled -- the reward pays its full per-unit-hour cap, undecayed,
/// however long the cap stays nonzero.
pub const AVAILABILITY_REWARD_DECAY_START_EPOCH_PARAM: &str =
    "reward.availability_decay_start_epoch";
/// Genesis: not scheduled.
pub const DEFAULT_AVAILABILITY_REWARD_DECAY_START_EPOCH: u64 = 0;
/// Latest start epoch governance may set. `u32::MAX` hours is well past any
/// horizon this network will reach without a parameter table change.
pub const MAX_AVAILABILITY_REWARD_DECAY_START_EPOCH: u64 = u32::MAX as u64;

/// Governed: half-life of the decay, in whole days. Zero disables decay --
/// the reward stays at its full per-unit-hour cap for as long as the cap
/// is nonzero, however the start epoch is set.
pub const AVAILABILITY_REWARD_DECAY_HALF_LIFE_DAYS_PARAM: &str =
    "reward.availability_decay_half_life_days";
/// Genesis: disabled.
pub const DEFAULT_AVAILABILITY_REWARD_DECAY_HALF_LIFE_DAYS: u64 = 0;
/// Highest half-life governance may set: 10 years.
pub const MAX_AVAILABILITY_REWARD_DECAY_HALF_LIFE_DAYS: u64 = 3_650;

/// Governed: whether a verified-available verdict must also show the
/// subject's `provider_did` is a machine identity with a TPM endorsement
/// chaining to a recognised root ([`super::funding::machine_endorsed`])
/// before it pays. While it is off the availability reward pays nothing at
/// all, whatever its cap, decay, demand offset or readiness tier: nothing
/// then ties a verdict to a real machine, and an uptime reward open to
/// identities that cost nothing to make is paid to made-up supply. Genesis
/// off: compute-bond providers are not required to register a machine
/// identity today (their bond is keyed by a bare `provider_did` string --
/// see `validate_compute_bond_provider_did`). Governance turns it on once
/// host registration is in place, and the reward starts paying then.
pub const AVAILABILITY_REWARD_REQUIRE_HARDWARE_PARAM: &str =
    "reward.availability_require_hardware_binding";
/// Genesis: disabled (0). Any nonzero value requires the TPM endorsement.
pub const DEFAULT_AVAILABILITY_REWARD_REQUIRE_HARDWARE: u64 = 0;
/// A toggle, not a magnitude: 0 or 1.
pub const MAX_AVAILABILITY_REWARD_REQUIRE_HARDWARE: u64 = 1;

/// Gate of the paid-activity requirement: the first epoch from which the
/// availability reward pays only a subject whose owner has recent paid work.
/// Its tunables are the three parameters below.
pub const AVAILABILITY_PAID_ACTIVITY_GATE: &str =
    "feature.availability_paid_activity.activation_epoch";

/// Governed: how many reward epochs back, counting the current one, the
/// subject's owner must have earned provider work for the availability
/// reward to pay it. Provider work is recorded only for settled payments
/// from another registered party, so an operator nobody pays is not paid for
/// being reachable. Zero asks for no paid activity.
pub const AVAILABILITY_REWARD_PAID_ACTIVITY_EPOCHS_PARAM: &str =
    "feature.availability_paid_activity.window_epochs";
/// Genesis: paid work within the last 30 reward epochs.
pub const DEFAULT_AVAILABILITY_REWARD_PAID_ACTIVITY_EPOCHS: u64 = 30;
/// Longest window governance may set.
pub const MAX_AVAILABILITY_REWARD_PAID_ACTIVITY_EPOCHS: u64 = 365;

/// Governed: least provider work, wei of reward weight, the subject's owner
/// must have earned over the paid-activity window. Provider work weight is
/// the governed share of the protocol fee a settlement paid, so this is a
/// floor on fees paid by other parties, not on a count of payments.
pub const AVAILABILITY_REWARD_MIN_PAID_WORK_PARAM: &str =
    "feature.availability_paid_activity.min_work_wei";
/// Genesis: 0.04 TNZO of weight, what 100 TNZO of settled payments earn at
/// the genesis settlement fee (10 bps) and provider share of it (40%).
pub const DEFAULT_AVAILABILITY_REWARD_MIN_PAID_WORK: u64 = 40_000_000_000_000_000;
/// Highest floor governance may set: 4 TNZO of weight.
pub const MAX_AVAILABILITY_REWARD_MIN_PAID_WORK: u64 = 4_000_000_000_000_000_000;

/// Governed: the reward epoch before which the paid-activity requirement is
/// waived, so a network with no paid demand yet can pay its first hardware-
/// bound operators. Zero (genesis) waives nothing.
pub const AVAILABILITY_REWARD_BOOTSTRAP_UNTIL_EPOCH_PARAM: &str =
    "feature.availability_paid_activity.bootstrap_until_epoch";
/// Genesis: no bootstrap period.
pub const DEFAULT_AVAILABILITY_REWARD_BOOTSTRAP_UNTIL_EPOCH: u64 = 0;
/// Latest epoch governance may set.
pub const MAX_AVAILABILITY_REWARD_BOOTSTRAP_UNTIL_EPOCH: u64 = u32::MAX as u64;

/// Governed: the verified-paid-demand target, in atto-USD per day (1e-18
/// USD), at which the demand offset has phased the availability reward all
/// the way to zero (ENERGY-VERIFY section 9's $60k/day). Converted to wei
/// via [`super::economy::usd_to_wei`] at the validator-signed rate in force,
/// the same conversion every other USD-denominated fee already uses.
/// Genesis zero disables the offset entirely: the reward pays its full
/// decayed cap regardless of settled demand, until governance sets a real
/// target.
pub const AVAILABILITY_REWARD_DEMAND_TARGET_ATTO_USD_PER_DAY_PARAM: &str =
    "reward.availability_demand_target_atto_usd_per_day";
/// Genesis: disabled.
pub const DEFAULT_AVAILABILITY_REWARD_DEMAND_TARGET_ATTO_USD_PER_DAY: u64 = 0;
/// Highest target the key holds: `u64::MAX` atto-USD, about 18.4 USD/day,
/// far below the design's 60,000 USD/day; from
/// [`AVAILABILITY_DEMAND_TARGET_USD_KEY`]'s epoch the target is read from
/// [`AVAILABILITY_REWARD_DEMAND_TARGET_USD_PER_DAY_PARAM`] instead.
pub const MAX_AVAILABILITY_REWARD_DEMAND_TARGET_ATTO_USD_PER_DAY: u64 = u64::MAX;

/// Gate of the whole-USD demand target. Never at genesis.
pub const AVAILABILITY_DEMAND_TARGET_USD_KEY: &str =
    "feature.availability_demand_target_usd.activation_epoch";
/// Governed: the verified-paid-demand target in whole USD per day at which
/// the demand offset has phased the reward to zero, read from
/// [`AVAILABILITY_DEMAND_TARGET_USD_KEY`]'s epoch. Zero disables the offset.
pub const AVAILABILITY_REWARD_DEMAND_TARGET_USD_PER_DAY_PARAM: &str =
    "feature.availability_demand_target_usd.usd_per_day";
/// Genesis: disabled.
pub const DEFAULT_AVAILABILITY_REWARD_DEMAND_TARGET_USD_PER_DAY: u64 = 0;
/// Highest target governance may set: 10M USD/day.
pub const MAX_AVAILABILITY_REWARD_DEMAND_TARGET_USD_PER_DAY: u64 = 10_000_000;

/// Governed: how many one-hour epochs the verified-paid-demand window
/// trails behind `epoch` when computing the demand offset. Section 9 anchors
/// a day-denominated target, so the genesis is 24.
pub const AVAILABILITY_REWARD_DEMAND_WINDOW_EPOCHS_PARAM: &str =
    "reward.availability_demand_window_epochs";
/// Genesis: one day of one-hour epochs.
pub const DEFAULT_AVAILABILITY_REWARD_DEMAND_WINDOW_EPOCHS: u64 = 24;
/// Highest window governance may set: 90 days. Bounded so a reward payout
/// never has to read an unbounded number of epoch records.
pub const MAX_AVAILABILITY_REWARD_DEMAND_WINDOW_EPOCHS: u64 = 90 * 24;

/// Gate of the indexed cap (see the module text). Never at genesis.
pub const AVAILABILITY_INDEX_CAP_KEY: &str = "feature.availability_index_cap.activation_epoch";
/// Basis points of the datacenter-GPU compute price index one proven GPU's
/// unit-hour may earn once the indexed cap is live.
pub const AVAILABILITY_INDEX_CAP_BPS_PARAM: &str = "feature.availability_index_cap.bps";
/// Genesis: 7.5% of the index, read only once the gate is live.
pub const DEFAULT_AVAILABILITY_INDEX_CAP_BPS: u64 = 750;
/// Highest share governance may set: 10% of the index.
pub const MAX_AVAILABILITY_INDEX_CAP_BPS: u64 = 1_000;

/// The indexed cap in wei per unit-hour: [`AVAILABILITY_INDEX_CAP_BPS_PARAM`]
/// of the datacenter-GPU compute price index in force at the TNZO rate in
/// force. `None` while validators have frozen no index.
fn index_cap_wei(state: &dyn VmState) -> Option<u128> {
    let symbol =
        super::economy::compute_index_symbol(tenzro_types::hardware::HardwareClass::DatacenterGpu)?;
    let (index_nano_usd, _) = super::economy::read_symbol_rate(state, symbol)?;
    let bps =
        network_param(state, AVAILABILITY_INDEX_CAP_BPS_PARAM).min(MAX_AVAILABILITY_INDEX_CAP_BPS);
    let cap_nano_usd = index_nano_usd.checked_mul(u128::from(bps))? / 10_000;
    let tnzo_nano_usd = super::economy::read_fee_rate(state).rate_nano_usd.max(1);
    const WEI_PER_TNZO: u128 = 1_000_000_000_000_000_000;
    Some(cap_nano_usd.checked_mul(WEI_PER_TNZO)? / tnzo_nano_usd)
}

/// One unit-hour's availability reward at `epoch` before the readiness
/// tier and the per-GPU count: the decayed, demand-offset cap, under the
/// indexed cap when its gate is live and `proven_gpu`.
pub fn unit_hour_reward(state: &dyn VmState, epoch: u64, proven_gpu: bool) -> u128 {
    under_index_cap(state, availability_reward_amount(state, epoch), proven_gpu)
}

/// `amount`, one unit-hour's reward before the readiness tier, under the
/// indexed cap when its gate is live and the unit is a proven GPU.
fn under_index_cap(state: &dyn VmState, amount: u128, proven_gpu: bool) -> u128 {
    if !proven_gpu || !crate::feature_gate::is_live_now(state, AVAILABILITY_INDEX_CAP_KEY) {
        return amount;
    }
    index_cap_wei(state).map_or(amount, |cap| amount.min(cap))
}

/// Log topic of an availability reward payout; data is
/// `subject_len_le(4) || subject_did || epoch_be(8) || amount_le(16)`.
pub const AVAILABILITY_REWARD_TOPIC: &[u8] = b"AvailabilityReward";

/// Gate: the first epoch from which the reward per verified unit is a share
/// of a budget pinned to verified paid demand instead of the governed
/// schedule. From it, each hour's budget is [`UNIT_BUDGET_DEMAND_BPS_PARAM`]
/// of the verified paid demand per hour over the demand window, split
/// equally over the units the last closed hour verified, and never more per
/// unit than the decayed cap. Every unit is paid alike, so splitting one
/// operator into several earns nothing more, and the total follows demand.
pub const UNIT_BUDGET_KEY: &str = "feature.unit_budget.activation_epoch";

/// Governed: share of verified paid demand per hour that budgets the
/// availability reward once [`UNIT_BUDGET_KEY`] is live, bps. Zero at
/// genesis: the vote that activates the budget sets it.
pub const UNIT_BUDGET_DEMAND_BPS_PARAM: &str = "feature.unit_budget.demand_bps";
/// Upper bound of [`UNIT_BUDGET_DEMAND_BPS_PARAM`].
pub const MAX_UNIT_BUDGET_DEMAND_BPS: u64 = 10_000;

fn verified_units_key(epoch: u64) -> String {
    format!("availability_units:{epoch:016x}")
}

/// Units verified available in `epoch` so far.
pub fn verified_units(state: &dyn VmState, epoch: u64) -> u64 {
    super::funding::read_json(state, &verified_units_key(epoch)).unwrap_or(0)
}

/// Adds `units` to `epoch`'s verified units and drops the count two hours
/// back, which nothing reads again.
fn add_verified_units(
    state: &mut dyn VmState,
    epoch: u64,
    units: u64,
    changes: &mut Vec<StateChange>,
) -> Result<()> {
    let total = verified_units(state, epoch).saturating_add(units);
    super::funding::write_json(state, &verified_units_key(epoch), &total, changes)?;
    if let Some(old) = epoch.checked_sub(2) {
        let key = verified_units_key(old);
        if let Some(prior) = state.get_storage(&SYSTEM_ADDRESS, key.as_bytes()) {
            state.set_storage(&SYSTEM_ADDRESS, key.as_bytes(), Vec::new());
            changes.push(StateChange::new(
                SYSTEM_ADDRESS.to_vec(),
                key.into_bytes(),
                Some(prior),
                None,
            ));
        }
    }
    Ok(())
}

/// The reward per verified unit in `epoch` under the demand-pinned budget:
/// the hour's budget over the units the hour before verified (at least one),
/// at most the decayed cap.
pub fn unit_budget_reward(state: &dyn VmState, epoch: u64) -> u128 {
    let bps = network_param(state, UNIT_BUDGET_DEMAND_BPS_PARAM).min(MAX_UNIT_BUDGET_DEMAND_BPS);
    let window = network_param(state, AVAILABILITY_REWARD_DEMAND_WINDOW_EPOCHS_PARAM)
        .clamp(1, MAX_AVAILABILITY_REWARD_DEMAND_WINDOW_EPOCHS);
    let budget = verified_paid_demand_wei(state, epoch, window).saturating_mul(u128::from(bps))
        / 10_000
        / u128::from(window);
    let units = verified_units(state, epoch.saturating_sub(1)).max(1);
    decayed_cap(state, epoch).min(budget / u128::from(units))
}

/// Gas charged for one `DeclareReadinessTier` transaction: a single small
/// state write, the same order of magnitude as `SlaAttest`/`FeeRateSubmit`.
pub const GAS_DECLARE_READINESS_TIER: u64 = 40_000;

/// Selector of `DeclareReadinessTier` (byte 0x3D is unused by every other
/// selector constant in this file as of this commit).
pub const SELECTOR_DECLARE_READINESS_TIER: [u8; 4] = [0x01, 0x00, 0x00, 0x3D];

/// A subject's self-declared readiness: how ready-to-serve it claims to be,
/// which the governed per-tier bps multipliers below scale the availability
/// reward by. Undeclared subjects are treated as [`ReadinessTier::Warm`],
/// so introducing tiers changes nothing for a subject that never declares
/// one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[repr(u8)]
pub enum ReadinessTier {
    Cold = 0,
    Cool = 1,
    Warm = 2,
}

impl ReadinessTier {
    fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Cold),
            1 => Some(Self::Cool),
            2 => Some(Self::Warm),
            _ => None,
        }
    }

    /// The governed multiplier this tier's availability reward is scaled by.
    const fn governed_param(self) -> &'static str {
        match self {
            Self::Cold => AVAILABILITY_READINESS_COLD_BPS_PARAM,
            Self::Cool => AVAILABILITY_READINESS_COOL_BPS_PARAM,
            Self::Warm => AVAILABILITY_READINESS_WARM_BPS_PARAM,
        }
    }
}

/// Governed: the availability reward's multiplier for a [`ReadinessTier`],
/// bps of the otherwise-decayed, otherwise-offset reward. Genesis 100% for
/// every tier, so readiness tiers change no payout until governance sets
/// them apart.
pub const AVAILABILITY_READINESS_COLD_BPS_PARAM: &str = "reward.availability_readiness_cold_bps";
pub const AVAILABILITY_READINESS_COOL_BPS_PARAM: &str = "reward.availability_readiness_cool_bps";
pub const AVAILABILITY_READINESS_WARM_BPS_PARAM: &str = "reward.availability_readiness_warm_bps";
/// Genesis and max share a value here: every tier pays the full reward
/// until governance differentiates them, and none may pay more than the
/// undecayed, un-offset reward.
pub const DEFAULT_AVAILABILITY_READINESS_BPS: u64 = 10_000;
pub const MAX_AVAILABILITY_READINESS_BPS: u64 = 10_000;

/// First epoch from which a validator judges each readiness tier's
/// verdict against its own governed SLA. Before it every subject is
/// available when it answered more than half of a validator's probes.
pub const SLA_TIERS_GATE: &str = "feature.sla_tiers.activation_epoch";
/// Governed: share of a validator's probes a Warm subject must answer, more
/// than this many bps, for its verdict to be available.
pub const SLA_WARM_AVAILABLE_BPS_PARAM: &str = "feature.sla_tiers.warm_available_bps";
/// Governed: the same for a Cool subject.
pub const SLA_COOL_AVAILABLE_BPS_PARAM: &str = "feature.sla_tiers.cool_available_bps";
/// Governed: the same for a Cold subject.
pub const SLA_COLD_AVAILABLE_BPS_PARAM: &str = "feature.sla_tiers.cold_available_bps";
/// Genesis SLA of every tier: more than half of the probes answered.
pub const DEFAULT_SLA_AVAILABLE_BPS: u64 = 5_000;

impl ReadinessTier {
    /// The share of probes, bps, this tier must answer more than to be
    /// available; more than half until [`SLA_TIERS_GATE`] is live.
    pub fn available_bps(self, state: &dyn VmState) -> u64 {
        if !crate::feature_gate::is_live_now(state, SLA_TIERS_GATE) {
            return DEFAULT_SLA_AVAILABLE_BPS;
        }
        network_param(
            state,
            match self {
                Self::Warm => SLA_WARM_AVAILABLE_BPS_PARAM,
                Self::Cool => SLA_COOL_AVAILABLE_BPS_PARAM,
                Self::Cold => SLA_COLD_AVAILABLE_BPS_PARAM,
            },
        )
        .min(9_999)
    }
}

/// Whether `subject` met its tier's SLA with `answered` of `answered +
/// failed` probes answered.
pub fn meets_sla(state: &dyn VmState, subject: &str, answered: u32, failed: u32) -> bool {
    let bps = declared_readiness_tier(state, subject).available_bps(state);
    let total = u64::from(answered) + u64::from(failed);
    total > 0 && u64::from(answered) * 10_000 > bps * total
}

/// First epoch from which a machine whose TPM its manufacturer certifies as
/// firmware on the host processor earns the firmware tier's share of the
/// availability reward, a tier below a discrete chip.
pub const FIRMWARE_TPM_TIER_GATE: &str = "feature.firmware_tpm_tier.activation_epoch";
/// Governed: the share of the availability reward, bps, a machine on a
/// firmware TPM earns once [`FIRMWARE_TPM_TIER_GATE`] is live.
pub const AVAILABILITY_FIRMWARE_TPM_BPS_PARAM: &str = "feature.firmware_tpm_tier.reward_bps";
/// Genesis firmware tier: half of a discrete chip's reward.
pub const DEFAULT_AVAILABILITY_FIRMWARE_TPM_BPS: u64 = 5_000;

/// `reward` at the firmware tier's share when `subject` runs on a firmware
/// TPM and the tier is live, whole otherwise.
fn apply_firmware_tier(state: &dyn VmState, subject: &str, reward: u128) -> u128 {
    if !crate::feature_gate::is_live_now(state, FIRMWARE_TPM_TIER_GATE)
        || !super::funding::machine_firmware_tpm(state, subject)
    {
        return reward;
    }
    let bps = network_param(state, AVAILABILITY_FIRMWARE_TPM_BPS_PARAM).min(10_000);
    reward.saturating_mul(u128::from(bps)) / 10_000
}

fn readiness_tier_key(subject: &str) -> String {
    format!("readiness_tier:{subject}")
}

/// The readiness tier `subject` (an SLA subject string:
/// [`super::role_stake::sla_subject`]'s argument, the same string
/// `SlaAttest` names a provider by) last declared, or
/// [`ReadinessTier::Warm`] if it never has.
pub fn declared_readiness_tier(state: &dyn VmState, subject: &str) -> ReadinessTier {
    state
        .get_storage(&SYSTEM_ADDRESS, readiness_tier_key(subject).as_bytes())
        .and_then(|b| b.first().copied())
        .and_then(ReadinessTier::from_u8)
        .unwrap_or(ReadinessTier::Warm)
}

/// `reward` scaled by `subject`'s declared readiness-tier multiplier.
fn apply_readiness_tier(state: &dyn VmState, subject: &str, reward: u128) -> u128 {
    let bps = network_param(
        state,
        declared_readiness_tier(state, subject).governed_param(),
    )
    .min(MAX_AVAILABILITY_READINESS_BPS);
    reward.saturating_mul(u128::from(bps)) / 10_000
}

#[derive(Debug, serde::Deserialize)]
struct DeclareReadinessTierPayload {
    subject: String,
    tier: u8,
}

/// Executes a `DeclareReadinessTier` transaction: `from` must be the owner
/// of the bond or stake backing `subject` ([`super::role_stake::sla_subject`]),
/// the same authority that already answers for that subject's SLA
/// obligations and slashing, reused here rather than inventing a second
/// notion of "who controls this subject."
pub(super) fn declare_readiness_tier(
    state: &mut dyn VmState,
    from: &[u8],
    _now_ms: i64,
    data: &[u8],
) -> Result<(Vec<StateChange>, Vec<Log>)> {
    let payload: DeclareReadinessTierPayload = serde_json::from_slice(data).map_err(|e| {
        VmError::InvalidTransaction(format!("Invalid DeclareReadinessTier payload: {e}"))
    })?;
    let tier = ReadinessTier::from_u8(payload.tier).ok_or_else(|| {
        refuse(format!(
            "{} is not a readiness tier (0, 1 or 2)",
            payload.tier
        ))
    })?;
    let subject = super::role_stake::sla_subject(state, &payload.subject)
        .ok_or_else(|| refuse(format!("{} is not a bonded SLA subject", payload.subject)))?;
    if subject.owner != from {
        return Err(refuse(format!(
            "{} is owned by a different account",
            payload.subject
        )));
    }
    let mut changes = Vec::new();
    let key = readiness_tier_key(&payload.subject);
    let old = state.get_storage(&SYSTEM_ADDRESS, key.as_bytes());
    let new = vec![tier as u8];
    state.set_storage(&SYSTEM_ADDRESS, key.as_bytes(), new.clone());
    changes.push(StateChange::new(
        SYSTEM_ADDRESS.to_vec(),
        key.into_bytes(),
        old,
        Some(new),
    ));
    Ok((changes, Vec::new()))
}

/// The reward one verified-available verdict at `epoch` pays, before
/// checking the treasury's balance against it: the governed per-unit-hour
/// cap, decayed by whole and partial half-lives (see [`halving_decay`])
/// since the decay's start epoch, then scaled down by the demand offset
/// (see [`demand_offset_bps`]) as real, verified-paid demand approaches the
/// governed target. Zero whenever the decayed cap is zero or the demand
/// offset has phased all the way to zero.
pub fn availability_reward_amount(state: &dyn VmState, epoch: u64) -> u128 {
    let cap = decayed_cap(state, epoch);
    if cap == 0 {
        return 0;
    }
    cap.saturating_mul(u128::from(demand_offset_bps(state, epoch))) / 10_000
}

/// The governed per-unit-hour cap, decayed by whole and partial half-lives
/// since the decay's start epoch. Zero whenever the cap is zero; the full
/// undecayed cap whenever the start epoch is unset, not yet reached, or no
/// half-life is governed.
fn decayed_cap(state: &dyn VmState, epoch: u64) -> u128 {
    let cap = network_param(state, AVAILABILITY_REWARD_PER_UNIT_HOUR_PARAM)
        .min(MAX_AVAILABILITY_REWARD_PER_UNIT_HOUR);
    if cap == 0 {
        return 0;
    }
    let half_life_days = network_param(state, AVAILABILITY_REWARD_DECAY_HALF_LIFE_DAYS_PARAM)
        .min(MAX_AVAILABILITY_REWARD_DECAY_HALF_LIFE_DAYS);
    if half_life_days == 0 {
        return u128::from(cap);
    }
    let start_epoch = network_param(state, AVAILABILITY_REWARD_DECAY_START_EPOCH_PARAM)
        .min(MAX_AVAILABILITY_REWARD_DECAY_START_EPOCH);
    if start_epoch == 0 || epoch < start_epoch {
        return u128::from(cap);
    }
    halving_decay(
        u128::from(cap),
        epoch - start_epoch,
        half_life_days.saturating_mul(24),
    )
}

/// `value` decayed by `elapsed_epochs` against a half-life of
/// `half_life_epochs`, as a deterministic, integer-only approximation of
/// exponential decay: exact at every whole half-life (`value >> n`, a plain
/// bit shift) and linearly interpolated between two consecutive halving
/// points everywhere else. Monotonically non-increasing; zero once a
/// shift has halved `value` all the way to zero (at most 128 halvings
/// survive a u128) or `half_life_epochs` is zero (a degenerate half-life,
/// not an infinite one -- callers must treat "no half-life governed"
/// as its own undecayed case, same as [`availability_reward_amount`] does).
fn halving_decay(value: u128, elapsed_epochs: u64, half_life_epochs: u64) -> u128 {
    if half_life_epochs == 0 || value == 0 {
        return 0;
    }
    let halvings = elapsed_epochs / half_life_epochs;
    if halvings >= 128 {
        return 0;
    }
    let at_halving = value >> halvings;
    if at_halving == 0 {
        return 0;
    }
    let next = at_halving >> 1;
    let remainder = u128::from(elapsed_epochs % half_life_epochs);
    at_halving - (at_halving - next).saturating_mul(remainder) / u128::from(half_life_epochs)
}

/// TNZO wei settled across the governed demand window of one-hour epochs
/// ending at and including `epoch`: the sum of
/// [`super::economy::EpochActivity::settled_value`] over that window. Every
/// settlement on the ledger records it (escrow claims and releases, plan
/// commits, netted plans, payer settlements); a payment made off the ledger
/// and recorded on it (proven or attested) records it once
/// [`super::economy::EXTERNAL_PAYMENT_ACTIVITY_GATE`] is live. Treasury
/// sponsorships and grants are not demand and record none.
fn verified_paid_demand_wei(state: &dyn VmState, epoch: u64, window_epochs: u64) -> u128 {
    let start = epoch.saturating_sub(window_epochs.saturating_sub(1));
    let mut total = 0u128;
    for e in start..=epoch {
        total = total.saturating_add(super::economy::read_epoch_activity(state, e).settled_value);
    }
    total
}

/// Whether `subject_owner` meets the paid-activity requirement, in force
/// once [`AVAILABILITY_PAID_ACTIVITY_GATE`] is live: within the
/// governed window of reward epochs it earned at least the governed minimum
/// of provider work, the window is zero, or the bootstrap period has not
/// ended. Provider work is recorded only for a settlement whose payer and
/// payee are registered identities of different roots, so paying oneself
/// earns none; the minimum is a weight, so a token payment does not reach
/// it. A 20-byte owner is the account its address names.
pub(super) fn paid_activity_met(state: &dyn VmState, subject_owner: &[u8]) -> Result<bool> {
    if !crate::feature_gate::is_live_now(state, AVAILABILITY_PAID_ACTIVITY_GATE) {
        return Ok(true);
    }
    let window = network_param(state, AVAILABILITY_REWARD_PAID_ACTIVITY_EPOCHS_PARAM)
        .min(MAX_AVAILABILITY_REWARD_PAID_ACTIVITY_EPOCHS);
    if window == 0 {
        return Ok(true);
    }
    let current = super::rewards::read_reward_state(state)?.current_epoch;
    if current < network_param(state, AVAILABILITY_REWARD_BOOTSTRAP_UNTIL_EPOCH_PARAM) {
        return Ok(true);
    }
    let Ok(owner) = super::pad_address_32(subject_owner) else {
        return Ok(false);
    };
    let earned = super::rewards::provider_work_since(
        state,
        &Address::new(owner),
        current.saturating_sub(window - 1),
    )?;
    let least = network_param(state, AVAILABILITY_REWARD_MIN_PAID_WORK_PARAM)
        .clamp(1, MAX_AVAILABILITY_REWARD_MIN_PAID_WORK);

    Ok(earned >= u128::from(least))
}

/// The availability reward's demand-offset multiplier, in bps of the
/// decayed cap: `10_000` (no offset) when the governed target is zero
/// (disabled) or the rate feed [`super::economy::usd_to_wei`] converts
/// through has not been populated (never divide by a zero target, and
/// never phase out the reward just because the rate feed is quiet); linear
/// in between, down to `0` once verified paid demand over the governed
/// window reaches the governed target.
/// The demand target in force, atto-USD per day: the whole-USD key once
/// its gate is live, the atto-USD key before.
fn demand_target_atto_usd(state: &dyn VmState) -> u128 {
    if crate::feature_gate::is_live_now(state, AVAILABILITY_DEMAND_TARGET_USD_KEY) {
        let usd = network_param(state, AVAILABILITY_REWARD_DEMAND_TARGET_USD_PER_DAY_PARAM)
            .min(MAX_AVAILABILITY_REWARD_DEMAND_TARGET_USD_PER_DAY);
        u128::from(usd) * 1_000_000_000_000_000_000
    } else {
        u128::from(network_param(
            state,
            AVAILABILITY_REWARD_DEMAND_TARGET_ATTO_USD_PER_DAY_PARAM,
        ))
    }
}

fn demand_offset_bps(state: &dyn VmState, epoch: u64) -> u64 {
    let target_atto_usd = demand_target_atto_usd(state);
    if target_atto_usd == 0 {
        return 10_000;
    }
    let target_wei = super::economy::usd_to_wei(state, target_atto_usd);
    if target_wei == 0 {
        return 10_000;
    }
    let window = network_param(state, AVAILABILITY_REWARD_DEMAND_WINDOW_EPOCHS_PARAM)
        .clamp(1, MAX_AVAILABILITY_REWARD_DEMAND_WINDOW_EPOCHS);
    let paid = verified_paid_demand_wei(state, epoch, window);
    let used_bps = paid.saturating_mul(10_000) / target_wei;
    10_000u128.saturating_sub(used_bps.min(10_000)) as u64
}

/// Pay the availability reward for a verified-available verdict of
/// `subject_owner` at `epoch`, out of the treasury, and log it under
/// [`AVAILABILITY_REWARD_TOPIC`]. Insufficient treasury balance forfeits
/// the reward for this epoch rather than refusing the transaction that
/// recorded the verdict -- the same graceful-skip pattern
/// `payment_settlement::recon::begin_block` uses for its own treasury-
/// funded reward.
///
/// When `subject_owner` is a genuine 32-byte [`Address`], splits
/// liquid/vesting exactly like a reward-coupon claim
/// (`rewards::CLAIM_LIQUID_PARAM`/`CLAIM_VESTING_PARAM`, both already
/// governed for every other earned reward): the liquid share pays the
/// subject's balance directly, the rest opens a
/// [`tenzro_token::vesting::VestingSchedule`] starting at `now_ms`. A role
/// stake or compute bond's owner is commonly a 20-byte account (see the
/// `provider_address` markers in `inference_fault`/`role_stake`), which has
/// no corresponding `Address` and so no vesting schedule to open against
/// (vesting is keyed by `Address`, a different, 32-byte, keyspace); for
/// those, the whole reward pays liquid, matching this function's behavior
/// before vesting was added -- not a silent truncation or zero-padding of
/// the real owner bytes, which would risk opening a schedule nothing can
/// ever claim.
///
/// Nothing is paid while [`AVAILABILITY_REWARD_REQUIRE_HARDWARE_PARAM`] is
/// off. When it is set, `subject_did` must also be a machine identity whose TPM endorsement chains to a root
/// governance recognises ([`super::funding::machine_endorsed`]) -- the same
/// verification validator admission already uses, reused rather than
/// re-implemented. That is the host half of hardware binding. The per-GPU
/// half is the GPUs the host proved, each by its own NVIDIA device
/// certificate and counted for one live identity only: the reward is paid
/// once per GPU counted in the current reward epoch or the one before, and
/// once for a host with none. Returns the amount paid (liquid plus
/// newly-vesting), or `None` if nothing was (the reward is zero, the
/// treasury cannot cover it, hardware binding is off, the subject does not
/// pass it, or its owner has no recent paid activity:
/// [`AVAILABILITY_REWARD_PAID_ACTIVITY_EPOCHS_PARAM`]).
pub(super) fn pay_if_available(
    state: &mut dyn VmState,
    subject_did: &str,
    subject_owner: &[u8],
    epoch: u64,
    now_ms: i64,
    changes: &mut Vec<StateChange>,
    logs: &mut Vec<Log>,
) -> Result<Option<u128>> {
    let require_hardware = network_param(state, AVAILABILITY_REWARD_REQUIRE_HARDWARE_PARAM)
        .min(MAX_AVAILABILITY_REWARD_REQUIRE_HARDWARE)
        != 0;
    if !require_hardware || super::funding::machine_endorsed(state, subject_did, now_ms).is_err() {
        return Ok(None);
    }
    if !paid_activity_met(state, subject_owner)? {
        return Ok(None);
    }
    let gpus = super::hardware_level::current_gpus(state, subject_did)
        .len()
        .max(1);
    let per_unit = if crate::feature_gate::is_live_now(state, UNIT_BUDGET_KEY) {
        add_verified_units(state, epoch, gpus as u64, changes)?;
        unit_budget_reward(state, epoch)
    } else {
        let proven_gpu = crate::feature_gate::is_live_now(state, AVAILABILITY_INDEX_CAP_KEY)
            && !super::hardware_level::current_gpus(state, subject_did).is_empty();
        unit_hour_reward(state, epoch, proven_gpu)
    };
    let reward = apply_readiness_tier(state, subject_did, per_unit);
    let reward = apply_firmware_tier(state, subject_did, reward);
    if reward == 0 {
        return Ok(None);
    }
    let reward = reward.saturating_mul(gpus as u128);
    let treasury: [u8; 32] = super::derive_treasury_address()
        .as_bytes()
        .try_into()
        .unwrap_or_default();
    if state.get_balance(&treasury) < reward {
        return Ok(None);
    }
    // Paid with no proposal, so it counts against the treasury's outflow
    // period like every other payout and is forfeited, not forced, once the
    // period's cap is spent.
    if super::funding::record_outflow(state, reward, now_ms, changes).is_err() {
        return Ok(None);
    }
    let subject_address: Option<[u8; 32]> = subject_owner.try_into().ok();
    let (liquid, vesting) = match subject_address {
        Some(_) => tenzro_token::rewards::split_claim(
            reward,
            network_param(state, super::rewards::CLAIM_LIQUID_PARAM).min(10_000) as u32,
        ),
        None => (reward, 0),
    };
    if liquid > 0 {
        move_balance(state, &treasury, subject_owner, liquid, changes)?;
    }
    if vesting > 0 {
        let vesting_ms = network_param(state, super::rewards::CLAIM_VESTING_PARAM) as i64;
        super::rewards::open_vesting(
            state,
            &treasury,
            Address::new(subject_address.expect("vesting>0 implies subject_address is Some")),
            tenzro_token::vesting::VestingKind::Reward,
            vesting,
            now_ms,
            0,
            vesting_ms,
            changes,
        )?;
    }
    logs.push(Log::new(
        SYSTEM_ADDRESS.to_vec(),
        vec![AVAILABILITY_REWARD_TOPIC.to_vec()],
        [
            (subject_did.len() as u32).to_le_bytes().as_slice(),
            subject_did.as_bytes(),
            epoch.to_be_bytes().as_slice(),
            reward.to_le_bytes().as_slice(),
        ]
        .concat(),
    ));
    Ok(Some(reward))
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use crate::state_adapter::StateAdapter;
    use tenzro_tee::tpm_attest::tests::{SoftTpm, evidence, evidence_from};
    use tenzro_tee::tpm_attest::{
        MachineAttestation, admission_challenge, attestation_key_sec1,
        machine_did_for_attestation_key,
    };

    fn state_adapter() -> StateAdapter {
        let mut state = StateAdapter::new();
        // The tests pay from small treasuries; the period cap is what a
        // test of the cap itself sets.
        super::super::set_governed_param_for_test(
            &mut state,
            crate::governance::MAX_PERIOD_OUTFLOW_PARAM,
            10_000,
        );
        state
    }

    fn set(state: &mut dyn VmState, key: &str, value: u64) {
        super::super::set_governed_param_for_test(state, key, value);
    }

    /// Registers a machine identity whose TPM endorsement chains to a root
    /// recognised in `state` (same fixture shape as
    /// `upgrade_tests::validator`, without the validator bond this module
    /// has no use for). Returns the DID.
    pub(in crate::native) fn register_endorsed_machine(
        state: &mut StateAdapter,
        seed: u8,
    ) -> String {
        register_endorsed_machine_from(state, seed, None)
    }

    /// [`register_endorsed_machine`] on a TPM whose EK certificate names
    /// `manufacturer` when given.
    fn register_endorsed_machine_from(
        state: &mut StateAdapter,
        seed: u8,
        manufacturer: Option<&str>,
    ) -> String {
        let tpm = SoftTpm::new(seed);
        let (probe, _) = evidence(&tpm, &[0; 32]);
        let ak = attestation_key_sec1(&probe).unwrap();
        let did = machine_did_for_attestation_key(&ak);
        let controller = vec![seed; 33];
        let nonce = [seed; 32];
        let (ev, root) = evidence_from(
            &tpm,
            &admission_challenge(&did, &controller, &nonce),
            manufacturer,
        );
        let att = MachineAttestation {
            evidence: ev,
            nonce: nonce.to_vec(),
            activated: true,
        };
        let mut metadata = std::collections::BTreeMap::new();
        metadata.insert(
            tenzro_tee::identity_evidence::TPM_ATTESTATION_KEY.to_string(),
            serde_json::to_string(&att).unwrap(),
        );
        let record = tenzro_types::identity::RegisterIdentityPayload {
            did: did.clone(),
            identity_type: "machine".into(),
            display_name: String::new(),
            controller_pubkey: controller,
            key_type: "p256".into(),
            wallet_id: String::new(),
            wallet_address: Address::new([seed; 32]),
            pq_verifying_key: Vec::new(),
            metadata,
            proof: tenzro_types::identity::RegistrationProof::Hardware {
                signature: tenzro_types::account_signature::CompositeSignature::classical(
                    tenzro_types::account_signature::ClassicalProof::Raw {
                        signature: Vec::new(),
                    },
                ),
            },
        };
        state.set_storage(
            &SYSTEM_ADDRESS,
            &identity_storage_key(&did),
            serde_json::to_vec(&record).unwrap(),
        );
        use base64::Engine;
        let root_pem = format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            base64::engine::general_purpose::STANDARD.encode(&root.der)
        );
        super::super::funding::set_endorsement_roots(state, &[root_pem], &mut Vec::new()).unwrap();
        did
    }

    /// Inside the test root certificate's validity window
    /// (`tenzro_tee::tpm_attest::tests::NOW` is 1_800_000_000 seconds).
    pub(in crate::native) const BOUND_NOW_MS: i64 = 1_800_000_000_000;

    /// Turns hardware binding on and registers a TPM-endorsed machine for
    /// Puts the paid-activity requirement in force and gives `owner` the
    /// least provider work it asks for at its genesis values, earned in the
    /// current reward epoch.
    pub(in crate::native) fn earn_paid_work(state: &mut StateAdapter, owner: &[u8]) {
        crate::native::set_genesis_param(state, AVAILABILITY_PAID_ACTIVITY_GATE, 0);
        crate::native::rewards::record_settled_work(
            state,
            Address::new(crate::native::pad_address_32(owner).unwrap()),
            tenzro_token::rewards::WorkClass::InferenceServed,
            u128::from(DEFAULT_AVAILABILITY_REWARD_MIN_PAID_WORK),
            &mut Vec::new(),
        )
        .unwrap();
    }

    /// `seed`: the only kind of subject the reward pays. Returns its DID.
    /// Its owner, the account `[seed; 20]` or `[seed; 32]`, has earned the
    /// least provider work the reward asks for in the current reward epoch.
    fn bound_subject(state: &mut StateAdapter, seed: u8) -> String {
        set(state, AVAILABILITY_REWARD_REQUIRE_HARDWARE_PARAM, 1);
        earn_paid_work(state, &[seed; 20]);
        earn_paid_work(state, &[seed; 32]);
        register_endorsed_machine(state, seed)
    }

    /// Records `settled_value` as the sole settled activity of reward
    /// epoch `epoch`, the way `economy::settle_payout` would on a real
    /// settlement.
    fn seed_epoch_activity(state: &mut StateAdapter, epoch: u64, settled_value: u128) {
        let activity = super::super::economy::EpochActivity {
            settled_value,
            ..Default::default()
        };
        state.set_storage(
            &SYSTEM_ADDRESS,
            super::super::economy::activity_key(epoch).as_bytes(),
            serde_json::to_vec(&activity).unwrap(),
        );
    }

    /// Registers a bare compute-bond marker (no bonded balance, no TPM
    /// attestation -- just enough for `role_stake::sla_subject` to resolve
    /// it, which is all the readiness-tier declaration needs).
    fn register_compute_bond(state: &mut StateAdapter, did: &str, owner: [u8; 20]) {
        let marker = serde_json::json!({
            "provider_did": did,
            "provider_address": hex::encode(owner),
            "amount": "0",
            "vault": hex::encode([0u8; 32]),
            "op": "Posted",
        });
        state.set_storage(
            &SYSTEM_ADDRESS,
            super::super::compute_bond_storage_key(did).as_bytes(),
            serde_json::to_vec(&marker).unwrap(),
        );
    }

    /// A datacenter-GPU index of 2.00 USD per compute-hour frozen at epoch 3,
    /// with TNZO at 0.10 USD: 7.5% is 0.15 USD, 1.5 TNZO.
    fn with_index(state: &mut StateAdapter) {
        state.set_storage(
            &SYSTEM_ADDRESS,
            b"fxr_live:IDXDCGPU",
            serde_json::to_vec(&serde_json::json!({ "rate_nano_usd": "2000000000", "epoch": 3 }))
                .unwrap(),
        );
        set_genesis_param(
            state,
            super::super::economy::GOVERNANCE_RATE_PARAM,
            100_000_000,
        );
    }

    const TNZO: u128 = 1_000_000_000_000_000_000;

    /// Before the gate the absolute cap holds for every unit, index or not.
    #[test]
    fn before_the_gate_the_absolute_cap_holds() {
        let mut state = StateAdapter::new();
        with_index(&mut state);
        assert_eq!(under_index_cap(&state, 5 * TNZO, true), 5 * TNZO);
    }

    /// From the gate a proven GPU earns at most its share of the index; a
    /// unit with no proven GPU, or a chain with no index, keeps the absolute
    /// cap, and a cap already below the index share is untouched.
    #[test]
    fn from_the_gate_a_proven_gpu_is_capped_at_its_share_of_the_index() {
        let mut state = StateAdapter::new();
        set_genesis_param(&mut state, AVAILABILITY_INDEX_CAP_KEY, 0);
        assert_eq!(
            under_index_cap(&state, 5 * TNZO, true),
            5 * TNZO,
            "no index yet"
        );
        with_index(&mut state);
        assert_eq!(index_cap_wei(&state), Some(3 * TNZO / 2));
        assert_eq!(under_index_cap(&state, 5 * TNZO, true), 3 * TNZO / 2);
        assert_eq!(under_index_cap(&state, 5 * TNZO, false), 5 * TNZO);
        assert_eq!(under_index_cap(&state, TNZO, true), TNZO);
        set_genesis_param(&mut state, AVAILABILITY_INDEX_CAP_BPS_PARAM, 5_000);
        assert_eq!(
            index_cap_wei(&state),
            Some(2 * TNZO),
            "bounded at 10% of the index"
        );
    }

    /// Before its gate the target is the atto-USD key, which cannot reach
    /// 60,000 USD a day; from it the whole-USD key sets 60,000 USD a day and
    /// the atto-USD key is no longer read.
    #[test]
    fn the_whole_usd_demand_target_holds_the_design_figure_only_from_its_gate() {
        let mut state = StateAdapter::new();
        set_genesis_param(
            &mut state,
            AVAILABILITY_REWARD_DEMAND_TARGET_ATTO_USD_PER_DAY_PARAM,
            u64::MAX,
        );
        set_genesis_param(
            &mut state,
            AVAILABILITY_REWARD_DEMAND_TARGET_USD_PER_DAY_PARAM,
            60_000,
        );
        assert_eq!(demand_target_atto_usd(&state), u128::from(u64::MAX));
        assert!(demand_target_atto_usd(&state) < 19 * 1_000_000_000_000_000_000);

        set_genesis_param(&mut state, AVAILABILITY_DEMAND_TARGET_USD_KEY, 0);
        assert_eq!(
            demand_target_atto_usd(&state),
            60_000 * 1_000_000_000_000_000_000
        );
        let gate = crate::governance::governed_param(AVAILABILITY_DEMAND_TARGET_USD_KEY).unwrap();
        assert!(crate::feature_gate::follows_convention(gate));
        assert_eq!(gate.genesis, crate::feature_gate::NEVER);
    }

    /// From the gate, settled demand of half the whole-USD target halves the
    /// reward.
    #[test]
    fn half_the_whole_usd_target_halves_the_reward() {
        let mut state = StateAdapter::new();
        set_genesis_param(&mut state, AVAILABILITY_DEMAND_TARGET_USD_KEY, 0);
        set_genesis_param(
            &mut state,
            AVAILABILITY_REWARD_DEMAND_TARGET_USD_PER_DAY_PARAM,
            60_000,
        );
        set_genesis_param(
            &mut state,
            super::super::economy::GOVERNANCE_RATE_PARAM,
            100_000_000,
        );
        set_genesis_param(
            &mut state,
            AVAILABILITY_REWARD_PER_UNIT_HOUR_PARAM,
            1_000_000,
        );
        // 30,000 USD at 0.10 USD per TNZO is 300,000 TNZO, settled in epoch 5.
        let activity = super::super::economy::EpochActivity {
            settled_value: 300_000 * 1_000_000_000_000_000_000,
            ..Default::default()
        };
        state.set_storage(
            &SYSTEM_ADDRESS,
            super::super::economy::activity_key(5).as_bytes(),
            serde_json::to_vec(&activity).unwrap(),
        );
        assert_eq!(demand_offset_bps(&state, 5), 5_000);
        assert_eq!(availability_reward_amount(&state, 5), 500_000);
    }

    /// The gate is dormant at genesis and both keys follow the convention.
    #[test]
    fn the_index_cap_gate_is_dormant_at_genesis() {
        let gate = crate::governance::governed_param(AVAILABILITY_INDEX_CAP_KEY).unwrap();
        assert!(crate::feature_gate::follows_convention(gate));
        assert_eq!(gate.genesis, crate::feature_gate::NEVER);
        let bps = crate::governance::governed_param(AVAILABILITY_INDEX_CAP_BPS_PARAM).unwrap();
        assert!(crate::feature_gate::follows_convention(bps));
        assert!(!crate::feature_gate::is_live_now(
            &StateAdapter::new(),
            AVAILABILITY_INDEX_CAP_KEY
        ));
    }

    #[test]
    fn declared_readiness_tier_defaults_to_warm_when_never_declared() {
        let state = state_adapter();
        assert_eq!(
            declared_readiness_tier(&state, "did:tenzro:machine:never-declared"),
            ReadinessTier::Warm
        );
    }

    #[test]
    fn declare_readiness_tier_requires_the_subjects_owner_to_sign() {
        let mut state = state_adapter();
        let owner = [3u8; 20];
        register_compute_bond(&mut state, "did:tenzro:machine:gpu3", owner);
        let payload = serde_json::to_vec(&serde_json::json!({
            "subject": "did:tenzro:machine:gpu3",
            "tier": 0,
        }))
        .unwrap();
        let not_the_owner = [9u8; 20];
        let err = declare_readiness_tier(&mut state, &not_the_owner, 0, &payload).unwrap_err();
        assert!(format!("{err}").contains("different account"));
        assert_eq!(
            declared_readiness_tier(&state, "did:tenzro:machine:gpu3"),
            ReadinessTier::Warm,
            "the refused declaration must not have written anything"
        );
    }

    #[test]
    fn declare_readiness_tier_rejects_an_invalid_tier_byte() {
        let mut state = state_adapter();
        let owner = [3u8; 20];
        register_compute_bond(&mut state, "did:tenzro:machine:gpu3", owner);
        let payload = serde_json::to_vec(&serde_json::json!({
            "subject": "did:tenzro:machine:gpu3",
            "tier": 5,
        }))
        .unwrap();
        assert!(declare_readiness_tier(&mut state, &owner, 0, &payload).is_err());
    }

    #[test]
    fn declare_readiness_tier_by_the_real_owner_sticks_and_reads_back() {
        let mut state = state_adapter();
        let owner = [3u8; 20];
        register_compute_bond(&mut state, "did:tenzro:machine:gpu3", owner);
        let payload = serde_json::to_vec(&serde_json::json!({
            "subject": "did:tenzro:machine:gpu3",
            "tier": 1,
        }))
        .unwrap();
        let (changes, _) = declare_readiness_tier(&mut state, &owner, 0, &payload).unwrap();
        assert_eq!(changes.len(), 1);
        assert_eq!(
            declared_readiness_tier(&state, "did:tenzro:machine:gpu3"),
            ReadinessTier::Cool
        );
    }

    #[test]
    fn readiness_tier_is_a_noop_at_genesis_bps() {
        let state = state_adapter();
        assert_eq!(
            apply_readiness_tier(&state, "did:tenzro:machine:undeclared", 1_000),
            1_000
        );
    }

    #[test]
    fn readiness_tier_scales_the_reward_once_governance_sets_it_apart() {
        let mut state = state_adapter();
        let owner = [3u8; 20];
        register_compute_bond(&mut state, "did:tenzro:machine:gpu3", owner);
        let payload = serde_json::to_vec(&serde_json::json!({
            "subject": "did:tenzro:machine:gpu3",
            "tier": 0,
        }))
        .unwrap();
        declare_readiness_tier(&mut state, &owner, 0, &payload).unwrap();
        set(&mut state, AVAILABILITY_READINESS_COLD_BPS_PARAM, 2_500);
        assert_eq!(
            apply_readiness_tier(&state, "did:tenzro:machine:gpu3", 1_000),
            250
        );
        // An untouched subject still pays the full (Warm, genesis 100%) rate.
        assert_eq!(
            apply_readiness_tier(&state, "did:tenzro:machine:someone-else", 1_000),
            1_000
        );
    }

    #[test]
    fn each_tier_is_scaled_by_its_own_governed_multiplier() {
        let mut state = state_adapter();
        let owner = [4u8; 20];
        set(&mut state, AVAILABILITY_READINESS_COLD_BPS_PARAM, 1_000);
        set(&mut state, AVAILABILITY_READINESS_COOL_BPS_PARAM, 5_000);
        set(&mut state, AVAILABILITY_READINESS_WARM_BPS_PARAM, 8_000);
        for (tier, subject, expected) in [
            (0u8, "did:tenzro:machine:gpu-cold", 100u128),
            (1, "did:tenzro:machine:gpu-cool", 500),
            (2, "did:tenzro:machine:gpu-warm", 800),
        ] {
            register_compute_bond(&mut state, subject, owner);
            let payload =
                serde_json::to_vec(&serde_json::json!({ "subject": subject, "tier": tier }))
                    .unwrap();
            declare_readiness_tier(&mut state, &owner, 0, &payload).unwrap();
            assert_eq!(
                apply_readiness_tier(&state, subject, 1_000),
                expected,
                "tier {tier}"
            );
        }
        // A subject that never declared is Warm.
        assert_eq!(
            apply_readiness_tier(&state, "did:tenzro:machine:undeclared", 1_000),
            800
        );
    }

    #[test]
    fn pay_if_available_scales_by_the_subjects_declared_readiness_tier() {
        let mut state = state_adapter();
        let owner = [3u8; 20];
        let did = bound_subject(&mut state, 3);
        register_compute_bond(&mut state, &did, owner);
        let payload = serde_json::to_vec(&serde_json::json!({
            "subject": did,
            "tier": 0,
        }))
        .unwrap();
        declare_readiness_tier(&mut state, &owner, 0, &payload).unwrap();
        set(&mut state, AVAILABILITY_READINESS_COLD_BPS_PARAM, 1_000); // 10%
        set(&mut state, AVAILABILITY_REWARD_PER_UNIT_HOUR_PARAM, 1_000);
        let treasury: [u8; 32] = super::super::derive_treasury_address()
            .as_bytes()
            .try_into()
            .unwrap();
        state.set_balance(&treasury, 10_000);
        let subject_owner = [3u8; 20];
        let mut changes = Vec::new();
        let mut logs = Vec::new();
        let paid = pay_if_available(
            &mut state,
            &did,
            &subject_owner,
            1,
            BOUND_NOW_MS,
            &mut changes,
            &mut logs,
        )
        .unwrap();
        assert_eq!(
            paid,
            Some(100),
            "10% of the 1,000 cap, per the Cold-tier multiplier"
        );
    }

    #[test]
    fn zero_cap_pays_nothing_whatever_the_decay_params_say() {
        let mut state = state_adapter();
        set(&mut state, AVAILABILITY_REWARD_DECAY_START_EPOCH_PARAM, 10);
        set(
            &mut state,
            AVAILABILITY_REWARD_DECAY_HALF_LIFE_DAYS_PARAM,
            30,
        );
        assert_eq!(availability_reward_amount(&state, 10), 0);
    }

    #[test]
    fn undecayed_cap_pays_in_full_before_and_after_the_start_epoch_when_no_half_life_is_set() {
        let mut state = state_adapter();
        set(&mut state, AVAILABILITY_REWARD_PER_UNIT_HOUR_PARAM, 1_000);
        assert_eq!(availability_reward_amount(&state, 0), 1_000);
        assert_eq!(availability_reward_amount(&state, 1_000_000), 1_000);
    }

    #[test]
    fn decay_has_not_started_before_the_governed_start_epoch() {
        let mut state = state_adapter();
        set(&mut state, AVAILABILITY_REWARD_PER_UNIT_HOUR_PARAM, 1_000);
        set(
            &mut state,
            AVAILABILITY_REWARD_DECAY_HALF_LIFE_DAYS_PARAM,
            30,
        );
        set(
            &mut state,
            AVAILABILITY_REWARD_DECAY_START_EPOCH_PARAM,
            1_000,
        );
        assert_eq!(availability_reward_amount(&state, 999), 1_000);
    }

    #[test]
    fn decay_halves_at_every_half_life_and_keeps_halving_past_the_second_one() {
        let mut state = state_adapter();
        set(&mut state, AVAILABILITY_REWARD_PER_UNIT_HOUR_PARAM, 1_000);
        set(
            &mut state,
            AVAILABILITY_REWARD_DECAY_HALF_LIFE_DAYS_PARAM,
            1,
        );
        set(&mut state, AVAILABILITY_REWARD_DECAY_START_EPOCH_PARAM, 100);
        let half_life_epochs = 24;
        // A true half-life never clamps to zero at 2x -- it keeps halving.
        assert_eq!(availability_reward_amount(&state, 100), 1_000);
        assert_eq!(
            availability_reward_amount(&state, 100 + half_life_epochs),
            500
        );
        assert_eq!(
            availability_reward_amount(&state, 100 + 2 * half_life_epochs),
            250
        );
        assert_eq!(
            availability_reward_amount(&state, 100 + 3 * half_life_epochs),
            125
        );
    }

    #[test]
    fn decay_interpolates_linearly_between_two_halving_points() {
        let mut state = state_adapter();
        set(&mut state, AVAILABILITY_REWARD_PER_UNIT_HOUR_PARAM, 1_000);
        set(
            &mut state,
            AVAILABILITY_REWARD_DECAY_HALF_LIFE_DAYS_PARAM,
            1,
        );
        set(&mut state, AVAILABILITY_REWARD_DECAY_START_EPOCH_PARAM, 100);
        let half_life_epochs = 24;
        // Halfway between the 1,000 and 500 halving points.
        assert_eq!(
            availability_reward_amount(&state, 100 + half_life_epochs / 2),
            750
        );
    }

    #[test]
    fn decay_eventually_reaches_zero_after_enough_halvings_of_a_u64_cap() {
        let mut state = state_adapter();
        set(
            &mut state,
            AVAILABILITY_REWARD_PER_UNIT_HOUR_PARAM,
            MAX_AVAILABILITY_REWARD_PER_UNIT_HOUR,
        );
        set(
            &mut state,
            AVAILABILITY_REWARD_DECAY_HALF_LIFE_DAYS_PARAM,
            1,
        );
        set(&mut state, AVAILABILITY_REWARD_DECAY_START_EPOCH_PARAM, 0);
        // AVAILABILITY_REWARD_DECAY_START_EPOCH_PARAM genesis of 0 means
        // "not scheduled"; set it to a real epoch instead.
        set(&mut state, AVAILABILITY_REWARD_DECAY_START_EPOCH_PARAM, 1);
        let half_life_epochs = 24u64;
        assert_eq!(
            availability_reward_amount(&state, 1 + 100 * half_life_epochs),
            0,
            "a u64 cap cannot survive 100 halvings"
        );
    }

    /// The sizing rule docs/ECONOMICS.md gives for a flat market, where only
    /// calendar decay binds: everything one unit can ever be paid is about
    /// 1.5 half-lives of the cap (each halving interval pays three quarters
    /// of the cap it starts at), so 36 x half-life in days x the hourly cap.
    #[test]
    fn calendar_decay_alone_pays_one_unit_at_most_one_and_a_half_half_lives_of_the_cap() {
        let cap: u128 = 1_000_000;
        for half_life_days in [1u64, 10, 90] {
            let h = half_life_days * 24;
            let total: u128 = (0..h * 60).map(|e| halving_decay(cap, e, h)).sum();
            let rule = 36 * u128::from(half_life_days) * cap;
            assert!(total <= rule + cap, "{half_life_days}d: {total} > {rule}");
            assert!(
                total * 1_000 >= rule * 995,
                "{half_life_days}d: {total} << {rule}"
            );
        }
    }

    #[test]
    fn halving_decay_matches_a_hand_computed_table() {
        assert_eq!(halving_decay(1_000, 0, 24), 1_000);
        assert_eq!(halving_decay(1_000, 12, 24), 750);
        assert_eq!(halving_decay(1_000, 24, 24), 500);
        assert_eq!(halving_decay(1_000, 36, 24), 375);
        assert_eq!(halving_decay(1_000, 48, 24), 250);
        assert_eq!(halving_decay(0, 10, 24), 0);
        assert_eq!(
            halving_decay(1_000, 10, 0),
            0,
            "a zero half-life is degenerate, not infinite"
        );
    }

    #[test]
    fn demand_offset_disabled_at_genesis_pays_the_full_decayed_cap() {
        let mut state = state_adapter();
        set(&mut state, AVAILABILITY_REWARD_PER_UNIT_HOUR_PARAM, 1_000);
        seed_epoch_activity(&mut state, 5, 999_999_999_999_999_999);
        assert_eq!(availability_reward_amount(&state, 5), 1_000);
    }

    #[test]
    fn demand_offset_halves_the_reward_at_half_the_target() {
        let mut state = state_adapter();
        set(&mut state, AVAILABILITY_REWARD_PER_UNIT_HOUR_PARAM, 1_000);
        set(
            &mut state,
            AVAILABILITY_REWARD_DEMAND_TARGET_ATTO_USD_PER_DAY_PARAM,
            1_000_000,
        );
        let target_wei = super::super::economy::usd_to_wei(&state, 1_000_000);
        assert!(
            target_wei > 0,
            "the genesis rate feed must convert a nonzero target"
        );
        seed_epoch_activity(&mut state, 5, target_wei / 2);
        assert_eq!(availability_reward_amount(&state, 5), 500);
    }

    #[test]
    fn demand_offset_reaches_zero_at_or_above_the_target() {
        let mut state = state_adapter();
        set(&mut state, AVAILABILITY_REWARD_PER_UNIT_HOUR_PARAM, 1_000);
        set(
            &mut state,
            AVAILABILITY_REWARD_DEMAND_TARGET_ATTO_USD_PER_DAY_PARAM,
            1_000_000,
        );
        let target_wei = super::super::economy::usd_to_wei(&state, 1_000_000);
        seed_epoch_activity(&mut state, 5, target_wei);
        assert_eq!(availability_reward_amount(&state, 5), 0);
        seed_epoch_activity(&mut state, 5, target_wei.saturating_mul(5));
        assert_eq!(
            availability_reward_amount(&state, 5),
            0,
            "overshooting the target must not wrap or pay a negative-as-huge amount"
        );
    }

    #[test]
    fn demand_offset_sums_settled_value_over_the_governed_window_and_nothing_outside_it() {
        let mut state = state_adapter();
        set(&mut state, AVAILABILITY_REWARD_PER_UNIT_HOUR_PARAM, 1_000);
        set(
            &mut state,
            AVAILABILITY_REWARD_DEMAND_TARGET_ATTO_USD_PER_DAY_PARAM,
            1_000_000,
        );
        set(
            &mut state,
            AVAILABILITY_REWARD_DEMAND_WINDOW_EPOCHS_PARAM,
            3,
        );
        let target_wei = super::super::economy::usd_to_wei(&state, 1_000_000);
        let third = target_wei / 3;
        // Window for epoch 5, width 3, is epochs {3, 4, 5}.
        seed_epoch_activity(&mut state, 3, third);
        seed_epoch_activity(&mut state, 4, third);
        seed_epoch_activity(&mut state, 5, target_wei - 2 * third);
        assert_eq!(availability_reward_amount(&state, 5), 0);
        // Epoch 2 is outside that window; piling demand onto it must not
        // change the epoch-5 reward at all.
        seed_epoch_activity(&mut state, 2, target_wei.saturating_mul(1_000));
        assert_eq!(
            availability_reward_amount(&state, 5),
            0,
            "epoch 2 is outside the 3-wide window ending at 5"
        );
        // And emptying epoch 3 back out should bring the reward back up
        // (confirms the window tracks real state, not a cached total).
        seed_epoch_activity(&mut state, 3, 0);
        let reward = availability_reward_amount(&state, 5);
        assert!(
            reward > 0 && reward < 1_000,
            "paid demand dropped by a third of the target, so the reward must rise \
             above zero but stay under the undecayed cap: got {reward}"
        );
    }

    #[test]
    fn decay_never_increases_as_epochs_pass() {
        let mut state = state_adapter();
        set(&mut state, AVAILABILITY_REWARD_PER_UNIT_HOUR_PARAM, 999);
        set(
            &mut state,
            AVAILABILITY_REWARD_DECAY_HALF_LIFE_DAYS_PARAM,
            7,
        );
        set(&mut state, AVAILABILITY_REWARD_DECAY_START_EPOCH_PARAM, 1);
        let mut last = u128::from(u64::MAX);
        for epoch in 1..2_000u64 {
            let now = availability_reward_amount(&state, epoch);
            assert!(now <= last, "epoch {epoch}: {now} > {last}");
            last = now;
        }
    }

    #[test]
    fn pay_if_available_moves_treasury_balance_to_the_subject_and_logs_it() {
        let mut state = state_adapter();
        let did = bound_subject(&mut state, 7);
        set(&mut state, AVAILABILITY_REWARD_PER_UNIT_HOUR_PARAM, 1_000);
        let treasury: [u8; 32] = super::super::derive_treasury_address()
            .as_bytes()
            .try_into()
            .unwrap();
        state.set_balance(&treasury, 10_000);
        let subject = [7u8; 32];
        let mut changes = Vec::new();
        let mut logs = Vec::new();
        let paid = pay_if_available(
            &mut state,
            &did,
            &subject,
            1,
            BOUND_NOW_MS,
            &mut changes,
            &mut logs,
        )
        .unwrap();
        // The treasury pays out the full reward either way; with no
        // CLAIM_LIQUID_PARAM override the genesis 25%/75% earned-reward
        // split applies, same as a reward-coupon claim.
        assert_eq!(paid, Some(1_000));
        assert_eq!(state.get_balance(&treasury), 9_000);
        assert_eq!(
            state.get_balance(&subject),
            250,
            "25% liquid at the genesis split"
        );
        let schedules =
            super::super::rewards::read_vesting(&state, &Address::new(subject)).unwrap();
        assert_eq!(schedules.len(), 1);
        assert_eq!(schedules[0].total, 750, "the remaining 75% vests");
        assert_eq!(schedules[0].released, 0);
        assert_eq!(schedules[0].cliff_ms, 0);
        assert_eq!(schedules[0].start_ms, BOUND_NOW_MS);
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].topics[0], AVAILABILITY_REWARD_TOPIC.to_vec());
    }

    #[test]
    fn pay_if_available_honors_a_governed_split_and_vesting_duration() {
        let mut state = state_adapter();
        let did = bound_subject(&mut state, 9);
        set(&mut state, AVAILABILITY_REWARD_PER_UNIT_HOUR_PARAM, 10_000);
        set(&mut state, super::super::rewards::CLAIM_LIQUID_PARAM, 3_000);
        set(
            &mut state,
            super::super::rewards::CLAIM_VESTING_PARAM,
            864_000_000,
        );
        let treasury: [u8; 32] = super::super::derive_treasury_address()
            .as_bytes()
            .try_into()
            .unwrap();
        state.set_balance(&treasury, 10_000);
        let subject = [9u8; 32];
        let mut changes = Vec::new();
        let mut logs = Vec::new();
        let paid = pay_if_available(
            &mut state,
            &did,
            &subject,
            1,
            BOUND_NOW_MS,
            &mut changes,
            &mut logs,
        )
        .unwrap();
        assert_eq!(paid, Some(10_000));
        assert_eq!(
            state.get_balance(&subject),
            3_000,
            "30% liquid, as governed"
        );
        let schedules =
            super::super::rewards::read_vesting(&state, &Address::new(subject)).unwrap();
        assert_eq!(schedules.len(), 1);
        assert_eq!(schedules[0].total, 7_000);
        assert_eq!(schedules[0].duration_ms, 864_000_000);
        assert_eq!(
            schedules[0].vested_at(BOUND_NOW_MS),
            0,
            "nothing is vested the instant the schedule opens"
        );
        assert_eq!(
            schedules[0].vested_at(BOUND_NOW_MS + 864_000_000),
            7_000,
            "fully vested after the governed duration"
        );
    }

    #[test]
    fn a_20_byte_role_stake_owner_pays_fully_liquid_since_it_has_no_vesting_address() {
        let mut state = state_adapter();
        let did = bound_subject(&mut state, 8);
        set(&mut state, AVAILABILITY_REWARD_PER_UNIT_HOUR_PARAM, 1_000);
        // Default genesis split would vest 75% of a real Address; a 20-byte
        // compute/role-stake owner (the common case: see
        // `provider_address` in the ComputeBond marker) has no such
        // address, so the whole reward must stay liquid.
        let treasury: [u8; 32] = super::super::derive_treasury_address()
            .as_bytes()
            .try_into()
            .unwrap();
        state.set_balance(&treasury, 10_000);
        let subject_owner = [8u8; 20];
        let mut changes = Vec::new();
        let mut logs = Vec::new();
        let paid = pay_if_available(
            &mut state,
            &did,
            &subject_owner,
            1,
            BOUND_NOW_MS,
            &mut changes,
            &mut logs,
        )
        .unwrap();
        assert_eq!(paid, Some(1_000));
        assert_eq!(state.get_balance(subject_owner.as_slice()), 1_000);
        assert_eq!(state.get_balance(&treasury), 9_000);
        assert_eq!(logs.len(), 1);
    }

    /// The reward carries no proposal, so the treasury's outflow period caps
    /// it: once the period's share of the balance is paid, the next verdict's
    /// reward is forfeited, not forced.
    #[test]
    fn the_reward_is_forfeited_once_the_treasury_outflow_period_is_spent() {
        let mut state = state_adapter();
        // The fixtures raise the cap; this test sets the genesis 3%.
        set(
            &mut state,
            crate::governance::MAX_PERIOD_OUTFLOW_PARAM,
            crate::governance::MAX_PERIOD_OUTFLOW_BPS,
        );
        let did = bound_subject(&mut state, 9);
        set(&mut state, AVAILABILITY_REWARD_PER_UNIT_HOUR_PARAM, 1_000);
        let treasury: [u8; 32] = super::super::derive_treasury_address()
            .as_bytes()
            .try_into()
            .unwrap();
        // 3% of 100,000 is 3,000: three rewards of 1,000.
        state.set_balance(&treasury, 100_000);
        let owner = [9u8; 20];
        let mut paid = Vec::new();
        for epoch in 1..=4 {
            paid.push(
                pay_if_available(
                    &mut state,
                    &did,
                    &owner,
                    epoch,
                    BOUND_NOW_MS,
                    &mut Vec::new(),
                    &mut Vec::new(),
                )
                .unwrap(),
            );
        }
        assert_eq!(paid, [Some(1_000), Some(1_000), Some(1_000), None]);
        assert_eq!(state.get_balance(&treasury), 97_000);
        assert_eq!(state.get_balance(owner.as_slice()), 3_000);
    }

    /// With hardware binding off the reward pays nothing, whatever its other
    /// parameters say, to an unregistered identity and to a TPM-endorsed
    /// machine alike: an uptime reward nothing ties to a real machine is
    /// paid to made-up supply.
    #[test]
    fn hardware_binding_off_pays_nothing_whatever_the_other_parameters() {
        let mut state = state_adapter();
        let endorsed = register_endorsed_machine(&mut state, 12);
        set(&mut state, AVAILABILITY_REWARD_PER_UNIT_HOUR_PARAM, 1_000);
        assert_eq!(
            network_param(&state, AVAILABILITY_REWARD_REQUIRE_HARDWARE_PARAM),
            0
        );
        let treasury: [u8; 32] = super::super::derive_treasury_address()
            .as_bytes()
            .try_into()
            .unwrap();
        state.set_balance(&treasury, 10_000);
        for did in ["did:tenzro:machine:unregistered", endorsed.as_str()] {
            let subject = [7u8; 32];
            let mut changes = Vec::new();
            let mut logs = Vec::new();
            let paid = pay_if_available(
                &mut state,
                did,
                &subject,
                1,
                BOUND_NOW_MS,
                &mut changes,
                &mut logs,
            )
            .unwrap();
            assert_eq!(paid, None, "{did}");
            assert!(logs.is_empty(), "{did}");
            assert_eq!(state.get_balance(&subject), 0, "{did}");
        }
        assert_eq!(state.get_balance(&treasury), 10_000);
    }

    #[test]
    fn hardware_binding_required_forfeits_an_unendorsed_subject() {
        let mut state = state_adapter();
        set(&mut state, AVAILABILITY_REWARD_PER_UNIT_HOUR_PARAM, 1_000);
        set(&mut state, AVAILABILITY_REWARD_REQUIRE_HARDWARE_PARAM, 1);
        let treasury: [u8; 32] = super::super::derive_treasury_address()
            .as_bytes()
            .try_into()
            .unwrap();
        state.set_balance(&treasury, 10_000);
        let subject = [7u8; 32];
        let mut changes = Vec::new();
        let mut logs = Vec::new();
        let paid = pay_if_available(
            &mut state,
            "did:tenzro:machine:never-registered",
            &subject,
            1,
            5_000,
            &mut changes,
            &mut logs,
        )
        .unwrap();
        assert_eq!(paid, None);
        assert_eq!(state.get_balance(&treasury), 10_000, "nothing moved");
        assert_eq!(state.get_balance(&subject), 0);
        assert!(logs.is_empty());
    }

    #[test]
    fn hardware_binding_required_pays_a_tpm_endorsed_machine() {
        let mut state = state_adapter();
        let did = register_endorsed_machine(&mut state, 11);
        set(&mut state, AVAILABILITY_REWARD_PER_UNIT_HOUR_PARAM, 1_000);
        set(&mut state, AVAILABILITY_REWARD_REQUIRE_HARDWARE_PARAM, 1);
        earn_paid_work(&mut state, &[11u8; 32]);
        let treasury: [u8; 32] = super::super::derive_treasury_address()
            .as_bytes()
            .try_into()
            .unwrap();
        state.set_balance(&treasury, 10_000);
        let subject = [11u8; 32];
        let mut changes = Vec::new();
        let mut logs = Vec::new();
        // Inside the test root cert's validity window
        // (`tenzro_tee::tpm_attest::tests::NOW` is 1_800_000_000 seconds).
        let now_ms = 1_800_000_000_000;
        let paid = pay_if_available(
            &mut state,
            &did,
            &subject,
            1,
            now_ms,
            &mut changes,
            &mut logs,
        )
        .unwrap();
        assert_eq!(paid, Some(1_000));
        assert_eq!(logs.len(), 1);
    }

    /// A hardware-bound operator is paid for being available only while its
    /// owner has earned the governed minimum of provider work within the
    /// governed window of reward epochs, or while the bootstrap period runs.
    /// Once the gate is live both are in force: an operator nobody pays earns
    /// nothing, and neither does one paid a token amount.
    #[test]
    fn an_operator_without_enough_recent_paid_work_earns_no_availability_reward() {
        use crate::native::rewards;
        use tenzro_token::rewards::WorkClass;
        let now_ms = BOUND_NOW_MS;
        let subject = [11u8; 32];
        let least = u128::from(DEFAULT_AVAILABILITY_REWARD_MIN_PAID_WORK);
        let treasury: [u8; 32] = super::super::derive_treasury_address()
            .as_bytes()
            .try_into()
            .unwrap();
        let fresh = || {
            let mut state = state_adapter();
            let did = register_endorsed_machine(&mut state, 11);
            set(&mut state, AVAILABILITY_REWARD_PER_UNIT_HOUR_PARAM, 1_000);
            set(&mut state, AVAILABILITY_REWARD_REQUIRE_HARDWARE_PARAM, 1);
            set(&mut state, AVAILABILITY_PAID_ACTIVITY_GATE, 0);
            state.set_balance(&treasury, 10_000);
            (state, did)
        };
        let pay = |state: &mut StateAdapter, did: &str, owner: &[u8]| {
            pay_if_available(
                state,
                did,
                owner,
                1,
                now_ms,
                &mut Vec::new(),
                &mut Vec::new(),
            )
            .unwrap()
        };
        let earn = |state: &mut StateAdapter, who: [u8; 32], class, weight: u128| {
            rewards::record_settled_work(state, Address::new(who), class, weight, &mut Vec::new())
                .unwrap()
        };
        let genesis = state_adapter();
        assert_eq!(
            network_param(&genesis, AVAILABILITY_REWARD_PAID_ACTIVITY_EPOCHS_PARAM),
            DEFAULT_AVAILABILITY_REWARD_PAID_ACTIVITY_EPOCHS
        );
        assert_eq!(
            network_param(&genesis, AVAILABILITY_REWARD_MIN_PAID_WORK_PARAM),
            DEFAULT_AVAILABILITY_REWARD_MIN_PAID_WORK
        );

        // No paid work: nothing, and nothing leaves the treasury.
        let (mut state, did) = fresh();
        assert_eq!(pay(&mut state, &did, &subject), None);
        assert_eq!(state.get_balance(&treasury), 10_000);

        // Before the gate is live the requirement is not in force.
        let (mut state, did) = fresh();
        set(
            &mut state,
            AVAILABILITY_PAID_ACTIVITY_GATE,
            crate::feature_gate::NEVER,
        );
        assert_eq!(pay(&mut state, &did, &subject), Some(1_000));
        assert_eq!(
            crate::feature_gate::activation_epoch(&genesis, AVAILABILITY_PAID_ACTIVITY_GATE),
            crate::feature_gate::NEVER
        );

        // A token payment's worth of work is below the minimum; the rest of
        // the minimum, earned in two payments, reaches it.
        let (mut state, did) = fresh();
        earn(&mut state, subject, WorkClass::InferenceServed, 1);
        assert_eq!(pay(&mut state, &did, &subject), None);
        earn(&mut state, subject, WorkClass::InferenceServed, least - 2);
        assert_eq!(pay(&mut state, &did, &subject), None);
        earn(&mut state, subject, WorkClass::InferenceServed, 1);
        assert_eq!(pay(&mut state, &did, &subject), Some(1_000));

        // Work that is not provider work, and another account's provider
        // work, do not count.
        let (mut state, did) = fresh();
        earn(&mut state, subject, WorkClass::AppUsage, least);
        earn(&mut state, [12u8; 32], WorkClass::InferenceServed, least);
        assert_eq!(pay(&mut state, &did, &subject), None);

        // A 20-byte owner is the account its address names.
        let (mut state, did) = fresh();
        let short = [11u8; 20];
        earn(
            &mut state,
            crate::native::pad_address_32(&short).unwrap(),
            WorkClass::InferenceServed,
            least,
        );
        assert_eq!(pay(&mut state, &did, &short), Some(1_000));

        // The bootstrap period waives the requirement until its epoch.
        let (mut state, did) = fresh();
        set(
            &mut state,
            AVAILABILITY_REWARD_BOOTSTRAP_UNTIL_EPOCH_PARAM,
            1,
        );
        assert_eq!(pay(&mut state, &did, &subject), Some(1_000));

        // A zero window asks for no paid activity.
        let (mut state, did) = fresh();
        set(
            &mut state,
            AVAILABILITY_REWARD_PAID_ACTIVITY_EPOCHS_PARAM,
            0,
        );
        assert_eq!(pay(&mut state, &did, &subject), Some(1_000));
    }

    fn pay(state: &mut StateAdapter, did: &str, seed: u8, epoch: u64) -> Option<u128> {
        let mut changes = Vec::new();
        pay_if_available(
            state,
            did,
            &[seed; 32],
            epoch,
            1_800_000_000_000,
            &mut changes,
            &mut Vec::new(),
        )
        .unwrap()
    }

    fn funded(state: &mut StateAdapter) {
        let treasury: [u8; 32] = super::super::derive_treasury_address()
            .as_bytes()
            .try_into()
            .unwrap();
        state.set_balance(&treasury, 1_000_000_000);
    }

    #[test]
    fn the_unit_budget_is_dormant_at_genesis_and_counts_no_units() {
        let mut state = state_adapter();
        funded(&mut state);
        let did = bound_subject(&mut state, 21);
        set(&mut state, AVAILABILITY_REWARD_PER_UNIT_HOUR_PARAM, 1_000);
        set(&mut state, UNIT_BUDGET_DEMAND_BPS_PARAM, 10_000);
        assert_eq!(
            pay(&mut state, &did, 21, 5),
            Some(1_000),
            "the schedule pays"
        );
        assert_eq!(verified_units(&state, 5), 0);
    }

    #[test]
    fn a_live_unit_budget_splits_demand_equally_over_last_hours_units() {
        let mut state = state_adapter();
        funded(&mut state);
        let a = bound_subject(&mut state, 22);
        let b = bound_subject(&mut state, 23);
        set(&mut state, UNIT_BUDGET_KEY, 0);
        set(
            &mut state,
            AVAILABILITY_REWARD_PER_UNIT_HOUR_PARAM,
            1_000_000,
        );
        set(
            &mut state,
            AVAILABILITY_REWARD_DEMAND_WINDOW_EPOCHS_PARAM,
            1,
        );
        set(&mut state, UNIT_BUDGET_DEMAND_BPS_PARAM, 1_000);
        // Hour 4: one unit verified, no demand yet, so nothing is paid.
        seed_epoch_activity(&mut state, 4, 0);
        assert_eq!(pay(&mut state, &a, 22, 4), None);
        assert_eq!(verified_units(&state, 4), 1);
        // Hour 5: 80,000 settled, a 10% budget of 8,000 over the one unit
        // hour 4 verified.
        seed_epoch_activity(&mut state, 5, 80_000);
        assert_eq!(pay(&mut state, &a, 22, 5), Some(8_000));
        assert_eq!(pay(&mut state, &b, 23, 5), Some(8_000));
        assert_eq!(verified_units(&state, 5), 2);
        // Hour 6: the same budget over hour 5's two units.
        seed_epoch_activity(&mut state, 6, 80_000);
        assert_eq!(pay(&mut state, &a, 22, 6), Some(4_000));
        // Hour 4's count is gone once hour 6 is counted.
        assert_eq!(verified_units(&state, 4), 0);
        // Never above the decayed cap.
        set(&mut state, AVAILABILITY_REWARD_PER_UNIT_HOUR_PARAM, 3_000);
        assert_eq!(pay(&mut state, &b, 23, 6), Some(3_000));
    }

    #[test]
    fn an_underfunded_treasury_forfeits_the_reward_rather_than_erroring() {
        let mut state = state_adapter();
        let did = bound_subject(&mut state, 7);
        set(&mut state, AVAILABILITY_REWARD_PER_UNIT_HOUR_PARAM, 1_000);
        let treasury: [u8; 32] = super::super::derive_treasury_address()
            .as_bytes()
            .try_into()
            .unwrap();
        state.set_balance(&treasury, 1); // short of the 1,000 reward
        let subject = [7u8; 32];
        let mut changes = Vec::new();
        let mut logs = Vec::new();
        let paid = pay_if_available(
            &mut state,
            &did,
            &subject,
            1,
            BOUND_NOW_MS,
            &mut changes,
            &mut logs,
        )
        .unwrap();
        assert_eq!(paid, None);
        assert_eq!(
            state.get_balance(&treasury),
            1,
            "an underfunded pool is untouched"
        );
        assert_eq!(state.get_balance(&subject), 0);
        assert!(logs.is_empty());
        assert!(
            super::super::rewards::read_vesting(&state, &Address::new(subject))
                .unwrap()
                .is_empty()
        );
    }

    /// Every readiness tier is available above half its probes until the
    /// gate is live; then each tier is judged against its own SLA.
    #[test]
    fn each_readiness_tier_has_its_own_sla_once_live() {
        let mut state = state_adapter();
        let (cold, warm) = ("did:tenzro:machine:cold", "did:tenzro:machine:warm");
        state.set_storage(
            &SYSTEM_ADDRESS,
            readiness_tier_key(cold).as_bytes(),
            vec![ReadinessTier::Cold as u8],
        );
        set_genesis_param(&mut state, SLA_COLD_AVAILABLE_BPS_PARAM, 9_000);

        // Dormant: more than half.
        assert!(meets_sla(&state, cold, 6, 4));

        set_genesis_param(&mut state, SLA_TIERS_GATE, 0);
        assert!(
            !meets_sla(&state, cold, 9, 1),
            "exactly the SLA is not above it"
        );
        assert!(meets_sla(&state, cold, 10, 0));
        assert!(meets_sla(&state, warm, 6, 4));
        assert!(!meets_sla(&state, warm, 0, 0), "no probe proves nothing");
    }

    /// A machine on a firmware TPM earns the firmware tier's share of the
    /// availability reward once the tier is live, and the whole reward
    /// before; a discrete chip earns the whole reward either way.
    #[test]
    fn a_firmware_tpm_earns_the_lower_tier_once_live() {
        let paid = |manufacturer: &str, live: bool| {
            let mut state = state_adapter();
            set(&mut state, AVAILABILITY_REWARD_REQUIRE_HARDWARE_PARAM, 1);
            set(&mut state, AVAILABILITY_REWARD_PER_UNIT_HOUR_PARAM, 1_000);
            if live {
                set_genesis_param(&mut state, FIRMWARE_TPM_TIER_GATE, 0);
            }
            let did = register_endorsed_machine_from(&mut state, 21, Some(manufacturer));
            let treasury: [u8; 32] = super::super::derive_treasury_address()
                .as_bytes()
                .try_into()
                .unwrap();
            state.set_balance(&treasury, 1_000_000);
            pay_if_available(
                &mut state,
                &did,
                &[7u8; 32],
                1,
                BOUND_NOW_MS,
                &mut Vec::new(),
                &mut Vec::new(),
            )
            .unwrap()
            .unwrap()
        };
        let (intel, infineon) = ("id:494E5443", "id:49465800");
        let whole = paid(infineon, false);
        assert!(whole > 0);
        assert_eq!(paid(intel, false), whole);
        assert_eq!(paid(infineon, true), whole);
        assert_eq!(
            paid(intel, true),
            whole * u128::from(DEFAULT_AVAILABILITY_FIRMWARE_TPM_BPS) / 10_000
        );
    }
}
