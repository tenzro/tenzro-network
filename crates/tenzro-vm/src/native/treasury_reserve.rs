//! The running-cost reserve: a keyless vault beside the treasury that pays
//! the network's running costs.
//!
//! No amount here is fixed. The reserve may start empty, the treasury may
//! start empty, and every flow follows from chain state and governed
//! parameters, applied at epoch boundaries by every node alike:
//!
//! - Inflow. At each epoch boundary `treasury.reserve_fill_share_bps` of the
//!   fee revenue the treasury realised since the last boundary moves from the
//!   treasury into the reserve, while the reserve is under its target and
//!   only as far as the target.
//! - Target. `treasury.reserve_target_months` months of observed running
//!   cost: the larger of what the reserve paid over the trailing month and
//!   what the trailing month's revenue allowed it to pay.
//! - Outflow. An enacted `RunningCostPayment` joins a queue, paid in order at
//!   epoch boundaries. One epoch pays at most the least of: the trailing
//!   month's allowance (`treasury.running_cost_revenue_share_bps` of the
//!   month's realised fee revenue plus `treasury.reserve_drawdown_bps` of the
//!   reserve balance, less what the month already paid); the epoch's sale cap
//!   (`treasury.sale_volume_share_bps` of the TNZO the market traded in an
//!   epoch, from the validators' sealed volume reports, zero without a recent
//!   one); and the reserve balance.
//!
//! An empty reserve, an empty treasury, a month without revenue or a market
//! without volume pays nothing and waits: nothing is refused, nothing goes
//! negative, no block is held up.

use serde::{Deserialize, Serialize};

use super::funding::{delete_record, move_balance, read_json, refuse, write_json};
use super::*;

/// Governed: share of the treasury's realised fee revenue moved into the
/// reserve at each epoch boundary while it is under its target, bps.
pub const FILL_SHARE_PARAM: &str = "treasury.reserve_fill_share_bps";
/// Governed: the reserve's target, in months of observed running cost.
pub const TARGET_MONTHS_PARAM: &str = "treasury.reserve_target_months";
/// Governed: the reserve balance, bps of its target, under which
/// discretionary treasury grants and tranche releases are refused.
pub const GRANT_FLOOR_PARAM: &str = "treasury.grant_reserve_floor_bps";
/// Genesis value of [`GRANT_FLOOR_PARAM`]: half the target.
pub const DEFAULT_GRANT_FLOOR_BPS: u64 = 5_000;
/// Governed: share of the trailing month's realised fee revenue running
/// costs may use in that month, bps.
pub const REVENUE_SHARE_PARAM: &str = "treasury.running_cost_revenue_share_bps";
/// Governed: share of the reserve balance running costs may draw in a
/// trailing month beyond the revenue share, bps.
pub const DRAWDOWN_PARAM: &str = "treasury.reserve_drawdown_bps";
/// Governed: epochs one accounting month spans.
pub const MONTH_EPOCHS_PARAM: &str = "treasury.month_epochs";
/// Governed: most the reserve pays out in one epoch, bps of the TNZO the
/// market traded in an epoch.
pub const SALE_VOLUME_SHARE_PARAM: &str = "treasury.sale_volume_share_bps";
/// Governed key: most the running-cost reserve pays out in one epoch, whole
/// TNZO, whatever the volume reports say.
pub const MAX_SALE_PARAM: &str = "treasury.max_sale_tnzo_epoch";
/// Governed: market epochs a volume report stays usable; an older one counts
/// as no volume.
pub const VOLUME_MAX_AGE_PARAM: &str = "treasury.volume_max_age_epochs";
/// Governed: market epochs of volume reports the sale cap takes the lowest
/// of, so a sale sized from them does not outrun a falling market.
pub const VOLUME_WINDOW_PARAM: &str = "treasury.volume_window_epochs";
/// Governed: epochs an enacted running-cost payment stays payable; what is
/// unpaid by then lapses, so a payment sized at one price is never paid out
/// at a much later one.
pub const PAYMENT_TTL_PARAM: &str = "treasury.payment_ttl_epochs";

/// Genesis values of the governed parameters above.
pub const DEFAULT_FILL_SHARE_BPS: u64 = 5_000;
pub const DEFAULT_TARGET_MONTHS: u64 = 12;
pub const DEFAULT_REVENUE_SHARE_BPS: u64 = 3_000;
pub const DEFAULT_DRAWDOWN_BPS: u64 = 300;
pub const DEFAULT_MONTH_EPOCHS: u64 = 720;
pub const DEFAULT_SALE_VOLUME_SHARE_BPS: u64 = 500;
pub const DEFAULT_MAX_SALE_TNZO_EPOCH: u64 = 10_000;
pub const DEFAULT_VOLUME_MAX_AGE_EPOCHS: u64 = 6;
pub const DEFAULT_PAYMENT_TTL_EPOCHS: u64 = 720;
pub const DEFAULT_VOLUME_WINDOW_EPOCHS: u64 = 168;
/// Most market epochs governance may set the volume window to: a month of
/// hourly epochs.
pub const MAX_VOLUME_WINDOW_EPOCHS: u64 = 720;

/// Most payments the queue holds; enactment beyond it is refused.
pub const QUEUE_CAPACITY: usize = 64;
/// Most epochs one boundary scans for revenue it has not yet seen, so a
/// long gap between blocks costs a bounded read. It also bounds the trailing
/// month, so no boundary reads the flows of an epoch this far behind it, and
/// each boundary deletes those.
const MAX_SCAN_EPOCHS: u64 = 8_760;

const BOOK_KEY: &str = "treasury_reserve_book";
const QUEUE_KEY: &str = "treasury_reserve_queue";
const VAULT_DOMAIN: &[u8] = b"tenzro/treasury/running-cost-reserve";

/// Topic of the log a running-cost payout emits.
pub const RESERVE_PAYOUT_TOPIC: &[u8] = b"RunningCostPaid";

mod u128_string {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &u128, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&v.to_string())
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> std::result::Result<u128, D::Error> {
        String::deserialize(d)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

/// The reserve vault: `Address(SHA-256("tenzro/treasury/running-cost-reserve"))`.
/// Nothing can sign for it; only the rules in this module move its balance.
pub fn reserve_address() -> Address {
    let digest = Sha256::digest(VAULT_DOMAIN);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    Address::new(out)
}

/// What the treasury realised and the reserve paid in one epoch.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochFlows {
    /// Fee revenue credited to the treasury, wei.
    #[serde(with = "u128_string")]
    pub revenue: u128,
    /// Running costs the reserve paid, wei.
    #[serde(with = "u128_string")]
    pub paid: u128,
}

fn flows_key(epoch: u64) -> String {
    format!("treasury_reserve_epoch:{epoch:016x}")
}

/// The flows recorded for `epoch`.
pub fn read_flows(state: &dyn VmState, epoch: u64) -> EpochFlows {
    read_json(state, &flows_key(epoch)).unwrap_or_default()
}

/// Refuses a discretionary grant while the running-cost reserve holds less
/// than `treasury.grant_reserve_floor_bps` of the target set at the last
/// boundary. A reserve with no target yet (no running cost observed) has no
/// floor.
pub fn check_grant_floor(state: &dyn VmState) -> Result<()> {
    let target = read_book(state).target;
    let floor = bps(target, network_param(state, GRANT_FLOOR_PARAM));
    let held = state.get_balance(reserve_address().as_bytes());
    if held < floor {
        return Err(refuse(format!(
            "treasury grants wait while the running-cost reserve holds {held} wei, under its floor of {floor} ({} bps of its {target} target)",
            network_param(state, GRANT_FLOOR_PARAM).min(10_000)
        )));
    }
    Ok(())
}

/// The reserve's accounts as of the last epoch boundary.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReserveBook {
    /// Epoch of the last boundary processed; `None` before the first.
    pub epoch: Option<u64>,
    /// Fee revenue the treasury realised over the trailing month.
    #[serde(with = "u128_string")]
    pub month_revenue: u128,
    /// Running costs paid over the trailing month.
    #[serde(with = "u128_string")]
    pub month_paid: u128,
    /// The reserve's target at the boundary.
    #[serde(with = "u128_string")]
    pub target: u128,
    /// Running costs the trailing month still allowed after the boundary.
    #[serde(with = "u128_string")]
    pub allowance_left: u128,
    /// TNZO traded in one epoch, as the volume reports observed it.
    #[serde(with = "u128_string")]
    pub epoch_volume: u128,
    /// Most one epoch may pay out under the sale cap.
    #[serde(with = "u128_string")]
    pub sale_cap: u128,
    /// Moved from the treasury into the reserve since genesis.
    #[serde(with = "u128_string")]
    pub total_filled: u128,
    /// Paid out of the reserve since genesis.
    #[serde(with = "u128_string")]
    pub total_paid: u128,
}

/// The reserve's accounts.
pub fn read_book(state: &dyn VmState) -> ReserveBook {
    read_json(state, BOOK_KEY).unwrap_or_default()
}

/// An enacted running-cost payment waiting to be paid.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueuedPayment {
    /// The enacted proposal.
    pub proposal_id: String,
    /// Who is paid, hex.
    pub recipient: String,
    /// What the proposal granted, wei.
    #[serde(with = "u128_string")]
    pub amount: u128,
    /// What is still owed, wei.
    #[serde(with = "u128_string")]
    pub remaining: u128,
    /// First epoch in which what is still owed has lapsed.
    pub expires_epoch: u64,
}

/// Payments waiting, oldest first.
pub fn read_queue(state: &dyn VmState) -> Vec<QueuedPayment> {
    read_json(state, QUEUE_KEY).unwrap_or_default()
}

/// The governed values one boundary runs on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReserveRules {
    pub fill_share_bps: u64,
    pub target_months: u64,
    pub revenue_share_bps: u64,
    pub drawdown_bps: u64,
    pub month_epochs: u64,
    pub sale_volume_share_bps: u64,
    /// Whole TNZO.
    pub max_sale_tnzo_epoch: u64,
}

impl ReserveRules {
    /// The values in force.
    pub fn read(state: &dyn VmState) -> Self {
        Self {
            fill_share_bps: network_param(state, FILL_SHARE_PARAM).min(10_000),
            target_months: network_param(state, TARGET_MONTHS_PARAM),
            revenue_share_bps: network_param(state, REVENUE_SHARE_PARAM).min(10_000),
            drawdown_bps: network_param(state, DRAWDOWN_PARAM).min(10_000),
            month_epochs: network_param(state, MONTH_EPOCHS_PARAM).max(1),
            sale_volume_share_bps: network_param(state, SALE_VOLUME_SHARE_PARAM).min(10_000),
            max_sale_tnzo_epoch: network_param(state, MAX_SALE_PARAM),
        }
    }
}

/// What one boundary starts from.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BoundaryInputs {
    /// Revenue realised since the last boundary.
    pub new_revenue: u128,
    /// Revenue over the trailing month.
    pub month_revenue: u128,
    /// Running costs paid over the trailing month.
    pub month_paid: u128,
    /// Treasury balance.
    pub treasury: u128,
    /// Reserve balance.
    pub reserve: u128,
    /// TNZO traded in one epoch, as observed; zero when unknown.
    pub epoch_volume: u128,
    /// Owed by the queue in total.
    pub owed: u128,
}

/// What one boundary does.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BoundaryPlan {
    /// The reserve's target.
    pub target: u128,
    /// Moved from the treasury into the reserve.
    pub fill: u128,
    /// The trailing month's allowance left before this boundary's payout.
    pub allowance_left: u128,
    /// The sale cap for the epoch.
    pub sale_cap: u128,
    /// Paid out of the reserve.
    pub payout: u128,
}

fn bps(value: u128, bps: u64) -> u128 {
    tenzro_types::split::bps_of(value, u128::from(bps.min(10_000)))
}

/// One boundary's flows, from its inputs and the rules in force. Every
/// amount is bounded by a balance it is taken from, so none can go
/// negative.
pub fn plan_boundary(rules: &ReserveRules, i: &BoundaryInputs) -> BoundaryPlan {
    // Observed running cost per month: what was paid, or what revenue
    // allowed, whichever is larger.
    let revenue_allowance = bps(i.month_revenue, rules.revenue_share_bps);
    let monthly_cost = i.month_paid.max(revenue_allowance);
    let target = monthly_cost.saturating_mul(u128::from(rules.target_months));
    let shortfall = target.saturating_sub(i.reserve);
    let fill = bps(i.new_revenue, rules.fill_share_bps)
        .min(shortfall)
        .min(i.treasury);
    let reserve = i.reserve.saturating_add(fill);
    let allowance = revenue_allowance.saturating_add(bps(reserve, rules.drawdown_bps));
    let allowance_left = allowance.saturating_sub(i.month_paid);
    // Volume reports can be washed; the absolute ceiling cannot.
    let sale_cap = bps(i.epoch_volume, rules.sale_volume_share_bps).min(
        u128::from(rules.max_sale_tnzo_epoch).saturating_mul(tenzro_types::constants::ONE_TNZO),
    );
    let payout = i.owed.min(allowance_left).min(sale_cap).min(reserve);
    BoundaryPlan {
        target,
        fill,
        allowance_left,
        sale_cap,
        payout,
    }
}

/// Add `amount` of fee revenue just credited to the treasury to the epoch's
/// record. Called wherever fee revenue reaches the treasury.
pub fn note_revenue(
    state: &mut dyn VmState,
    amount: u128,
    changes: &mut Vec<StateChange>,
) -> Result<()> {
    if amount == 0 {
        return Ok(());
    }
    let epoch = params_epoch(state);
    let mut f = read_flows(state, epoch);
    f.revenue = f.revenue.saturating_add(amount);
    write_json(state, &flows_key(epoch), &f, changes)?;
    Ok(())
}

/// Put an enacted running-cost payment on the queue.
pub(super) fn queue_payment(
    state: &mut dyn VmState,
    proposal_id: &str,
    recipient: &Address,
    amount: u128,
    changes: &mut Vec<StateChange>,
) -> Result<()> {
    let mut queue = read_queue(state);
    if queue.len() >= QUEUE_CAPACITY {
        return Err(refuse(format!(
            "the running-cost queue holds {QUEUE_CAPACITY} payments already"
        )));
    }
    queue.push(QueuedPayment {
        proposal_id: proposal_id.to_string(),
        recipient: hex::encode(recipient.as_bytes()),
        amount,
        remaining: amount,
        expires_epoch: params_epoch(state).saturating_add(network_param(state, PAYMENT_TTL_PARAM)),
    });
    write_json(state, QUEUE_KEY, &queue, changes)?;
    Ok(())
}

/// TNZO traded in one epoch of `month_epochs`, wei, from the validators'
/// volume reports: zero when none is recent enough.
fn observed_epoch_volume(state: &dyn VmState, now_ms: i64, month_epochs: u64) -> u128 {
    let max_age = network_param(state, VOLUME_MAX_AGE_PARAM);
    let market_epoch = (now_ms.max(0) / MARKET_EPOCH_MS) as u64;
    let window = network_param(state, VOLUME_WINDOW_PARAM);
    let day = super::economy::observed_daily_volume(state, market_epoch, max_age, window);
    // A month is thirty days of `month_epochs / 30` epochs each.
    day.saturating_mul(30) / u128::from(month_epochs.max(1))
}

/// What one boundary did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReserveTick {
    pub fill: u128,
    pub payout: u128,
}

/// The reserve's epoch boundary, run at block start after the governed
/// parameters for the epoch apply: records the trailing month, fills the
/// reserve, and pays the queue within its caps. Runs once per epoch; every
/// node executing the block does the same.
pub fn begin_block(state: &mut dyn VmState, epoch: u64, now_ms: i64) -> Result<ReserveTick> {
    let mut book = read_book(state);
    if book.epoch.is_some_and(|e| e >= epoch) {
        return Ok(ReserveTick::default());
    }
    let mut changes = Vec::new();
    let prior_epoch = book.epoch;
    let rules = ReserveRules::read(state);
    let from = book
        .epoch
        .unwrap_or(epoch)
        .max(epoch.saturating_sub(MAX_SCAN_EPOCHS));
    let new_revenue =
        (from..epoch).fold(0u128, |a, e| a.saturating_add(read_flows(state, e).revenue));
    let window = epoch.saturating_sub(rules.month_epochs.min(MAX_SCAN_EPOCHS))..epoch;
    let (month_revenue, month_paid) = window.fold((0u128, 0u128), |(r, p), e| {
        let f = read_flows(state, e);
        (r.saturating_add(f.revenue), p.saturating_add(f.paid))
    });
    let treasury = derive_treasury_address();
    let reserve = reserve_address();
    let mut queue = read_queue(state);
    let before = queue.len();
    queue.retain(|q| q.expires_epoch > epoch);
    let mut lapsed = queue.len() != before;
    let owed = queue
        .iter()
        .fold(0u128, |a, q| a.saturating_add(q.remaining));
    let epoch_volume = observed_epoch_volume(state, now_ms, rules.month_epochs);
    let plan = plan_boundary(
        &rules,
        &BoundaryInputs {
            new_revenue,
            month_revenue,
            month_paid,
            treasury: state.get_balance(treasury.as_bytes()),
            reserve: state.get_balance(reserve.as_bytes()),
            epoch_volume,
            owed,
        },
    );
    if plan.fill > 0 {
        move_balance(
            state,
            treasury.as_bytes(),
            reserve.as_bytes(),
            plan.fill,
            &mut changes,
        )?;
    }
    let mut left = plan.payout;
    let mut paid = 0u128;
    for q in queue.iter_mut() {
        if left == 0 {
            break;
        }
        let Ok(to) = hex::decode(&q.recipient) else {
            continue;
        };
        // An operator whose approval was revoked while the payment waited is
        // owed nothing further.
        if super::payout_gates::require_approved_operator(state, &to).is_err() {
            q.remaining = 0;
            lapsed = true;
            continue;
        }
        // The treasury's period outflow limit bounds what the reserve pays
        // too; a payment the period cannot cover waits for the next one.
        let pay = q
            .remaining
            .min(left)
            .min(super::funding::outflow_headroom(state, now_ms));
        if pay == 0 {
            continue;
        }
        super::funding::record_outflow(state, pay, now_ms, &mut changes)?;
        move_balance(state, reserve.as_bytes(), &to, pay, &mut changes)?;
        q.remaining -= pay;
        left -= pay;
        paid = paid.saturating_add(pay);
    }
    if paid > 0 || lapsed {
        queue.retain(|q| q.remaining > 0);
        write_json(state, QUEUE_KEY, &queue, &mut changes)?;
    }
    if paid > 0 {
        let mut f = read_flows(state, epoch);
        f.paid = f.paid.saturating_add(paid);
        write_json(state, &flows_key(epoch), &f, &mut changes)?;
    }
    book = ReserveBook {
        epoch: Some(epoch),
        month_revenue,
        month_paid: month_paid.saturating_add(paid),
        target: plan.target,
        allowance_left: plan.allowance_left.saturating_sub(paid),
        epoch_volume,
        sale_cap: plan.sale_cap,
        total_filled: book.total_filled.saturating_add(plan.fill),
        total_paid: book.total_paid.saturating_add(paid),
    };
    write_json(state, BOOK_KEY, &book, &mut changes)?;
    if let Some(prior) = prior_epoch {
        let to = epoch.saturating_sub(MAX_SCAN_EPOCHS);
        let from = prior
            .saturating_sub(MAX_SCAN_EPOCHS)
            .max(to.saturating_sub(MAX_SCAN_EPOCHS));
        for e in from..to {
            delete_record(state, &flows_key(e), &mut changes);
        }
    }
    Ok(ReserveTick {
        fill: plan.fill,
        payout: paid,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::StateAdapter;

    const T: u128 = 1_000_000_000_000_000_000;

    #[test]
    fn grants_are_refused_while_the_reserve_is_under_its_floor() {
        let mut state = StateAdapter::new();
        // No target yet: no floor.
        assert!(check_grant_floor(&state).is_ok());
        let book = ReserveBook {
            target: 1_000 * T,
            ..Default::default()
        };
        write_json(&mut state, BOOK_KEY, &book, &mut Vec::new()).unwrap();
        state.set_balance(reserve_address().as_bytes(), 499 * T);
        let err = check_grant_floor(&state).unwrap_err().to_string();
        assert!(err.contains("treasury grants wait"), "{err}");
        // The enactment path refuses before anything moves.
        let treasury = derive_treasury_address();
        state.set_balance(treasury.as_bytes(), 1_000_000 * T);
        super::super::payout_gates::approve_grantee_for_test(
            &mut state,
            &[0x42; 32],
            crate::governance::GranteeClass::Developer,
        );
        let err = super::super::funding::enact_grant(
            &mut state,
            "p1",
            &Address::new([0x42; 32]),
            T,
            &[],
            &["milestone".to_string()],
            crate::governance::GrantVesting::Liquid,
            None,
            &crate::governance::GrantRelease::Governed,
            0,
            &mut Vec::new(),
            &mut Vec::new(),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("treasury grants wait"), "{err}");
        assert_eq!(state.get_balance(treasury.as_bytes()), 1_000_000 * T);
        // At the floor, grants go ahead; a lower governed floor lets them
        // through sooner.
        state.set_balance(reserve_address().as_bytes(), 500 * T);
        assert!(check_grant_floor(&state).is_ok());
        state.set_balance(reserve_address().as_bytes(), 100 * T);
        super::super::set_governed_param_for_test(&mut state, GRANT_FLOOR_PARAM, 1_000);
        assert!(check_grant_floor(&state).is_ok());
    }

    fn rules() -> ReserveRules {
        ReserveRules {
            fill_share_bps: DEFAULT_FILL_SHARE_BPS,
            target_months: DEFAULT_TARGET_MONTHS,
            revenue_share_bps: DEFAULT_REVENUE_SHARE_BPS,
            drawdown_bps: DEFAULT_DRAWDOWN_BPS,
            month_epochs: DEFAULT_MONTH_EPOCHS,
            sale_volume_share_bps: DEFAULT_SALE_VOLUME_SHARE_BPS,
            max_sale_tnzo_epoch: DEFAULT_MAX_SALE_TNZO_EPOCH,
        }
    }

    #[test]
    fn a_hundredfold_volume_report_sells_no_more_than_the_ceiling() {
        let r = rules();
        let base = BoundaryInputs {
            month_revenue: 100_000_000 * T,
            treasury: 1_000_000_000 * T,
            reserve: 100_000_000 * T,
            epoch_volume: 100_000 * T,
            owed: 100_000_000 * T,
            ..BoundaryInputs::default()
        };
        let honest = plan_boundary(&r, &base);
        assert_eq!(honest.sale_cap, 5_000 * T);
        let washed = plan_boundary(
            &r,
            &BoundaryInputs {
                epoch_volume: 100 * base.epoch_volume,
                ..base
            },
        );
        let ceiling = u128::from(DEFAULT_MAX_SALE_TNZO_EPOCH) * T;
        assert_eq!(washed.sale_cap, ceiling);
        assert_eq!(washed.payout, ceiling);
        let mut state = StateAdapter::new();
        set_param(&mut state, MAX_SALE_PARAM, 7);
        assert_eq!(ReserveRules::read(&state).max_sale_tnzo_epoch, 7);
    }

    fn set_param(state: &mut StateAdapter, key: &str, value: u64) {
        set_genesis_param(state, key, value);
    }

    fn registered(state: &mut StateAdapter, addr: &[u8]) {
        state.set_storage(
            &SYSTEM_ADDRESS,
            identity_wallet_index_key(addr).as_bytes(),
            b"did:tenzro:human:test".to_vec(),
        );
    }

    /// Volume reports as the rate tally leaves them: TNZO traded over a day,
    /// nano-TNZO, observed in market epoch `epoch`.
    fn report_volume(state: &mut StateAdapter, epoch: u64, tnzo_per_day: u128) {
        super::super::economy::write_volume_for_tests(state, epoch, tnzo_per_day * 1_000_000_000);
    }

    #[test]
    fn a_zero_seed_genesis_runs_every_boundary_without_moving_anything() {
        let mut state = StateAdapter::new();
        for epoch in 0..50u64 {
            let tick = begin_block(&mut state, epoch, epoch as i64 * MARKET_EPOCH_MS).unwrap();
            assert_eq!(tick, ReserveTick::default());
        }
        let book = read_book(&state);
        assert_eq!(book.epoch, Some(49));
        assert_eq!(book.target, 0);
        assert_eq!(state.get_balance(reserve_address().as_bytes()), 0);
        assert_eq!(state.get_balance(derive_treasury_address().as_bytes()), 0);
    }

    #[test]
    fn revenue_fills_an_empty_reserve_only_up_to_its_target() {
        let r = rules();
        let i = BoundaryInputs {
            new_revenue: 100 * T,
            month_revenue: 1_000 * T,
            treasury: 100 * T,
            ..Default::default()
        };
        let p = plan_boundary(&r, &i);
        // Target: 12 months of the revenue allowance (30% of 1,000).
        assert_eq!(p.target, 12 * 300 * T);
        assert_eq!(p.fill, 50 * T);
        // At target, nothing more moves.
        let full = plan_boundary(
            &r,
            &BoundaryInputs {
                reserve: p.target,
                ..i
            },
        );
        assert_eq!(full.fill, 0);
        // The fill never takes more than the treasury holds.
        let poor = plan_boundary(
            &r,
            &BoundaryInputs {
                treasury: 3 * T,
                ..i
            },
        );
        assert_eq!(poor.fill, 3 * T);
    }

    #[test]
    fn an_empty_reserve_pays_nothing_and_keeps_the_debt() {
        let mut state = StateAdapter::new();
        let payee = [7u8; 32];
        registered(&mut state, &payee);
        report_volume(&mut state, 0, 1_000_000);
        let mut ch = Vec::new();
        queue_payment(&mut state, "p1", &Address::new(payee), 50 * T, &mut ch).unwrap();
        for epoch in 1..10u64 {
            let tick = begin_block(&mut state, epoch, epoch as i64 * MARKET_EPOCH_MS).unwrap();
            assert_eq!(tick.payout, 0);
        }
        assert_eq!(state.get_balance(&payee), 0);
        assert_eq!(read_queue(&state)[0].remaining, 50 * T);
    }

    #[test]
    fn a_revenue_drought_limits_payouts_to_the_drawdown_cap() {
        let r = rules();
        let i = BoundaryInputs {
            month_revenue: 0,
            reserve: 1_000 * T,
            epoch_volume: 1_000_000 * T,
            owed: 1_000 * T,
            ..Default::default()
        };
        let p = plan_boundary(&r, &i);
        // 3% of the reserve in a month, no revenue share.
        assert_eq!(p.allowance_left, 30 * T);
        assert_eq!(p.payout, 30 * T);
        // Once the month has drawn its 3%, the rest of the month pays nothing.
        let drawn = plan_boundary(
            &r,
            &BoundaryInputs {
                month_paid: 30 * T,
                reserve: 970 * T,
                ..i
            },
        );
        assert_eq!(drawn.payout, 0);
        // A drought with nothing left at all pays nothing.
        let dry = plan_boundary(&r, &BoundaryInputs { reserve: 0, ..i });
        assert_eq!(dry.payout, 0);
    }

    #[test]
    fn payouts_never_exceed_the_share_of_traded_volume() {
        let r = rules();
        let i = BoundaryInputs {
            month_revenue: 100_000 * T,
            reserve: 100_000 * T,
            epoch_volume: 2_000 * T,
            owed: 10_000 * T,
            ..Default::default()
        };
        let p = plan_boundary(&r, &i);
        assert_eq!(p.sale_cap, 100 * T);
        assert_eq!(p.payout, 100 * T);
        // No observed volume: nothing is sold.
        let thin = plan_boundary(
            &r,
            &BoundaryInputs {
                epoch_volume: 0,
                ..i
            },
        );
        assert_eq!(thin.payout, 0);
    }

    #[test]
    fn the_queue_is_paid_in_order_within_the_sale_cap_each_epoch() {
        let mut state = StateAdapter::new();
        let (a, b) = ([1u8; 32], [2u8; 32]);
        registered(&mut state, &a);
        registered(&mut state, &b);
        state.set_balance(reserve_address().as_bytes(), 10_000 * T);
        state.record_supply_change(10_000 * T, 0);
        // A drawdown cap that does not bind, so the volume cap does.
        set_param(&mut state, DRAWDOWN_PARAM, 10_000);
        // 24,000 TNZO a day over 720-epoch months: 1,000 an epoch; 5% is 50.
        report_volume(&mut state, 0, 24_000);
        let mut ch = Vec::new();
        // The reserve pays approved operators, inside the treasury period limit.
        for who in [&a, &b] {
            super::super::payout_gates::approve_operator_for_test(
                &mut state,
                who,
                crate::governance::OperatorClass::Validator,
            );
        }
        state.set_balance(derive_treasury_address().as_bytes(), 1_000_000 * T);
        queue_payment(&mut state, "p1", &Address::new(a), 70 * T, &mut ch).unwrap();
        queue_payment(&mut state, "p2", &Address::new(b), 70 * T, &mut ch).unwrap();
        begin_block(&mut state, 1, MARKET_EPOCH_MS).unwrap();
        assert_eq!(state.get_balance(&a), 50 * T);
        begin_block(&mut state, 2, 2 * MARKET_EPOCH_MS).unwrap();
        assert_eq!(state.get_balance(&a), 70 * T);
        assert_eq!(state.get_balance(&b), 30 * T);
        // A report older than the governed age counts as no volume.
        begin_block(&mut state, 100, 100 * MARKET_EPOCH_MS).unwrap();
        assert_eq!(state.get_balance(&b), 30 * T);
        assert_eq!(read_book(&state).sale_cap, 0);
    }

    #[test]
    fn the_sale_cap_takes_the_lowest_recent_volume_report() {
        let mut state = StateAdapter::new();
        // A week of 24,000 TNZO a day, one day at 2,400, then a recovery.
        for e in 0..10u64 {
            report_volume(&mut state, e, if e == 5 { 2_400 } else { 24_000 });
        }
        let low = super::super::economy::observed_daily_volume(&state, 10, 6, 168);
        assert_eq!(low, 2_400 * T);
        // Once the low report leaves the window, the cap recovers.
        let recent = super::super::economy::observed_daily_volume(&state, 10, 6, 3);
        assert_eq!(recent, 24_000 * T);
    }

    #[test]
    fn an_unpaid_payment_lapses_after_its_ttl() {
        let mut state = StateAdapter::new();
        let payee = [9u8; 32];
        registered(&mut state, &payee);
        set_param(&mut state, PAYMENT_TTL_PARAM, 3);
        let mut ch = Vec::new();
        queue_payment(&mut state, "p1", &Address::new(payee), 5 * T, &mut ch).unwrap();
        assert_eq!(read_queue(&state)[0].expires_epoch, 3);
        begin_block(&mut state, 2, 2 * MARKET_EPOCH_MS).unwrap();
        assert_eq!(read_queue(&state).len(), 1);
        begin_block(&mut state, 3, 3 * MARKET_EPOCH_MS).unwrap();
        assert!(read_queue(&state).is_empty());
        assert_eq!(state.get_balance(&payee), 0);
    }

    /// The flows of an epoch further behind a boundary than any window reads
    /// are deleted; the ones a later boundary may still read stay.
    #[test]
    fn flows_older_than_the_longest_window_are_deleted() {
        let mut state = StateAdapter::new();
        let mut ch = Vec::new();
        let flows = EpochFlows {
            revenue: T,
            paid: 0,
        };
        for e in 0..6 {
            write_json(&mut state, &flows_key(e), &flows, &mut ch).unwrap();
        }
        begin_block(&mut state, 5, 5 * MARKET_EPOCH_MS).unwrap();
        let at = MAX_SCAN_EPOCHS + 3;
        begin_block(&mut state, at, at as i64 * MARKET_EPOCH_MS).unwrap();
        for e in 0..3 {
            let key = flows_key(e);
            assert_eq!(state.get_storage(&SYSTEM_ADDRESS, key.as_bytes()), None);
        }
        for e in 3..6 {
            assert_eq!(read_flows(&state, e), flows);
        }
    }

    #[test]
    fn a_boundary_runs_once_per_epoch() {
        let mut state = StateAdapter::new();
        let mut ch = Vec::new();
        note_revenue(&mut state, 10 * T, &mut ch).unwrap();
        state.set_balance(derive_treasury_address().as_bytes(), 10 * T);
        state.record_supply_change(10 * T, 0);
        begin_block(&mut state, 0, 0).unwrap();
        let first = begin_block(&mut state, 1, MARKET_EPOCH_MS).unwrap();
        // Target is 12 months of 30% of the month's revenue: room for the
        // fill of half the revenue.
        assert_eq!(first.fill, 5 * T);
        assert_eq!(
            begin_block(&mut state, 1, MARKET_EPOCH_MS).unwrap(),
            ReserveTick::default()
        );
        assert_eq!(read_book(&state).total_filled, 5 * T);
    }
}
