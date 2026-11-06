//! Governance gates on sponsorship and grants.
//!
//! The treasury sponsors operators and pays grants only with existing TNZO,
//! one governance proposal at a time, and only to a recipient governance has
//! approved and only against verified work or an approved milestone. Running
//! a node and building stay permissionless; only these two payouts are gated.
//!
//! - **Approved operators.** [`ProposalAction::ApproveOperator`] records a
//!   validator or provider with the criteria it was approved on. The chain
//!   checks the operator's machine identity holds a TPM endorsement a
//!   recognised root signs, counts its verified-available hours in the
//!   history named, and stores the result with the stated region and
//!   independence declaration. [`ProposalAction::RevokeOperator`] stops every
//!   later payment at once.
//! - **Approved grantees.** [`ProposalAction::ApproveGrantee`] records a
//!   developer, contributor or community grantee with its criteria;
//!   [`ProposalAction::RevokeGrantee`] stops every later tranche.
//! - **Running-cost sponsorship.** [`ProposalAction::SponsorOperatorRunningCost`]
//!   pays an approved operator only for hours the network's challenge
//!   protocol judged it available ([`super::read_sla_verdict`]); one verified
//!   hour backs one payment.
//! - **Caps.** Per-operator share of the yearly sponsorship (one third), the
//!   yearly sponsorship, the yearly amount per grantee and the yearly total
//!   of sponsorship and grants together are governed and zero at genesis, so
//!   nothing flows until governance sets them. Every payment also counts
//!   against the treasury outflow caps.
//! - **Events.** Every disbursement appends a [`PayoutRecord`] naming the
//!   recipient, amount and class, logged as `TreasuryPayout`, so who received
//!   what can be published.
//!
//! Nothing here issues TNZO, and approval carries no vote, reward or class.

use serde::{Deserialize, Serialize};

use super::funding::{move_balance, read_json, refuse, treasury_outflow, write_json};
use super::{SYSTEM_ADDRESS, derive_treasury_address, identity_did_of, network_param};
use crate::error::Result;
use crate::governance::{
    GranteeClass, GranteeCriteria, MAX_RUNNING_COST_EPOCHS, OperatorClass, OperatorCriteria,
};
use crate::traits::VmState;
use crate::types::{Log, StateChange};
use tenzro_types::primitives::Address;

/// Governed key: most treasury TNZO sponsorship commits in a year, whole TNZO.
pub const SPONSORSHIP_YEARLY_PARAM: &str = "sponsorship.yearly_max_tnzo";
/// Governed key: most one verified-available hour backs, wei.
pub const PER_VERIFIED_EPOCH_PARAM: &str = "sponsorship.running_cost_per_verified_epoch_wei";
/// Governed key: most treasury sponsorship in a stable asset commits in a
/// year, whole US dollars.
pub const SPONSORSHIP_YEARLY_USD_PARAM: &str = "sponsorship.yearly_max_usd";
/// Governed key: most one verified-available hour backs in a stable asset,
/// micro-dollars.
pub const PER_VERIFIED_EPOCH_USD_PARAM: &str = "sponsorship.running_cost_per_verified_epoch_usd_e6";
/// Governed key: most one grantee is paid in a stable asset in a year, whole
/// US dollars.
pub const GRANTEE_YEARLY_USD_PARAM: &str = "grants.per_grantee_yearly_max_usd";
/// Governed key: most sponsorship and grants pay together in a stable asset
/// in a year, whole US dollars.
pub const COMBINED_YEARLY_USD_PARAM: &str = "treasury.sponsorship_grants_yearly_max_usd";
/// Governed key: most one grantee is paid in a year, whole TNZO.
pub const GRANTEE_YEARLY_PARAM: &str = "grants.per_grantee_yearly_max_tnzo";
/// Governed key: most sponsorship and grants pay together in a year, whole TNZO.
pub const COMBINED_YEARLY_PARAM: &str = "treasury.sponsorship_grants_yearly_max_tnzo";

/// Log topic: an operator was approved or its approval renewed.
pub const OPERATOR_APPROVED_TOPIC: &[u8] = b"OperatorApproved";
/// Log topic: an operator's approval was revoked.
pub const OPERATOR_REVOKED_TOPIC: &[u8] = b"OperatorRevoked";
/// Log topic: a grantee was approved or its approval renewed.
pub const GRANTEE_APPROVED_TOPIC: &[u8] = b"GranteeApproved";
/// Log topic: a grantee's approval was revoked.
pub const GRANTEE_REVOKED_TOPIC: &[u8] = b"GranteeRevoked";
/// Log topic: treasury TNZO was disbursed; the data is a [`PayoutRecord`].
pub const PAYOUT_TOPIC: &[u8] = b"TreasuryPayout";

/// One operator may receive at most this fraction of the yearly sponsorship.
const OPERATOR_SHARE_DIVISOR: u128 = 3;
/// Length of a payout year.
const YEAR_MS: i64 = 365 * 24 * 60 * 60 * 1000;
const ONE_TNZO: u128 = tenzro_types::constants::ONE_TNZO;
const PAYOUT_COUNT_KEY: &str = "payout_log_n";

/// Every class a payout can carry.
pub const CLASSES: [&str; 5] = [
    "validator",
    "provider",
    "developer",
    "contributor",
    "community",
];

/// What was disbursed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PayoutKind {
    /// Treasury TNZO bonded on an approved validator's behalf.
    BondSponsorship,
    /// A running-cost payment to an approved operator.
    RunningCost,
    /// A grant payment to an approved grantee.
    Grant,
    /// A running-cost payment to an approved operator on another chain.
    RemoteRunningCost,
}

/// The unit a payout is counted in against the yearly caps: TNZO in wei, or
/// US dollars in micro-dollars for a stable asset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Unit {
    Tnzo,
    Usd,
}

impl Unit {
    fn year_prefix(self) -> &'static str {
        match self {
            Unit::Tnzo => "payout_year",
            Unit::Usd => "payout_year_usd",
        }
    }
}

impl PayoutKind {
    fn label(self) -> &'static str {
        match self {
            PayoutKind::BondSponsorship => "bond_sponsorship",
            PayoutKind::RunningCost => "running_cost",
            PayoutKind::Grant => "grant",
            PayoutKind::RemoteRunningCost => "remote_running_cost",
        }
    }
}

/// An operator's approval as stored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorApproval {
    /// Validator or provider.
    pub class: OperatorClass,
    /// The criteria it was approved on.
    pub criteria: OperatorCriteria,
    /// Verified-available hours the chain counted in the history named.
    pub verified_epochs: u64,
    /// The machine identity held a recognised TPM endorsement at approval.
    pub hardware_attested: bool,
    /// When it was approved.
    pub approved_ms: i64,
    /// The proposal that approved it.
    pub proposal_id: String,
    /// Whether governance has revoked it.
    pub revoked: bool,
}

/// A grantee's approval as stored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GranteeApproval {
    /// Developer, contributor or community.
    pub class: GranteeClass,
    /// The criteria it was approved on.
    pub criteria: GranteeCriteria,
    /// When it was approved.
    pub approved_ms: i64,
    /// The proposal that approved it.
    pub proposal_id: String,
    /// Whether governance has revoked it.
    pub revoked: bool,
}

/// One disbursement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PayoutRecord {
    /// Position in the log, from zero.
    pub n: u64,
    /// Bond sponsorship, running cost or grant.
    pub kind: String,
    /// Who received it, hex.
    pub recipient: String,
    /// validator, provider, developer, contributor or community.
    pub class: String,
    /// How much, in the smallest unit.
    #[serde(with = "tenzro_types::primitives::u128_serde")]
    pub amount: u128,
    /// The proposal that enacted or released it.
    pub proposal_id: String,
    /// The milestone or the verified hours it was paid against.
    pub milestone: String,
    /// When it was paid.
    pub at_ms: i64,
    /// The settlement asset paid, a token id; empty for TNZO.
    #[serde(default)]
    pub asset: String,
    /// What a stable payout was worth, micro-dollars; zero for TNZO.
    #[serde(default, with = "tenzro_types::primitives::u128_serde")]
    pub usd_e6: u128,
}

#[derive(Default, Serialize, Deserialize)]
struct Total {
    #[serde(with = "tenzro_types::primitives::u128_serde")]
    amount: u128,
}

#[derive(Default, Serialize, Deserialize)]
struct YearTotals {
    #[serde(with = "tenzro_types::primitives::u128_serde")]
    sponsorship: u128,
    #[serde(with = "tenzro_types::primitives::u128_serde")]
    grants: u128,
}

fn operator_key(account: &[u8]) -> String {
    format!("approved_operator:{}", hex::encode(account))
}

fn grantee_key(account: &[u8]) -> String {
    format!("approved_grantee:{}", hex::encode(account))
}

fn payout_key(n: u64) -> String {
    format!("payout_log:{n}")
}

fn year_key(unit: Unit, year: i64) -> String {
    format!("{}:{year}", unit.year_prefix())
}

fn year_recipient_key(unit: Unit, year: i64, kind: &str, account: &[u8]) -> String {
    format!(
        "{}:{year}:{kind}:{}",
        unit.year_prefix(),
        hex::encode(account)
    )
}

fn class_total_key(class: &str) -> String {
    format!("payout_class_total:{class}")
}

fn recipient_total_key(account: &[u8]) -> String {
    format!("payout_recipient_total:{}", hex::encode(account))
}

fn class_total_usd_key(class: &str) -> String {
    format!("payout_class_total_usd:{class}")
}

fn recipient_total_usd_key(account: &[u8]) -> String {
    format!("payout_recipient_total_usd:{}", hex::encode(account))
}

fn consumed_key(did: &str, epoch: u64) -> String {
    format!("running_cost_epoch:{did}:{epoch}")
}

fn year_of(now_ms: i64) -> i64 {
    now_ms.max(0) / YEAR_MS
}

fn whole_tnzo(state: &dyn VmState, key: &str) -> u128 {
    u128::from(network_param(state, key)).saturating_mul(ONE_TNZO)
}

/// A cap in `unit`: whole TNZO in wei, or whole dollars in micro-dollars.
fn cap_in(state: &dyn VmState, unit: Unit, tnzo_key: &str, usd_key: &str) -> u128 {
    match unit {
        Unit::Tnzo => whole_tnzo(state, tnzo_key),
        Unit::Usd => u128::from(network_param(state, usd_key)).saturating_mul(1_000_000),
    }
}

/// The operator's approval, revoked or not.
pub fn operator_approval(state: &dyn VmState, account: &[u8]) -> Option<OperatorApproval> {
    read_json(state, &operator_key(account))
}

/// The grantee's approval, revoked or not.
pub fn grantee_approval(state: &dyn VmState, account: &[u8]) -> Option<GranteeApproval> {
    read_json(state, &grantee_key(account))
}

/// Test seam: records an operator approval as enactment would, without the
/// identity and availability checks, and opens the yearly caps wide.
#[cfg(test)]
pub(crate) fn approve_operator_for_test(
    state: &mut dyn VmState,
    account: &[u8],
    class: OperatorClass,
) {
    let approval = OperatorApproval {
        class,
        criteria: OperatorCriteria {
            provider_did: String::new(),
            region: "test".into(),
            history_from_epoch: 0,
            history_to_epoch: 0,
            independence: "test".into(),
            link: String::new(),
        },
        verified_epochs: 1,
        hardware_attested: true,
        approved_ms: 0,
        proposal_id: String::new(),
        revoked: false,
    };
    write_json(state, &operator_key(account), &approval, &mut Vec::new()).unwrap();
    open_caps_for_test(state);
}

/// Test seam: records a grantee approval as enactment would and opens the
/// yearly caps wide.
#[cfg(test)]
pub(crate) fn approve_grantee_for_test(
    state: &mut dyn VmState,
    account: &[u8],
    class: GranteeClass,
) {
    let approval = GranteeApproval {
        class,
        criteria: GranteeCriteria {
            summary: "test".into(),
            link: String::new(),
        },
        approved_ms: 0,
        proposal_id: String::new(),
        revoked: false,
    };
    write_json(state, &grantee_key(account), &approval, &mut Vec::new()).unwrap();
    open_caps_for_test(state);
}

/// Test seam: sets every yearly cap to its highest value.
#[cfg(test)]
pub(crate) fn open_caps_for_test(state: &mut dyn VmState) {
    for key in [
        SPONSORSHIP_YEARLY_PARAM,
        GRANTEE_YEARLY_PARAM,
        COMBINED_YEARLY_PARAM,
    ] {
        super::set_governed_param_for_test(state, key, 1_000_000_000);
    }
}

/// `account` must be an operator governance has approved and not revoked.
pub fn require_approved_operator(state: &dyn VmState, account: &[u8]) -> Result<OperatorApproval> {
    match operator_approval(state, account) {
        Some(a) if !a.revoked => Ok(a),
        Some(_) => Err(refuse(format!(
            "{} was approved for sponsorship and the approval is revoked",
            hex::encode(account)
        ))),
        None => Err(refuse(format!(
            "{} is not an approved operator; sponsorship goes only to operators governance has approved",
            hex::encode(account)
        ))),
    }
}

/// `account` must be a grantee governance has approved and not revoked.
pub fn require_approved_grantee(state: &dyn VmState, account: &[u8]) -> Result<GranteeApproval> {
    match grantee_approval(state, account) {
        Some(a) if !a.revoked => Ok(a),
        Some(_) => Err(refuse(format!(
            "{} was approved to receive grants and the approval is revoked",
            hex::encode(account)
        ))),
        None => Err(refuse(format!(
            "{} is not an approved grantee; grants go only to grantees governance has approved",
            hex::encode(account)
        ))),
    }
}

fn log(topic: &[u8], data: Vec<u8>) -> Log {
    Log::new(SYSTEM_ADDRESS.to_vec(), vec![topic.to_vec()], data)
}

/// Verified-available hours of `did` in `from..=to`, oldest first, that no
/// earlier payment has used.
fn unused_verified_epochs(state: &dyn VmState, did: &str, from: u64, to: u64) -> Vec<u64> {
    (from..=to)
        .filter(|e| {
            super::read_sla_verdict(state, did, *e).is_some_and(|v| v.available)
                && state
                    .get_storage(&SYSTEM_ADDRESS, consumed_key(did, *e).as_bytes())
                    .is_none_or(|b| b.is_empty())
        })
        .collect()
}

/// Verified-available hours of `did` in `from..=to`.
fn verified_epoch_count(state: &dyn VmState, did: &str, from: u64, to: u64) -> u64 {
    (from..=to)
        .filter(|e| super::read_sla_verdict(state, did, *e).is_some_and(|v| v.available))
        .count() as u64
}

/// Submission check for an operator approval: the operator holds a
/// registered identity that is the machine identity named, that identity's
/// TPM endorsement chains to a recognised root, and it has at least one
/// verified-available hour in the history named.
pub fn check_approve_operator(
    state: &dyn VmState,
    operator: &[u8],
    criteria: &OperatorCriteria,
    now_ms: i64,
) -> Result<u64> {
    if identity_did_of(state, operator).as_deref() != Some(criteria.provider_did.as_str()) {
        return Err(refuse(format!(
            "{} is not the account of {}",
            hex::encode(operator),
            criteria.provider_did
        )));
    }
    super::funding::machine_endorsed(state, &criteria.provider_did, now_ms).map_err(|e| {
        refuse(format!(
            "{} has no hardware attestation a recognised root signs: {e}",
            criteria.provider_did
        ))
    })?;
    let verified = verified_epoch_count(
        state,
        &criteria.provider_did,
        criteria.history_from_epoch,
        criteria.history_to_epoch,
    );
    if verified == 0 {
        return Err(refuse(format!(
            "{} has no verified-available hour in epochs {} to {}",
            criteria.provider_did, criteria.history_from_epoch, criteria.history_to_epoch
        )));
    }
    Ok(verified)
}

/// Enact an operator approval.
pub(super) fn approve_operator(
    state: &mut dyn VmState,
    proposal_id: &str,
    operator: &Address,
    class: OperatorClass,
    criteria: &OperatorCriteria,
    now_ms: i64,
    changes: &mut Vec<StateChange>,
    logs: &mut Vec<Log>,
) -> Result<()> {
    let verified_epochs = check_approve_operator(state, operator.as_bytes(), criteria, now_ms)?;
    let approval = OperatorApproval {
        class,
        criteria: criteria.clone(),
        verified_epochs,
        hardware_attested: true,
        approved_ms: now_ms,
        proposal_id: proposal_id.to_string(),
        revoked: false,
    };
    write_json(
        state,
        &operator_key(operator.as_bytes()),
        &approval,
        changes,
    )?;
    logs.push(log(
        OPERATOR_APPROVED_TOPIC,
        serde_json::to_vec(&(hex::encode(operator.as_bytes()), &approval)).unwrap_or_default(),
    ));
    Ok(())
}

/// Submission check for a revocation.
pub fn check_revoke_operator(state: &dyn VmState, operator: &[u8]) -> Result<()> {
    require_approved_operator(state, operator).map(|_| ())
}

/// Enact an operator revocation: every later payment is refused.
pub(super) fn revoke_operator(
    state: &mut dyn VmState,
    operator: &Address,
    changes: &mut Vec<StateChange>,
    logs: &mut Vec<Log>,
) -> Result<()> {
    let mut approval = require_approved_operator(state, operator.as_bytes())?;
    approval.revoked = true;
    write_json(
        state,
        &operator_key(operator.as_bytes()),
        &approval,
        changes,
    )?;
    logs.push(log(
        OPERATOR_REVOKED_TOPIC,
        hex::encode(operator.as_bytes()).into_bytes(),
    ));
    Ok(())
}

/// Enact a grantee approval. The grantee must hold a registered identity.
pub(super) fn approve_grantee(
    state: &mut dyn VmState,
    proposal_id: &str,
    grantee: &Address,
    class: GranteeClass,
    criteria: &GranteeCriteria,
    now_ms: i64,
    changes: &mut Vec<StateChange>,
    logs: &mut Vec<Log>,
) -> Result<()> {
    super::funding::require_registered_recipient(state, grantee.as_bytes())?;
    let approval = GranteeApproval {
        class,
        criteria: criteria.clone(),
        approved_ms: now_ms,
        proposal_id: proposal_id.to_string(),
        revoked: false,
    };
    write_json(state, &grantee_key(grantee.as_bytes()), &approval, changes)?;
    logs.push(log(
        GRANTEE_APPROVED_TOPIC,
        serde_json::to_vec(&(hex::encode(grantee.as_bytes()), &approval)).unwrap_or_default(),
    ));
    Ok(())
}

/// Submission check for a grantee revocation.
pub fn check_revoke_grantee(state: &dyn VmState, grantee: &[u8]) -> Result<()> {
    require_approved_grantee(state, grantee).map(|_| ())
}

/// Enact a grantee revocation: every later tranche is refused.
pub(super) fn revoke_grantee(
    state: &mut dyn VmState,
    grantee: &Address,
    changes: &mut Vec<StateChange>,
    logs: &mut Vec<Log>,
) -> Result<()> {
    let mut approval = require_approved_grantee(state, grantee.as_bytes())?;
    approval.revoked = true;
    write_json(state, &grantee_key(grantee.as_bytes()), &approval, changes)?;
    logs.push(log(
        GRANTEE_REVOKED_TOPIC,
        hex::encode(grantee.as_bytes()).into_bytes(),
    ));
    Ok(())
}

/// The yearly figures a payment is checked against, read without changing
/// anything.
pub(super) struct YearView {
    unit: Unit,
    year: i64,
    totals: YearTotals,
    recipient: u128,
}

fn year_view(state: &dyn VmState, unit: Unit, kind: &str, account: &[u8], now_ms: i64) -> YearView {
    let year = year_of(now_ms);
    YearView {
        unit,
        year,
        totals: read_json(state, &year_key(unit, year)).unwrap_or_default(),
        recipient: read_json::<Total>(state, &year_recipient_key(unit, year, kind, account))
            .unwrap_or_default()
            .amount,
    }
}

/// Whether `amount` more sponsorship to `operator` stays within the yearly
/// caps: disabled while a cap is zero, an operator at most a third of the
/// sponsorship cap, and sponsorship plus grants within the combined cap.
pub(super) fn check_sponsorship_caps(
    state: &dyn VmState,
    unit: Unit,
    operator: &[u8],
    amount: u128,
    now_ms: i64,
) -> Result<YearView> {
    let cap = cap_in(
        state,
        unit,
        SPONSORSHIP_YEARLY_PARAM,
        SPONSORSHIP_YEARLY_USD_PARAM,
    );
    let combined = cap_in(
        state,
        unit,
        COMBINED_YEARLY_PARAM,
        COMBINED_YEARLY_USD_PARAM,
    );
    if cap == 0 || combined == 0 {
        return Err(refuse(format!(
            "sponsorship is disabled: governance has not set the {} yearly sponsorship and \
             combined caps",
            if unit == Unit::Usd { "USD" } else { "TNZO" }
        )));
    }
    let view = year_view(state, unit, "sponsorship", operator, now_ms);
    let operator_total = view.recipient.saturating_add(amount);
    if operator_total.saturating_mul(OPERATOR_SHARE_DIVISOR) > cap {
        return Err(refuse(format!(
            "{} would receive {operator_total} this year, above one third of the {cap} yearly sponsorship",
            hex::encode(operator)
        )));
    }
    let sponsorship = view.totals.sponsorship.saturating_add(amount);
    if sponsorship > cap {
        return Err(refuse(format!(
            "{sponsorship} of sponsorship this year is above the {cap} cap"
        )));
    }
    if sponsorship.saturating_add(view.totals.grants) > combined {
        return Err(refuse(format!(
            "sponsorship and grants together would pay {} this year, above the {combined} cap",
            sponsorship.saturating_add(view.totals.grants)
        )));
    }
    Ok(view)
}

/// Whether `amount` more in grants to `grantee` stays within the yearly caps.
pub(super) fn check_grant_caps(
    state: &dyn VmState,
    unit: Unit,
    grantee: &[u8],
    amount: u128,
    now_ms: i64,
) -> Result<YearView> {
    let per = cap_in(state, unit, GRANTEE_YEARLY_PARAM, GRANTEE_YEARLY_USD_PARAM);
    let combined = cap_in(
        state,
        unit,
        COMBINED_YEARLY_PARAM,
        COMBINED_YEARLY_USD_PARAM,
    );
    if per == 0 || combined == 0 {
        return Err(refuse(format!(
            "grants are disabled: governance has not set the {} per-grantee and combined caps",
            if unit == Unit::Usd { "USD" } else { "TNZO" }
        )));
    }
    let view = year_view(state, unit, "grant", grantee, now_ms);
    let grantee_total = view.recipient.saturating_add(amount);
    if grantee_total > per {
        return Err(refuse(format!(
            "{} would be paid {grantee_total} this year, above the {per} one grantee may receive",
            hex::encode(grantee)
        )));
    }
    let all = view
        .totals
        .sponsorship
        .saturating_add(view.totals.grants)
        .saturating_add(amount);
    if all > combined {
        return Err(refuse(format!(
            "sponsorship and grants together would pay {all} this year, above the {combined} cap"
        )));
    }
    Ok(view)
}

fn append_payout(
    state: &mut dyn VmState,
    record: &PayoutRecord,
    changes: &mut Vec<StateChange>,
    logs: &mut Vec<Log>,
) -> Result<()> {
    write_json(state, &payout_key(record.n), record, changes)?;
    write_json(state, PAYOUT_COUNT_KEY, &(record.n + 1), changes)?;
    let account = hex::decode(&record.recipient).unwrap_or_default();
    let (class_key, recipient_key, counted) = if record.asset.is_empty() {
        (
            class_total_key(&record.class),
            recipient_total_key(&account),
            record.amount,
        )
    } else {
        (
            class_total_usd_key(&record.class),
            recipient_total_usd_key(&account),
            record.usd_e6,
        )
    };
    for key in [class_key, recipient_key] {
        let total: Total = read_json(state, &key).unwrap_or_default();
        write_json(
            state,
            &key,
            &Total {
                amount: total.amount.saturating_add(counted),
            },
            changes,
        )?;
    }
    logs.push(log(
        PAYOUT_TOPIC,
        serde_json::to_vec(record).unwrap_or_default(),
    ));
    Ok(())
}

/// Count `amount` against the year and log the disbursement.
#[allow(clippy::too_many_arguments)]
fn commit_payout(
    state: &mut dyn VmState,
    view: YearView,
    kind: PayoutKind,
    account: &[u8],
    class: &str,
    amount: u128,
    proposal_id: &str,
    milestone: &str,
    now_ms: i64,
    changes: &mut Vec<StateChange>,
    logs: &mut Vec<Log>,
) -> Result<()> {
    commit_in_unit(
        state,
        view,
        kind,
        account,
        class,
        amount,
        amount,
        "",
        proposal_id,
        milestone,
        now_ms,
        changes,
        logs,
    )
}

/// Count `counted` (in the view's unit) against the year and log a
/// disbursement of `amount` smallest units of `asset` (empty for TNZO).
#[allow(clippy::too_many_arguments)]
pub(super) fn commit_in_unit(
    state: &mut dyn VmState,
    view: YearView,
    kind: PayoutKind,
    account: &[u8],
    class: &str,
    amount: u128,
    counted: u128,
    asset: &str,
    proposal_id: &str,
    milestone: &str,
    now_ms: i64,
    changes: &mut Vec<StateChange>,
    logs: &mut Vec<Log>,
) -> Result<()> {
    let mut totals = view.totals;
    let ledger_kind = match kind {
        PayoutKind::Grant => {
            totals.grants = totals.grants.saturating_add(counted);
            "grant"
        }
        PayoutKind::BondSponsorship | PayoutKind::RunningCost | PayoutKind::RemoteRunningCost => {
            totals.sponsorship = totals.sponsorship.saturating_add(counted);
            "sponsorship"
        }
    };
    write_json(state, &year_key(view.unit, view.year), &totals, changes)?;
    write_json(
        state,
        &year_recipient_key(view.unit, view.year, ledger_kind, account),
        &Total {
            amount: view.recipient.saturating_add(counted),
        },
        changes,
    )?;
    let n = read_json::<u64>(state, PAYOUT_COUNT_KEY).unwrap_or(0);
    append_payout(
        state,
        &PayoutRecord {
            n,
            kind: kind.label().to_string(),
            recipient: hex::encode(account),
            class: class.to_string(),
            amount,
            proposal_id: proposal_id.to_string(),
            milestone: milestone.to_string(),
            at_ms: now_ms,
            asset: asset.to_string(),
            usd_e6: if view.unit == Unit::Usd { counted } else { 0 },
        },
        changes,
        logs,
    )
}

/// Submission check for a sponsored bond: the validator is an approved
/// operator.
pub fn check_sponsored_bond_operator(state: &dyn VmState, validator: &[u8]) -> Result<()> {
    require_approved_operator(state, validator).map(|_| ())
}

/// Count a sponsored bond against the yearly sponsorship caps and log it.
/// Refused unless the validator is an approved operator and the caps admit
/// it.
pub(super) fn record_bond_sponsorship(
    state: &mut dyn VmState,
    proposal_id: &str,
    validator: &[u8],
    amount: u128,
    now_ms: i64,
    changes: &mut Vec<StateChange>,
    logs: &mut Vec<Log>,
) -> Result<()> {
    let approval = require_approved_operator(state, validator)?;
    let view = check_sponsorship_caps(state, Unit::Tnzo, validator, amount, now_ms)?;
    commit_payout(
        state,
        view,
        PayoutKind::BondSponsorship,
        validator,
        approval.class.label(),
        amount,
        proposal_id,
        "sponsored validator bond",
        now_ms,
        changes,
        logs,
    )
}

/// Count one grant payment against the yearly grant caps and log it. Refused
/// unless the grantee is approved and the caps admit it.
pub(super) fn record_grant_payment(
    state: &mut dyn VmState,
    proposal_id: &str,
    grantee: &[u8],
    amount: u128,
    milestone: &str,
    now_ms: i64,
    changes: &mut Vec<StateChange>,
    logs: &mut Vec<Log>,
) -> Result<()> {
    let approval = require_approved_grantee(state, grantee)?;
    let view = check_grant_caps(state, Unit::Tnzo, grantee, amount, now_ms)?;
    commit_payout(
        state,
        view,
        PayoutKind::Grant,
        grantee,
        approval.class.label(),
        amount,
        proposal_id,
        milestone,
        now_ms,
        changes,
        logs,
    )
}

/// The hours a running-cost payment is paid against.
pub(super) struct RunningCostPlan {
    pub(super) did: String,
    pub(super) hours: Vec<u64>,
}

/// Mark the hours of `plan` as paid by `proposal_id`, each once.
pub(super) fn consume_hours(
    state: &mut dyn VmState,
    plan: &RunningCostPlan,
    proposal_id: &str,
    changes: &mut Vec<StateChange>,
) {
    for hour in &plan.hours {
        let key = consumed_key(&plan.did, *hour);
        let prior = state.get_storage(&SYSTEM_ADDRESS, key.as_bytes());
        state.set_storage(
            &SYSTEM_ADDRESS,
            key.as_bytes(),
            proposal_id.as_bytes().to_vec(),
        );
        changes.push(StateChange::new(
            SYSTEM_ADDRESS.to_vec(),
            key.into_bytes(),
            prior,
            Some(proposal_id.as_bytes().to_vec()),
        ));
    }
}

/// Whether `amount` can be paid to `operator` for the hours in
/// `from..=to`: the operator is approved, the per-hour value is set, and
/// enough unused verified-available hours back the amount.
fn plan_running_cost(
    state: &dyn VmState,
    operator: &[u8],
    from: u64,
    to: u64,
    amount: u128,
) -> Result<RunningCostPlan> {
    let rate = u128::from(network_param(state, PER_VERIFIED_EPOCH_PARAM));
    plan_hours(
        state,
        operator,
        from,
        to,
        amount,
        rate,
        PER_VERIFIED_EPOCH_PARAM,
    )
}

/// Whether `amount` (in the unit `rate` is in) can be paid to `operator` for
/// the hours in `from..=to`: approved, a rate set, and enough unused
/// verified-available hours back it.
pub(super) fn plan_hours(
    state: &dyn VmState,
    operator: &[u8],
    from: u64,
    to: u64,
    amount: u128,
    rate: u128,
    rate_param: &str,
) -> Result<RunningCostPlan> {
    if amount == 0 || to < from || to - from >= MAX_RUNNING_COST_EPOCHS {
        return Err(refuse(
            "a running-cost sponsorship needs an amount and an hour range",
        ));
    }
    let approval = require_approved_operator(state, operator)?;
    if rate == 0 {
        return Err(refuse(format!(
            "running-cost sponsorship is disabled: governance has not set {rate_param}"
        )));
    }
    let did = approval.criteria.provider_did;
    let verified = unused_verified_epochs(state, &did, from, to);
    if verified.is_empty() {
        return Err(refuse(format!(
            "{did} has no verified-available hour in epochs {from} to {to} that is not already paid; \
             nothing is paid without verified work"
        )));
    }
    let backed = rate.saturating_mul(verified.len() as u128);
    if amount > backed {
        return Err(refuse(format!(
            "{} verified hours back at most {backed}; {amount} is more",
            verified.len()
        )));
    }
    let needed = amount.div_ceil(rate) as usize;
    Ok(RunningCostPlan {
        did,
        hours: verified.into_iter().take(needed).collect(),
    })
}

/// Submission check for a running-cost sponsorship.
pub fn check_running_cost(
    state: &dyn VmState,
    operator: &[u8],
    from: u64,
    to: u64,
    amount: u128,
) -> Result<()> {
    plan_running_cost(state, operator, from, to, amount).map(|_| ())
}

/// Enact a running-cost sponsorship: pay existing treasury TNZO to an
/// approved operator against its unused verified-available hours, within
/// the yearly caps and the treasury outflow caps.
#[allow(clippy::too_many_arguments)]
pub(super) fn sponsor_running_cost(
    state: &mut dyn VmState,
    proposal_id: &str,
    operator: &Address,
    from: u64,
    to: u64,
    amount: u128,
    now_ms: i64,
    changes: &mut Vec<StateChange>,
    logs: &mut Vec<Log>,
) -> Result<()> {
    let plan = plan_running_cost(state, operator.as_bytes(), from, to, amount)?;
    let class = require_approved_operator(state, operator.as_bytes())?.class;
    let view = check_sponsorship_caps(state, Unit::Tnzo, operator.as_bytes(), amount, now_ms)?;
    treasury_outflow(state, amount, amount, now_ms, changes)?;
    move_balance(
        state,
        derive_treasury_address().as_bytes(),
        operator.as_bytes(),
        amount,
        changes,
    )?;
    consume_hours(state, &plan, proposal_id, changes);
    let basis = format!(
        "{} verified-available hours of {} in epochs {from} to {to}",
        plan.hours.len(),
        plan.did
    );
    commit_payout(
        state,
        view,
        PayoutKind::RunningCost,
        operator.as_bytes(),
        class.label(),
        amount,
        proposal_id,
        &basis,
        now_ms,
        changes,
        logs,
    )
}

/// Gate a running-cost payment the reserve will pay: an approved operator,
/// backed by unused verified-available hours, within the yearly sponsorship
/// caps and the per-proposal limit, and logged as a payout. The reserve
/// queue then pays it within its own caps and the treasury period limit.
#[allow(clippy::too_many_arguments)]
pub(super) fn commit_reserve_payment(
    state: &mut dyn VmState,
    proposal_id: &str,
    recipient: &Address,
    from: u64,
    to: u64,
    amount: u128,
    now_ms: i64,
    changes: &mut Vec<StateChange>,
    logs: &mut Vec<Log>,
) -> Result<()> {
    let plan = plan_running_cost(state, recipient.as_bytes(), from, to, amount)?;
    let class = require_approved_operator(state, recipient.as_bytes())?.class;
    let view = check_sponsorship_caps(state, Unit::Tnzo, recipient.as_bytes(), amount, now_ms)?;
    super::funding::commit_outflow(state, amount)?;
    consume_hours(state, &plan, proposal_id, changes);
    let basis = format!(
        "{} verified-available hours of {} in epochs {from} to {to}, paid from the running-cost reserve",
        plan.hours.len(),
        plan.did
    );
    commit_payout(
        state,
        view,
        PayoutKind::RunningCost,
        recipient.as_bytes(),
        class.label(),
        amount,
        proposal_id,
        &basis,
        now_ms,
        changes,
        logs,
    )
}

/// What a query returns.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PayoutReport {
    /// Disbursements logged so far.
    pub count: u64,
    /// Total paid per class, wei, as decimal strings.
    pub by_class: std::collections::BTreeMap<String, String>,
    /// Total paid per class in stable assets, micro-dollars, as decimal
    /// strings.
    pub by_class_usd_e6: std::collections::BTreeMap<String, String>,
    /// The page of disbursements asked for, oldest first.
    pub records: Vec<PayoutRecord>,
}

/// Disbursements logged so far.
pub fn payout_count(state: &dyn VmState) -> u64 {
    read_json(state, PAYOUT_COUNT_KEY).unwrap_or(0)
}

/// The total paid to `account` over all time, wei.
pub fn recipient_total(state: &dyn VmState, account: &[u8]) -> u128 {
    read_json::<Total>(state, &recipient_total_key(account))
        .unwrap_or_default()
        .amount
}

/// The total paid per class, wei.
pub fn class_total(state: &dyn VmState, class: &str) -> u128 {
    read_json::<Total>(state, &class_total_key(class))
        .unwrap_or_default()
        .amount
}

/// The total paid per class in stable assets, micro-dollars.
pub fn class_total_usd(state: &dyn VmState, class: &str) -> u128 {
    read_json::<Total>(state, &class_total_usd_key(class))
        .unwrap_or_default()
        .amount
}

/// The total paid to `account` in stable assets over all time, micro-dollars.
pub fn recipient_total_usd(state: &dyn VmState, account: &[u8]) -> u128 {
    read_json::<Total>(state, &recipient_total_usd_key(account))
        .unwrap_or_default()
        .amount
}

/// `limit` disbursements from `offset`, oldest first, with the totals per
/// class.
pub fn payout_report(state: &dyn VmState, offset: u64, limit: u64) -> PayoutReport {
    let count = payout_count(state);
    let records = (offset..count.min(offset.saturating_add(limit)))
        .filter_map(|n| read_json::<PayoutRecord>(state, &payout_key(n)))
        .collect();
    PayoutReport {
        count,
        by_class: CLASSES
            .iter()
            .map(|c| (c.to_string(), class_total(state, c).to_string()))
            .collect(),
        by_class_usd_e6: CLASSES
            .iter()
            .map(|c| (c.to_string(), class_total_usd(state, c).to_string()))
            .collect(),
        records,
    }
}
